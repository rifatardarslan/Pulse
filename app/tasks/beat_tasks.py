import asyncio
import logging
from datetime import datetime, timezone

from app.tasks.worker import celery_app

logger = logging.getLogger(__name__)

_MAX_ERRORS_BEFORE_PAUSE = 5


@celery_app.task(name="beat.check_and_trigger_schedules")
def check_and_trigger_schedules():
    """Runs every minute via Celery Beat. Fires scan tasks for due schedules."""
    asyncio.run(_check_schedules_async())


async def _check_schedules_async():
    from app.core import database
    from app.models.schedule import Schedule, ScheduleStatus
    from app.models.scan import Scan, ScanStatus, ScannerType
    from app.tasks.orchestration import run_scan_pipeline
    from sqlalchemy.future import select
    from sqlalchemy.orm import selectinload

    async with database.AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        stmt = (
            select(Schedule)
            .where(Schedule.status == ScheduleStatus.ACTIVE, Schedule.next_run_at <= now)
            .options(selectinload(Schedule.project))
        )
        result = await session.execute(stmt)
        due_schedules = result.scalars().all()

        for sched in due_schedules:
            sched_id = sched.id  # cache PK — accessible even after rollback/expiry

            try:
                project = sched.project
                if not project:
                    continue

                # Compute next_run BEFORE any DB writes so a bad cron expression
                # won't leave the schedule with next_run_at=None after dispatch.
                try:
                    from croniter import croniter
                    next_run = croniter(sched.cron_expression, now).get_next(datetime)
                except Exception:
                    next_run = None

                scan = Scan(
                    project_id=project.id,
                    scanner_type=ScannerType.GITLEAKS,
                    status=ScanStatus.PENDING,
                    started_at=now,
                )
                session.add(scan)
                await session.flush()

                run_scan_pipeline.delay(str(project.id), str(scan.id), skip_ai=sched.skip_ai)

                sched.last_run_at = now
                sched.last_scan_id = scan.id
                sched.run_count += 1
                sched.next_run_at = next_run

                if next_run is None:
                    sched.error_count = (sched.error_count or 0) + 1
                    sched.last_error = "croniter failed to compute next_run_at — check cron expression."
                    logger.warning("Schedule %s has invalid cron expression, next_run_at set to None.", sched_id)

                await session.commit()
                logger.info("Scheduled scan triggered: project=%s scan=%s", project.id, scan.id)

            except Exception as exc:
                await session.rollback()
                logger.error("Scheduled scan failed for schedule %s: %s", sched_id, exc)

                # After rollback all ORM objects are expired — re-fetch to avoid MissingGreenlet.
                try:
                    fresh = await session.get(Schedule, sched_id)
                    if fresh:
                        fresh.error_count = (fresh.error_count or 0) + 1
                        fresh.last_error = str(exc)
                        # Only lock after repeated failures; a single infra blip shouldn't
                        # permanently disable a schedule.
                        if fresh.error_count >= _MAX_ERRORS_BEFORE_PAUSE:
                            fresh.status = ScheduleStatus.ERROR
                            logger.error(
                                "Schedule %s locked in ERROR after %d consecutive failures.",
                                sched_id,
                                fresh.error_count,
                            )
                        await session.commit()
                except Exception as inner:
                    logger.error("Could not persist error state for schedule %s: %s", sched_id, inner)
