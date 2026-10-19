from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from uuid import UUID
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.schedule import Schedule, ScheduleStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus, ScannerType
from app.schemas.schedule import ScheduleCreateRequest, ScheduleUpdateRequest, ScheduleResponse
from app.api.deps import verify_api_key
from app.tasks.orchestration import run_scan_pipeline

router = APIRouter()


def _compute_next_run(cron_expr: str, base: datetime) -> datetime:
    from croniter import croniter
    if not croniter.is_valid(cron_expr):
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail=f"Invalid cron expression: '{cron_expr}'")
    return croniter(cron_expr, base).get_next(datetime)


@router.post("/", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    request: ScheduleCreateRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Create a scheduled scan for a repository."""
    result = await db.execute(select(Project).where(Project.repo_url == request.repo_url))
    project = result.scalar_one_or_none()
    if not project:
        project = Project(repo_url=request.repo_url, name="Auto-Generated")
        db.add(project)
        await db.commit()
        await db.refresh(project)

    now = datetime.now(timezone.utc)
    next_run = _compute_next_run(request.cron_expression, now)

    schedule = Schedule(
        project_id=project.id,
        cron_expression=request.cron_expression,
        skip_ai=request.skip_ai,
        next_run_at=next_run,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.get("/", response_model=List[ScheduleResponse])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """List all schedules."""
    result = await db.execute(select(Schedule).order_by(Schedule.created_at.desc()))
    return result.scalars().all()


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return schedule


@router.patch("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    request: ScheduleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Update schedule cron expression, status (ACTIVE/PAUSED), or skip_ai flag."""
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found.")

    if request.cron_expression is not None:
        schedule.cron_expression = request.cron_expression
        schedule.next_run_at = _compute_next_run(request.cron_expression, datetime.now(timezone.utc))
    if request.status is not None:
        schedule.status = ScheduleStatus(request.status)
    if request.skip_ai is not None:
        schedule.skip_ai = request.skip_ai

    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    await db.delete(schedule)
    await db.commit()


@router.post("/{schedule_id}/run", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def trigger_schedule_now(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Immediately trigger a scheduled scan outside its normal cron window."""
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found.")

    project = await db.get(Project, schedule.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")

    scan = Scan(
        project_id=project.id,
        scanner_type=ScannerType.GITLEAKS,
        status=ScanStatus.PENDING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    task = run_scan_pipeline.delay(str(project.id), str(scan.id), skip_ai=schedule.skip_ai)

    schedule.last_run_at = datetime.now(timezone.utc)
    schedule.last_scan_id = scan.id
    schedule.run_count += 1
    await db.commit()

    return {"message": "Scan triggered.", "scan_id": str(scan.id), "task_id": str(task.id)}
