import os
from celery import Celery
from celery.schedules import crontab

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "pulse_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.orchestration", "app.tasks.beat_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_soft_time_limit=3600,
    task_time_limit=3660,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    task_routes={
        "orchestration.run_scan_pipeline": {"queue": "scans"},
        "orchestration.trigger_enrichment_batch": {"queue": "ai"},
        "orchestration.process_ai_enrichment": {"queue": "ai"},
        "beat.check_and_trigger_schedules": {"queue": "scans"},
    },
    task_default_queue="scans",
    # Celery Beat — scheduled scan checker runs every minute
    beat_schedule={
        "check-scheduled-scans-every-minute": {
            "task": "beat.check_and_trigger_schedules",
            "schedule": crontab(minute="*"),
        },
    },
    beat_scheduler="celery.beat:PersistentScheduler",
    beat_schedule_filename="/tmp/celerybeat-schedule",
)
