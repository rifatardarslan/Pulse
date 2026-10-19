from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional
from datetime import datetime
from uuid import UUID


class ScheduleCreateRequest(BaseModel):
    repo_url: str = Field(..., description="Repository URL to scan on schedule.")
    cron_expression: str = Field(..., description="Cron expression, e.g. '0 2 * * *'.")
    skip_ai: bool = Field(False, description="Skip AI remediation for scheduled scans.")

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        try:
            from croniter import croniter
            if not croniter.is_valid(v):
                raise ValueError("Invalid cron expression.")
        except ImportError:
            pass  # croniter not available; skip validation
        return v


class ScheduleUpdateRequest(BaseModel):
    cron_expression: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(ACTIVE|PAUSED)$")
    skip_ai: Optional[bool] = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            from croniter import croniter
            if not croniter.is_valid(v):
                raise ValueError("Invalid cron expression.")
        except ImportError:
            pass
        return v


class ScheduleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    cron_expression: str
    status: str
    skip_ai: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    run_count: int
    error_count: int
    created_at: datetime
