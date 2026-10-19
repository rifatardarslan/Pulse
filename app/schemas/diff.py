from pydantic import BaseModel, ConfigDict
from typing import List
from uuid import UUID

from app.schemas.scan import VulnerabilityResponse


class DiffSummary(BaseModel):
    new_count: int
    fixed_count: int
    persisting_count: int


class ScanDiffResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    current_scan_id: UUID
    previous_scan_id: UUID
    is_first_scan: bool = False
    new: List[VulnerabilityResponse] = []
    fixed: List[VulnerabilityResponse] = []
    persisting: List[VulnerabilityResponse] = []
    summary: DiffSummary
