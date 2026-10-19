from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime
from uuid import UUID

from app.models.vulnerability import Severity
from app.models.scan import ScanStatus


class ScanRequest(BaseModel):
    repo_url: str = Field(..., description="Target GitHub repository URL or local path to scan.")
    skip_ai: bool = Field(False, description="Whether to skip AI remediation analysis.")


class ScanHistoryItem(BaseModel):
    id: str
    repo_url: str
    status: str
    started_at: Optional[datetime]
    vuln_count: int


class RemediationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ai_model: str
    suggested_fix: Optional[str] = None
    remediation_steps: Optional[str] = None
    confidence_score: Optional[float] = None
    is_reviewed: bool


class VulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    severity: Severity
    vulnerability_type: str
    tool_vulnerability_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    description: Optional[str] = None
    raw_evidence: Optional[Dict[str, Any]] = None
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None
    remediations: List[RemediationResponse] = []


class FalsePositiveRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Optional reason for marking as false positive.")


class ScanStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    status: ScanStatus
    vuln_count: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    logs: Optional[str] = None


class ScanResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: ScanStatus
    vulnerabilities: List[VulnerabilityResponse] = []
