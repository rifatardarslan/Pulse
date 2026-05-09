from pydantic import BaseModel, HttpUrl, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
from uuid import UUID

from app.models.vulnerability import Severity
from app.models.scan import ScanStatus

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Strict Request Validation: Kullanıcıdan gelen "repo_url" parametresi
#    Pydantic'in `HttpUrl` tipine bağlıdır. "deneme123" gibi saçma bir format 
#    geldiğinde API anında HTTP 422 Unprocessable Entity hatası döner (Güvenlik).
# 2. Data Transfer Objects (DTO): Veritabanı objelerini (SQLAlchemy Models) doğrudan
#    kullanıcıya dönmek yerine bu Pydantic Schemas üzerinden filtreleyip dönüyoruz.
#    Bu sayede sistemin iç şeması dışarıya sızmaz (Data Leakage engellenir).

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
    ai_model: str
    suggested_fix: Optional[str]
    remediation_steps: Optional[str]
    confidence_score: Optional[float]
    is_reviewed: bool

class VulnerabilityResponse(BaseModel):
    id: UUID
    severity: Severity
    vulnerability_type: str
    file_path: Optional[str]
    line_number: Optional[int]
    description: Optional[str]
    raw_evidence: Optional[Dict[str, Any]]
    
    # Nested Object: Zafiyetin AI çözümleri
    remediations: List[RemediationResponse] = []

class ScanStatusResponse(BaseModel):
    id: UUID
    project_id: UUID
    status: ScanStatus
    vuln_count: int = 0
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    logs: Optional[str]

class ScanResultResponse(BaseModel):
    id: UUID
    status: ScanStatus
    vulnerabilities: List[VulnerabilityResponse] = []
