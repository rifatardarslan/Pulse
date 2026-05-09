import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Text, Float, Boolean, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. AI Output Isolation: Remediation'ı Vulnerability içine bir JSON kolonu olarak
#    basmak yerine ayrı model olarak tasarladım. Bu sayede, aynı zafiyete Llama3'ün 
#    ve GPT-4'ün verdiği farklı çözümleri aynı anda tutup "A/B Testing" yapabiliriz.
# 2. Confidence & Review: AI'ın kendi ürettiği çözüme olan güvenini (confidence_score) 
#    ve bir güvenlik mühendisinin (Security Engineer) bunu onaylayıp onaylamadığını
#    (is_reviewed) tutmak, sistemi "sadece otomatize" değil "güvenilir" kılar.

class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    
    ai_model: Mapped[str] = mapped_column(String(64), nullable=False) # e.g., "llama3", "gpt-4o"
    
    suggested_fix: Mapped[str | None] = mapped_column(Text, nullable=True) # AI tarafından üretilen kod/config bloğu
    remediation_steps: Mapped[str | None] = mapped_column(Text, nullable=True) # Adım adım talimatlar
    
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True) # 0.0 - 1.0 arası güven skoru
    is_reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="remediations")
