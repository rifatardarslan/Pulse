import uuid
import enum
from datetime import datetime
from sqlalchemy import String, Enum, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Enums (ScanStatus & ScannerType): Veritabanına string yazmak yerine Enum 
#    kullanarak data integrity (veri bütünlüğü) sağlanır. Hatalı statü girilmesi engellenir.
# 2. docker_container_id: Tarama container'ının ID'sini tutmak, worker çöktüğünde 
#    veya timeout (zaman aşımı) olduğunda orphan (yetim) kalan container'ları 
#    tespit edip öldürmek (cleanup) için kritiktir.

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ScannerType(str, enum.Enum):
    GITLEAKS = "GITLEAKS"
    SEMGREP = "SEMGREP"

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    
    scanner_type: Mapped[ScannerType] = mapped_column(Enum(ScannerType), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    
    docker_container_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    logs: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
