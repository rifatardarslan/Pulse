import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Type Hinting (Mapped[T]): Python 3.12 ile tam uyumlu, IDE'lerde kusursuz 
#    autocomplete ve Mypy/Pyright gibi statik analiz araçlarıyla %100 tip güvenliği sağlar.
# 2. UUID Primary Key: Distributed sistemlerde (farklı worker'ların aynı anda veri 
#    yazması) çakışmaları önler ve Insecure Direct Object Reference (IDOR) 
#    zafiyetlerini zorlaştırır (Tahmin edilemez ID'ler).

class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    branch: Mapped[str] = mapped_column(String(255), default="main")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationship
    # cascade="all, delete-orphan": Proje silindiğinde ona ait tüm taramalar da DB'den temizlenir.
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
