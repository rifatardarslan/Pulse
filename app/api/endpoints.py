from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.encoders import jsonable_encoder
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from uuid import UUID
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.scan import (
    ScanRequest, ScanStatusResponse, ScanResultResponse, ScanHistoryItem,
    FalsePositiveRequest, VulnerabilityResponse,
)
from app.tasks.orchestration import run_scan_pipeline
from app.tasks.worker import celery_app
from app.api.deps import verify_api_key
from celery.result import AsyncResult

router = APIRouter()

@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_202_ACCEPTED)
async def create_scan(request: ScanRequest, db: AsyncSession = Depends(get_db), _: str = Depends(verify_api_key)):
    """
    Fire-and-Forget: Taramayı kuyruğa ekler ve anında task_id ile döner.
    Taramayı beklemez — polling ile takip edilir.
    """
    repo_url_str = request.repo_url
    
    # Local paths and GitHub both supported
    # (Validation happened in CLI)

    # 1. Önce projeyi veritabanında ara
    result = await db.execute(select(Project).where(Project.repo_url == repo_url_str))
    project = result.scalar_one_or_none()

    # 2. Yoksa oluştur ve MUTLAKA COMMIT ET
    if not project:
        project = Project(repo_url=repo_url_str, name="Auto-Generated")
        db.add(project)
        await db.commit()
        await db.refresh(project)

    # 3. Create Scan object immediately
    from app.models.scan import ScannerType, ScanStatus
    from datetime import datetime, timezone
    
    scan = Scan(
        project_id=project.id,
        scanner_type=ScannerType.GITLEAKS,
        status=ScanStatus.PENDING,
        started_at=datetime.now(timezone.utc)
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # 4. Görevi kuyruğa ekle
    task = run_scan_pipeline.delay(str(project.id), str(scan.id), skip_ai=request.skip_ai)
    
    return {
        "message": "Task accepted. Tarama kuyruğa alındı.",
        "task_id": str(task.id),
        "scan_id": str(scan.id)
    }


@router.get("/status/{task_id}", response_model=Dict[str, Any])
async def get_task_status(task_id: str, db: AsyncSession = Depends(get_db), _: str = Depends(verify_api_key)):
    """
    Celery task durumunu polling ile sorgular.
    """
    result = AsyncResult(task_id, app=celery_app)
    
    response = {
        "task_id": task_id,
        "state": result.state,
    }
    
    if result.state == "SUCCESS":
        task_result = result.result
        response["result"] = task_result
        if isinstance(task_result, dict):
            response["scan_id"] = task_result.get("scan_id")
            response["vuln_count"] = task_result.get("vuln_count", 0)
            response["state"] = "SUCCESS"
            
    elif result.state == "FAILURE":
        response["error"] = str(result.result) if result.result else "Unknown error"
    
    elif result.state == "STARTED":
        # Proaktif kontrol: Eğer DB'de bulgular oluşmaya başladıysa bildir
        # (Not: CLI zaten scan_id'yi biliyor ama biz de destek veriyoruz)
        pass
    
    return response


@router.get("/all", response_model=List[ScanHistoryItem])
async def list_scans(db: AsyncSession = Depends(get_db), _: str = Depends(verify_api_key)):
    """
    Sistemdeki tüm taramaları (Scans) en yeniden en eskiye doğru listeler.
    """
    stmt = select(Scan).options(selectinload(Scan.project), selectinload(Scan.vulnerabilities)).order_by(Scan.started_at.desc()).limit(50)
    result = await db.execute(stmt)
    scans = result.scalars().all()
    
    history = []
    for s in scans:
        history.append({
            "id": str(s.id),
            "repo_url": s.project.repo_url if s.project else "N/A",
            "status": s.status.value if s.status else "N/A",
            "started_at": s.started_at,
            "vuln_count": len(s.vulnerabilities) if s.vulnerabilities else 0
        })
    return jsonable_encoder(history)


@router.get("/project/{project_id}/latest", response_model=ScanStatusResponse)
async def get_latest_scan_by_project(project_id: UUID, db: AsyncSession = Depends(get_db), _: str = Depends(verify_api_key)):
    """
    Belirli bir projenin en son taramasını döndürür. (CLI polling için gereklidir)
    """
    stmt = select(Scan).where(Scan.project_id == project_id).order_by(Scan.started_at.desc())
    result = await db.execute(stmt)
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(status_code=404, detail="Proje için henüz bir tarama bulunamadı.")

    return scan

@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: UUID, db: AsyncSession = Depends(get_db), _: str = Depends(verify_api_key)):
    """
    Verilen Scan ID'sine ait güncel durumu döner.
    """
    stmt = select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.vulnerabilities))
    result = await db.execute(stmt)
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(status_code=404, detail="Geçersiz Scan ID. Tarama bulunamadı.")

    # Pydantic schema expects vuln_count
    scan.vuln_count = len(scan.vulnerabilities) if scan.vulnerabilities else 0

    return scan

@router.get("/{scan_id}/results", response_model=ScanResultResponse)
async def get_scan_results(scan_id: UUID, db: AsyncSession = Depends(get_db), _: str = Depends(verify_api_key)):
    """
    Tarama tamamlandıysa, bulunan tüm zafiyetleri (Vulnerabilities) ve onlara
    ait olan AI çözüm önerilerini (Remediations) ağaç (nested) formatında getirir.
    """
    # N+1 Query problemini önlemek için ilişkileri tek sorguda (Eager Load) getir.
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.vulnerabilities).selectinload(Vulnerability.remediations)
        )
    )
    result = await db.execute(stmt)
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(status_code=404, detail="Geçersiz Scan ID. Tarama bulunamadı.")

    return scan


@router.patch("/{scan_id}/vulnerabilities/{vuln_id}/false-positive", response_model=VulnerabilityResponse)
async def toggle_false_positive(
    scan_id: UUID,
    vuln_id: UUID,
    request: FalsePositiveRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Toggle a vulnerability's false positive status. Acts as a toggle: FP→not FP, not FP→FP."""
    stmt = (
        select(Vulnerability)
        .where(Vulnerability.id == vuln_id, Vulnerability.scan_id == scan_id)
        .options(selectinload(Vulnerability.remediations))
    )
    result = await db.execute(stmt)
    vuln = result.scalar_one_or_none()

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found in this scan.")

    vuln.is_false_positive = not vuln.is_false_positive
    if vuln.is_false_positive:
        vuln.false_positive_reason = request.reason
        vuln.false_positive_marked_at = datetime.now(timezone.utc)
    else:
        vuln.false_positive_reason = None
        vuln.false_positive_marked_at = None

    await db.commit()
    await db.refresh(vuln)
    return vuln


@router.get("/{scan_id}/false-positives", response_model=List[VulnerabilityResponse])
async def list_false_positives(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """List all false positive vulnerabilities for a scan."""
    stmt = (
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id, Vulnerability.is_false_positive == True)
        .options(selectinload(Vulnerability.remediations))
    )
    result = await db.execute(stmt)
    return result.scalars().all()
