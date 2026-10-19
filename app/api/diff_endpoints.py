from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from uuid import UUID

from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.api.deps import verify_api_key
from app.services.diff_service import compute_scan_diff
from app.schemas.diff import ScanDiffResponse, DiffSummary

router = APIRouter()


async def _get_scan_or_404(scan_id: UUID, session: AsyncSession) -> Scan:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.get("/{scan_id}/diff", response_model=ScanDiffResponse)
async def diff_vs_previous(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Diff current scan against the most recent previous completed scan of the same project."""
    current = await _get_scan_or_404(scan_id, db)

    stmt = (
        select(Scan)
        .where(
            Scan.project_id == current.project_id,
            Scan.id != scan_id,
            Scan.status == ScanStatus.COMPLETED,
            Scan.started_at < current.started_at,
        )
        .order_by(Scan.started_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    previous = result.scalars().first()

    if not previous:
        return ScanDiffResponse(
            current_scan_id=scan_id,
            previous_scan_id=scan_id,
            is_first_scan=True,
            summary=DiffSummary(new_count=0, fixed_count=0, persisting_count=0),
        )

    diff = await compute_scan_diff(scan_id, previous.id, db)
    return ScanDiffResponse(
        current_scan_id=scan_id,
        previous_scan_id=previous.id,
        is_first_scan=False,
        new=diff["new"],
        fixed=diff["fixed"],
        persisting=diff["persisting"],
        summary=DiffSummary(**diff["summary"]),
    )


@router.get("/{scan_id}/diff/{other_scan_id}", response_model=ScanDiffResponse)
async def diff_explicit(
    scan_id: UUID,
    other_scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Diff two specific scans (scan_id = current, other_scan_id = previous baseline)."""
    await _get_scan_or_404(scan_id, db)
    await _get_scan_or_404(other_scan_id, db)

    diff = await compute_scan_diff(scan_id, other_scan_id, db)
    return ScanDiffResponse(
        current_scan_id=scan_id,
        previous_scan_id=other_scan_id,
        is_first_scan=False,
        new=diff["new"],
        fixed=diff["fixed"],
        persisting=diff["persisting"],
        summary=DiffSummary(**diff["summary"]),
    )
