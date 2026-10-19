from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.core.database import get_db
from app.api.deps import verify_api_key
from app.services.report_service import generate_html_report

router = APIRouter()


@router.get("/{scan_id}/report", response_class=HTMLResponse)
async def get_scan_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Generate and download an HTML security report for a completed scan."""
    html = await generate_html_report(scan_id, db)
    if html is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return HTMLResponse(content=html, status_code=200)
