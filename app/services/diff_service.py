from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.vulnerability import Vulnerability
from app.models.scan import Scan


def _vuln_key(v: Vulnerability) -> tuple:
    """Strict match: file_path + tool_vulnerability_id + line_number."""
    return (
        (v.file_path or "").strip(),
        (v.tool_vulnerability_id or "").strip(),
        v.line_number or 0,
    )


async def compute_scan_diff(
    current_scan_id: UUID,
    previous_scan_id: UUID,
    session: AsyncSession,
) -> dict:
    """
    Compares vulnerability sets between two scans of the same project.
    Matching strategy: file_path + tool_vulnerability_id + line_number (strict).
    False positives are excluded from all categories.
    """
    async def _load_vulns(scan_id: UUID):
        stmt = (
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan_id, Vulnerability.is_false_positive == False)
            .options(selectinload(Vulnerability.remediations))
        )
        result = await session.execute(stmt)
        return result.scalars().all()

    current_vulns = await _load_vulns(current_scan_id)
    previous_vulns = await _load_vulns(previous_scan_id)

    current_keys = {_vuln_key(v): v for v in current_vulns}
    previous_keys = {_vuln_key(v): v for v in previous_vulns}

    new_vulns = [v for k, v in current_keys.items() if k not in previous_keys]
    fixed_vulns = [v for k, v in previous_keys.items() if k not in current_keys]
    persisting_vulns = [v for k, v in current_keys.items() if k in previous_keys]

    return {
        "new": new_vulns,
        "fixed": fixed_vulns,
        "persisting": persisting_vulns,
        "summary": {
            "new_count": len(new_vulns),
            "fixed_count": len(fixed_vulns),
            "persisting_count": len(persisting_vulns),
        },
    }
