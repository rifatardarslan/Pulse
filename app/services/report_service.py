import os
from datetime import datetime, timezone
from uuid import UUID
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "j2"]),
)


async def generate_html_report(scan_id: UUID, session: AsyncSession) -> Optional[str]:
    """Renders an HTML security report for the given scan. Returns None if scan not found."""
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.project),
            selectinload(Scan.vulnerabilities).selectinload(Vulnerability.remediations),
        )
    )
    result = await session.execute(stmt)
    scan = result.scalars().first()
    if not scan:
        return None

    vulns = scan.vulnerabilities or []
    real_vulns = [v for v in vulns if not v.is_false_positive]
    fp_vulns = [v for v in vulns if v.is_false_positive]

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in real_vulns:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        if sev in counts:
            counts[sev] += 1

    risk_score = (
        counts["CRITICAL"] * 10
        + counts["HIGH"] * 5
        + counts["MEDIUM"] * 2
        + counts["LOW"] * 1
    )

    ai_vulns = []
    for v in real_vulns:
        if v.remediations:
            ai_vulns.append({"vuln": v, "rem": v.remediations[0]})

    repo_url = scan.project.repo_url if scan.project else str(scan_id)

    started_at = "N/A"
    duration = "N/A"
    if scan.started_at:
        started_at = scan.started_at.strftime("%Y-%m-%d %H:%M UTC")
    if scan.started_at and scan.finished_at:
        secs = int((scan.finished_at - scan.started_at).total_seconds())
        duration = f"{secs}s"

    scanners_run = scan.scanners_run or {}
    active_scanners = [k for k, v in scanners_run.items() if v]
    scanners_str = ", ".join(active_scanners).upper() if active_scanners else "Gitleaks, pip-audit"

    template = _jinja_env.get_template("report.html.j2")
    return template.render(
        scan_id=str(scan_id),
        repo_url=repo_url,
        started_at=started_at,
        duration=duration,
        scanners=scanners_str,
        counts=counts,
        risk_score=risk_score,
        real_vulns=real_vulns,
        fp_vulns=fp_vulns,
        ai_vulns=ai_vulns,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
