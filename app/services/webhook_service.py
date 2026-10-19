import os
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
_WEBHOOK_TIMEOUT = int(os.getenv("WEBHOOK_TIMEOUT", "10"))


async def send_scan_webhook(
    *,
    scan_id: str,
    repo_url: str,
    status: str,
    vuln_count: int,
    critical_count: int,
    high_count: int,
    scan_duration_seconds: float,
    webhook_url: Optional[str] = None,
) -> bool:
    """
    POSTs a scan completion event to the configured webhook URL.
    Payload is generic JSON with an embedded 'blocks' field for Slack compatibility.
    Returns True on HTTP 2xx, False otherwise.
    """
    target_url = webhook_url or _WEBHOOK_URL
    if not target_url:
        return False

    timestamp = datetime.now(timezone.utc).isoformat()
    severity_line = f"{vuln_count} total ({critical_count} CRITICAL, {high_count} HIGH)"
    status_emoji = "✅" if status == "COMPLETED" else "❌"

    payload = {
        "event": "scan.completed",
        "scan_id": scan_id,
        "repo_url": repo_url,
        "status": status,
        "vuln_count": vuln_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "scan_duration_seconds": round(scan_duration_seconds, 1),
        "timestamp": timestamp,
        # Slack blocks format for direct Slack webhook compatibility
        "text": f"{status_emoji} Pulse Scan {status}: {repo_url}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Pulse Security Scan {status}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repository:*\n{repo_url}"},
                    {"type": "mrkdwn", "text": f"*Vulnerabilities:*\n{severity_line}"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{scan_duration_seconds:.0f}s"},
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id[:8]}`"},
                ],
            },
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=_WEBHOOK_TIMEOUT) as client:
            response = await client.post(target_url, json=payload)
            success = response.status_code < 300
            if not success:
                logger.warning("Webhook POST failed: %s %s", response.status_code, response.text[:200])
            return success
    except Exception as exc:
        logger.error("Webhook delivery error: %s", exc)
        return False
