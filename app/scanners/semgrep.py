import json
import uuid
import asyncio
from typing import Any, Dict, List

from app.scanners.base import BaseScanner

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner — runs semgrep directly as a subprocess."""

    def __init__(self, scan_id: uuid.UUID, target_dir: str):
        super().__init__(scan_id, target_dir)

    async def prepare_container(self) -> Dict[str, Any]:
        # Semgrep runs as a direct subprocess, not in a Docker container.
        return {
            "command": ["semgrep", "--config", "auto", "--json", "--quiet", "--timeout", "120", "."],
            "cwd": self.target_dir,
        }

    async def execute(self) -> tuple[int, str]:
        cmd = ["semgrep", "--config", "auto", "--json", "--quiet", "--timeout", "120", "."]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.target_dir,
        )
        stdout, _ = await process.communicate()
        return process.returncode or 0, stdout.decode("utf-8", errors="replace")

    async def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output.strip():
            return []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []

        findings = []
        for result in data.get("results", []):
            raw_sev = result.get("extra", {}).get("severity", "INFO").upper()
            severity = SEVERITY_MAP.get(raw_sev, "LOW")
            findings.append({
                "tool_vulnerability_id": result.get("check_id", "unknown-rule"),
                "severity": severity,
                "vulnerability_type": "sast-finding",
                "file_path": result.get("path", "unknown"),
                "line_number": result.get("start", {}).get("line", 0),
                "description": result.get("extra", {}).get("message", "SAST finding detected"),
                "raw_evidence": result,
            })
        return findings
