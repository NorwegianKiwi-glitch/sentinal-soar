from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field

from .config import get_settings


@dataclass
class ScanResult:
    image: str
    vulnerabilities: list[dict] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.vulnerabilities)

    def summary_text(self, limit: int = 3000) -> str:
        lines = [
            f"- [{v.get('Severity')}] {v.get('VulnerabilityID')}: {v.get('PkgName')}"
            for v in self.vulnerabilities
        ]
        return "\n".join(lines)[:limit]


def scan_image(image: str) -> ScanResult:
    settings = get_settings()
    proc = subprocess.run(
        ["trivy", "image", "--severity", settings.trivy_severity, "--format", "json", "--quiet", image],
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )
    report = json.loads(proc.stdout or "{}")
    vulnerabilities = [
        vuln
        for result in report.get("Results") or []
        for vuln in result.get("Vulnerabilities") or []
    ]
    return ScanResult(image=image, vulnerabilities=vulnerabilities)
