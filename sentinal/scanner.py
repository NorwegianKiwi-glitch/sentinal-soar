from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field

from .config import get_settings

log = logging.getLogger(__name__)


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


def _is_hypothetical(vuln: dict) -> bool:
    """A finding for a CVE that does not (yet) describe a real vulnerability.

    Two cases are suppressed so the user is not warned about "something that
    does not exist yet":
    - **Rejected** CVEs: the ID was withdrawn, so the vulnerability does not
      exist. NVD marks these with a "** REJECT" prefix in the description
      (newer records use a "Rejected reason:" prefix).
    - **Unpublished/reserved** CVEs: an ID is allocated but no advisory has
      been published yet (no PublishedDate), so there is nothing to act on.
    """
    if not vuln.get("PublishedDate"):
        return True
    description = (vuln.get("Description") or "").lstrip().upper()
    return description.startswith("REJECT") or "** REJECT" in description


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
    all_vulns = [
        vuln
        for result in report.get("Results") or []
        for vuln in result.get("Vulnerabilities") or []
    ]
    vulnerabilities = [v for v in all_vulns if not _is_hypothetical(v)]
    suppressed = len(all_vulns) - len(vulnerabilities)
    if suppressed:
        log.info("Suppressed %d rejected/unpublished CVE finding(s) for %s", suppressed, image)
    return ScanResult(image=image, vulnerabilities=vulnerabilities)
