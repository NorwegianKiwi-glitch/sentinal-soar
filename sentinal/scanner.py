from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field

from .config import get_settings

log = logging.getLogger(__name__)

_POLL_SECONDS = 1
_TIMEOUT_SECONDS = 300


class ScanCancelled(Exception):
    """Raised when a scan is stopped mid-run; the Trivy process is killed so a
    stopped scan does not have to wait out a multi-minute image pull + scan."""


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


def scan_image(image: str, cancel: threading.Event | None = None) -> ScanResult:
    report = _run_trivy(image, cancel)
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


def _run_trivy(image: str, cancel: threading.Event | None) -> dict:
    """Run Trivy to a temp file (stdout can be megabytes — a pipe would risk a
    buffer deadlock), polling so a set `cancel` kills the process promptly."""
    settings = get_settings()
    cmd = ["trivy", "image", "--severity", settings.trivy_severity, "--format", "json", "--quiet", image]
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(out_fd, "w") as out_file:
            proc = subprocess.Popen(cmd, stdout=out_file, stderr=subprocess.DEVNULL, text=True)
            deadline = time.monotonic() + _TIMEOUT_SECONDS
            while proc.poll() is None:
                if cancel is not None and cancel.is_set():
                    proc.kill()
                    proc.wait()
                    raise ScanCancelled(image)
                if time.monotonic() > deadline:
                    proc.kill()
                    proc.wait()
                    raise subprocess.TimeoutExpired(cmd, _TIMEOUT_SECONDS)
                time.sleep(_POLL_SECONDS)
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, cmd)
        with open(out_path) as result_file:
            return json.loads(result_file.read() or "{}")
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
