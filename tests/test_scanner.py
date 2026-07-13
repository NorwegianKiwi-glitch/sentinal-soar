from __future__ import annotations

import threading

import pytest

from sentinal import scanner


def _vuln(cid, published="2026-01-01T00:00:00Z", desc="A real bug", **extra):
    v = {
        "VulnerabilityID": cid,
        "Severity": "HIGH",
        "PkgName": "libx",
        "PublishedDate": published,
        "Description": desc,
    }
    v.update(extra)
    return v


def test_is_hypothetical_flags_rejected_and_unpublished():
    assert scanner._is_hypothetical(_vuln("CVE-1", desc="** REJECT ** DO NOT USE")) is True
    assert scanner._is_hypothetical(_vuln("CVE-2", desc="Rejected reason: not a real bug")) is True
    assert scanner._is_hypothetical(_vuln("CVE-3", published=None)) is True
    assert scanner._is_hypothetical(_vuln("CVE-3b", published="")) is True
    # a normal published, non-rejected finding survives
    assert scanner._is_hypothetical(_vuln("CVE-4")) is False


def test_scan_image_filters_hypothetical(monkeypatch):
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    _vuln("CVE-REAL"),
                    _vuln("CVE-REJECT", desc="** REJECT ** withdrawn"),
                    _vuln("CVE-RESERVED", published=None),
                ]
            }
        ]
    }
    monkeypatch.setattr(scanner, "_run_trivy", lambda image, cancel=None: report)

    result = scanner.scan_image("some/image:1.0")

    assert [v["VulnerabilityID"] for v in result.vulnerabilities] == ["CVE-REAL"]
    assert result.has_findings is True


def test_scan_image_all_hypothetical_means_clean(monkeypatch):
    report = {
        "Results": [
            {"Vulnerabilities": [_vuln("CVE-REJECT", desc="** REJECT **"), _vuln("CVE-RESERVED", published=None)]}
        ]
    }
    monkeypatch.setattr(scanner, "_run_trivy", lambda image, cancel=None: report)

    result = scanner.scan_image("some/image:1.0")

    assert result.vulnerabilities == []
    assert result.has_findings is False


class _NeverExitsProc:
    """A Trivy process that keeps running until killed — models a slow scan."""

    def __init__(self, *a, **k):
        self.returncode = None

    def poll(self):
        return None

    def kill(self):
        self.returncode = -9

    def wait(self):
        return self.returncode


def test_scan_image_raises_scancancelled_when_cancel_is_set(monkeypatch):
    monkeypatch.setattr(scanner.subprocess, "Popen", _NeverExitsProc)
    cancel = threading.Event()
    cancel.set()

    with pytest.raises(scanner.ScanCancelled):
        scanner.scan_image("some/image:1.0", cancel=cancel)
