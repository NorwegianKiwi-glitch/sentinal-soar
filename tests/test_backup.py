from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinal import backup


def _proc(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_returns_snapshot_id(monkeypatch):
    monkeypatch.setattr(
        backup.subprocess,
        "run",
        lambda *a, **k: _proc(stdout="processed 42 GiB\nsnapshot 59990d27 saved\n=== done ==="),
    )

    assert backup.run_pre_upgrade_backup("immich-server") == "59990d27"


def test_script_failure_raises(monkeypatch):
    monkeypatch.setattr(backup.subprocess, "run", lambda *a, **k: _proc(returncode=1, stderr="disk full"))

    with pytest.raises(RuntimeError, match="disk full"):
        backup.run_pre_upgrade_backup("immich-server")


def test_missing_snapshot_id_raises(monkeypatch):
    monkeypatch.setattr(backup.subprocess, "run", lambda *a, **k: _proc(stdout="did some things"))

    with pytest.raises(RuntimeError, match="no snapshot id"):
        backup.run_pre_upgrade_backup("immich-server")


def test_tags_the_snapshot_with_the_app_name(monkeypatch):
    commands = []
    monkeypatch.setattr(
        backup.subprocess,
        "run",
        lambda cmd, **k: commands.append(cmd) or _proc(stdout="snapshot abcdef12 saved"),
    )

    backup.run_pre_upgrade_backup("n8n")

    assert commands == [["bash", "/usr/local/bin/sentinal-backup.sh", "pre-upgrade-n8n"]]
