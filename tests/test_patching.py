from __future__ import annotations

from sentinal import patching


def test_digest_pinned_cannot_patch():
    assert patching.describe_patch("app@sha256:" + "a" * 64, None, None).can_patch is False
    p = patching.describe_patch("sha256:" + "b" * 64, None, None)
    assert p.can_patch is False
    assert "digest" in p.advice


def test_proposed_image_is_patchable():
    p = patching.describe_patch("redis:6.2.6", "redis:6.2.22", None)
    assert p.can_patch is True
    assert p.target == "redis:6.2.22"


def test_mutable_tag_is_patchable():
    p = patching.describe_patch("ghcr.io/x/app:latest", None, None)
    assert p.can_patch is True
    assert p.target == "ghcr.io/x/app:latest"


def test_major_only_non_database_advises_major_upgrade():
    p = patching.describe_patch(
        "ghcr.io/immich-app/immich-server:v2.7.5", None, "ghcr.io/immich-app/immich-server:v3.0.2"
    )
    assert p.can_patch is False
    assert "Major Upgrade" in p.advice


def test_major_only_database_advises_dump_restore():
    p = patching.describe_patch("postgres:14.2", None, "postgres:16")
    assert p.can_patch is False
    assert "dump/restore" in p.advice


def test_pinned_version_with_no_upgrade_advises_snooze_or_refuse():
    p = patching.describe_patch("vaultwarden/server:1.36.0", None, None)
    assert p.can_patch is False
    assert "Snooze" in p.advice and "Refuse" in p.advice


def test_is_database_image():
    assert patching.is_database_image("library/postgres") is True
    assert patching.is_database_image("immich-app/postgres") is True
    assert patching.is_database_image("n8nio/n8n") is False
