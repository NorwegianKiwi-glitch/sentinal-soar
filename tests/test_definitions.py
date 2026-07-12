from __future__ import annotations

from unittest import mock

from sentinal import definitions


def test_rewrite_replaces_exact_references_only():
    text = (
        "image: vaultwarden/server:1.32.7\n"
        'quoted: "vaultwarden/server:1.32.7"\n'
        "longer-tag: vaultwarden/server:1.32.75\n"
        "different-repo: ghcr.io/x/vaultwarden/server:1.32.7\n"
    )

    rewritten, count = definitions._rewrite_image_reference(
        text, "vaultwarden/server:1.32.7", "vaultwarden/server:1.36.0"
    )

    assert count == 2
    assert "image: vaultwarden/server:1.36.0" in rewritten
    assert '"vaultwarden/server:1.36.0"' in rewritten
    # neither the longer tag nor the other repository may be touched
    assert "vaultwarden/server:1.32.75" in rewritten
    assert "ghcr.io/x/vaultwarden/server:1.32.7" in rewritten


def _client_with_labels(labels):
    client = mock.Mock()
    client.containers.get.return_value.labels = labels
    return client


def test_sync_rewrites_file_and_keeps_backup(tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  redis-nextcloud:\n    image: redis:6.2.6\n")
    monkeypatch.setattr(
        definitions.docker_client,
        "get_client",
        lambda: _client_with_labels({"com.docker.compose.project.config_files": str(compose)}),
    )

    note = definitions.sync_image_reference("redis-nextcloud", "redis:6.2.6", "redis:6.2.22")

    assert "Updated 1 image reference(s)" in note
    assert "image: redis:6.2.22" in compose.read_text()
    assert "image: redis:6.2.6" in (tmp_path / "docker-compose.yml.sentinal-bak").read_text()


def test_sync_reports_unreachable_definition(monkeypatch):
    monkeypatch.setattr(
        definitions.docker_client,
        "get_client",
        lambda: _client_with_labels(
            {"com.docker.compose.project.config_files": "/nowhere/docker-compose.yml"}
        ),
    )

    note = definitions.sync_image_reference("app", "a:1", "a:2")

    assert "not reachable" in note
    assert "manually" in note


def test_sync_handles_non_compose_containers(monkeypatch):
    monkeypatch.setattr(definitions.docker_client, "get_client", lambda: _client_with_labels({}))

    note = definitions.sync_image_reference("app", "a:1", "a:2")

    assert "not created by compose" in note


def test_sync_never_raises(monkeypatch):
    def _boom():
        raise RuntimeError("docker socket unavailable")

    monkeypatch.setattr(definitions.docker_client, "get_client", _boom)

    note = definitions.sync_image_reference("app", "a:1", "a:2")

    assert "Definition sync failed" in note
    assert "manually" in note
