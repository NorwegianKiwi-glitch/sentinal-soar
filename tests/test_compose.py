from __future__ import annotations

from unittest import mock

import pytest

from sentinal import compose

IMMICH_STYLE = """name: test-immich
services:
  server:
    image: ghcr.io/immich-app/immich-server:v2.7.5
  ml:
    image: ghcr.io/immich-app/immich-machine-learning:v2.7.5
  database:
    image: ghcr.io/immich-app/postgres:14-vectorchord0.3.0
  cache:
    image: redis:6.2-alpine
"""


def _client(project, config_file):
    client = mock.Mock()
    client.containers.get.return_value.labels = {
        "com.docker.compose.project": project,
        "com.docker.compose.project.config_files": str(config_file),
    }
    return client


def _wire(monkeypatch, tmp_path, project="test-immich", own_project="sentinal-soar"):
    config = tmp_path / "docker-compose.yml"
    config.write_text(IMMICH_STYLE)
    monkeypatch.setattr(compose.docker_client, "get_client", lambda: _client(project, config))
    monkeypatch.setattr(compose.docker_client, "own_compose_project", lambda client=None: own_project)
    return config


def test_preview_lists_family_and_companions(tmp_path, monkeypatch):
    _wire(monkeypatch, tmp_path)

    project, family, companions = compose.preview_major_upgrade(
        "immich-server", "ghcr.io/immich-app/immich-server:v2.7.5"
    )

    assert project == "test-immich"
    assert family == [
        "ghcr.io/immich-app/immich-server:v2.7.5",
        "ghcr.io/immich-app/immich-machine-learning:v2.7.5",
    ]
    assert companions == ["ghcr.io/immich-app/postgres:14-vectorchord0.3.0", "redis:6.2-alpine"]


def test_apply_rewrites_family_and_composes_up(tmp_path, monkeypatch):
    config = _wire(monkeypatch, tmp_path)
    ups = []
    monkeypatch.setattr(compose, "_compose_up", lambda project, path: ups.append((project, str(path))) or "ok")

    project, details = compose.apply_major_upgrade(
        "ghcr.io/immich-app/immich-server:v3.0.2",
        "ghcr.io/immich-app/immich-server:v2.7.5",
        "immich-server",
    )

    text = config.read_text()
    assert project == "test-immich"
    assert "ghcr.io/immich-app/immich-server:v3.0.2" in text
    assert "ghcr.io/immich-app/immich-machine-learning:v3.0.2" in text
    # companions stay pinned
    assert "ghcr.io/immich-app/postgres:14-vectorchord0.3.0" in text
    assert "redis:6.2-alpine" in text
    assert (tmp_path / "docker-compose.yml.sentinal-bak").read_text() == IMMICH_STYLE
    assert ups == [("test-immich", str(config))]
    assert "→ ghcr.io/immich-app/immich-server:v3.0.2" in details
    assert "redis:6.2-alpine" in details  # companion warning included


def test_apply_refuses_own_stack(tmp_path, monkeypatch):
    _wire(monkeypatch, tmp_path, project="sentinal-soar", own_project="sentinal-soar")

    with pytest.raises(RuntimeError, match="own stack"):
        compose.apply_major_upgrade("a:2", "a:1", "sentinal-soar-db-1")


def test_apply_restores_definition_when_compose_up_fails(tmp_path, monkeypatch):
    config = _wire(monkeypatch, tmp_path, own_project=None)
    attempts: list[str] = []

    def _up(project, path):
        attempts.append(config.read_text())
        if len(attempts) == 1:
            raise RuntimeError("compose exploded")
        return "ok"

    monkeypatch.setattr(compose, "_compose_up", _up)

    with pytest.raises(RuntimeError, match="compose exploded"):
        compose.apply_major_upgrade(
            "ghcr.io/immich-app/immich-server:v3.0.2",
            "ghcr.io/immich-app/immich-server:v2.7.5",
            "immich-server",
        )

    assert "v3.0.2" in attempts[0]  # first attempt ran on the new definition
    assert config.read_text() == IMMICH_STYLE  # definition restored…
    assert "v2.7.5" in attempts[1]  # …and re-applied


def test_apply_rejects_non_compose_containers(monkeypatch):
    client = mock.Mock()
    client.containers.get.return_value.labels = {}
    monkeypatch.setattr(compose.docker_client, "get_client", lambda: client)

    with pytest.raises(RuntimeError, match="not created by compose"):
        compose.apply_major_upgrade("a:2", "a:1", "hand-rolled")
