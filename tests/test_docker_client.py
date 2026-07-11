from __future__ import annotations

from unittest import mock

import pytest

from sentinal import docker_client


def test_pull_and_recreate_rejects_digest_pinned_images():
    client = mock.Mock()

    with pytest.raises(ValueError, match="digest"):
        docker_client.pull_and_recreate("sha256:" + "a" * 64, "whatever", client=client)

    client.images.pull.assert_not_called()


def test_pull_and_recreate_refuses_own_container(monkeypatch):
    client = mock.Mock()
    client.containers.get.return_value.id = "f" * 64
    monkeypatch.setattr(docker_client.socket, "gethostname", lambda: "f" * 12)

    with pytest.raises(RuntimeError, match="own container"):
        docker_client.pull_and_recreate("nginx:alpine", "sentinal-soar-app-1", client=client)

    client.images.pull.assert_not_called()
    client.containers.get.return_value.stop.assert_not_called()


def test_pull_and_recreate_converts_exposed_ports_for_sdk(monkeypatch):
    client = mock.Mock()
    old = client.containers.get.return_value
    old.id = "b" * 64
    old.attrs = {
        "Config": {"ExposedPorts": {"80/tcp": {}, "53/udp": {}}},
        "HostConfig": {"NetworkMode": "bridge"},
        "NetworkSettings": {"Networks": {"bridge": {}}},
    }
    client.api.create_container.return_value = {"Id": "c" * 64}
    monkeypatch.setattr(docker_client.socket, "gethostname", lambda: "not-a-container")

    docker_client.pull_and_recreate("nginx:alpine", "web", client=client)

    kwargs = client.api.create_container.call_args.kwargs
    assert sorted(kwargs["ports"]) == [("53", "udp"), ("80", "tcp")]
    assert "exposed_ports" not in kwargs
    old.remove.assert_called_once()


def test_pull_and_recreate_refuses_own_compose_stack(monkeypatch):
    own = mock.Mock()
    own.id = "f" * 64
    own.labels = {"com.docker.compose.project": "sentinal-soar"}
    target = mock.Mock()
    target.id = "b" * 64
    target.labels = {"com.docker.compose.project": "sentinal-soar"}
    client = mock.Mock()
    client.containers.get.side_effect = lambda name: own if name == "f" * 12 else target
    monkeypatch.setattr(docker_client.socket, "gethostname", lambda: "f" * 12)

    with pytest.raises(RuntimeError, match="own compose stack"):
        docker_client.pull_and_recreate("postgres:16-alpine", "sentinal-soar-db-1", client=client)

    client.images.pull.assert_not_called()
    target.stop.assert_not_called()


def test_pull_and_recreate_preserves_aliases_and_healthcheck(monkeypatch):
    client = mock.Mock()
    old = client.containers.get.return_value
    old.id = "b" * 64
    old.name = "mydb"
    old.attrs = {
        "Config": {
            "ExposedPorts": {"5432/tcp": {}},
            "Healthcheck": {"Test": ["CMD-SHELL", "pg_isready"]},
        },
        "HostConfig": {"NetworkMode": "stack_default"},
        "NetworkSettings": {
            "Networks": {
                # the short-id alias belongs to the old container and must be
                # dropped; the compose service aliases must survive
                "stack_default": {"Aliases": ["db", "b" * 12]},
                "extra_net": {"Aliases": ["cache-db", "b" * 12]},
            }
        },
    }
    client.api.create_container.return_value = {"Id": "c" * 64}
    monkeypatch.setattr(docker_client.socket, "gethostname", lambda: "not-a-container")

    docker_client.pull_and_recreate("postgres:16-alpine", "mydb", client=client)

    client.api.create_endpoint_config.assert_called_once_with(aliases=["db"])
    kwargs = client.api.create_container.call_args.kwargs
    assert kwargs["networking_config"] == client.api.create_networking_config.return_value
    assert kwargs["healthcheck"] == {"Test": ["CMD-SHELL", "pg_isready"]}
    client.api.connect_container_to_network.assert_called_once_with(
        "c" * 64, "extra_net", aliases=["cache-db"]
    )
