from __future__ import annotations

import docker
from docker.models.containers import Container

from .config import get_settings


def get_client() -> docker.DockerClient:
    settings = get_settings()
    return docker.DockerClient(base_url=settings.docker_socket)


def list_containers(client: docker.DockerClient | None = None) -> list[Container]:
    client = client or get_client()
    return client.containers.list(all=True)


def pull_and_restart(image: str, container_name: str, client: docker.DockerClient | None = None) -> None:
    # restart() reuses the container's original image, not the freshly pulled tag — recreation, not restart, is the correct long-term fix (see ARCHITECTURE.md)
    client = client or get_client()
    client.images.pull(image)
    container = client.containers.get(container_name)
    container.restart()
