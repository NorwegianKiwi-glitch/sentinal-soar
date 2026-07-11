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


def pull_and_recreate(image: str, container_name: str, client: docker.DockerClient | None = None) -> None:
    """Pull `image` and recreate `container_name` from it.

    A plain `restart()` reuses the image ID the container was originally created from, so a
    freshly pulled tag never actually takes effect until the container is recreated. Removing
    a container never deletes the named volumes or bind mounts it references (we don't pass
    `-v`), so stored data survives. The old container is stopped and renamed aside rather than
    removed outright; it's only deleted once the replacement is confirmed started, and is
    renamed back and restarted if anything in between fails, so a failed recreate rolls back
    instead of leaving the service down with no container at all.
    """
    client = client or get_client()
    client.images.pull(image)

    old = client.containers.get(container_name)
    attrs = old.attrs
    config = attrs["Config"]
    host_config = attrs["HostConfig"]
    networks = attrs["NetworkSettings"]["Networks"]
    primary_network = host_config.get("NetworkMode")

    backup_name = f"{container_name}_sentinal_bak"
    old.stop()
    old.rename(backup_name)

    try:
        created = client.api.create_container(
            image=image,
            name=container_name,
            command=config.get("Cmd"),
            entrypoint=config.get("Entrypoint"),
            environment=config.get("Env"),
            labels=config.get("Labels"),
            working_dir=config.get("WorkingDir"),
            user=config.get("User"),
            exposed_ports=list(config.get("ExposedPorts") or {}),
            host_config=host_config,
        )
        container_id = created["Id"]
        for network_name in networks:
            if network_name != primary_network:
                client.api.connect_container_to_network(container_id, network_name)
        client.api.start(container_id)
    except Exception:
        old.rename(container_name)
        old.start()
        raise

    old.remove()
