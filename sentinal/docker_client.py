from __future__ import annotations

import re
import socket

import docker
from docker.models.containers import Container

from .config import get_settings


def get_client() -> docker.DockerClient:
    settings = get_settings()
    return docker.DockerClient(base_url=settings.docker_socket)


def list_containers(client: docker.DockerClient | None = None) -> list[Container]:
    client = client or get_client()
    return client.containers.list(all=True)


def _own_container_id() -> str | None:
    """Short id of the container this process runs in, or None if unknown.

    Docker sets a container's hostname to its short id unless overridden, so a
    hex-looking hostname is the best signal available without extra mounts.
    """
    hostname = socket.gethostname()
    if re.fullmatch(r"[0-9a-f]{12,64}", hostname):
        return hostname
    return None


def _own_container(client: docker.DockerClient) -> Container | None:
    own_id = _own_container_id()
    if own_id is None:
        return None
    try:
        return client.containers.get(own_id)
    except docker.errors.DockerException:
        return None


def _preserved_aliases(endpoint: dict, old: Container) -> list[str]:
    """Network aliases the replacement container must keep.

    Compose attaches the service name ("db", "app", …) as a DNS alias at
    creation time; recreating without it silently breaks every container that
    reaches this one by service name. Only the old container's auto-generated
    identifiers are dropped — the replacement gets its own.
    """
    return [
        alias for alias in endpoint.get("Aliases") or [] if alias not in (old.name, old.id[:12])
    ]


def pull_and_recreate(image: str, container_name: str, client: docker.DockerClient | None = None) -> None:
    """Pull `image` and recreate `container_name` from it.

    A plain `restart()` reuses the image ID the container was originally created from, so a
    freshly pulled tag never actually takes effect until the container is recreated. Removing
    a container never deletes the named volumes or bind mounts it references (we don't pass
    `-v`), so stored data survives. The old container is stopped and renamed aside rather than
    removed outright; it's only deleted once the replacement is confirmed started, and is
    renamed back and restarted if anything in between fails, so a failed recreate rolls back
    instead of leaving the service down with no container at all.

    Raises ValueError for images that only have a digest (nothing newer can ever be pulled)
    and RuntimeError for any container in Sentinal's own compose stack — stopping its own app
    or database kills the remediation (and the audit trail) mid-flight.
    """
    if image.startswith("sha256:") or "@sha256:" in image:
        raise ValueError(
            f"{image} is pinned to a digest, not a mutable tag, so pulling can never fetch "
            "a newer version. Rebuild or retag the image to patch it."
        )

    client = client or get_client()
    old = client.containers.get(container_name)

    own = _own_container(client)
    if own is not None:
        if old.id == own.id:
            raise RuntimeError(
                "refusing to recreate Sentinal's own container from inside itself — stopping it "
                "would kill the remediation before the replacement starts. Update Sentinal on "
                "the host instead: docker compose up -d --build"
            )
        own_project = own.labels.get("com.docker.compose.project")
        if own_project and own_project == old.labels.get("com.docker.compose.project"):
            raise RuntimeError(
                f"refusing to recreate {container_name}: it belongs to Sentinal's own compose stack "
                f"({own_project!r}), and stopping any part of it (like the database) takes Sentinal "
                "down mid-remediation. Update the stack on the host instead: docker compose up -d --build"
            )

    client.images.pull(image)

    attrs = old.attrs
    config = attrs["Config"]
    host_config = attrs["HostConfig"]
    networks = attrs["NetworkSettings"]["Networks"]
    primary_network = host_config.get("NetworkMode")

    backup_name = f"{container_name}_sentinal_bak"
    old.stop()
    old.rename(backup_name)

    try:
        networking_config = None
        primary_endpoint = networks.get(primary_network)
        if primary_endpoint:
            aliases = _preserved_aliases(primary_endpoint, old)
            if aliases:
                networking_config = client.api.create_networking_config(
                    {primary_network: client.api.create_endpoint_config(aliases=aliases)}
                )
        created = client.api.create_container(
            image=image,
            name=container_name,
            command=config.get("Cmd"),
            entrypoint=config.get("Entrypoint"),
            environment=config.get("Env"),
            labels=config.get("Labels"),
            working_dir=config.get("WorkingDir"),
            user=config.get("User"),
            healthcheck=config.get("Healthcheck"),
            # Inspect reports ExposedPorts as "80/tcp"-style keys; the SDK's `ports`
            # parameter wants (port, proto) tuples and mangles the raw strings.
            ports=[tuple(port.split("/", 1)) for port in (config.get("ExposedPorts") or {})],
            host_config=host_config,
            networking_config=networking_config,
        )
        container_id = created["Id"]
        for network_name, endpoint in networks.items():
            if network_name != primary_network:
                client.api.connect_container_to_network(
                    container_id, network_name, aliases=_preserved_aliases(endpoint, old) or None
                )
        client.api.start(container_id)
    except Exception:
        old.rename(container_name)
        old.start()
        raise

    old.remove()
