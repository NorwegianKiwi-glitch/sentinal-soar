"""Apply a confirm-gated major upgrade by re-applying an app's own compose file.

Minor patches recreate a single container through the Docker API, but a major
upgrade rewrites the app's compose definition and runs `docker compose up -d`
on it — the same thing CasaOS does — so multi-service apps (immich's server +
machine-learning) move together and the definition stays the single source of
truth. The docker CLI and compose plugin ship in the image for exactly this.

Failure handling: if the new version fails to come up, the previous definition
(kept as `.sentinal-bak`) is restored and re-applied. That rolls back the
*code*; data migrations that already ran forward are why the Discord confirm
step tells the human to have backups.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from . import definitions, docker_client, registry

log = logging.getLogger(__name__)

_COMPOSE_TIMEOUT = 600


def preview_major_upgrade(container_name: str, current_image: str) -> tuple[str, list[str], list[str]]:
    """(project, family refs that will move, pinned companions) — no writes."""
    project, path = _app_definition(container_name)
    family, companions = definitions.find_image_family(path.read_text(), current_image)
    if current_image not in family:
        raise RuntimeError(
            f"{path} does not reference {current_image} — the definition has drifted; upgrade via CasaOS instead"
        )
    return project, family, companions


def apply_major_upgrade(target_image: str, current_image: str, container_name: str) -> tuple[str, str]:
    """Rewrite the app's definition to `target_image`'s tag and re-apply it.

    Returns (project, human-readable details). Raises on failure after
    attempting to restore and re-apply the previous definition.
    """
    project, path = _app_definition(container_name)
    text = path.read_text()
    family, companions = definitions.find_image_family(text, current_image)
    if current_image not in family:
        raise RuntimeError(
            f"{path} does not reference {current_image} — the definition has drifted; upgrade via CasaOS instead"
        )

    target_tag = registry.parse_image_ref(target_image).tag
    changes: list[str] = []
    for ref in family:
        new_ref = f"{ref.rsplit(':', 1)[0]}:{target_tag}"
        text, count = definitions._rewrite_image_reference(text, ref, new_ref)
        if count:
            changes.append(f"{ref} → {new_ref}")
    if not changes:
        raise RuntimeError(f"nothing to rewrite in {path} — upgrade via CasaOS instead")

    backup = path.with_name(path.name + ".sentinal-bak")
    shutil.copy2(path, backup)
    path.write_text(text)
    try:
        _compose_up(project, path)
    except Exception:
        shutil.copy2(backup, path)
        try:
            _compose_up(project, path)
            log.error("Major upgrade of %s failed; previous definition restored and re-applied", project)
        except Exception:
            log.exception("Rollback compose up ALSO failed for %s — manual attention needed", project)
        raise

    details = f"Major upgrade of app '{project}': " + "; ".join(changes) + "."
    if companions:
        details += (
            f" Pinned companions left untouched: {', '.join(companions[:6])} — check the "
            "release notes on whether they need updating too."
        )
    return project, details


def _app_definition(container_name: str) -> tuple[str, Path]:
    """The compose project and definition file a container was created from."""
    labels = docker_client.get_client().containers.get(container_name).labels or {}
    project = labels.get("com.docker.compose.project")
    config_files = labels.get(definitions._CONFIG_FILES_LABEL)
    if not project or not config_files:
        raise RuntimeError(f"{container_name} was not created by compose; upgrade it manually")
    if "," in config_files:
        raise RuntimeError(f"{container_name} uses multiple compose files; upgrade it manually")
    own_project = docker_client.own_compose_project()
    if own_project and own_project == project:
        raise RuntimeError(
            "refusing to major-upgrade Sentinal's own stack — update it on the host: docker compose up -d --build"
        )
    path = Path(config_files)
    if not path.is_file():
        raise RuntimeError(f"definition {config_files} is not reachable from Sentinal's container")
    return project, path


def _compose_up(project: str, config_file: Path) -> str:
    proc = subprocess.run(
        ["docker", "compose", "-p", project, "-f", str(config_file), "up", "-d"],
        capture_output=True,
        text=True,
        timeout=_COMPOSE_TIMEOUT,
    )
    output = f"{proc.stdout}\n{proc.stderr}".strip()
    if proc.returncode != 0:
        raise RuntimeError(f"docker compose up failed (exit {proc.returncode}): …{output[-600:]}")
    return output
