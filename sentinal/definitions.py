"""Keep the compose/CasaOS definition of a patched container in sync.

pull_and_recreate upgrades the live container, but the compose file that
CasaOS (or docker compose) created it from still references the old tag — so
the CasaOS UI keeps showing the old version, and re-applying the app from
there would silently roll the security patch back. After a successful upgrade
this module rewrites that file's image reference to match reality.

The app container can only reach definition files whose host directory is
bind-mounted at the identical path (docker-compose.yml mounts CasaOS's
`/var/lib/casaos/apps` for exactly this). Anything unreachable degrades to an
"update it manually" note in the audit log rather than an error — the patch
itself has already happened by the time we get here.
"""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path

from . import docker_client

log = logging.getLogger(__name__)

_CONFIG_FILES_LABEL = "com.docker.compose.project.config_files"


def sync_image_reference(container_name: str, old_image: str, new_image: str) -> str:
    """Best-effort rewrite of the patched container's compose file(s).

    Returns a human-readable sentence for the audit log; never raises.
    """
    try:
        return _sync(container_name, old_image, new_image)
    except Exception as exc:  # a sync failure must never fail the patch itself
        log.exception("Definition sync failed for %s", container_name)
        return f"Definition sync failed ({exc}); set the app's tag to {new_image} manually."


def _sync(container_name: str, old_image: str, new_image: str) -> str:
    labels = docker_client.get_client().containers.get(container_name).labels or {}
    config_files = labels.get(_CONFIG_FILES_LABEL)
    if not config_files:
        return "No compose definition to sync (container was not created by compose)."

    sentences = []
    for config_file in config_files.split(","):
        path = Path(config_file)
        if not path.is_file():
            sentences.append(
                f"Definition {config_file} is not reachable from Sentinal's container; "
                f"set the app's tag to {new_image} manually (e.g. in CasaOS settings)."
            )
            continue
        text = path.read_text()
        rewritten, count = _rewrite_image_reference(text, old_image, new_image)
        if count == 0:
            sentences.append(f"Definition {config_file} has no reference to {old_image}; nothing to sync.")
            continue
        shutil.copy2(path, path.with_name(path.name + ".sentinal-bak"))
        path.write_text(rewritten)
        sentences.append(f"Updated {count} image reference(s) in {config_file}.")
    return " ".join(sentences)


def _rewrite_image_reference(text: str, old_image: str, new_image: str) -> tuple[str, int]:
    """Replace exact references to `old_image`, counting the replacements.

    Exact means exact: `vaultwarden/server:1.32.7` must match neither
    `vaultwarden/server:1.32.75` nor `ghcr.io/x/vaultwarden/server:1.32.7`.
    """
    pattern = re.compile(rf"(?<![\w./-]){re.escape(old_image)}(?![\w.-])")
    return pattern.subn(new_image, text)
