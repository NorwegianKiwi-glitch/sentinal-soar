"""Take a restic snapshot before a major upgrade.

The backup runs through the host-authored script bind-mounted into this
container (docker-compose.yml mounts the script, the restic repository, the
password file, and the data paths at identical host paths), so manual host
runs and pre-upgrade runs share one implementation and one repository.

The contract with the caller is strict: no snapshot id, no upgrade.
"""

from __future__ import annotations

import logging
import re
import subprocess

log = logging.getLogger(__name__)

_SCRIPT = "/usr/local/bin/sentinal-backup.sh"
_TIMEOUT = 3600
_SNAPSHOT_RE = re.compile(r"snapshot ([0-9a-f]{8,}) saved")


def run_pre_upgrade_backup(app: str) -> str:
    """Run a tagged backup and return the restic snapshot id."""
    proc = subprocess.run(
        ["bash", _SCRIPT, f"pre-upgrade-{app}"],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
    )
    output = f"{proc.stdout}\n{proc.stderr}".strip()
    if proc.returncode != 0:
        raise RuntimeError(f"backup script failed (exit {proc.returncode}): …{output[-500:]}")
    match = _SNAPSHOT_RE.search(output)
    if match is None:
        raise RuntimeError(f"backup script reported no snapshot id: …{output[-500:]}")
    return match.group(1)
