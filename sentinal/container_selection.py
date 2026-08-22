"""Which containers scans touch, editable at runtime from Settings.

Opt-out: a container is scanned unless its name is listed in
`db.ExcludedContainer`, so anything not yet reviewed on the Settings page —
including a container that appears on the host after this feature shipped —
is still covered, matching the scan-everything default from before.
"""

from __future__ import annotations

from sqlalchemy import delete, select

from . import db


def excluded_names() -> set[str]:
    with db.SessionLocal() as session:
        return set(session.scalars(select(db.ExcludedContainer.container_name)).all())


def set_excluded(names: list[str]) -> set[str]:
    """Replace the whole exclusion set with `names` (the Settings page always
    submits every unchecked container, so a full replace — not a diff —
    keeps this idempotent and immune to races with other browser tabs)."""
    cleaned = {n.strip() for n in names if n and n.strip()}
    with db.SessionLocal() as session:
        session.execute(delete(db.ExcludedContainer))
        session.add_all(db.ExcludedContainer(container_name=name) for name in cleaned)
        session.commit()
    return cleaned
