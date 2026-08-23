"""Which hostnames the Access page's Cloudflare poller watches.

Seeded from CLOUDFLARE_HOSTNAMES exactly once (see seed_from_env(), called
from __main__.main() right after init_db()), then DB-authoritative — add and
remove happen from the Settings page and take effect on the next poll tick,
no .env edit or redeploy needed. The "seeded" marker is db.AccessConfig, a
separate singleton row — not "the table has rows" — so removing every
hostname from Settings sticks permanently, including across restarts, rather
than getting re-seeded from the env var the next time the process boots.
"""

from __future__ import annotations

import re

from sqlalchemy import select

from . import db
from .config import get_settings

_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _normalize(hostname: str) -> str:
    value = hostname.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)  # tolerate a pasted "https://host/..." URL
    value = value.split("/", 1)[0].split(":", 1)[0]  # drop any path or port
    if not _HOSTNAME_RE.match(value):
        raise ValueError(f"{hostname!r} doesn't look like a valid hostname")
    return value


def _names(session) -> list[str]:
    rows = session.scalars(select(db.WatchedHostname).order_by(db.WatchedHostname.hostname))
    return [r.hostname for r in rows]


def seed_from_env() -> None:
    """Insert CLOUDFLARE_HOSTNAMES the first time this ever runs — see the
    module docstring for why db.AccessConfig, not row count, is the marker."""
    with db.SessionLocal() as session:
        if session.get(db.AccessConfig, 1) is not None:
            return
        for name in get_settings().cloudflare_hostname_list:
            session.add(db.WatchedHostname(hostname=name))
        session.add(db.AccessConfig(id=1, hostnames_seeded=True))
        session.commit()


def get_hostnames() -> list[str]:
    with db.SessionLocal() as session:
        return _names(session)


def add_hostname(hostname: str) -> list[str]:
    normalized = _normalize(hostname)
    with db.SessionLocal() as session:
        exists = session.scalar(select(db.WatchedHostname).where(db.WatchedHostname.hostname == normalized))
        if exists is None:
            session.add(db.WatchedHostname(hostname=normalized))
            session.commit()
        return _names(session)


def remove_hostname(hostname: str) -> list[str]:
    with db.SessionLocal() as session:
        row = session.scalar(select(db.WatchedHostname).where(db.WatchedHostname.hostname == hostname.strip().lower()))
        if row is not None:
            session.delete(row)
            session.commit()
        return _names(session)
