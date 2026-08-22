"""Dashboard login credentials, editable at runtime from Settings.

Seeded from DASHBOARD_USERNAME/DASHBOARD_PASSWORD on first boot (same pattern
as ScanSchedule — see schedule.py), then DB-authoritative so a change from the
console takes effect immediately and survives restarts without editing .env.
The password is stored hashed (werkzeug's salted scrypt/pbkdf2), never in
plaintext.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .config import get_settings


@dataclass(frozen=True)
class Credentials:
    username: str
    password_hash: str


def _get_or_seed(session) -> db.DashboardCredentials:
    row = session.get(db.DashboardCredentials, 1)
    if row is None:
        settings = get_settings()
        row = db.DashboardCredentials(
            id=1,
            username=settings.dashboard_username,
            password_hash=generate_password_hash(settings.dashboard_password),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
    return row


def get() -> Credentials:
    with db.SessionLocal() as session:
        row = _get_or_seed(session)
        return Credentials(username=row.username, password_hash=row.password_hash)


def verify(username: str, password: str) -> bool:
    creds = get()
    return hmac.compare_digest(username or "", creds.username) and check_password_hash(
        creds.password_hash, password or ""
    )


def update(*, current_password: str, new_username: str, new_password: str | None) -> Credentials:
    """Change the login username and/or password. Requires the current password.

    Raises ValueError (safe to show to the user) on a wrong current password
    or a blank username.
    """
    new_username = (new_username or "").strip()
    if not new_username:
        raise ValueError("Username cannot be blank")
    with db.SessionLocal() as session:
        row = _get_or_seed(session)
        if not check_password_hash(row.password_hash, current_password or ""):
            raise ValueError("Current password is incorrect")
        row.username = new_username
        if new_password:
            row.password_hash = generate_password_hash(new_password)
        session.commit()
        session.refresh(row)
        return Credentials(username=row.username, password_hash=row.password_hash)
