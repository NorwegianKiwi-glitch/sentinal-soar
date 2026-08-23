"""Turns Cloudflare edge traffic into stored AccessEvent rows and flags
patterns that look like brute-force login activity.

Cloudflare only tells us what hit the edge, not whether an app-level login
succeeded — see cloudflare.py and the Access page for that caveat. The
heuristic here is deliberately conservative: it flags volume/failure-status
patterns against login-shaped paths, not confirmed failed logins. Closing
that gap fully needs the deferred trusted_proxies fix on each app plus
parsing their own auth logs — out of scope for this feature.
"""

from __future__ import annotations

import datetime as dt
import logging
import time

from sqlalchemy import select

from . import cloudflare, db, hostnames
from .config import get_settings

log = logging.getLogger(__name__)

# Cloudflare's Adaptive Groups data can arrive with a short processing lag, so
# each poll re-covers a little of the previous window; the unique constraint
# on AccessEvent (see db.py) makes re-ingesting the overlap a no-op instead of
# a duplicate row.
_OVERLAP = dt.timedelta(minutes=2)
_BUCKET = dt.timedelta(minutes=1)

_LOGIN_PATH_HINTS = ("login", "signin", "sign-in", "session", "auth", "token")
_FAILURE_STATUS = {401, 403, 429}
_FAILURE_THRESHOLD = 5
_VOLUME_THRESHOLD = 20


def looks_like_login_path(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _LOGIN_PATH_HINTS)


def is_suspicious(path: str, status_code: int, request_count: int) -> bool:
    """A same-IP, same-path, same-status group is one row here (see
    cloudflare.TrafficGroup), so `request_count` is already "this many
    requests, this shape, in one minute" — no separate grouping needed."""
    if not looks_like_login_path(path):
        return False
    if status_code in _FAILURE_STATUS and request_count >= _FAILURE_THRESHOLD:
        return True
    return request_count >= _VOLUME_THRESHOLD


def _last_window_end() -> dt.datetime | None:
    with db.SessionLocal() as session:
        return session.scalars(
            select(db.AccessEvent.window_end).order_by(db.AccessEvent.window_end.desc())
        ).first()


def ingest_recent(now: dt.datetime | None = None) -> int:
    """Fetch traffic since the last ingest (with overlap) and store new rows.

    Returns the number of newly-stored rows. Never raises: cloudflare.fetch_traffic
    already degrades to [] on API failure, and a DB hiccup here is caught too —
    a bad tick just means the next one covers the gap via the overlap window.
    """
    settings = get_settings()
    if not settings.cloudflare_configured:
        return 0
    watched = hostnames.get_hostnames()
    if not watched:
        return 0
    now = now or dt.datetime.utcnow()
    since = (_last_window_end() or now - dt.timedelta(minutes=settings.cloudflare_poll_minutes)) - _OVERLAP
    try:
        groups = cloudflare.fetch_traffic(
            api_token=settings.cloudflare_api_token,
            zone_id=settings.cloudflare_zone_id,
            hostnames=watched,
            since=since,
            until=now,
        )
        return _store(groups)
    except Exception:
        log.exception("Cloudflare access-traffic ingest failed")
        return 0


def _store(groups: list[cloudflare.TrafficGroup]) -> int:
    if not groups:
        return 0
    with db.SessionLocal() as session:
        window_start = min(g.minute for g in groups)
        existing = {
            (row.hostname, row.client_ip, row.path, row.status_code, row.window_start)
            for row in session.scalars(select(db.AccessEvent).where(db.AccessEvent.window_start >= window_start))
        }
        added = 0
        for g in groups:
            key = (g.hostname, g.client_ip, g.path, g.status_code, g.minute)
            if key in existing:
                continue
            session.add(
                db.AccessEvent(
                    hostname=g.hostname,
                    client_ip=g.client_ip,
                    country=g.country,
                    path=g.path,
                    status_code=g.status_code,
                    request_count=g.request_count,
                    window_start=g.minute,
                    window_end=g.minute + _BUCKET,
                    flagged=is_suspicious(g.path, g.status_code, g.request_count),
                )
            )
            existing.add(key)
            added += 1
        session.commit()
        return added


def run_poller() -> None:
    """Loop forever, ingesting on a fixed interval from config.

    Simpler than schedule.py's Event-based loop on purpose: this interval has
    no Settings-page toggle (env config only), so there's nothing that needs
    to wake it early — plain time.sleep is enough.
    """
    settings = get_settings()
    if not settings.cloudflare_configured:
        log.info("Cloudflare access ingestion not configured — skipping.")
        return
    while True:
        try:
            added = ingest_recent()
            if added:
                log.info("Ingested %d new Cloudflare access-traffic rows", added)
        except Exception:
            log.exception("Cloudflare access polling tick failed")
        time.sleep(max(30.0, settings.cloudflare_poll_minutes * 60))
