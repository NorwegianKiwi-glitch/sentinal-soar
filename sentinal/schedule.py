"""Periodic-scan scheduling, editable at runtime from the web console.

The old scheduler read `SCAN_INTERVAL_HOURS` once and slept for hours, so it
could neither be toggled nor re-timed without a restart. This replaces it with
a DB-backed config (`db.ScanSchedule`) and a loop that sleeps on an Event, so a
change from the console takes effect immediately.

Two modes:
- **interval** — run every `interval_hours` (next = last run + N hours).
- **daily**   — run once a day at `daily_time` ("HH:MM"), interpreted in the
  server's local timezone (mount /etc/localtime into the container so that is
  the Pi's zone, not UTC). All stored timestamps stay UTC-naive like the rest
  of the DB; only the daily target is converted through the local zone.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from datetime import timezone
from threading import Event

from . import db, pipeline
from .config import get_settings

log = logging.getLogger(__name__)

# Set by update() so a config change wakes the loop at once; also caps how long
# the loop sleeps so a missed signal is still noticed within the hour.
_wake = Event()
_MAX_SLEEP = 3600.0


@dataclass(frozen=True)
class Schedule:
    enabled: bool
    mode: str
    interval_hours: int
    daily_time: str
    last_run_at: dt.datetime | None


def _snapshot(row: db.ScanSchedule) -> Schedule:
    return Schedule(row.enabled, row.mode, row.interval_hours, row.daily_time, row.last_run_at)


def get() -> Schedule:
    """Current schedule, creating the row from env defaults on first access."""
    with db.SessionLocal() as session:
        row = session.get(db.ScanSchedule, 1)
        if row is None:
            interval = get_settings().scan_interval_hours
            row = db.ScanSchedule(
                id=1,
                enabled=interval > 0,
                mode="interval",
                interval_hours=interval if interval > 0 else 24,
                daily_time="03:00",
                last_run_at=dt.datetime.utcnow(),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
        return _snapshot(row)


def update(*, enabled: bool, mode: str, interval_hours: int, daily_time: str) -> Schedule:
    with db.SessionLocal() as session:
        row = session.get(db.ScanSchedule, 1)
        if row is None:
            row = db.ScanSchedule(id=1)
            session.add(row)
        was_enabled = row.enabled
        row.enabled = enabled
        row.mode = mode
        row.interval_hours = interval_hours
        row.daily_time = daily_time
        # Turning scanning back on restarts the interval countdown from now,
        # so re-enabling doesn't immediately fire because last_run is stale.
        if enabled and not was_enabled:
            row.last_run_at = dt.datetime.utcnow()
        session.commit()
        snapshot = _snapshot(row)
    _wake.set()
    return snapshot


def _mark_ran() -> None:
    with db.SessionLocal() as session:
        row = session.get(db.ScanSchedule, 1)
        if row is not None:
            row.last_run_at = dt.datetime.utcnow()
            session.commit()


def next_run_at(cfg: Schedule) -> dt.datetime | None:
    """UTC-naive datetime of the next scheduled scan, or None if disabled."""
    if not cfg.enabled:
        return None
    if cfg.mode == "daily":
        return _next_daily(cfg.daily_time, cfg.last_run_at)
    hours = cfg.interval_hours if cfg.interval_hours > 0 else 24
    base = cfg.last_run_at or dt.datetime.utcnow()
    return base + dt.timedelta(hours=hours)


def _next_daily(daily_time: str, last_run_at: dt.datetime | None) -> dt.datetime:
    hour, minute = (int(part) for part in daily_time.split(":"))
    local_now = dt.datetime.now().astimezone()  # local-aware "now"
    todays_target_local = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    todays_target = _to_utc_naive(todays_target_local)
    now = dt.datetime.utcnow()
    if now < todays_target:
        return todays_target  # today's time is still ahead
    if last_run_at is None or last_run_at < todays_target:
        return todays_target  # passed today but not yet run today -> due now
    return _to_utc_naive(todays_target_local + dt.timedelta(days=1))


def _to_utc_naive(aware: dt.datetime) -> dt.datetime:
    return aware.astimezone(timezone.utc).replace(tzinfo=None)


def run_scheduler(run_once) -> None:
    """Loop forever, running `run_once` when the schedule says it is due.

    `run_once` performs the full scan (with its notifications); this owns only
    the timing. A scan already running (e.g. a manual one) defers the tick.
    """
    while True:
        cfg = get()
        due = next_run_at(cfg)
        now = dt.datetime.utcnow()
        if due is not None and now >= due:
            if pipeline.scan_running():
                _sleep(5)
                continue
            try:
                run_once()
            except Exception:
                log.exception("Scheduled scan failed")
            finally:
                _mark_ran()
            _sleep(5)
            continue
        _sleep(_MAX_SLEEP if due is None else max(1.0, min((due - now).total_seconds(), _MAX_SLEEP)))


def _sleep(seconds: float) -> None:
    _wake.wait(timeout=seconds)
    _wake.clear()
