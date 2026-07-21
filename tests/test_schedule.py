from __future__ import annotations

import datetime as dt

from sentinal import db as db_module
from sentinal import schedule


def _sched(**kw):
    base = dict(enabled=True, mode="interval", interval_hours=6, daily_time="03:00", last_run_at=None)
    base.update(kw)
    return schedule.Schedule(**base)


def test_get_creates_and_seeds_a_row_when_missing():
    with db_module.SessionLocal() as session:
        assert session.get(db_module.ScanSchedule, 1) is None

    cfg = schedule.get()

    assert cfg.mode == "interval"
    with db_module.SessionLocal() as session:
        assert session.get(db_module.ScanSchedule, 1) is not None


def test_next_run_interval_is_last_run_plus_hours():
    last = dt.datetime(2026, 7, 21, 10, 0, 0)
    cfg = _sched(mode="interval", interval_hours=6, last_run_at=last)
    assert schedule.next_run_at(cfg) == last + dt.timedelta(hours=6)


def test_next_run_disabled_is_none():
    assert schedule.next_run_at(_sched(enabled=False)) is None


def test_next_run_daily_lands_on_the_configured_local_time():
    cfg = _sched(mode="daily", daily_time="03:30", last_run_at=None)
    nxt = schedule.next_run_at(cfg)

    assert nxt is not None
    now = dt.datetime.utcnow()
    assert now - dt.timedelta(hours=24, minutes=1) <= nxt <= now + dt.timedelta(hours=24, minutes=1)
    # the UTC target, converted back to local, is exactly 03:30
    local = nxt.replace(tzinfo=dt.timezone.utc).astimezone()
    assert (local.hour, local.minute) == (3, 30)


def test_update_roundtrips_through_get():
    schedule.update(enabled=True, mode="daily", interval_hours=12, daily_time="04:15")
    cfg = schedule.get()
    assert cfg.mode == "daily"
    assert cfg.daily_time == "04:15"
    assert cfg.interval_hours == 12


def test_enabling_from_disabled_restarts_the_interval_countdown():
    schedule.update(enabled=False, mode="interval", interval_hours=6, daily_time="03:00")
    before = dt.datetime.utcnow()
    cfg = schedule.update(enabled=True, mode="interval", interval_hours=6, daily_time="03:00")
    assert cfg.last_run_at is not None
    assert cfg.last_run_at >= before - dt.timedelta(seconds=2)
