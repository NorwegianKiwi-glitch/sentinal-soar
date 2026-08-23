from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from sentinal import access, cloudflare, db, hostnames


def _group(**kw):
    defaults = dict(
        hostname="nextcloud.example.com",
        client_ip="203.0.113.5",
        country="US",
        path="/login",
        status_code=401,
        request_count=1,
        minute=dt.datetime(2026, 8, 22, 10, 0),
    )
    defaults.update(kw)
    return cloudflare.TrafficGroup(**defaults)


# --- is_suspicious -----------------------------------------------------------


def test_flags_repeated_failures_on_login_path():
    assert access.is_suspicious("/login", 401, 5) is True


def test_does_not_flag_login_path_below_failure_threshold():
    assert access.is_suspicious("/login", 401, 4) is False


def test_does_not_flag_non_login_path_even_with_many_failures():
    assert access.is_suspicious("/photos/thumbnail", 401, 999) is False


def test_flags_high_volume_login_traffic_regardless_of_status():
    assert access.is_suspicious("/api/auth/login", 200, 20) is True


def test_does_not_flag_ordinary_successful_login_traffic():
    assert access.is_suspicious("/login", 200, 1) is False


# --- ingest_recent / _store ---------------------------------------------------


def _fake_settings():
    return type(
        "S",
        (),
        {
            "cloudflare_configured": True,
            "cloudflare_api_token": "tok",
            "cloudflare_zone_id": "zone",
            "cloudflare_poll_minutes": 5,
        },
    )()


def test_ingest_recent_is_noop_when_not_configured(monkeypatch):
    monkeypatch.setattr(access, "get_settings", lambda: type("S", (), {"cloudflare_configured": False})())
    assert access.ingest_recent() == 0


def test_ingest_recent_is_noop_when_no_hostnames_watched(monkeypatch):
    monkeypatch.setattr(access, "get_settings", _fake_settings)
    monkeypatch.setattr(hostnames, "get_hostnames", lambda: [])
    assert access.ingest_recent() == 0


def test_ingest_recent_stores_groups_and_flags_suspicious_ones(monkeypatch):
    monkeypatch.setattr(access, "get_settings", _fake_settings)
    monkeypatch.setattr(hostnames, "get_hostnames", lambda: ["nextcloud.example.com"])
    groups = [
        _group(client_ip="203.0.113.5", path="/login", status_code=401, request_count=6),
        _group(client_ip="203.0.113.9", path="/photos/thumb", status_code=200, request_count=3),
    ]
    monkeypatch.setattr(cloudflare, "fetch_traffic", lambda **kw: groups)

    added = access.ingest_recent(now=dt.datetime(2026, 8, 22, 10, 5))

    assert added == 2
    with db.SessionLocal() as session:
        rows = session.scalars(select(db.AccessEvent)).all()
        by_ip = {r.client_ip: r for r in rows}
        assert by_ip["203.0.113.5"].flagged is True
        assert by_ip["203.0.113.9"].flagged is False


def test_ingest_recent_calls_on_flagged_only_for_newly_stored_flagged_rows(monkeypatch):
    monkeypatch.setattr(access, "get_settings", _fake_settings)
    monkeypatch.setattr(hostnames, "get_hostnames", lambda: ["nextcloud.example.com"])
    groups = [
        _group(client_ip="203.0.113.5", path="/login", status_code=401, request_count=6),  # flagged
        _group(client_ip="203.0.113.9", path="/photos/thumb", status_code=200, request_count=3),  # not flagged
    ]
    monkeypatch.setattr(cloudflare, "fetch_traffic", lambda **kw: groups)
    seen = []

    access.ingest_recent(now=dt.datetime(2026, 8, 22, 10, 5), on_flagged=seen.append)

    assert len(seen) == 1
    assert seen[0].client_ip == "203.0.113.5"


def test_ingest_recent_does_not_recall_on_flagged_for_already_stored_rows(monkeypatch):
    monkeypatch.setattr(access, "get_settings", _fake_settings)
    monkeypatch.setattr(hostnames, "get_hostnames", lambda: ["nextcloud.example.com"])
    flagged_group = _group(client_ip="203.0.113.5", path="/login", status_code=401, request_count=6)
    monkeypatch.setattr(cloudflare, "fetch_traffic", lambda **kw: [flagged_group])
    seen = []

    access.ingest_recent(now=dt.datetime(2026, 8, 22, 10, 5), on_flagged=seen.append)
    access.ingest_recent(now=dt.datetime(2026, 8, 22, 10, 6), on_flagged=seen.append)  # overlaps the same minute

    assert len(seen) == 1


def test_ingest_recent_survives_a_raising_on_flagged_callback(monkeypatch):
    monkeypatch.setattr(access, "get_settings", _fake_settings)
    monkeypatch.setattr(hostnames, "get_hostnames", lambda: ["nextcloud.example.com"])
    flagged_group = _group(client_ip="203.0.113.5", path="/login", status_code=401, request_count=6)
    monkeypatch.setattr(cloudflare, "fetch_traffic", lambda **kw: [flagged_group])

    def _boom(event):
        raise RuntimeError("discord is down")

    added = access.ingest_recent(now=dt.datetime(2026, 8, 22, 10, 5), on_flagged=_boom)

    assert added == 1
    with db.SessionLocal() as session:
        assert len(session.scalars(select(db.AccessEvent)).all()) == 1


def test_ingest_recent_does_not_duplicate_overlapping_groups(monkeypatch):
    monkeypatch.setattr(access, "get_settings", _fake_settings)
    monkeypatch.setattr(hostnames, "get_hostnames", lambda: ["nextcloud.example.com"])
    group = _group()
    monkeypatch.setattr(cloudflare, "fetch_traffic", lambda **kw: [group])

    first = access.ingest_recent(now=dt.datetime(2026, 8, 22, 10, 5))
    second = access.ingest_recent(now=dt.datetime(2026, 8, 22, 10, 6))  # overlaps the same minute

    assert first == 1
    assert second == 0
    with db.SessionLocal() as session:
        assert len(session.scalars(select(db.AccessEvent)).all()) == 1


def test_ingest_recent_degrades_gracefully_on_store_failure(monkeypatch):
    monkeypatch.setattr(access, "get_settings", _fake_settings)
    monkeypatch.setattr(hostnames, "get_hostnames", lambda: ["nextcloud.example.com"])
    monkeypatch.setattr(cloudflare, "fetch_traffic", lambda **kw: [_group()])

    def _boom(groups):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(access, "_store", _boom)

    assert access.ingest_recent() == 0
