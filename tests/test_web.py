import base64
import datetime as dt
import threading
from types import SimpleNamespace

from sentinal import db as db_module
from sentinal import pipeline
from sentinal.web import create_app


def _client():
    app = create_app()
    app.testing = True
    return app.test_client()


def _auth_header(username="test-user", password="test-pass"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _pending(**kw):
    defaults = dict(
        image_name="redis:6.2.6",
        container_name="redis",
        proposed_image=None,
        proposed_major_image=None,
        summary="- [HIGH] CVE-1: libx",
        ai_analysis="analysis",
        status="PENDING",
    )
    defaults.update(kw)
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(**defaults)
        session.add(decision)
        session.commit()
        session.refresh(decision)
        return decision.id


def test_index_requires_auth():
    assert _client().get("/").status_code == 401


def test_rejects_wrong_credentials():
    assert _client().get("/", headers=_auth_header(password="nope")).status_code == 401


def test_index_redirects_to_decisions():
    response = _client().get("/", headers=_auth_header(), follow_redirects=True)
    assert response.status_code == 200
    assert b"Sentinal" in response.data
    assert b"Pending decisions" in response.data


def test_decisions_page_shows_buttons_by_patchability():
    _pending(image_name="redis:6.2.6", container_name="redis", proposed_image="redis:6.2.22")
    _pending(image_name="sha256:" + "a" * 64, container_name="weird")

    response = _client().get("/decisions", headers=_auth_header())
    body = response.data.decode()
    assert "redis:6.2.6" in body
    assert "Apply Patch" in body  # the patchable one offers it
    assert "No pull-based patch" in body  # the digest-pinned one explains instead


def test_decision_action_runs_resolve(monkeypatch):
    done = threading.Event()
    calls = []

    def fake_resolve(decision_id, choice):
        calls.append((decision_id, choice))
        done.set()

    monkeypatch.setattr(pipeline, "resolve_decision", fake_resolve)

    response = _client().post("/api/decisions/5/snooze", headers=_auth_header())
    assert response.status_code == 202
    assert done.wait(2.0)
    assert calls == [(5, "snooze")]


def test_decision_action_rejects_unknown_choice():
    response = _client().post("/api/decisions/5/bogus", headers=_auth_header())
    assert response.status_code == 400


def test_scan_status_and_stop_endpoints():
    client = _client()
    assert client.get("/api/scan/status", headers=_auth_header()).get_json() == {"running": False}
    assert client.post("/api/scan/stop", headers=_auth_header()).status_code == 202


def test_logs_filter_by_action():
    with db_module.SessionLocal() as session:
        session.add_all(
            [
                db_module.ScanLog(image_name="immich:1", action_taken="FAILED", log_payload={"details": "boom"}),
                db_module.ScanLog(image_name="redis:1", action_taken="CLEAN", log_payload={"details": "fine"}),
            ]
        )
        session.commit()

    body = _client().get("/logs?action=FAILED", headers=_auth_header()).data.decode()
    assert "immich:1" in body
    assert "redis:1" not in body


def test_access_page_requires_auth():
    assert _client().get("/access").status_code == 401


def test_access_page_shows_configuration_hint_when_disabled():
    body = _client().get("/access", headers=_auth_header()).data.decode()
    assert "isn't configured" in body


def test_access_page_filters_by_flagged():
    with db_module.SessionLocal() as session:
        session.add_all(
            [
                db_module.AccessEvent(
                    hostname="nextcloud.example.com",
                    client_ip="203.0.113.5",
                    path="/login",
                    status_code=401,
                    request_count=6,
                    window_start=dt.datetime(2026, 8, 22, 10, 0),
                    window_end=dt.datetime(2026, 8, 22, 10, 1),
                    flagged=True,
                ),
                db_module.AccessEvent(
                    hostname="nextcloud.example.com",
                    client_ip="203.0.113.9",
                    path="/photos/thumb",
                    status_code=200,
                    request_count=1,
                    window_start=dt.datetime(2026, 8, 22, 10, 0),
                    window_end=dt.datetime(2026, 8, 22, 10, 1),
                    flagged=False,
                ),
            ]
        )
        session.commit()

    body = _client().get("/access?flagged=1", headers=_auth_header()).data.decode()
    assert "203.0.113.5" in body
    assert "203.0.113.9" not in body


def test_access_page_shows_no_hostnames_hint_when_configured_but_empty(monkeypatch):
    monkeypatch.setattr("sentinal.web.routes.get_settings", lambda: type("S", (), {"cloudflare_configured": True})())
    body = _client().get("/access", headers=_auth_header()).data.decode()
    assert "No hostnames are being watched yet" in body


def test_delete_access_event_requires_auth():
    assert _client().post("/api/access-events/1/delete").status_code == 401


def test_delete_access_event_removes_it_and_is_idempotent_on_missing():
    with db_module.SessionLocal() as session:
        event = db_module.AccessEvent(
            hostname="nextcloud.example.com",
            client_ip="203.0.113.5",
            path="/login",
            status_code=401,
            request_count=6,
            window_start=dt.datetime(2026, 8, 22, 10, 0),
            window_end=dt.datetime(2026, 8, 22, 10, 1),
        )
        session.add(event)
        session.commit()
        session.refresh(event)
        event_id = event.id

    res = _client().post(f"/api/access-events/{event_id}/delete", headers=_auth_header())
    assert res.status_code == 200
    with db_module.SessionLocal() as session:
        assert session.get(db_module.AccessEvent, event_id) is None

    res = _client().post(f"/api/access-events/{event_id}/delete", headers=_auth_header())
    assert res.status_code == 404


def test_settings_page_lists_watched_hostnames():
    from sentinal import hostnames

    hostnames.add_hostname("cloud.example.com")
    body = _client().get("/settings", headers=_auth_header()).data.decode()
    assert "cloud.example.com" in body


def test_add_access_hostname_persists_and_normalizes():
    res = _client().post(
        "/api/access-hostnames",
        headers=_auth_header(),
        json={"hostname": "HTTPS://Cloud.Example.com/path"},
    )
    assert res.status_code == 200
    assert res.get_json()["hostnames"] == ["cloud.example.com"]


def test_add_access_hostname_rejects_invalid():
    res = _client().post("/api/access-hostnames", headers=_auth_header(), json={"hostname": "not a hostname"})
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_delete_access_hostname_removes_it():
    from sentinal import hostnames

    hostnames.add_hostname("cloud.example.com")
    res = _client().post("/api/access-hostnames/cloud.example.com/delete", headers=_auth_header())
    assert res.status_code == 200
    assert res.get_json()["hostnames"] == []


def test_archive_log_is_soft_delete_not_hard_delete():
    with db_module.SessionLocal() as session:
        log = db_module.ScanLog(image_name="nginx:latest", action_taken="CLEAN", log_payload={"details": "test"})
        session.add(log)
        session.commit()
        session.refresh(log)
        log_id = log.id

    response = _client().post(f"/api/logs/{log_id}/archive", headers=_auth_header())
    assert response.status_code == 200

    with db_module.SessionLocal() as session:
        # the row must still exist — archiving is not the same as the n8n
        # dashboard's hard DELETE, which destroyed audit history outright
        archived = session.get(db_module.ScanLog, log_id)
        assert archived is not None and archived.archived is True
        visible = [r.id for r in session.query(db_module.ScanLog).filter_by(archived=False).all()]
        assert log_id not in visible


def test_delete_exception_requires_auth():
    assert _client().post("/api/exceptions/1/delete").status_code == 401


def test_settings_page_renders():
    body = _client().get("/settings", headers=_auth_header()).data.decode()
    assert "Scan schedule" in body
    assert "Periodic scans" in body


def test_update_schedule_persists():
    from sentinal import schedule

    response = _client().post(
        "/api/schedule",
        headers=_auth_header(),
        json={"enabled": True, "mode": "daily", "interval_hours": 8, "daily_time": "05:00"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["mode"] == "daily" and data["daily_time"] == "05:00"
    assert schedule.get().mode == "daily"


def test_update_schedule_rejects_bad_time_and_falls_back():
    response = _client().post(
        "/api/schedule",
        headers=_auth_header(),
        json={"enabled": True, "mode": "daily", "interval_hours": 8, "daily_time": "99:99"},
    )
    assert response.get_json()["daily_time"] == "03:00"


def test_settings_page_shows_current_username():
    body = _client().get("/settings", headers=_auth_header()).data.decode()
    assert "Login credentials" in body
    assert 'value="test-user"' in body


def test_update_credentials_requires_current_password():
    response = _client().post(
        "/api/credentials",
        headers=_auth_header(),
        json={"username": "test-user", "current_password": "wrong", "new_password": None},
    )
    assert response.status_code == 400
    assert "incorrect" in response.get_json()["error"].lower()


def test_update_credentials_changes_login_and_old_creds_stop_working():
    client = _client()
    response = client.post(
        "/api/credentials",
        headers=_auth_header(),
        json={"username": "new-admin", "current_password": "test-pass", "new_password": "new-secret"},
    )
    assert response.status_code == 200
    assert response.get_json()["username"] == "new-admin"

    # old Basic-Auth credentials are now rejected
    assert client.get("/decisions", headers=_auth_header()).status_code == 401
    # new ones work
    new_auth = _auth_header(username="new-admin", password="new-secret")
    assert client.get("/decisions", headers=new_auth).status_code == 200


def test_update_credentials_rejects_blank_username():
    response = _client().post(
        "/api/credentials",
        headers=_auth_header(),
        json={"username": "   ", "current_password": "test-pass", "new_password": None},
    )
    assert response.status_code == 400


def _fake_container(name, image_tag):
    container = SimpleNamespace()
    container.name = name
    container.image = SimpleNamespace(tags=[image_tag] if image_tag else [], id="sha256:" + "a" * 64)
    return container


def test_settings_page_lists_containers_checked_by_default(monkeypatch):
    from sentinal import docker_client

    monkeypatch.setattr(
        docker_client,
        "list_containers",
        lambda *a, **k: [_fake_container("redis", "redis:6.2.6"), _fake_container("nginx", "nginx:latest")],
    )

    body = _client().get("/settings", headers=_auth_header()).data.decode()

    assert "Containers scanned" in body
    assert "redis" in body and "nginx" in body
    redis_line = next(line for line in body.splitlines() if 'value="redis"' in line)
    assert "checked" in redis_line


def test_settings_page_unchecks_excluded_containers(monkeypatch):
    from sentinal import container_selection, docker_client

    monkeypatch.setattr(docker_client, "list_containers", lambda *a, **k: [_fake_container("redis", "redis:6.2.6")])
    container_selection.set_excluded(["redis"])

    body = _client().get("/settings", headers=_auth_header()).data.decode()

    redis_line = next(line for line in body.splitlines() if 'value="redis"' in line)
    assert "checked" not in redis_line


def test_settings_page_handles_docker_error_gracefully(monkeypatch):
    from sentinal import docker_client

    def _boom(*a, **k):
        raise RuntimeError("docker socket unavailable")

    monkeypatch.setattr(docker_client, "list_containers", _boom)

    response = _client().get("/settings", headers=_auth_header())
    assert response.status_code == 200
    assert b"Couldn't list containers" in response.data


def test_update_scan_selection_persists():
    from sentinal import container_selection

    response = _client().post(
        "/api/scan-selection", headers=_auth_header(), json={"excluded": ["redis", "nginx"]}
    )
    assert response.status_code == 200
    assert set(response.get_json()["excluded"]) == {"redis", "nginx"}
    assert container_selection.excluded_names() == {"redis", "nginx"}


def test_update_scan_selection_rejects_non_list():
    response = _client().post("/api/scan-selection", headers=_auth_header(), json={"excluded": "redis"})
    assert response.status_code == 400


def test_settings_page_shows_discord_toggle_when_connected():
    body = _client().get("/settings", headers=_auth_header()).data.decode()
    assert "Discord notifications" in body
    assert "Disable Discord notifications" in body  # enabled by default


def test_settings_page_hides_toggle_when_discord_not_connected(monkeypatch):
    from sentinal.web import routes

    monkeypatch.setattr(routes, "get_settings", lambda: SimpleNamespace(discord_enabled=False, cloudflare_configured=False))

    body = _client().get("/settings", headers=_auth_header()).data.decode()
    assert "isn't connected" in body
    assert 'id="discord-toggle"' not in body  # button itself isn't rendered (JS still references the id, guarded)


def test_toggle_discord_notifications_flips_state():
    from sentinal import notifications

    client = _client()
    response = client.post("/api/notifications/discord", headers=_auth_header(), json={"enabled": False})
    assert response.status_code == 200
    assert response.get_json() == {"enabled": False}
    assert notifications.enabled() is False

    response = client.post("/api/notifications/discord", headers=_auth_header(), json={"enabled": True})
    assert response.get_json() == {"enabled": True}
    assert notifications.enabled() is True


def test_toggle_discord_notifications_rejects_non_boolean():
    response = _client().post("/api/notifications/discord", headers=_auth_header(), json={"enabled": None})
    assert response.status_code == 400


def test_toggle_discord_notifications_requires_connection(monkeypatch):
    from sentinal.web import routes

    monkeypatch.setattr(routes, "get_settings", lambda: SimpleNamespace(discord_enabled=False))

    response = _client().post("/api/notifications/discord", headers=_auth_header(), json={"enabled": False})
    assert response.status_code == 400
