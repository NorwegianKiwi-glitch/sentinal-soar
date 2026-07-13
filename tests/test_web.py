import base64
import threading

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
