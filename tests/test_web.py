import base64

from sentinal import db as db_module
from sentinal.web import create_app


def _client():
    app = create_app()
    app.testing = True
    return app.test_client()


def _auth_header(username="test-user", password="test-pass"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_dashboard_requires_auth():
    response = _client().get("/")
    assert response.status_code == 401


def test_dashboard_rejects_wrong_credentials():
    response = _client().get("/", headers=_auth_header(password="nope"))
    assert response.status_code == 401


def test_dashboard_renders_with_valid_credentials():
    response = _client().get("/", headers=_auth_header())
    assert response.status_code == 200
    assert b"Sentinal" in response.data


def test_archive_log_is_soft_delete_not_hard_delete():
    with db_module.SessionLocal() as session:
        log = db_module.ScanLog(
            image_name="nginx:latest",
            action_taken="CLEAN",
            log_payload={"details": "test"},
        )
        session.add(log)
        session.commit()
        session.refresh(log)
        log_id = log.id

    client = _client()
    response = client.post(f"/api/logs/{log_id}/archive", headers=_auth_header())
    assert response.status_code == 200

    with db_module.SessionLocal() as session:
        # the row must still exist — archiving is not the same as the n8n
        # dashboard's hard DELETE, which destroyed audit history outright
        archived = session.get(db_module.ScanLog, log_id)
        assert archived is not None
        assert archived.archived is True

        visible_ids = [
            row.id
            for row in session.query(db_module.ScanLog).filter_by(archived=False).all()
        ]
        assert log_id not in visible_ids


def test_delete_exception_requires_auth():
    response = _client().post("/api/exceptions/1/delete")
    assert response.status_code == 401
