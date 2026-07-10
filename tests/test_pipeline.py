import datetime as dt

from sentinal import db as db_module
from sentinal import pipeline


def test_not_deferred_when_never_seen():
    assert pipeline._is_deferred(None) is False


def test_deferred_when_refused():
    exception = db_module.ContainerException(image_name="nginx:latest", status="REFUSED")
    assert pipeline._is_deferred(exception) is True


def test_deferred_when_snooze_active():
    exception = db_module.ContainerException(
        image_name="nginx:latest",
        status="SNOOZED",
        snooze_until=dt.datetime.utcnow() + dt.timedelta(days=1),
    )
    assert pipeline._is_deferred(exception) is True


def test_not_deferred_when_snooze_expired():
    exception = db_module.ContainerException(
        image_name="nginx:latest",
        status="SNOOZED",
        snooze_until=dt.datetime.utcnow() - dt.timedelta(days=1),
    )
    assert pipeline._is_deferred(exception) is False


def test_snooze_creates_exception_with_matching_review_date():
    with db_module.SessionLocal() as session:
        action, ok, _details = pipeline._snooze(session, "redis:latest", days=7)
        session.commit()

    assert action == db_module.ActionTaken.SNOOZED
    assert ok is True

    with db_module.SessionLocal() as session:
        exception = (
            session.query(db_module.ContainerException).filter_by(image_name="redis:latest").first()
        )
        assert exception is not None
        assert exception.status == "SNOOZED"
        assert exception.snooze_until > dt.datetime.utcnow()
        assert exception.review_after == exception.snooze_until


def test_refuse_sets_a_review_date_instead_of_forever():
    with db_module.SessionLocal() as session:
        pipeline._refuse(session, "redis:latest", review_days=180)
        session.commit()

    with db_module.SessionLocal() as session:
        exception = (
            session.query(db_module.ContainerException).filter_by(image_name="redis:latest").first()
        )
        assert exception.status == "REFUSED"
        # Unlike the n8n prototype (snooze_until hardcoded to 9999-12-31), refusals
        # here still get a re-attestation date rather than being accepted forever.
        assert exception.review_after is not None
        assert exception.review_after < dt.datetime.utcnow() + dt.timedelta(days=366)


def test_resolve_decision_rejects_unknown_id():
    try:
        pipeline.resolve_decision(999, "patch")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_resolve_decision_patch_failure_is_logged_as_failed(monkeypatch):
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="broken:latest",
            container_name="broken-container",
            summary="fake vulnerability summary",
            status="PENDING",
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    def _boom(image, container_name, client=None):
        raise RuntimeError("pull failed")

    monkeypatch.setattr(pipeline.docker_client, "pull_and_restart", _boom)

    result = pipeline.resolve_decision(decision_id, "patch")

    assert result["ok"] is False
    assert result["action"] == "FAILED"

    with db_module.SessionLocal() as session:
        latest_log = session.query(db_module.ScanLog).order_by(db_module.ScanLog.id.desc()).first()
        assert latest_log.action_taken == "FAILED"
        assert latest_log.image_name == "broken:latest"


def test_resolve_decision_patch_success_is_logged_as_patched(monkeypatch):
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="nginx:latest",
            container_name="nginx-container",
            summary="fake vulnerability summary",
            status="PENDING",
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    monkeypatch.setattr(pipeline.docker_client, "pull_and_restart", lambda *a, **k: None)

    result = pipeline.resolve_decision(decision_id, "patch")

    assert result["ok"] is True
    assert result["action"] == "PATCHED"
