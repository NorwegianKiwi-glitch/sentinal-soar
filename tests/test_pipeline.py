import datetime as dt
from types import SimpleNamespace

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

    monkeypatch.setattr(pipeline.docker_client, "pull_and_recreate", _boom)

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

    monkeypatch.setattr(pipeline.docker_client, "pull_and_recreate", lambda *a, **k: None)

    result = pipeline.resolve_decision(decision_id, "patch")

    assert result["ok"] is True
    assert result["action"] == "PATCHED"


def test_evaluate_container_logs_clean_scan_with_no_findings(monkeypatch):
    container = SimpleNamespace(
        image=SimpleNamespace(tags=["nginx:latest"], id="sha256:fake"),
        name="nginx-container",
    )
    monkeypatch.setattr(
        pipeline.scanner, "scan_image", lambda image: pipeline.scanner.ScanResult(image=image, vulnerabilities=[])
    )

    alerts = []
    pipeline._evaluate_container(container, lambda *a, **k: alerts.append((a, k)))

    assert alerts == []
    with db_module.SessionLocal() as session:
        latest_log = session.query(db_module.ScanLog).order_by(db_module.ScanLog.id.desc()).first()
        assert latest_log.action_taken == "CLEAN"
        assert latest_log.image_name == "nginx:latest"
        assert latest_log.log_payload["details"] == "Scanned — no HIGH, CRITICAL vulnerabilities found."
        assert latest_log.log_payload["status"] == "SUCCESS"


def test_evaluate_container_alerts_on_findings(monkeypatch):
    container = SimpleNamespace(
        image=SimpleNamespace(tags=["nginx:latest"], id="sha256:fake"),
        name="nginx-container",
    )
    vuln = {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl"}
    monkeypatch.setattr(
        pipeline.scanner,
        "scan_image",
        lambda image: pipeline.scanner.ScanResult(image=image, vulnerabilities=[vuln]),
    )
    monkeypatch.setattr(pipeline.ai, "analyze", lambda image, summary: "fake AI analysis")

    alerts = []
    pipeline._evaluate_container(container, lambda *a, **k: alerts.append((a, k)))

    assert len(alerts) == 1
    with db_module.SessionLocal() as session:
        decision = session.query(db_module.PendingDecision).order_by(db_module.PendingDecision.id.desc()).first()
        assert decision.image_name == "nginx:latest"
        assert decision.status == "PENDING"
        # ":latest" has no version to compare, so no upgrade gets proposed —
        # and, crucially, no registry/network call is ever attempted.
        assert decision.proposed_image is None


def test_evaluate_container_proposes_trivy_verified_upgrade(monkeypatch):
    container = SimpleNamespace(
        image=SimpleNamespace(tags=["n8nio/n8n:1.123.0"], id="sha256:fake"),
        name="n8n",
    )
    vuln = {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl"}
    findings_by_image = {
        "n8nio/n8n:1.123.0": [vuln],
        "n8nio/n8n:1.124.2": [],
    }
    monkeypatch.setattr(
        pipeline.scanner,
        "scan_image",
        lambda image: pipeline.scanner.ScanResult(image=image, vulnerabilities=findings_by_image[image]),
    )
    monkeypatch.setattr(pipeline.ai, "analyze", lambda image, summary: "fake AI analysis")
    monkeypatch.setattr(pipeline.registry, "list_tags", lambda ref: ["1.122.0", "1.123.0", "1.124.2", "latest"])

    alerts = []
    pipeline._evaluate_container(container, lambda *a, **k: alerts.append((a, k)))

    with db_module.SessionLocal() as session:
        decision = session.query(db_module.PendingDecision).order_by(db_module.PendingDecision.id.desc()).first()
        assert decision.proposed_image == "n8nio/n8n:1.124.2"
    (args, _kwargs) = alerts[0]
    assert args[4] == "n8nio/n8n:1.124.2"  # proposed_image reaches the alert sink
    assert "n8nio/n8n:1.124.2" in args[3]  # and is mentioned in the alert text


def test_evaluate_container_skips_proposal_when_candidate_is_not_better(monkeypatch):
    container = SimpleNamespace(
        image=SimpleNamespace(tags=["n8nio/n8n:1.123.0"], id="sha256:fake"),
        name="n8n",
    )
    vuln = {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl"}
    monkeypatch.setattr(
        pipeline.scanner,
        "scan_image",
        lambda image: pipeline.scanner.ScanResult(image=image, vulnerabilities=[vuln]),
    )
    monkeypatch.setattr(pipeline.ai, "analyze", lambda image, summary: "fake AI analysis")
    monkeypatch.setattr(pipeline.registry, "list_tags", lambda ref: ["1.123.0", "1.124.2"])

    pipeline._evaluate_container(container, lambda *a, **k: None)

    with db_module.SessionLocal() as session:
        decision = session.query(db_module.PendingDecision).order_by(db_module.PendingDecision.id.desc()).first()
        assert decision.proposed_image is None


def test_resolve_decision_patch_pulls_the_proposed_image(monkeypatch):
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="n8nio/n8n:1.123.0",
            container_name="n8n",
            proposed_image="n8nio/n8n:1.124.2",
            summary="fake vulnerability summary",
            status="PENDING",
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    pulled = []
    monkeypatch.setattr(
        pipeline.docker_client,
        "pull_and_recreate",
        lambda image, container_name, client=None: pulled.append((image, container_name)),
    )

    result = pipeline.resolve_decision(decision_id, "patch")

    assert pulled == [("n8nio/n8n:1.124.2", "n8n")]
    assert result["ok"] is True
    assert result["action"] == "PATCHED"
    assert "n8nio/n8n:1.123.0 → n8nio/n8n:1.124.2" in result["details"]
