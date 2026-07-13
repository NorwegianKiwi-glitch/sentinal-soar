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
        pipeline.scanner, "scan_image", lambda image, cancel=None: pipeline.scanner.ScanResult(image=image, vulnerabilities=[])
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
        lambda image, cancel=None: pipeline.scanner.ScanResult(image=image, vulnerabilities=[vuln]),
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
        lambda image, cancel=None: pipeline.scanner.ScanResult(image=image, vulnerabilities=findings_by_image[image]),
    )
    monkeypatch.setattr(pipeline.ai, "analyze", lambda image, summary: "fake AI analysis")
    monkeypatch.setattr(
        pipeline.registry, "list_tags_for_upgrade", lambda ref, should_continue=None: ["1.122.0", "1.123.0", "1.124.2", "latest"]
    )

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
        lambda image, cancel=None: pipeline.scanner.ScanResult(image=image, vulnerabilities=[vuln]),
    )
    monkeypatch.setattr(pipeline.ai, "analyze", lambda image, summary: "fake AI analysis")
    monkeypatch.setattr(
        pipeline.registry, "list_tags_for_upgrade", lambda ref, should_continue=None: ["1.123.0", "1.124.2"]
    )

    pipeline._evaluate_container(container, lambda *a, **k: None)

    with db_module.SessionLocal() as session:
        decision = session.query(db_module.PendingDecision).order_by(db_module.PendingDecision.id.desc()).first()
        assert decision.proposed_image is None


def test_evaluate_container_never_offers_major_button_for_database_engines(monkeypatch):
    container = SimpleNamespace(
        image=SimpleNamespace(
            tags=["ghcr.io/immich-app/postgres:14-vectorchord0.3.0-pgvectors0.2.0"], id="sha256:fake"
        ),
        name="immich-postgres",
    )
    vuln = {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl"}
    monkeypatch.setattr(
        pipeline.scanner,
        "scan_image",
        lambda image, cancel=None: pipeline.scanner.ScanResult(image=image, vulnerabilities=[vuln]),
    )
    monkeypatch.setattr(pipeline.ai, "analyze", lambda image, summary: "fake AI analysis")
    monkeypatch.setattr(
        pipeline.registry,
        "list_tags_for_upgrade",
        lambda ref, should_continue=None: ["14-vectorchord0.3.0-pgvectors0.2.0", "16-vectorchord0.3.0-pgvectors0.2.0"],
    )

    pipeline._evaluate_container(container, lambda *a, **k: None)

    with db_module.SessionLocal() as session:
        decision = session.query(db_module.PendingDecision).order_by(db_module.PendingDecision.id.desc()).first()
        # a pg16 binary cannot read a pg14 data dir — swapping the image would only crash it
        assert decision.proposed_major_image is None
        assert decision.proposed_image is None
        assert "database engine" in decision.ai_analysis
        assert "dump/restore" in decision.ai_analysis


def test_resolve_decision_major_runs_compose_and_retires_siblings(monkeypatch):
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="ghcr.io/immich-app/immich-server:v2.7.5",
            container_name="immich-server",
            proposed_major_image="ghcr.io/immich-app/immich-server:v3.0.2",
            summary="fake vulnerability summary",
            status="PENDING",
        )
        sibling = db_module.PendingDecision(
            image_name="ghcr.io/immich-app/immich-machine-learning:v2.7.5",
            container_name="immich-machine-learning",
            summary="fake vulnerability summary",
            status="PENDING",
        )
        session.add_all([decision, sibling])
        session.commit()
        session.refresh(decision)
        session.refresh(sibling)
        decision_id, sibling_id = decision.id, sibling.id

    events = []
    monkeypatch.setattr(
        pipeline.backup,
        "run_pre_upgrade_backup",
        lambda app: events.append(("backup", app)) or "cafe1234",
    )
    monkeypatch.setattr(
        pipeline.compose,
        "apply_major_upgrade",
        lambda target, current, container: events.append(("upgrade", target, current, container))
        or ("big-bear-immich", "Major upgrade of app 'big-bear-immich': done."),
    )
    project_containers = [
        SimpleNamespace(name="immich-server"),
        SimpleNamespace(name="immich-machine-learning"),
    ]
    monkeypatch.setattr(
        pipeline.docker_client,
        "get_client",
        lambda: SimpleNamespace(
            containers=SimpleNamespace(list=lambda all=True, filters=None: project_containers)
        ),
    )

    result = pipeline.resolve_decision(decision_id, "major")

    assert events == [
        ("backup", "immich-server"),  # the snapshot exists before anything is touched
        (
            "upgrade",
            "ghcr.io/immich-app/immich-server:v3.0.2",
            "ghcr.io/immich-app/immich-server:v2.7.5",
            "immich-server",
        ),
    ]
    assert result["ok"] is True
    assert result["action"] == "MAJOR_UPGRADED"
    assert "Pre-upgrade snapshot cafe1234 taken." in result["details"]
    assert "Retired 1 stale sibling alert(s)" in result["details"]
    with db_module.SessionLocal() as session:
        # the sibling's patch button would have downgraded the freshly-upgraded app
        assert session.get(db_module.PendingDecision, sibling_id).status == "RESOLVED"
        assert session.get(db_module.PendingDecision, decision_id).status == "RESOLVED"
        latest = session.query(db_module.ScanLog).order_by(db_module.ScanLog.id.desc()).first()
        assert latest.action_taken == "MAJOR_UPGRADED"


def test_resolve_decision_major_aborts_when_backup_fails(monkeypatch):
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="ghcr.io/immich-app/immich-server:v2.7.5",
            container_name="immich-server",
            proposed_major_image="ghcr.io/immich-app/immich-server:v3.0.2",
            summary="fake vulnerability summary",
            status="PENDING",
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    def _no_backup(app):
        raise RuntimeError("repository locked")

    monkeypatch.setattr(pipeline.backup, "run_pre_upgrade_backup", _no_backup)
    upgraded = []
    monkeypatch.setattr(
        pipeline.compose, "apply_major_upgrade", lambda *a, **k: upgraded.append(a)
    )

    result = pipeline.resolve_decision(decision_id, "major")

    assert upgraded == []  # no snapshot, no upgrade
    assert result["ok"] is False
    assert result["action"] == "FAILED"
    assert "NOT attempted" in result["details"]


def test_resolve_decision_major_without_target_is_rejected():
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="a:1", container_name="c", summary="s", status="PENDING"
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    try:
        pipeline.resolve_decision(decision_id, "major")
        assert False, "expected ValueError"
    except ValueError:
        pass

    with db_module.SessionLocal() as session:
        # the failed attempt must release its claim so the buttons still work
        assert session.get(db_module.PendingDecision, decision_id).status == "PENDING"


def test_run_scan_cycle_stops_when_cancelled(monkeypatch):
    containers = [SimpleNamespace(name=f"c{i}") for i in range(4)]
    monkeypatch.setattr(pipeline.docker_client, "get_client", lambda: SimpleNamespace())
    monkeypatch.setattr(pipeline.docker_client, "list_containers", lambda client: containers)

    evaluated = []

    def fake_eval(container, sink):
        evaluated.append(container.name)
        pipeline.request_scan_stop()  # ask to stop after the first container

    monkeypatch.setattr(pipeline, "_evaluate_container", fake_eval)

    count = pipeline.run_scan_cycle(lambda *a, **k: None)

    assert count == 1  # stopped before the second container
    assert evaluated == ["c0"]
    assert pipeline.scan_running() is False  # flag cleared even on early stop


def test_evaluate_container_does_not_realert_while_decision_open(monkeypatch):
    with db_module.SessionLocal() as session:
        session.add(
            db_module.PendingDecision(
                image_name="nginx:latest",
                container_name="nginx-container",
                summary="already awaiting a human",
                status="PENDING",
            )
        )
        session.commit()

    container = SimpleNamespace(
        image=SimpleNamespace(tags=["nginx:latest"], id="sha256:fake"),
        name="nginx-container",
    )
    scans, alerts = [], []
    monkeypatch.setattr(pipeline.scanner, "scan_image", lambda image, cancel=None: scans.append(image))

    pipeline._evaluate_container(container, lambda *a, **k: alerts.append(a))

    assert scans == []  # no redundant Trivy scan while the alert is open
    assert alerts == []
    with db_module.SessionLocal() as session:
        assert session.query(db_module.PendingDecision).count() == 1
        latest = session.query(db_module.ScanLog).order_by(db_module.ScanLog.id.desc()).first()
        assert latest.action_taken == "AUTO_SKIP"
        assert "awaiting a human" in latest.log_payload["details"]


def test_apply_patch_syncs_definition_only_on_real_upgrades(monkeypatch):
    monkeypatch.setattr(pipeline.docker_client, "pull_and_recreate", lambda *a, **k: None)
    sync_calls = []
    monkeypatch.setattr(
        pipeline.definitions,
        "sync_image_reference",
        lambda name, old, new: sync_calls.append((name, old, new)) or "Updated 1 image reference(s) in /x.",
    )

    action, ok, details = pipeline._apply_patch("redis:6.2.22", "redis:6.2.6", "redis-nextcloud")

    assert ok is True
    assert action == db_module.ActionTaken.PATCHED
    assert sync_calls == [("redis-nextcloud", "redis:6.2.6", "redis:6.2.22")]
    assert "Updated 1 image reference(s)" in details

    sync_calls.clear()
    pipeline._apply_patch("redis:6.2.6", "redis:6.2.6", "redis-nextcloud")
    assert sync_calls == []  # same-tag re-pull: definition already correct


def test_resolve_decision_rejects_decision_already_in_progress():
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="nginx:latest",
            container_name="nginx-container",
            summary="fake vulnerability summary",
            status="IN_PROGRESS",
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    try:
        pipeline.resolve_decision(decision_id, "patch")
        assert False, "expected ValueError"
    except ValueError:
        pass

    with db_module.SessionLocal() as session:
        assert session.get(db_module.PendingDecision, decision_id).status == "IN_PROGRESS"


def test_resolve_decision_releases_claim_when_resolution_raises(monkeypatch):
    with db_module.SessionLocal() as session:
        decision = db_module.PendingDecision(
            image_name="redis:7",
            container_name="redis-container",
            summary="fake vulnerability summary",
            status="PENDING",
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    def _boom(session, image, days):
        raise RuntimeError("db exploded mid-snooze")

    monkeypatch.setattr(pipeline, "_snooze", _boom)

    try:
        pipeline.resolve_decision(decision_id, "snooze")
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass

    # The claim must be released so the human gets a working button back,
    # and nothing may be logged for a resolution that never happened.
    with db_module.SessionLocal() as session:
        assert session.get(db_module.PendingDecision, decision_id).status == "PENDING"
        logged = (
            session.query(db_module.ScanLog).filter_by(image_name="redis:7").count()
        )
        assert logged == 0


def test_evaluate_container_mentions_newer_major_without_proposing_it(monkeypatch):
    container = SimpleNamespace(
        image=SimpleNamespace(tags=["ghcr.io/immich-app/immich-server:v2.7.5"], id="sha256:fake"),
        name="immich-server",
    )
    vuln = {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl"}
    scans = []
    monkeypatch.setattr(
        pipeline.scanner,
        "scan_image",
        lambda image, cancel=None: scans.append(image)
        or pipeline.scanner.ScanResult(image=image, vulnerabilities=[vuln]),
    )
    monkeypatch.setattr(pipeline.ai, "analyze", lambda image, summary: "fake AI analysis")
    monkeypatch.setattr(
        pipeline.registry, "list_tags_for_upgrade", lambda ref, should_continue=None: ["v2.7.5", "v3.0.0-rc.3", "v3.0.2"]
    )

    alerts = []
    pipeline._evaluate_container(container, lambda *a, **k: alerts.append(a))

    assert scans == ["ghcr.io/immich-app/immich-server:v2.7.5"]  # no candidate scanned
    with db_module.SessionLocal() as session:
        decision = session.query(db_module.PendingDecision).order_by(db_module.PendingDecision.id.desc()).first()
        assert decision.proposed_image is None  # a major bump is never the one-click patch target
        assert decision.proposed_major_image == "ghcr.io/immich-app/immich-server:v3.0.2"
        assert "No same-major upgrade exists" in decision.ai_analysis
        assert "immich-server:v3.0.2" in decision.ai_analysis


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
