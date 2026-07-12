from __future__ import annotations

import datetime as dt
import logging
import threading
from typing import Protocol

from sqlalchemy import select, update

from . import ai, db, definitions, docker_client, registry, scanner
from .config import get_settings

log = logging.getLogger(__name__)


class AlertSink(Protocol):
    def __call__(
        self, decision_id: int, image: str, container_name: str, ai_text: str, proposed_image: str | None
    ) -> None: ...


def run_scan_cycle(post_alert: AlertSink) -> int:
    client = docker_client.get_client()
    containers = docker_client.list_containers(client)
    for container in containers:
        _evaluate_container(container, post_alert)
    return len(containers)


def _evaluate_container(container, post_alert: AlertSink) -> None:
    image = container.image.tags[0] if container.image.tags else container.image.id
    name = container.name

    with db.SessionLocal() as session:
        exception = session.scalar(
            select(db.ContainerException).where(db.ContainerException.image_name == image)
        )
        if _is_deferred(exception):
            _write_log(session, image, db.ActionTaken.AUTO_SKIP, "Active snooze or refusal on file.")
            return

        open_decision = session.scalar(
            select(db.PendingDecision).where(
                db.PendingDecision.image_name == image,
                db.PendingDecision.container_name == name,
                db.PendingDecision.status.in_(
                    [db.DecisionStatus.PENDING.value, db.DecisionStatus.IN_PROGRESS.value]
                ),
            )
        )
        if open_decision is not None:
            # Re-alerting while a human hasn't answered the previous alert just
            # breeds duplicate Discord messages whose buttons race each other
            # (and duplicate remediations when both get clicked). It also lets
            # us skip the redundant Trivy scan and AI call entirely.
            _write_log(
                session,
                image,
                db.ActionTaken.AUTO_SKIP,
                f"Alert for decision #{open_decision.id} is still awaiting a human in Discord; not re-alerting.",
            )
            return

    try:
        result = scanner.scan_image(image)
    except Exception as exc:
        log.exception("Scan failed for %s", image)
        with db.SessionLocal() as session:
            _write_log(session, image, db.ActionTaken.FAILED, f"Scan failed: {exc}", ok=False)
        return

    if not result.has_findings:
        severities = ", ".join(s.strip() for s in get_settings().trivy_severity.split(","))
        with db.SessionLocal() as session:
            _write_log(session, image, db.ActionTaken.CLEAN, f"Scanned — no {severities} vulnerabilities found.")
        return

    summary = result.summary_text()
    try:
        ai_text = ai.analyze(image, summary)
    except Exception as exc:
        log.exception("AI analysis failed for %s", image)
        ai_text = f"(AI analysis unavailable: {exc})\n\n{summary}"

    proposed_image, proposal_note = _propose_version_bump(image, len(result.vulnerabilities))
    if proposal_note:
        ai_text = f"{ai_text}\n\n{proposal_note}"

    with db.SessionLocal() as session:
        decision = db.PendingDecision(
            image_name=image,
            container_name=name,
            proposed_image=proposed_image,
            summary=summary,
            ai_analysis=ai_text,
            status=db.DecisionStatus.PENDING.value,
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    post_alert(decision_id, image, name, ai_text, proposed_image)


def _propose_version_bump(image: str, current_findings: int) -> tuple[str | None, str | None]:
    """Find a newer same-major tag that Trivy confirms has fewer findings.

    Returns (candidate_image, human-readable note), or (None, None) when there
    is no verifiably better tag. Never raises: a registry hiccup should degrade
    to the plain same-tag patch, not fail the scan cycle.
    """
    if image.startswith("sha256:") or "@sha256:" in image:
        return None, None
    try:
        ref = registry.parse_image_ref(image)
        if registry.parse_version_tag(ref.tag) is None:
            return None, None
        tags = registry.list_tags_for_upgrade(ref)
        candidate_tag = registry.pick_upgrade_candidate(ref.tag, tags)
        if candidate_tag is None:
            newest_tag = registry.newest_release(ref.tag, tags)
            if newest_tag is None:
                return None, None
            # A newer major exists but the old major line is over: too risky to
            # one-click (migrations, breaking changes) yet too important to
            # keep quiet about.
            return None, (
                f"**No same-major upgrade exists** for `{image}` — the project has moved on to "
                f"`{image.rpartition(':')[0]}:{newest_tag}`. Major upgrades can require migration "
                "steps; review the release notes and upgrade via CasaOS when ready. The patch "
                "button below only re-pulls the current tag."
            )
        candidate = f"{image.rpartition(':')[0]}:{candidate_tag}"
        candidate_findings = len(scanner.scan_image(candidate).vulnerabilities)
    except Exception as exc:
        log.warning("Version-bump lookup failed for %s: %s", image, exc)
        return None, None
    if candidate_findings >= current_findings:
        log.info(
            "Newest same-major tag %s has %d finding(s) vs %d current — not proposing",
            candidate, candidate_findings, current_findings,
        )
        return None, None
    note = (
        f"**Proposed upgrade:** `{candidate}` — Trivy-verified at {candidate_findings} finding(s) "
        f"vs {current_findings} on the current tag."
    )
    return candidate, note


def _is_deferred(exception: db.ContainerException | None) -> bool:
    if exception is None:
        return False
    if exception.status == db.ExceptionStatus.REFUSED.value:
        return True
    return bool(exception.snooze_until and exception.snooze_until > dt.datetime.utcnow())


def resolve_decision(decision_id: int, choice: str) -> dict:
    """choice: 'patch' | 'snooze' | 'refuse'. Called from a Discord button handler.

    The decision is claimed atomically up front instead of holding one session
    open across the remediation: a patch pulls an image, which can take minutes
    on a Pi, and a second click during that window must not start a duplicate
    remediation — nor should a DB hiccup at the end erase the audit trail of a
    remediation that already happened.
    """
    settings = get_settings()

    with db.SessionLocal() as session:
        claimed = session.execute(
            update(db.PendingDecision)
            .where(
                db.PendingDecision.id == decision_id,
                db.PendingDecision.status == db.DecisionStatus.PENDING.value,
            )
            .values(status=db.DecisionStatus.IN_PROGRESS.value)
        ).rowcount
        if not claimed:
            session.rollback()
            raise ValueError("Decision already resolved, in progress, or not found")
        decision = session.get(db.PendingDecision, decision_id)
        image_name = decision.image_name
        container_name = decision.container_name
        proposed_image = decision.proposed_image
        session.commit()

    try:
        if choice == "patch":
            action, ok, details = _apply_patch(proposed_image or image_name, image_name, container_name)
        elif choice == "snooze":
            with db.SessionLocal() as session:
                action, ok, details = _snooze(session, image_name, settings.snooze_days)
                session.commit()
        elif choice == "refuse":
            with db.SessionLocal() as session:
                action, ok, details = _refuse(session, image_name, settings.refuse_review_days)
                session.commit()
        else:
            raise ValueError(f"Unknown choice: {choice}")
    except Exception:
        with db.SessionLocal() as session:
            session.execute(
                update(db.PendingDecision)
                .where(db.PendingDecision.id == decision_id)
                .values(status=db.DecisionStatus.PENDING.value)
            )
            session.commit()
        raise

    with db.SessionLocal() as session:
        decision = session.get(db.PendingDecision, decision_id)
        decision.status = db.DecisionStatus.RESOLVED.value
        decision.resolved_at = dt.datetime.utcnow()
        _write_log(session, image_name, action, details, ok=ok)
        return {"action": action.value, "ok": ok, "details": details}


# One remediation at a time: every approval pulls an image, and concurrent
# multi-hundred-MB pulls can IO-starve a Pi until SSH and the dashboard freeze.
_remediation_lock = threading.Lock()


def _apply_patch(target_image: str, current_image: str, container_name: str) -> tuple[db.ActionTaken, bool, str]:
    try:
        with _remediation_lock:
            docker_client.pull_and_recreate(target_image, container_name)
    except Exception as exc:
        log.exception("Remediation failed for %s", target_image)
        return db.ActionTaken.FAILED, False, f"Remediation failed: {exc}"
    if target_image != current_image:
        sync_note = definitions.sync_image_reference(container_name, current_image, target_image)
        return (
            db.ActionTaken.PATCHED,
            True,
            f"Upgraded {container_name}: {current_image} → {target_image}. {sync_note}",
        )
    return db.ActionTaken.PATCHED, True, f"Pulled {target_image} and recreated {container_name}."


def _snooze(session, image: str, days: int) -> tuple[db.ActionTaken, bool, str]:
    until = dt.datetime.utcnow() + dt.timedelta(days=days)
    _upsert_exception(
        session, image, db.ExceptionStatus.SNOOZED.value, snooze_until=until, review_after=until
    )
    return db.ActionTaken.SNOOZED, True, f"Snoozed until {until.isoformat()}."


def _refuse(session, image: str, review_days: int) -> tuple[db.ActionTaken, bool, str]:
    review_after = dt.datetime.utcnow() + dt.timedelta(days=review_days)
    _upsert_exception(
        session, image, db.ExceptionStatus.REFUSED.value, snooze_until=None, review_after=review_after
    )
    return db.ActionTaken.REFUSED, True, f"Refused; re-attestation due {review_after.date().isoformat()}."


def _upsert_exception(
    session, image: str, status: str, snooze_until: dt.datetime | None, review_after: dt.datetime | None
) -> None:
    exception = session.scalar(select(db.ContainerException).where(db.ContainerException.image_name == image))
    if exception is None:
        exception = db.ContainerException(image_name=image)
        session.add(exception)
    exception.status = status
    exception.snooze_until = snooze_until
    exception.review_after = review_after
    exception.updated_at = dt.datetime.utcnow()


def _write_log(session, image: str, action: db.ActionTaken, details: str, ok: bool = True) -> None:
    session.add(
        db.ScanLog(
            image_name=image,
            action_taken=action.value,
            log_payload={
                "timestamp": dt.datetime.utcnow().isoformat(),
                "image": image,
                "action": action.value,
                "status": "SUCCESS" if ok else "FAILED",
                "details": details,
            },
        )
    )
    session.commit()
