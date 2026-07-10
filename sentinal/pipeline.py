from __future__ import annotations

import datetime as dt
import logging
from typing import Protocol

from sqlalchemy import select

from . import ai, db, docker_client, scanner
from .config import get_settings

log = logging.getLogger(__name__)


class AlertSink(Protocol):
    def __call__(self, decision_id: int, image: str, container_name: str, ai_text: str) -> None: ...


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

    try:
        result = scanner.scan_image(image)
    except Exception as exc:
        log.exception("Scan failed for %s", image)
        with db.SessionLocal() as session:
            _write_log(session, image, db.ActionTaken.FAILED, f"Scan failed: {exc}", ok=False)
        return

    if not result.has_findings:
        with db.SessionLocal() as session:
            _write_log(session, image, db.ActionTaken.CLEAN, "No high/critical vulnerabilities found.")
        return

    summary = result.summary_text()
    try:
        ai_text = ai.analyze(image, summary)
    except Exception as exc:
        log.exception("AI analysis failed for %s", image)
        ai_text = f"(AI analysis unavailable: {exc})\n\n{summary}"

    with db.SessionLocal() as session:
        decision = db.PendingDecision(
            image_name=image,
            container_name=name,
            summary=summary,
            ai_analysis=ai_text,
            status=db.DecisionStatus.PENDING.value,
        )
        session.add(decision)
        session.commit()
        session.refresh(decision)
        decision_id = decision.id

    post_alert(decision_id, image, name, ai_text)


def _is_deferred(exception: db.ContainerException | None) -> bool:
    if exception is None:
        return False
    if exception.status == db.ExceptionStatus.REFUSED.value:
        return True
    return bool(exception.snooze_until and exception.snooze_until > dt.datetime.utcnow())


def resolve_decision(decision_id: int, choice: str) -> dict:
    """choice: 'patch' | 'snooze' | 'refuse'. Called from a Discord button handler."""
    settings = get_settings()
    with db.SessionLocal() as session:
        decision = session.get(db.PendingDecision, decision_id)
        if decision is None or decision.status != db.DecisionStatus.PENDING.value:
            raise ValueError("Decision already resolved or not found")

        if choice == "patch":
            action, ok, details = _apply_patch(decision.image_name, decision.container_name)
        elif choice == "snooze":
            action, ok, details = _snooze(session, decision.image_name, settings.snooze_days)
        elif choice == "refuse":
            action, ok, details = _refuse(session, decision.image_name, settings.refuse_review_days)
        else:
            raise ValueError(f"Unknown choice: {choice}")

        decision.status = db.DecisionStatus.RESOLVED.value
        decision.resolved_at = dt.datetime.utcnow()
        _write_log(session, decision.image_name, action, details, ok=ok)
        session.commit()
        return {"action": action.value, "ok": ok, "details": details}


def _apply_patch(image: str, container_name: str) -> tuple[db.ActionTaken, bool, str]:
    try:
        docker_client.pull_and_restart(image, container_name)
        return db.ActionTaken.PATCHED, True, f"Pulled {image} and restarted {container_name}."
    except Exception as exc:
        log.exception("Remediation failed for %s", image)
        return db.ActionTaken.FAILED, False, f"Remediation failed: {exc}"


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
