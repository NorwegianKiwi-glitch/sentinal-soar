from __future__ import annotations

import datetime as dt
import hmac
import logging
import threading

from flask import Blueprint, Response, jsonify, redirect, render_template, request, url_for
from sqlalchemy import select

from .. import db, patching, pipeline
from ..config import get_settings

log = logging.getLogger(__name__)

bp = Blueprint("dashboard", __name__)

_RESOLUTION_CHOICES = {"patch", "snooze", "refuse", "major"}


@bp.before_request
def _require_auth():
    settings = get_settings()
    auth = request.authorization
    valid = bool(
        auth
        and hmac.compare_digest(auth.username or "", settings.dashboard_username)
        and hmac.compare_digest(auth.password or "", settings.dashboard_password)
    )
    if not valid:
        return Response(
            "Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Sentinal"'}
        )


# --- pages ------------------------------------------------------------------


@bp.get("/")
def index():
    return redirect(url_for("dashboard.decisions"))


@bp.get("/decisions")
def decisions():
    with db.SessionLocal() as session:
        rows = session.scalars(
            select(db.PendingDecision)
            .where(
                db.PendingDecision.status.in_(
                    [db.DecisionStatus.PENDING.value, db.DecisionStatus.IN_PROGRESS.value]
                )
            )
            .order_by(db.PendingDecision.id.desc())
        ).all()
        items = [
            {"d": d, "patch": patching.describe_patch(d.image_name, d.proposed_image, d.proposed_major_image)}
            for d in rows
        ]
    return render_template("decisions.html", items=items, active="decisions")


@bp.get("/logs")
def logs():
    filters = {key: (request.args.get(key) or "").strip() for key in ("image", "action", "date_from", "date_to", "id")}
    stmt = select(db.ScanLog).where(db.ScanLog.archived.is_(False))
    if filters["image"]:
        stmt = stmt.where(db.ScanLog.image_name.ilike(f"%{filters['image']}%"))
    if filters["action"]:
        stmt = stmt.where(db.ScanLog.action_taken == filters["action"])
    if filters["id"].isdigit():
        stmt = stmt.where(db.ScanLog.id == int(filters["id"]))
    date_from = _parse_date(filters["date_from"])
    if date_from:
        stmt = stmt.where(db.ScanLog.scan_time >= date_from)
    date_to = _parse_date(filters["date_to"])
    if date_to:
        stmt = stmt.where(db.ScanLog.scan_time < date_to + dt.timedelta(days=1))
    with db.SessionLocal() as session:
        rows = session.scalars(stmt.order_by(db.ScanLog.id.desc())).all()
    return render_template(
        "logs.html", logs=rows, filters=filters, actions=[a.value for a in db.ActionTaken], active="logs"
    )


@bp.get("/exceptions")
def exceptions():
    with db.SessionLocal() as session:
        rows = session.scalars(
            select(db.ContainerException).order_by(db.ContainerException.updated_at.desc())
        ).all()
    return render_template("exceptions.html", exceptions=rows, active="exceptions")


@bp.get("/decisions/<int:decision_id>/major")
def major_confirm(decision_id: int):
    try:
        target, project, family, companions = pipeline.preview_major_upgrade(decision_id)
    except Exception as exc:
        return render_template("confirm_major.html", error=str(exc), decision_id=decision_id, active="decisions")
    return render_template(
        "confirm_major.html",
        decision_id=decision_id,
        target=target,
        project=project,
        family=family,
        companions=companions,
        error=None,
        active="decisions",
    )


# --- decision actions -------------------------------------------------------


def _run_decision_async(decision_id: int, choice: str) -> None:
    def _run() -> None:
        try:
            pipeline.resolve_decision(decision_id, choice)
        except ValueError:
            pass  # already resolved or claimed elsewhere (e.g. via Discord)
        except Exception:
            log.exception("Web-triggered %s on decision %d failed", choice, decision_id)

    threading.Thread(target=_run, daemon=True).start()


@bp.post("/api/decisions/<int:decision_id>/<choice>")
def act_on_decision(decision_id: int, choice: str):
    if choice not in _RESOLUTION_CHOICES:
        return jsonify({"error": "unknown choice"}), 400
    _run_decision_async(decision_id, choice)
    return jsonify({"status": "started"}), 202


@bp.get("/api/decisions/<int:decision_id>")
def decision_status(decision_id: int):
    with db.SessionLocal() as session:
        decision = session.get(db.PendingDecision, decision_id)
        if decision is None:
            return jsonify({"error": "not found"}), 404
        details = ""
        if decision.status == db.DecisionStatus.RESOLVED.value:
            latest = session.scalars(
                select(db.ScanLog)
                .where(db.ScanLog.image_name == decision.image_name)
                .order_by(db.ScanLog.id.desc())
            ).first()
            if latest:
                details = latest.log_payload.get("details", "")
        return jsonify({"status": decision.status, "details": details})


# --- scan control -----------------------------------------------------------


@bp.post("/api/scan")
def trigger_scan():
    from .. import bot

    if pipeline.scan_running():
        return jsonify({"status": "already-running"}), 409

    def _run() -> None:
        bot.post_scan_started_threadsafe()
        bot.set_scanning_presence_threadsafe(True)
        try:
            count = pipeline.run_scan_cycle(bot.post_alert_threadsafe)
            bot.post_scan_complete_threadsafe(count)
        except Exception as exc:
            bot.post_error_threadsafe("manual scan", str(exc))
        finally:
            bot.set_scanning_presence_threadsafe(False)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"}), 202


@bp.post("/api/scan/stop")
def stop_scan():
    pipeline.request_scan_stop()
    return jsonify({"status": "stopping"}), 202


@bp.get("/api/scan/status")
def scan_status():
    return jsonify({"running": pipeline.scan_running()})


# --- log / exception mutations ---------------------------------------------


@bp.post("/api/logs/<int:log_id>/archive")
def archive_log(log_id: int):
    with db.SessionLocal() as session:
        log_row = session.get(db.ScanLog, log_id)
        if log_row is None:
            return jsonify({"error": "not found"}), 404
        log_row.archived = True
        log_row.archived_at = dt.datetime.utcnow()
        session.commit()
    return jsonify({"status": "archived"})


@bp.post("/api/exceptions/<int:exception_id>/delete")
def delete_exception(exception_id: int):
    with db.SessionLocal() as session:
        exception = session.get(db.ContainerException, exception_id)
        if exception is None:
            return jsonify({"error": "not found"}), 404
        session.delete(exception)
        session.commit()
    return jsonify({"status": "deleted"})


def _parse_date(value: str) -> dt.datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None
