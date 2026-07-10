from __future__ import annotations

import datetime as dt
import hmac
import threading

from flask import Blueprint, Response, jsonify, render_template, request
from sqlalchemy import select

from .. import db, pipeline
from ..config import get_settings

bp = Blueprint("dashboard", __name__)


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


@bp.get("/")
def dashboard():
    with db.SessionLocal() as session:
        logs = session.scalars(
            select(db.ScanLog).where(db.ScanLog.archived.is_(False)).order_by(db.ScanLog.id.desc())
        ).all()
        exceptions = session.scalars(
            select(db.ContainerException).order_by(db.ContainerException.updated_at.desc())
        ).all()
    return render_template("dashboard.html", logs=logs, exceptions=exceptions)


@bp.post("/api/scan")
def trigger_scan():
    from .. import bot

    def _run() -> None:
        try:
            count = pipeline.run_scan_cycle(bot.post_alert_threadsafe)
            bot.post_scan_complete_threadsafe(count)
        except Exception as exc:
            bot.post_error_threadsafe("manual scan", str(exc))

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"}), 202


@bp.post("/api/logs/<int:log_id>/archive")
def archive_log(log_id: int):
    with db.SessionLocal() as session:
        log = session.get(db.ScanLog, log_id)
        if log is None:
            return jsonify({"error": "not found"}), 404
        log.archived = True
        log.archived_at = dt.datetime.utcnow()
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
