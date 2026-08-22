from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import DateTime, JSON, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


class ActionTaken(str, enum.Enum):
    CLEAN = "CLEAN"
    AUTO_SKIP = "AUTO_SKIP"
    PATCHED = "PATCHED"
    MAJOR_UPGRADED = "MAJOR_UPGRADED"
    SNOOZED = "SNOOZED"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


class ExceptionStatus(str, enum.Enum):
    SNOOZED = "SNOOZED"
    REFUSED = "REFUSED"


class DecisionStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class ScanLog(Base):
    """Append-only audit trail. Rows are archived, never hard-deleted — see ARCHITECTURE.md."""

    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    image_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_time: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    action_taken: Mapped[str] = mapped_column(String(50), default=ActionTaken.CLEAN.value)
    log_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    archived: Mapped[bool] = mapped_column(default=False)
    archived_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class ContainerException(Base):
    """A snooze or refuse decision for an image — governance state, not audit history."""

    __tablename__ = "container_exceptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    image_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    snooze_until: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    review_after: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )


class PendingDecision(Base):
    """A scan awaiting a human decision over Discord — replaces n8n's sendAndWait suspend/resume."""

    __tablename__ = "pending_decisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    image_name: Mapped[str] = mapped_column(String(255), nullable=False)
    container_name: Mapped[str] = mapped_column(String(255), nullable=False)
    proposed_image: Mapped[str | None] = mapped_column(String(255), nullable=True)
    proposed_major_image: Mapped[str | None] = mapped_column(String(255), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    ai_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=DecisionStatus.PENDING.value)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class ScanSchedule(Base):
    """Single row (id=1) holding the periodic-scan config the web console edits.
    Seeded from SCAN_INTERVAL_HOURS on first boot, then DB-authoritative so the
    schedule survives restarts and can change without one."""

    __tablename__ = "scan_schedule"

    id: Mapped[int] = mapped_column(primary_key=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    mode: Mapped[str] = mapped_column(String(20), default="interval")  # "interval" | "daily"
    interval_hours: Mapped[int] = mapped_column(default=24)
    daily_time: Mapped[str] = mapped_column(String(5), default="03:00")  # "HH:MM", server-local
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )


class NotificationSettings(Base):
    """Single row (id=1): runtime mute switch for Discord notifications.

    Independent of whether Discord is connected at all (DISCORD_BOT_TOKEN /
    DISCORD_CHANNEL_ID — see config.Settings.discord_enabled, decided at
    boot). This toggles on top of an already-connected bot, so flipping it
    off silences alerts without dropping the connection, and flipping it
    back on takes effect immediately — see notifications.py."""

    __tablename__ = "notification_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    discord_enabled: Mapped[bool] = mapped_column(default=True)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )


class ExcludedContainer(Base):
    """A container name deselected from scans — see container_selection.py.

    Opt-out by design: absence from this table means "scanned," so a
    container that shows up on the host after this feature ships is covered
    by default, matching the scan-everything behavior from before it existed.
    """

    __tablename__ = "excluded_containers"

    id: Mapped[int] = mapped_column(primary_key=True)
    container_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class DashboardCredentials(Base):
    """Single row (id=1) holding the web console's login username/password hash.
    Seeded from DASHBOARD_USERNAME/DASHBOARD_PASSWORD on first boot, then
    DB-authoritative — a change from Settings takes effect immediately and
    survives restarts without editing .env."""

    __tablename__ = "dashboard_credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )


engine = create_engine(get_settings().database_url, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(engine)
    _apply_migrations()


def _apply_migrations() -> None:
    """create_all only creates missing tables; additive columns on already
    existing tables land here. Postgres-only on purpose — tests build a fresh
    schema from the models on SQLite and never need migrating.
    """
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE pending_decisions ADD COLUMN IF NOT EXISTS proposed_image VARCHAR(255)")
        )
        conn.execute(
            text("ALTER TABLE pending_decisions ADD COLUMN IF NOT EXISTS proposed_major_image VARCHAR(255)")
        )
