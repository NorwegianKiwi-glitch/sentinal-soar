import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("DISCORD_BOT_TOKEN", "test-token")
os.environ.setdefault("DISCORD_GUILD_ID", "1")
os.environ.setdefault("DISCORD_CHANNEL_ID", "1")
os.environ.setdefault("GEMINI_API_KEY", "test-key")
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret")
os.environ.setdefault("DASHBOARD_USERNAME", "test-user")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-pass")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinal import db as db_module


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch):
    """Every module reaches the session factory via `db.SessionLocal()` at call
    time (not `from .db import SessionLocal` at import time), so patching it
    here in one place is enough to isolate pipeline, bot, and web tests alike.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db_module.Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, expire_on_commit=False, future=True)

    monkeypatch.setattr(db_module, "engine", engine)
    monkeypatch.setattr(db_module, "SessionLocal", test_session)
    yield


@pytest.fixture(autouse=True)
def _stub_docker_containers(monkeypatch):
    """The Settings page lists live containers via docker_client.list_containers
    at request time; stub it so web tests are hermetic and don't depend on a
    real Docker daemon being reachable. Tests that care about specific
    containers monkeypatch this again themselves, which simply overrides it.
    """
    from sentinal import docker_client

    monkeypatch.setattr(docker_client, "list_containers", lambda *a, **k: [])
    yield


@pytest.fixture(autouse=True)
def _reset_scan_state():
    """The scan cancel/running flags are module-level (a real scan clears them
    at the start of each cycle). Reset them per test so a cancellation test
    can't leak a set flag into tests that call _evaluate_container directly.
    """
    from sentinal import pipeline

    pipeline._scan_cancel.clear()
    pipeline._scan_running.clear()
    yield
