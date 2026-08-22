from __future__ import annotations

from sentinal import db as db_module, notifications


def test_enabled_defaults_true_when_no_row_exists():
    with db_module.SessionLocal() as session:
        assert session.get(db_module.NotificationSettings, 1) is None
    assert notifications.enabled() is True


def test_set_enabled_false_then_true_roundtrips():
    assert notifications.set_enabled(False) is False
    assert notifications.enabled() is False

    assert notifications.set_enabled(True) is True
    assert notifications.enabled() is True


def test_set_enabled_creates_row_on_first_write():
    notifications.set_enabled(False)
    with db_module.SessionLocal() as session:
        row = session.get(db_module.NotificationSettings, 1)
        assert row is not None and row.discord_enabled is False
