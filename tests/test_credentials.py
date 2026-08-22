from __future__ import annotations

from sentinal import credentials, db as db_module


def test_get_seeds_a_row_from_env_defaults_when_missing():
    with db_module.SessionLocal() as session:
        assert session.get(db_module.DashboardCredentials, 1) is None

    creds = credentials.get()

    assert creds.username == "test-user"
    with db_module.SessionLocal() as session:
        assert session.get(db_module.DashboardCredentials, 1) is not None


def test_verify_accepts_seeded_credentials():
    assert credentials.verify("test-user", "test-pass") is True


def test_verify_rejects_wrong_password():
    assert credentials.verify("test-user", "nope") is False


def test_verify_rejects_wrong_username():
    assert credentials.verify("nope", "test-pass") is False


def test_password_is_stored_hashed_not_plaintext():
    creds = credentials.get()
    assert creds.password_hash != "test-pass"


def test_update_changes_username_and_password():
    updated = credentials.update(current_password="test-pass", new_username="new-admin", new_password="new-pass")

    assert updated.username == "new-admin"
    assert credentials.verify("new-admin", "new-pass") is True
    assert credentials.verify("test-user", "test-pass") is False


def test_update_without_new_password_keeps_old_password():
    credentials.update(current_password="test-pass", new_username="new-admin", new_password=None)

    assert credentials.verify("new-admin", "test-pass") is True


def test_update_rejects_wrong_current_password():
    try:
        credentials.update(current_password="wrong", new_username="new-admin", new_password="new-pass")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "current password" in str(exc).lower()
    assert credentials.verify("test-user", "test-pass") is True


def test_update_rejects_blank_username():
    try:
        credentials.update(current_password="test-pass", new_username="   ", new_password=None)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "username" in str(exc).lower()
