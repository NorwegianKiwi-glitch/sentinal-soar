from __future__ import annotations

import pytest

from sentinal import hostnames


def test_get_hostnames_empty_by_default():
    assert hostnames.get_hostnames() == []


def test_add_hostname_normalizes_case_and_scheme_and_path():
    result = hostnames.add_hostname("HTTPS://Cloud.Example.com/some/path")
    assert result == ["cloud.example.com"]


def test_add_hostname_is_idempotent():
    hostnames.add_hostname("cloud.example.com")
    result = hostnames.add_hostname("cloud.example.com")
    assert result == ["cloud.example.com"]


def test_add_hostname_rejects_garbage():
    with pytest.raises(ValueError):
        hostnames.add_hostname("not a hostname!!")


def test_add_hostname_rejects_blank():
    with pytest.raises(ValueError):
        hostnames.add_hostname("   ")


def test_remove_hostname_drops_it_and_is_a_noop_if_absent():
    hostnames.add_hostname("a.example.com")
    hostnames.add_hostname("b.example.com")

    result = hostnames.remove_hostname("a.example.com")
    assert result == ["b.example.com"]

    result = hostnames.remove_hostname("a.example.com")  # already gone
    assert result == ["b.example.com"]


def test_get_hostnames_sorted():
    hostnames.add_hostname("z.example.com")
    hostnames.add_hostname("a.example.com")
    assert hostnames.get_hostnames() == ["a.example.com", "z.example.com"]


def test_seed_from_env_populates_an_empty_table_on_first_run(monkeypatch):
    monkeypatch.setattr(
        hostnames,
        "get_settings",
        lambda: type("S", (), {"cloudflare_hostname_list": ["seed-a.example.com", "seed-b.example.com"]})(),
    )
    hostnames.seed_from_env()
    assert hostnames.get_hostnames() == ["seed-a.example.com", "seed-b.example.com"]


def test_seed_from_env_survives_a_restart_after_full_removal(monkeypatch):
    # __main__.main() calls seed_from_env() exactly once, right after init_db(),
    # before anything else can touch the table — so the realistic sequence to
    # test is seed -> user clears the list from Settings -> process restarts
    # (seed_from_env runs again). A deliberate empty list must survive that;
    # the marker is db.AccessConfig, not "does the table have rows" — see
    # hostnames.py's module docstring.
    monkeypatch.setattr(
        hostnames, "get_settings", lambda: type("S", (), {"cloudflare_hostname_list": ["seed.example.com"]})()
    )
    hostnames.seed_from_env()  # first boot: seeds
    hostnames.remove_hostname("seed.example.com")  # user clears it from Settings
    hostnames.seed_from_env()  # simulated restart

    assert hostnames.get_hostnames() == []
