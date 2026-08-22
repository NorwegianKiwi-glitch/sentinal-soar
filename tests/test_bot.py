from __future__ import annotations

from unittest import mock

from sentinal import bot, notifications


def test_dispatch_noops_when_discord_not_connected(monkeypatch):
    monkeypatch.setattr(bot, "get_settings", lambda: mock.Mock(discord_enabled=False))
    run_coroutine = mock.Mock()
    monkeypatch.setattr(bot.asyncio, "run_coroutine_threadsafe", run_coroutine)

    bot._dispatch(lambda: None)

    run_coroutine.assert_not_called()


def test_dispatch_noops_when_notifications_muted(monkeypatch):
    monkeypatch.setattr(bot, "get_settings", lambda: mock.Mock(discord_enabled=True))
    notifications.set_enabled(False)
    run_coroutine = mock.Mock()
    monkeypatch.setattr(bot.asyncio, "run_coroutine_threadsafe", run_coroutine)

    bot._dispatch(lambda: None)

    run_coroutine.assert_not_called()


def test_dispatch_runs_when_connected_and_notifications_enabled(monkeypatch):
    monkeypatch.setattr(bot, "get_settings", lambda: mock.Mock(discord_enabled=True))
    notifications.set_enabled(True)
    run_coroutine = mock.Mock()
    monkeypatch.setattr(bot.asyncio, "run_coroutine_threadsafe", run_coroutine)
    make_coro = mock.Mock(return_value="the-coro")

    bot._dispatch(make_coro)

    make_coro.assert_called_once()
    run_coroutine.assert_called_once_with("the-coro", bot.bot.loop)
