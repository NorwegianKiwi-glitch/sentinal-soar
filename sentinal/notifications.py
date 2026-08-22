"""Runtime mute switch for Discord notifications, editable from Settings.

Separate from config.Settings.discord_enabled, which reflects whether Discord
is *connected* at all (DISCORD_BOT_TOKEN/DISCORD_CHANNEL_ID set at boot) —
this is a DB-backed toggle on top of that connection: bot.py's `_dispatch`
checks both, so turning notifications off stops alerts, scan pings, and error
posts without tearing the bot down, and turning them back on takes effect on
the next dispatched message.
"""

from __future__ import annotations

from . import db


def enabled() -> bool:
    with db.SessionLocal() as session:
        row = session.get(db.NotificationSettings, 1)
        return row is None or row.discord_enabled


def set_enabled(value: bool) -> bool:
    with db.SessionLocal() as session:
        row = session.get(db.NotificationSettings, 1)
        if row is None:
            row = db.NotificationSettings(id=1, discord_enabled=value)
            session.add(row)
        else:
            row.discord_enabled = value
        session.commit()
        session.refresh(row)
        return row.discord_enabled
