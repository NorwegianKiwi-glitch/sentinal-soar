from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv


def _env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value or ""


@dataclass(frozen=True)
class Settings:
    database_url: str
    discord_bot_token: str
    discord_guild_id: int
    discord_channel_id: int
    gemini_api_key: str
    gemini_model: str
    docker_socket: str
    trivy_severity: str
    snooze_days: int
    refuse_review_days: int
    scan_interval_hours: int
    web_host: str
    web_port: int
    flask_secret_key: str
    dashboard_username: str
    dashboard_password: str

    @property
    def discord_enabled(self) -> bool:
        """Discord is an optional notifier — configured only when both a bot
        token and a channel are set. When off, the web console is the sole UI."""
        return bool(self.discord_bot_token and self.discord_channel_id)


@lru_cache
def get_settings() -> Settings:
    load_dotenv()
    return Settings(
        database_url=_env("DATABASE_URL", required=True),
        discord_bot_token=_env("DISCORD_BOT_TOKEN"),
        discord_guild_id=int(_env("DISCORD_GUILD_ID", "0") or "0"),
        discord_channel_id=int(_env("DISCORD_CHANNEL_ID", "0") or "0"),
        gemini_api_key=_env("GEMINI_API_KEY", required=True),
        gemini_model=_env("GEMINI_MODEL", "gemini-2.5-flash"),
        docker_socket=_env("DOCKER_SOCKET", "unix://var/run/docker.sock"),
        trivy_severity=_env("TRIVY_SEVERITY", "HIGH,CRITICAL"),
        snooze_days=int(_env("SNOOZE_DAYS", "7")),
        refuse_review_days=int(_env("REFUSE_REVIEW_DAYS", "180")),
        scan_interval_hours=int(_env("SCAN_INTERVAL_HOURS", "24")),
        web_host=_env("WEB_HOST", "0.0.0.0"),
        web_port=int(_env("WEB_PORT", "8080")),
        flask_secret_key=_env("FLASK_SECRET_KEY", required=True),
        dashboard_username=_env("DASHBOARD_USERNAME", required=True),
        dashboard_password=_env("DASHBOARD_PASSWORD", required=True),
    )
