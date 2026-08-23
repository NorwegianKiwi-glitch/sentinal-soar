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


# Which env vars each AI_PROVIDER needs to actually work. Checked in
# get_settings() against the *selected* provider only — unlike the old
# unconditional `GEMINI_API_KEY required=True`, a user running with
# AI_PROVIDER=anthropic no longer needs a dummy Gemini key just to boot.
# gemini/anthropic ship a real default model (see ai.py/get_settings below);
# openai and openai_compatible don't, since no default here can be trusted
# not to be stale — those providers must name a model explicitly.
_AI_PROVIDERS = ("gemini", "openai", "anthropic", "openai_compatible")
_AI_PROVIDER_REQUIRED_VARS = {
    "gemini": ("GEMINI_API_KEY",),
    "openai": ("OPENAI_API_KEY", "OPENAI_MODEL"),
    "anthropic": ("ANTHROPIC_API_KEY",),
    # A generic OpenAI-wire-compatible endpoint — DeepSeek, Qwen, Moonshot/
    # Kimi, and most other providers, or a self-hosted server (Ollama, LM
    # Studio, vLLM, llama.cpp) all speak this. AI_API_KEY is deliberately
    # NOT required: most self-hosted servers don't check it — see ai.py.
    "openai_compatible": ("AI_BASE_URL", "AI_MODEL"),
}


@dataclass(frozen=True)
class Settings:
    database_url: str
    discord_bot_token: str
    discord_guild_id: int
    discord_channel_id: int
    ai_provider: str
    gemini_api_key: str
    gemini_model: str
    openai_api_key: str
    openai_model: str
    anthropic_api_key: str
    anthropic_model: str
    ai_base_url: str
    ai_api_key: str
    ai_model: str
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
    cloudflare_api_token: str
    cloudflare_zone_id: str
    cloudflare_hostnames: str
    cloudflare_poll_minutes: int

    @property
    def discord_enabled(self) -> bool:
        """Discord is an optional notifier — configured only when both a bot
        token and a channel are set. When off, the web console is the sole UI."""
        return bool(self.discord_bot_token and self.discord_channel_id)

    @property
    def cloudflare_configured(self) -> bool:
        """Whether Cloudflare API credentials are present. Deliberately does
        NOT check for any watched hostnames — that list is DB-authoritative
        (see hostnames.py) and editable from Settings at runtime, so it can
        legitimately be empty even when credentials are configured."""
        return bool(self.cloudflare_api_token and self.cloudflare_zone_id)

    @property
    def cloudflare_hostname_list(self) -> list[str]:
        return [h.strip() for h in self.cloudflare_hostnames.split(",") if h.strip()]


def _require_ai_provider_configured(settings: Settings) -> None:
    """AI triage is always-on (unlike Discord/Cloudflare) — pipeline.py calls
    it on every scan — so unlike those, a missing var here is fatal at boot,
    same as the old unconditional GEMINI_API_KEY check. Scoped to whichever
    provider AI_PROVIDER selects, not all four at once."""
    if settings.ai_provider not in _AI_PROVIDERS:
        raise RuntimeError(
            f"AI_PROVIDER={settings.ai_provider!r} is not supported — choose one of: "
            + ", ".join(_AI_PROVIDERS)
        )
    missing = [
        var for var in _AI_PROVIDER_REQUIRED_VARS[settings.ai_provider] if not getattr(settings, var.lower())
    ]
    if missing:
        raise RuntimeError(
            f"AI_PROVIDER={settings.ai_provider!r} requires {', '.join(missing)} to be set"
        )


@lru_cache
def get_settings() -> Settings:
    load_dotenv()
    settings = Settings(
        database_url=_env("DATABASE_URL", required=True),
        discord_bot_token=_env("DISCORD_BOT_TOKEN"),
        discord_guild_id=int(_env("DISCORD_GUILD_ID", "0") or "0"),
        discord_channel_id=int(_env("DISCORD_CHANNEL_ID", "0") or "0"),
        ai_provider=_env("AI_PROVIDER", "gemini").strip().lower(),
        gemini_api_key=_env("GEMINI_API_KEY"),
        gemini_model=_env("GEMINI_MODEL", "gemini-2.5-flash"),
        openai_api_key=_env("OPENAI_API_KEY"),
        openai_model=_env("OPENAI_MODEL"),
        anthropic_api_key=_env("ANTHROPIC_API_KEY"),
        anthropic_model=_env("ANTHROPIC_MODEL", "claude-opus-5"),
        ai_base_url=_env("AI_BASE_URL"),
        ai_api_key=_env("AI_API_KEY"),
        ai_model=_env("AI_MODEL"),
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
        cloudflare_api_token=_env("CLOUDFLARE_API_TOKEN"),
        cloudflare_zone_id=_env("CLOUDFLARE_ZONE_ID"),
        cloudflare_hostnames=_env("CLOUDFLARE_HOSTNAMES"),
        cloudflare_poll_minutes=int(_env("CLOUDFLARE_POLL_MINUTES", "5")),
    )
    _require_ai_provider_configured(settings)
    return settings
