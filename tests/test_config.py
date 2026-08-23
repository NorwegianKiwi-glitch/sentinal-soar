from __future__ import annotations

import pytest

from sentinal.config import Settings, _require_ai_provider_configured

# Built directly (not via get_settings) so the test never touches the real
# .env mounted into the test container.
_BASE = dict(
    database_url="sqlite://",
    discord_bot_token="",
    discord_guild_id=0,
    discord_channel_id=0,
    ai_provider="gemini",
    gemini_api_key="k",
    gemini_model="m",
    openai_api_key="",
    openai_model="",
    anthropic_api_key="",
    anthropic_model="claude-opus-5",
    ai_base_url="",
    ai_api_key="",
    ai_model="",
    docker_socket="unix://x",
    trivy_severity="HIGH,CRITICAL",
    snooze_days=7,
    refuse_review_days=180,
    scan_interval_hours=24,
    web_host="0.0.0.0",
    web_port=8080,
    flask_secret_key="s",
    dashboard_username="u",
    dashboard_password="p",
    cloudflare_api_token="",
    cloudflare_zone_id="",
    cloudflare_hostnames="",
    cloudflare_poll_minutes=5,
)


def test_discord_disabled_without_token_and_channel():
    assert Settings(**_BASE).discord_enabled is False


def test_discord_enabled_with_token_and_channel():
    settings = Settings(**{**_BASE, "discord_bot_token": "tok", "discord_channel_id": 42})
    assert settings.discord_enabled is True


def test_discord_disabled_with_token_but_no_channel():
    assert Settings(**{**_BASE, "discord_bot_token": "tok"}).discord_enabled is False


def test_cloudflare_not_configured_without_token_or_zone():
    assert Settings(**_BASE).cloudflare_configured is False


def test_cloudflare_configured_with_token_and_zone_regardless_of_hostnames():
    # Hostnames are DB-authoritative (see hostnames.py) and editable from
    # Settings at runtime, so "configured" must not depend on them.
    settings = Settings(**{**_BASE, "cloudflare_api_token": "tok", "cloudflare_zone_id": "zone"})
    assert settings.cloudflare_configured is True


def test_cloudflare_hostname_list_parses_and_strips_the_seed_env_var():
    settings = Settings(**{**_BASE, "cloudflare_hostnames": "a.example.com, b.example.com"})
    assert settings.cloudflare_hostname_list == ["a.example.com", "b.example.com"]


# --- AI provider selection --------------------------------------------------


def test_gemini_provider_requires_gemini_key():
    _require_ai_provider_configured(Settings(**_BASE))  # has a key: fine
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        _require_ai_provider_configured(Settings(**{**_BASE, "gemini_api_key": ""}))


def test_openai_provider_requires_key_and_model():
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        _require_ai_provider_configured(Settings(**{**_BASE, "ai_provider": "openai"}))
    with pytest.raises(RuntimeError, match="OPENAI_MODEL"):
        _require_ai_provider_configured(
            Settings(**{**_BASE, "ai_provider": "openai", "openai_api_key": "sk-x"})
        )
    _require_ai_provider_configured(
        Settings(**{**_BASE, "ai_provider": "openai", "openai_api_key": "sk-x", "openai_model": "gpt-x"})
    )


def test_anthropic_provider_requires_only_the_key_since_model_has_a_default():
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        _require_ai_provider_configured(Settings(**{**_BASE, "ai_provider": "anthropic"}))
    _require_ai_provider_configured(
        Settings(**{**_BASE, "ai_provider": "anthropic", "anthropic_api_key": "sk-ant-x"})
    )


def test_openai_compatible_provider_requires_base_url_and_model_but_not_api_key():
    # A self-hosted server (Ollama, LM Studio, ...) typically doesn't check
    # the key at all, so it must not be required — see ai.py.
    with pytest.raises(RuntimeError, match="AI_BASE_URL"):
        _require_ai_provider_configured(Settings(**{**_BASE, "ai_provider": "openai_compatible"}))
    with pytest.raises(RuntimeError, match="AI_MODEL"):
        _require_ai_provider_configured(
            Settings(**{**_BASE, "ai_provider": "openai_compatible", "ai_base_url": "http://x:11434/v1"})
        )
    _require_ai_provider_configured(
        Settings(
            **{
                **_BASE,
                "ai_provider": "openai_compatible",
                "ai_base_url": "http://x:11434/v1",
                "ai_model": "llama3",
            }
        )
    )


def test_unknown_ai_provider_is_rejected():
    with pytest.raises(RuntimeError, match="AI_PROVIDER"):
        _require_ai_provider_configured(Settings(**{**_BASE, "ai_provider": "watson"}))
