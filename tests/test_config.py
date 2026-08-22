from __future__ import annotations

from sentinal.config import Settings

# Built directly (not via get_settings) so the test never touches the real
# .env mounted into the test container.
_BASE = dict(
    database_url="sqlite://",
    discord_bot_token="",
    discord_guild_id=0,
    discord_channel_id=0,
    gemini_api_key="k",
    gemini_model="m",
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


def test_cloudflare_disabled_without_token_zone_or_hostnames():
    assert Settings(**_BASE).cloudflare_enabled is False


def test_cloudflare_enabled_with_token_zone_and_hostnames():
    settings = Settings(
        **{
            **_BASE,
            "cloudflare_api_token": "tok",
            "cloudflare_zone_id": "zone",
            "cloudflare_hostnames": "a.example.com, b.example.com",
        }
    )
    assert settings.cloudflare_enabled is True
    assert settings.cloudflare_hostname_list == ["a.example.com", "b.example.com"]


def test_cloudflare_disabled_when_hostnames_blank():
    settings = Settings(**{**_BASE, "cloudflare_api_token": "tok", "cloudflare_zone_id": "zone"})
    assert settings.cloudflare_enabled is False
