"""Validate .env credentials against their live services before running docker compose up.

Usage: .venv/Scripts/python.exe scripts/check_credentials.py
"""
from __future__ import annotations

import os
import sys

import requests
from dotenv import load_dotenv


def check_discord(token: str, guild_id: int, channel_id: int) -> bool:
    headers = {"Authorization": f"Bot {token}"}
    r = requests.get("https://discord.com/api/v10/users/@me", headers=headers, timeout=10)
    if r.status_code != 200:
        print(f"  [FAIL] DISCORD_BOT_TOKEN rejected by Discord API: {r.status_code} {r.text}")
        return False
    bot = r.json()
    print(f"  [OK] DISCORD_BOT_TOKEN valid - logged in as {bot['username']}#{bot.get('discriminator', '0')}")

    ok = True
    r = requests.get(f"https://discord.com/api/v10/guilds/{guild_id}", headers=headers, timeout=10)
    if r.status_code == 200:
        print(f"  [OK] DISCORD_GUILD_ID reachable - bot is a member of '{r.json()['name']}'")
    else:
        print(f"  [FAIL] DISCORD_GUILD_ID {guild_id} not visible to bot: {r.status_code} {r.text}")
        ok = False

    r = requests.get(f"https://discord.com/api/v10/channels/{channel_id}", headers=headers, timeout=10)
    if r.status_code == 200:
        print(f"  [OK] DISCORD_CHANNEL_ID reachable - channel '#{r.json().get('name', channel_id)}'")
    else:
        print(f"  [FAIL] DISCORD_CHANNEL_ID {channel_id} not visible to bot: {r.status_code} {r.text}")
        ok = False

    return ok


def check_gemini(api_key: str, model: str) -> bool:
    try:
        from google import genai
    except ImportError:
        print("  [SKIP] google-genai not installed")
        return False

    try:
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(model=model, contents="Reply with the single word: pong")
        text = (resp.text or "").strip()
        print(f"  [OK] GEMINI_API_KEY valid - model '{model}' responded: {text!r}")
        return True
    except Exception as e:
        print(f"  [FAIL] GEMINI_API_KEY/GEMINI_MODEL rejected: {e}")
        return False


def main() -> int:
    load_dotenv()

    token = os.environ["DISCORD_BOT_TOKEN"]
    guild_id = int(os.environ["DISCORD_GUILD_ID"])
    channel_id = int(os.environ["DISCORD_CHANNEL_ID"])
    gemini_key = os.environ["GEMINI_API_KEY"]
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    print("Discord:")
    discord_ok = check_discord(token, guild_id, channel_id)

    print("Gemini:")
    gemini_ok = check_gemini(gemini_key, gemini_model)

    print()
    if discord_ok and gemini_ok:
        print("All credentials look valid. Safe to run: docker compose up")
        return 0
    print("One or more credentials failed - fix .env before running docker compose up.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
