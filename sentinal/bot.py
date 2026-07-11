from __future__ import annotations

import asyncio
import logging

import discord
from discord.ext import commands
from sqlalchemy import select

from . import db, pipeline
from .config import get_settings

log = logging.getLogger(__name__)

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

IDLE_ACTIVITY = discord.Activity(type=discord.ActivityType.watching, name="for vulnerabilities")
SCANNING_ACTIVITY = discord.Game(name="Scanning containers…")


class DecisionView(discord.ui.View):
    def __init__(self, decision_id: int):
        super().__init__(timeout=None)
        self.decision_id = decision_id

    async def _handle(self, interaction: discord.Interaction, choice: str, label: str) -> None:
        for child in self.children:
            child.disabled = True
        # Acknowledge within Discord's 3-second window — a real patch pulls an
        # image, which takes minutes on a Pi, and an unacknowledged interaction
        # shows the user "interaction failed" even when the patch succeeds.
        await interaction.response.defer()
        try:
            result = await asyncio.to_thread(pipeline.resolve_decision, self.decision_id, choice)
        except ValueError as exc:
            await interaction.edit_original_response(content=f"Already handled: {exc}", view=self)
            return
        except Exception as exc:
            log.exception("Resolving decision %d as %s failed", self.decision_id, choice)
            await interaction.edit_original_response(content=f"**{label} — ERROR**\n{exc}", view=self)
            return
        status = "done" if result["ok"] else "FAILED"
        await interaction.edit_original_response(
            content=f"**{label} — {status}**\n{result['details']}", view=self
        )

    @discord.ui.button(
        label="Apply Patch (pull + recreate)", style=discord.ButtonStyle.success, custom_id="sentinal:patch"
    )
    async def patch(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._handle(interaction, "patch", "Apply Patch (pull + recreate)")

    @discord.ui.button(label="Snooze (7 Days)", style=discord.ButtonStyle.secondary, custom_id="sentinal:snooze")
    async def snooze(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._handle(interaction, "snooze", "Snooze")

    @discord.ui.button(label="Refuse", style=discord.ButtonStyle.danger, custom_id="sentinal:refuse")
    async def refuse(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._handle(interaction, "refuse", "Refuse")


async def _get_channel() -> discord.abc.Messageable:
    settings = get_settings()
    channel = bot.get_channel(settings.discord_channel_id)
    if channel is None:
        channel = await bot.fetch_channel(settings.discord_channel_id)
    return channel


async def post_alert(
    decision_id: int, image: str, container_name: str, ai_text: str, proposed_image: str | None = None
) -> None:
    channel = await _get_channel()
    header = f"**Security Alert: {image}**\n({container_name})\n\n"
    if proposed_image:
        footer = (
            "\n\n---\n"
            f"**Apply Patch** will pull `{proposed_image}` and recreate `{container_name}` "
            f"from it, replacing `{image}` (your data/volumes are untouched). The proposed "
            "tag was Trivy-scanned before being suggested. If you'd rather stay on the "
            "current version, use Snooze or Refuse."
        )
    else:
        footer = (
            "\n\n---\n"
            f"**Apply Patch** always does the same thing: re-pull `{image}` and recreate "
            f"`{container_name}` from it (your data/volumes are untouched). It does **not** "
            "selectively implement any one of the fixes suggested above — if the analysis "
            "recommends something else (a different image/tag, a manual package change, etc.), "
            "this button won't do that; use Refuse or Snooze and handle it by hand instead."
        )
    budget = 2000 - len(header) - len(footer)
    message = f"{header}{ai_text[:budget]}{footer}"
    await channel.send(message, view=DecisionView(decision_id))


async def post_scan_started() -> None:
    channel = await _get_channel()
    await channel.send("🔍 SOAR scan starting…")


async def post_scan_complete(count: int) -> None:
    channel = await _get_channel()
    await channel.send(f"✅ SOAR scan complete — {count} container(s) evaluated.")


async def post_error(source: str, message: str) -> None:
    channel = await _get_channel()
    await channel.send(f"**Sentinal error — {source}**\n{message}")


async def set_scanning_presence(active: bool) -> None:
    await bot.change_presence(activity=SCANNING_ACTIVITY if active else IDLE_ACTIVITY)


def post_alert_threadsafe(
    decision_id: int, image: str, container_name: str, ai_text: str, proposed_image: str | None = None
) -> None:
    asyncio.run_coroutine_threadsafe(
        post_alert(decision_id, image, container_name, ai_text, proposed_image), bot.loop
    )


def post_scan_started_threadsafe() -> None:
    asyncio.run_coroutine_threadsafe(post_scan_started(), bot.loop)


def post_scan_complete_threadsafe(count: int) -> None:
    asyncio.run_coroutine_threadsafe(post_scan_complete(count), bot.loop)


def post_error_threadsafe(source: str, message: str) -> None:
    asyncio.run_coroutine_threadsafe(post_error(source, message), bot.loop)


def set_scanning_presence_threadsafe(active: bool) -> None:
    asyncio.run_coroutine_threadsafe(set_scanning_presence(active), bot.loop)


@bot.event
async def on_ready() -> None:
    log.info("Logged in as %s", bot.user)
    await bot.change_presence(activity=IDLE_ACTIVITY)
    # re-register button callbacks for any decision that was still pending across a restart
    with db.SessionLocal() as session:
        pending = session.scalars(
            select(db.PendingDecision).where(db.PendingDecision.status == db.DecisionStatus.PENDING.value)
        ).all()
        for decision in pending:
            bot.add_view(DecisionView(decision.id))
    log.info("Re-registered %d pending decision(s)", len(pending))


def run_bot() -> None:
    settings = get_settings()
    bot.run(settings.discord_bot_token)
