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


class DecisionView(discord.ui.View):
    def __init__(self, decision_id: int):
        super().__init__(timeout=None)
        self.decision_id = decision_id

    async def _handle(self, interaction: discord.Interaction, choice: str, label: str) -> None:
        for child in self.children:
            child.disabled = True
        try:
            result = await asyncio.to_thread(pipeline.resolve_decision, self.decision_id, choice)
        except ValueError as exc:
            await interaction.response.edit_message(content=f"Already handled: {exc}", view=self)
            return
        status = "done" if result["ok"] else "FAILED"
        await interaction.response.edit_message(
            content=f"**{label} — {status}**\n{result['details']}", view=self
        )

    @discord.ui.button(label="Apply Patch", style=discord.ButtonStyle.success, custom_id="sentinal:patch")
    async def patch(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._handle(interaction, "patch", "Apply Patch")

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


async def post_alert(decision_id: int, image: str, container_name: str, ai_text: str) -> None:
    channel = await _get_channel()
    message = f"**Security Alert: {image}**\n({container_name})\n\n{ai_text[:1800]}"
    await channel.send(message, view=DecisionView(decision_id))


async def post_scan_complete(count: int) -> None:
    channel = await _get_channel()
    await channel.send(f"SOAR scan complete — {count} container(s) evaluated.")


async def post_error(source: str, message: str) -> None:
    channel = await _get_channel()
    await channel.send(f"**Sentinal error — {source}**\n{message}")


def post_alert_threadsafe(decision_id: int, image: str, container_name: str, ai_text: str) -> None:
    asyncio.run_coroutine_threadsafe(post_alert(decision_id, image, container_name, ai_text), bot.loop)


def post_scan_complete_threadsafe(count: int) -> None:
    asyncio.run_coroutine_threadsafe(post_scan_complete(count), bot.loop)


def post_error_threadsafe(source: str, message: str) -> None:
    asyncio.run_coroutine_threadsafe(post_error(source, message), bot.loop)


@bot.event
async def on_ready() -> None:
    log.info("Logged in as %s", bot.user)
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
