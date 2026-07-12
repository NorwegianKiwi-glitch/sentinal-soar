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


async def _resolve_and_report(
    interaction: discord.Interaction, view: discord.ui.View, decision_id: int, choice: str, label: str
) -> None:
    for child in view.children:
        child.disabled = True
    # Acknowledge within Discord's 3-second window with visible progress and
    # the buttons actually disabled — a real remediation pulls images, which
    # can take minutes on a Pi. A silent defer() looks like nothing happened
    # and leaves the buttons clickable, inviting duplicate remediations.
    await interaction.response.edit_message(
        content=f"⏳ **{label} — working…** (pulling images can take several minutes on the Pi)",
        view=view,
    )
    try:
        result = await asyncio.to_thread(pipeline.resolve_decision, decision_id, choice)
    except ValueError as exc:
        await interaction.edit_original_response(content=f"Already handled: {exc}", view=view)
        return
    except Exception as exc:
        log.exception("Resolving decision %d as %s failed", decision_id, choice)
        await interaction.edit_original_response(content=f"**{label} — ERROR**\n{exc}", view=view)
        return
    status = "done" if result["ok"] else "FAILED"
    await interaction.edit_original_response(
        content=f"**{label} — {status}**\n{result['details']}", view=view
    )


class DecisionView(discord.ui.View):
    """The buttons under one alert.

    custom_ids embed the decision id: persistent views are dispatched by
    custom_id, so re-registering many decisions under the same static ids
    (the original design) routed every old message's click to whichever
    view happened to be registered last.
    """

    def __init__(self, decision_id: int, major_target: str | None = None):
        super().__init__(timeout=None)
        self.decision_id = decision_id
        self.major_target = major_target
        self._add_button(
            "Apply Patch (pull + recreate)", discord.ButtonStyle.success, f"sentinal:patch:{decision_id}", self._patch
        )
        self._add_button("Snooze (7 Days)", discord.ButtonStyle.secondary, f"sentinal:snooze:{decision_id}", self._snooze)
        self._add_button("Refuse", discord.ButtonStyle.danger, f"sentinal:refuse:{decision_id}", self._refuse)
        if major_target:
            self._add_button(
                "Major Upgrade…", discord.ButtonStyle.danger, f"sentinal:major:{decision_id}", self._major
            )

    def _add_button(self, label: str, style: discord.ButtonStyle, custom_id: str, callback) -> None:
        button = discord.ui.Button(label=label, style=style, custom_id=custom_id)
        button.callback = callback
        self.add_item(button)

    async def _patch(self, interaction: discord.Interaction) -> None:
        await _resolve_and_report(interaction, self, self.decision_id, "patch", "Apply Patch (pull + recreate)")

    async def _snooze(self, interaction: discord.Interaction) -> None:
        await _resolve_and_report(interaction, self, self.decision_id, "snooze", "Snooze")

    async def _refuse(self, interaction: discord.Interaction) -> None:
        await _resolve_and_report(interaction, self, self.decision_id, "refuse", "Refuse")

    async def _major(self, interaction: discord.Interaction) -> None:
        # No claim yet — this only swaps the message to an explicit confirmation.
        try:
            target, project, family, companions = await asyncio.to_thread(
                pipeline.preview_major_upgrade, self.decision_id
            )
        except Exception as exc:
            await interaction.response.edit_message(
                content=f"**Major Upgrade — cannot prepare**\n{exc}", view=self
            )
            return
        target_tag = target.rsplit(":", 1)[1]
        lines = [
            f"**Confirm major upgrade of app `{project}` → `{target}`?**",
            "",
            "This rewrites the app's definition and re-applies it (docker compose up):",
            *[f"• `{ref}` → `:{target_tag}`" for ref in family],
        ]
        if companions:
            lines += [
                "",
                "⚠️ Pinned companions left untouched: "
                + ", ".join(f"`{companion}`" for companion in companions[:5])
                + " — majors sometimes require updating these too; check the release notes.",
            ]
        lines += [
            "",
            "A fresh backup snapshot is taken automatically before anything is touched "
            "(adds a few minutes); if the backup fails, the upgrade is not attempted.",
        ]
        await interaction.response.edit_message(
            content="\n".join(lines)[:2000], view=ConfirmMajorView(self.decision_id)
        )


class ConfirmMajorView(discord.ui.View):
    def __init__(self, decision_id: int):
        super().__init__(timeout=None)
        self.decision_id = decision_id
        confirm = discord.ui.Button(
            label="Yes, run the major upgrade",
            style=discord.ButtonStyle.danger,
            custom_id=f"sentinal:major-confirm:{decision_id}",
        )
        confirm.callback = self._confirm
        self.add_item(confirm)
        cancel = discord.ui.Button(
            label="Cancel", style=discord.ButtonStyle.secondary, custom_id=f"sentinal:major-cancel:{decision_id}"
        )
        cancel.callback = self._cancel
        self.add_item(cancel)

    async def _confirm(self, interaction: discord.Interaction) -> None:
        await _resolve_and_report(interaction, self, self.decision_id, "major", "Major Upgrade")

    async def _cancel(self, interaction: discord.Interaction) -> None:
        try:
            image, container_name, ai_text, proposed, major = await asyncio.to_thread(
                pipeline.get_decision_view_data, self.decision_id
            )
        except Exception as exc:
            await interaction.response.edit_message(content=f"Cancelled ({exc}).", view=None)
            return
        await interaction.response.edit_message(
            content=_alert_content(image, container_name, ai_text, proposed, major),
            view=DecisionView(self.decision_id, major),
        )


async def _get_channel() -> discord.abc.Messageable:
    settings = get_settings()
    channel = bot.get_channel(settings.discord_channel_id)
    if channel is None:
        channel = await bot.fetch_channel(settings.discord_channel_id)
    return channel


def _alert_content(
    image: str,
    container_name: str,
    ai_text: str,
    proposed_image: str | None = None,
    proposed_major_image: str | None = None,
) -> str:
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
        if proposed_major_image:
            footer += (
                f"\n**Major Upgrade** moves the whole app to `{proposed_major_image}` after an "
                "explicit confirmation step."
            )
    budget = 2000 - len(header) - len(footer)
    return f"{header}{ai_text[:budget]}{footer}"


async def post_alert(
    decision_id: int,
    image: str,
    container_name: str,
    ai_text: str,
    proposed_image: str | None = None,
    proposed_major_image: str | None = None,
) -> None:
    channel = await _get_channel()
    await channel.send(
        _alert_content(image, container_name, ai_text, proposed_image, proposed_major_image),
        view=DecisionView(decision_id, proposed_major_image),
    )


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
    decision_id: int,
    image: str,
    container_name: str,
    ai_text: str,
    proposed_image: str | None = None,
    proposed_major_image: str | None = None,
) -> None:
    asyncio.run_coroutine_threadsafe(
        post_alert(decision_id, image, container_name, ai_text, proposed_image, proposed_major_image),
        bot.loop,
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
            select(db.PendingDecision).where(
                db.PendingDecision.status.in_(
                    [db.DecisionStatus.PENDING.value, db.DecisionStatus.IN_PROGRESS.value]
                )
            )
        ).all()
        # IN_PROGRESS here means the app died mid-remediation; hand the human
        # back a working button instead of a decision claimed forever.
        for decision in pending:
            decision.status = db.DecisionStatus.PENDING.value
        session.commit()
        for decision in pending:
            bot.add_view(DecisionView(decision.id, decision.proposed_major_image))
            if decision.proposed_major_image:
                bot.add_view(ConfirmMajorView(decision.id))
    log.info("Re-registered %d pending decision(s)", len(pending))


def run_bot() -> None:
    settings = get_settings()
    bot.run(settings.discord_bot_token)
