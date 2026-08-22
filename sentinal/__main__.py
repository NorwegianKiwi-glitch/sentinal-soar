from __future__ import annotations

import logging
import threading

from waitress import serve

from . import access
from . import bot as bot_module
from . import pipeline, schedule
from .config import get_settings
from .db import init_db
from .web import create_app

log = logging.getLogger(__name__)


def _run_web() -> None:
    settings = get_settings()
    app = create_app()
    serve(app, host=settings.web_host, port=settings.web_port)


def _scheduled_scan() -> None:
    bot_module.post_scan_started_threadsafe()
    bot_module.set_scanning_presence_threadsafe(True)
    try:
        count = pipeline.run_scan_cycle(bot_module.post_alert_threadsafe)
        bot_module.post_scan_complete_threadsafe(count)
    except Exception as exc:
        bot_module.post_error_threadsafe("scheduled scan", str(exc))
    finally:
        bot_module.set_scanning_presence_threadsafe(False)


def _run_scheduler() -> None:
    # Timing lives in schedule.run_scheduler (DB-backed, runtime-editable); this
    # just supplies the work to run when a tick is due.
    schedule.run_scheduler(_scheduled_scan)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db()
    threading.Thread(target=_run_scheduler, daemon=True, name="scheduler").start()
    # No-op (logs and returns) when Cloudflare isn't configured — see
    # config.Settings.cloudflare_enabled.
    threading.Thread(target=access.run_poller, daemon=True, name="access-poller").start()
    if get_settings().discord_enabled:
        # The bot owns the asyncio event loop on the main thread; web is a daemon.
        threading.Thread(target=_run_web, daemon=True, name="web").start()
        bot_module.run_bot()  # blocks here
    else:
        # No Discord: the web console is the only UI, so it owns the main thread.
        log.info("Discord not configured — running web-only; the dashboard is the console.")
        _run_web()  # blocks here


if __name__ == "__main__":
    main()
