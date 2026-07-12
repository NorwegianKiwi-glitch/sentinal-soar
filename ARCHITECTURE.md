# Architecture

Sentinal is one Python process with three concurrent responsibilities: a Discord
bot (asyncio), a Flask dashboard (WSGI, served by waitress), and the scan
pipeline they both call into. It replaces [the original n8n prototype](https://github.com/NorwegianKiwi-glitch/Sentinal),
keeping the same behavior — scan running containers, explain findings with AI,
ask a human to patch/snooze/refuse over Discord, log the outcome — as real,
tested code instead of a workflow graph.

## Components

```
sentinal/
  config.py        env vars -> Settings (fails fast if a required var is missing)
  db.py             SQLAlchemy models: ScanLog, ContainerException, PendingDecision
  docker_client.py  wraps docker-py against /var/run/docker.sock
  registry.py       Registry v2 API client: lists an image's tags, picks a safe upgrade
  scanner.py        shells out to a bundled trivy binary, parses JSON findings
  ai.py             Gemini wrapper (google-genai)
  pipeline.py       enumerate -> governance check -> scan -> analyze -> log
                      (pure-ish functions; called by Flask, the scheduler, and tests)
  bot.py            discord.py bot + Button-based approval view
  web/              Flask blueprint: dashboard, manual-scan trigger, archive/delete
  __main__.py       wires bot + web + scheduler together in one process
```

`pipeline.py` is the direct translation of the n8n graph's node sequence, and is
where almost all of the actual security logic lives. Everything else is I/O
around it.

### Process model

Flask (WSGI) and discord.py (asyncio) don't share a runtime by default, so the
bot's event loop is the backbone: it owns the main thread. `__main__.py` starts
the Flask app (via `waitress`) and the scheduler loop each in their own daemon
thread, then blocks on `bot.run()`. Code on either side of that boundary talks
to the other via plain functions and `asyncio.run_coroutine_threadsafe` — see
`bot.post_alert_threadsafe` and friends — rather than shared mutable state.

### Human-in-the-loop approval

n8n's `sendAndWait` suspends a workflow mid-execution and resumes it from a
generated webhook when someone clicks a form button. There's no equivalent
primitive in plain Python, so the same behavior is modeled explicitly:

1. A vulnerable scan creates a `PendingDecision` row and posts a Discord
   message with a `discord.ui.View` (persistent, `custom_id`-based buttons).
2. A button click calls `pipeline.resolve_decision(decision_id, choice)` in a
   worker thread (`asyncio.to_thread`, so it doesn't block the bot's event loop).
3. On `on_ready` (including after a restart), any still-pending decision gets
   its view re-registered — otherwise buttons on old messages would silently
   stop working after a bot restart, which the n8n version had no equivalent
   failure mode for (it never restarts mid-`sendAndWait`, since the entire
   suspended state lives in n8n's own execution store, not in your db).

### Version-bump proposals

Re-pulling the tag a container already runs only fixes anything when the tag
is mutable (`:latest`); pinned tags like `postgres:14.2` never change. So when
a scan finds vulnerabilities, the pipeline asks the image's registry for its
tag list, picks the newest **same-flavor, same-major** tag (`14.2 → 14.19`,
never `→ 15.x`; `16-alpine` stays `-alpine`; `v2.7.5` keeps its `v`), and
Trivy-scans that candidate. Only if the candidate has strictly fewer findings
does it become the decision's `proposed_image`: the Discord alert then says
what Apply Patch will actually pull, and `resolve_decision` upgrades to it.
In every other case (no better tag, non-version tags, registry unreachable,
private repositories) the behavior degrades to the original same-tag re-pull —
a proposal failure never fails the scan cycle.

## Deliberate deviations from the n8n prototype

The [v1 spec](https://github.com/NorwegianKiwi-glitch/Sentinal) called out several
bugs and gaps in the original design. Each is fixed here, not just carried
forward:

| v1 (n8n) | v2 (this repo) | Why |
|---|---|---|
| SSH to the Pi for every Docker command | `docker` SDK against a socket-mounted `/var/run/docker.sock` | The app now runs on the same host it manages; SSH-to-self and a stored password added nothing |
| Remediation backgrounded with `nohup … &`; only the wrapper's exit code was checked | `docker_client.pull_and_recreate` runs synchronously and lets real failures propagate | A failed pull/recreate used to still log `SUCCESS` — see `test_resolve_decision_patch_failure_is_logged_as_failed` |
| `snooze_until = '9999-12-31'` on refusal | `review_after` set on **every** exception, refusals included | Permanent risk acceptance with no re-attestation is an anti-pattern in real vulnerability-management programs, not just here |
| Dashboard could `DELETE FROM scan_logs` outright | `/api/logs/<id>/archive` soft-deletes (`archived = true`); no hard-delete route exists for the audit table | An audit trail that the tool being audited can erase isn't one — see `test_archive_log_is_soft_delete_not_hard_delete` |
| Delete queries built by interpolating `targetId` into a SQL string | SQLAlchemy `select()` / ORM everywhere | Was SQL-injection-shaped even with a trusted caller |
| Dashboard webhook was unauthenticated | HTTP Basic Auth on the whole blueprint, compared with `hmac.compare_digest` | Closes the "anyone on the LAN can trigger a scan or delete logs" gap; timing-safe comparison avoids leaking credential length/prefix via response timing |
| No scheduler; scan only ran on manual trigger | `SCAN_INTERVAL_HOURS` (default 24) runs the cycle on a timer, in addition to the manual trigger | A SOAR tool that only scans when you remember to click a button isn't really automating anything |
| Trivy reached over SSH to a host-installed binary | Trivy binary copied into the app image from `aquasec/trivy` at build time | One artifact to deploy; no host-side setup step to forget |

## Known limitations (not fixed yet, on purpose)

- **Docker socket access is root-equivalent.** Mounting `/var/run/docker.sock`
  gives the app container the same practical power as root on the host. Fine
  for a single-user homelab v1; a `docker-socket-proxy` sidecar that
  allowlists specific API endpoints is the natural v2 hardening step.
- **HTTP Basic Auth has no transport encryption of its own.** Credentials are
  base64, not encrypted, over plain HTTP. Acceptable behind a LAN/VPN; put a
  reverse proxy with TLS in front (or a Tailscale/WireGuard network) before
  exposing this beyond your own network.
- **Definition sync only reaches mounted files.** After an upgrade, Sentinal
  rewrites the compose file the container came from (`definitions.py`), so
  the CasaOS UI shows the real version and a CasaOS re-apply can't roll a
  patch back; a `.sentinal-bak` copy is left beside the file. This works
  because CasaOS keeps every app definition under `/var/lib/casaos/apps`,
  which is bind-mounted into the app container at the identical path. A
  compose project outside that path degrades to a "set the tag manually"
  note in the scan log — add another identical-path mount to cover it. The
  CasaOS web UI may show the old tag until its page is refreshed.
- **Test coverage is concentrated on `pipeline.py` and the web layer.**
  `scanner.py` (subprocess + Trivy JSON parsing) and `bot.py` (Discord
  interactions) don't have automated tests yet — they need mocked
  subprocess/Discord fixtures, which is a reasonable next increment rather
  than something to rush into this pass.

## Testing without the Raspberry Pi

Nothing about local development actually needs the Pi:

- Discord, Gemini, and Postgres behave identically wherever they're called
  from — there is no hardware dependency in any of the three.
- `docker_client.py` talks to whatever Docker daemon `DOCKER_SOCKET` points
  at. Locally that's Docker Desktop; on the Pi it's CasaOS's Docker Engine —
  same code path, different daemon underneath.
- Point it at a couple of deliberately outdated local containers
  (`docker run -d nginx:1.14`, an old Alpine, …) to get real Trivy findings
  without touching anything production.
- `docker buildx build --platform linux/amd64,linux/arm64 .` builds both
  architectures from a single Windows/Docker Desktop machine; the arm64
  result can be run locally under QEMU emulation (`docker run --platform
  linux/arm64 …`) before it ever touches the Pi.
- CasaOS itself isn't a distinct runtime to test against — it's a management
  UI over standard Docker Compose. If `docker compose up` works, CasaOS's
  "custom install" (which imports a compose file) works the same way.
