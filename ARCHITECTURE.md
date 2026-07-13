# Architecture

Sentinal is one Python process with three concurrent responsibilities: a Flask
web console (WSGI, served by waitress), an **optional** Discord bot (asyncio),
and the scan pipeline they both call into. It replaces [the original n8n prototype](https://github.com/NorwegianKiwi-glitch/Sentinal),
keeping the same behavior — scan running containers, explain findings with AI,
ask a human to patch/snooze/refuse, log the outcome — as real, tested code
instead of a workflow graph.

The **web console is the primary UI**; Discord is a bolt-on notifier that
mirrors the same alerts and decision buttons into a channel. Both call the same
UI-agnostic `pipeline.resolve_decision`, and both are safe to use at once
because a decision is claimed atomically (PENDING → IN_PROGRESS) before any
work starts.

## Components

```
sentinal/
  config.py        env vars -> Settings; `discord_enabled` gates the optional bot
  db.py             SQLAlchemy models: ScanLog, ContainerException, PendingDecision
  docker_client.py  wraps docker-py against /var/run/docker.sock
  registry.py       Registry v2 API client: lists an image's tags, picks a safe upgrade
  patching.py       describe_patch(): is a pull-based patch actionable, and if not, why
  definitions.py    keeps the CasaOS/compose file of a patched container in sync
  compose.py        confirm-gated major upgrades: rewrite the app's definition, compose up
  backup.py         pre-upgrade restic snapshot via the host backup script
  scanner.py        runs a killable trivy process, drops rejected/unpublished CVEs
  ai.py             Gemini wrapper (google-genai)
  pipeline.py       enumerate -> governance check -> scan -> analyze -> log; stoppable
                      (pure-ish functions; called by web, the scheduler, and tests)
  bot.py            optional discord.py bot + Button-based approval view
  web/              Flask console: decisions / scan log / exceptions + scan control
  __main__.py       wires web + scheduler (+ bot when configured) into one process
```

`pipeline.py` is the direct translation of the n8n graph's node sequence, and is
where almost all of the actual security logic lives. Everything else is I/O
around it.

### Process model

`__main__.py` runs the scheduler in a daemon thread and then serves the web
console. When Discord is configured, the bot owns the asyncio event loop on the
main thread and the web server is the daemon instead; when it is not, the web
server owns the main thread and the bot never starts. The scheduler and web
layer call `bot.post_alert_threadsafe` and friends unconditionally — a shared
`_dispatch` guard makes them no-ops when Discord is disabled — so the same scan
path works with or without Discord. Decisions are written to the DB before any
alert is posted, which is why the web console is fully functional alone.

### Stopping a scan

`run_scan_cycle` runs under module-level cancel/running flags. It checks the
cancel flag between containers, and because a single container's evaluation can
spend minutes pulling and scanning a candidate image or paging a huge tag list,
the slow parts are cancellable too: `scanner.scan_image` runs Trivy as a
killable subprocess that raises `ScanCancelled` when asked to stop, and
`registry.list_tags_for_upgrade` takes a `should_continue` predicate. A Stop
button in the console halts a live scan in seconds rather than waiting it out.

### Human-in-the-loop approval

n8n's `sendAndWait` suspends a workflow mid-execution and resumes it from a
generated webhook when someone clicks a form button. There's no equivalent
primitive in plain Python, so the same behavior is modeled explicitly:

1. A vulnerable scan creates a `PendingDecision` row. The web console lists it
   at `/decisions`, and — if Discord is enabled — a `discord.ui.View`
   (persistent, `custom_id`-based buttons) is also posted.
2. A button (web or Discord) calls `pipeline.resolve_decision(decision_id,
   choice)` in a worker thread. The call claims the decision atomically, so the
   two UIs (and double-clicks) can't start duplicate remediations.
3. On `on_ready` (including after a restart), any still-pending decision gets
   its Discord view re-registered — otherwise buttons on old messages would
   silently stop working after a bot restart, which the n8n version had no
   equivalent failure mode for (it never restarts mid-`sendAndWait`, since the
   suspended state lives in n8n's own execution store, not in your db).

Which buttons appear is decided in one place, `patching.describe_patch`, used
by both UIs: **Apply Patch** shows only when a pull could actually change what
runs (a verified upgrade, or a moving tag); otherwise the alert states what to
do instead (rebuild a digest-pinned image, use Major Upgrade, dump/restore a
database, or Snooze/Refuse).

### Which findings alert

`scanner.scan_image` drops two classes of finding that would only be noise,
because they don't describe a vulnerability that (yet) exists: CVEs marked
**REJECTED** (withdrawn) and CVEs with **no PublishedDate** (an ID is reserved
but no advisory is published). Everything else within the configured severity
(`HIGH,CRITICAL` by default) still alerts.

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

Two refinements keep this useful on awkward repositories. Mega-repos that
tag every commit (immich) overflow the page cap before their release tags
appear, so a truncated listing triggers a second one seeded with
`last=<current tag>` — in insertion-ordered registries like GHCR that means
"everything published since the running release". And when the same-major
line is simply over (immich v2 → v3), the alert states the newest release as
information for the human instead of proposing it: major upgrades can
require migration steps and never hide behind the one-click patch.

### Major upgrades (confirm-gated)

When only a newer major exists, the alert grows a **Major Upgrade** button.
It never acts on the first click: it swaps to a confirmation that shows
exactly which image references will move (same registry + namespace + tag
move together, so immich's server and machine-learning bump in lockstep),
warns about pinned companion images it will *not* touch, and reminds about
backups — data migrations run forward-only. On confirm, `compose.py`
rewrites the app's definition (`.sentinal-bak` kept), then runs
`docker compose -p <project> -f <file> up -d` via the docker CLI baked into
the image — the same mechanism CasaOS uses, so the definition stays the
source of truth. If the new version fails to come up, the old definition is
restored and re-applied. A successful major upgrade also retires the app's
other pending alerts, whose patch buttons would otherwise downgrade
freshly-upgraded containers.

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
