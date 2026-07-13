# Sentinal

A self-hosted SOAR (Security Orchestration, Automation and Response) service
for a home-lab Docker host: it scans running containers for known CVEs
(Trivy), has Gemini explain the findings in plain language, and asks a human
to approve, defer, or refuse remediation from a web console (with optional
Discord notifications) — logging every decision to Postgres for an audit trail.

This is the Python/Docker rewrite of **[Sentinal v1](https://github.com/NorwegianKiwi-glitch/Sentinal)**,
which prototyped the same workflow in n8n. See [ARCHITECTURE.md](ARCHITECTURE.md)
for the full design, what changed from v1 and why, and known limitations.

## Requirements

- Docker + Docker Compose
- A Google Gemini API key — [aistudio.google.com/apikey](https://aistudio.google.com/apikey)
- *Optional:* a Discord bot (token, guild ID, channel ID) — [discord.com/developers](https://discord.com/developers/applications). Leave it unset to use the web console alone.

## Quickstart

```sh
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, GEMINI_API_KEY, FLASK_SECRET_KEY, DASHBOARD_*
# (DISCORD_* are optional — set them to also mirror alerts into a channel)

docker compose up --build
```

The console is then at `http://localhost:6767` (HTTP Basic Auth, using the
`DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` you set), with **Decisions**,
**Scan Log**, and **Exceptions** pages and a Run/Stop-scan control.

## Configuration

All configuration is environment variables — see [.env.example](.env.example)
for the full list with defaults. Notable ones:

| Variable | Default | Meaning |
|---|---|---|
| `SNOOZE_DAYS` | `7` | How long a "Snooze" decision defers re-scanning an image |
| `REFUSE_REVIEW_DAYS` | `180` | How long a "Refuse" decision holds before it needs re-attestation |
| `SCAN_INTERVAL_HOURS` | `24` | How often the background scheduler runs a full scan cycle; `0` disables it |
| `TRIVY_SEVERITY` | `HIGH,CRITICAL` | Severity floor passed to Trivy |
| `DOCKER_SOCKET` | `unix://var/run/docker.sock` | Where the app reaches the Docker daemon it's managing |

## Deploying to CasaOS / Raspberry Pi

1. Build (or pull) a multi-arch image so the same tag works on your dev
   machine and the Pi's arm64 CPU:
   ```sh
   docker buildx build --platform linux/amd64,linux/arm64 -t <your-registry>/sentinal:latest --push .
   ```
2. Copy `docker-compose.yml` and `.env` to the Pi, or import the compose file
   directly through CasaOS's "Custom Install."
3. `docker compose pull && docker compose up -d`.

## Development

```sh
python -m venv .venv
.venv/Scripts/activate      # .venv/bin/activate on Linux/macOS
pip install -r requirements-dev.txt
pytest
```

Tests run against an isolated in-memory SQLite database — no Postgres, Docker
socket, Discord, or Gemini access required.
