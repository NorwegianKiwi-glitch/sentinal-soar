"""Query Cloudflare's GraphQL Analytics API for recent edge traffic.

The deployed setup routes everything through a Cloudflare Tunnel, and local
app logs (checked on Nextcloud) currently record the docker bridge IP rather
than the real client — see ARCHITECTURE.md. Cloudflare's edge, by contrast,
always sees the real client IP for a Cloudflare-proxied hostname. The
`httpRequestsAdaptiveGroups` dataset exposes that traffic pre-aggregated (by
IP/path/status/minute) on every plan, including Free — no Logpush/Enterprise
access needed.

This module only speaks HTTP to Cloudflare and returns plain data; access.py
owns turning the result into AccessEvent rows and applying the brute-force
heuristic. Cloudflare can't see inside an app's response body, so this can
tell you who is hitting a login-shaped path and how often — not whether a
login actually succeeded.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

import requests

log = logging.getLogger(__name__)

_API_URL = "https://api.cloudflare.com/client/v4/graphql"
_TIMEOUT = 30
_LIMIT = 10000

_QUERY = """
query AccessTraffic($zoneTag: String!, $since: Time!, $until: Time!, $hostnames: [String!]!, $limit: Int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      httpRequestsAdaptiveGroups(
        limit: $limit
        filter: { datetime_geq: $since, datetime_lt: $until, clientRequestHTTPHost_in: $hostnames }
      ) {
        count
        dimensions {
          clientIP
          clientRequestHTTPHost
          clientRequestPath
          edgeResponseStatus
          datetimeMinute
        }
      }
    }
  }
}
"""


@dataclass(frozen=True)
class TrafficGroup:
    hostname: str
    client_ip: str
    path: str
    status_code: int
    request_count: int
    minute: dt.datetime  # UTC, naive — start of the 1-minute bucket


def fetch_traffic(
    *,
    api_token: str,
    zone_id: str,
    hostnames: list[str],
    since: dt.datetime,
    until: dt.datetime,
    session: requests.Session | None = None,
) -> list[TrafficGroup]:
    """Aggregated edge-traffic groups for `hostnames` in [since, until).

    Never raises — a Cloudflare API hiccup should degrade to "no new data
    this tick", not take down the polling thread or a request that triggers
    an ingest, matching how registry.py degrades on registry hiccups.
    """
    session = session or requests.Session()
    variables = {
        "zoneTag": zone_id,
        "since": _iso(since),
        "until": _iso(until),
        "hostnames": hostnames,
        "limit": _LIMIT,
    }
    try:
        response = session.post(
            _API_URL,
            json={"query": _QUERY, "variables": variables},
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        log.warning("Cloudflare Analytics request failed: %s", exc)
        return []
    if payload.get("errors"):
        log.warning("Cloudflare Analytics returned errors: %s", payload["errors"])
        return []
    return _parse_groups(payload)


def _parse_groups(payload: dict) -> list[TrafficGroup]:
    groups: list[TrafficGroup] = []
    zones = ((payload.get("data") or {}).get("viewer") or {}).get("zones") or []
    for zone in zones:
        for row in zone.get("httpRequestsAdaptiveGroups") or []:
            dims = row.get("dimensions") or {}
            minute = _parse_iso(dims.get("datetimeMinute"))
            if minute is None:
                continue
            try:
                status_code = int(dims.get("edgeResponseStatus"))
                request_count = int(row.get("count"))
            except (TypeError, ValueError):
                continue
            groups.append(
                TrafficGroup(
                    hostname=dims.get("clientRequestHTTPHost") or "",
                    client_ip=dims.get("clientIP") or "",
                    path=dims.get("clientRequestPath") or "",
                    status_code=status_code,
                    request_count=request_count,
                    minute=minute,
                )
            )
    return groups


def _iso(value: dt.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.strptime(value.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
