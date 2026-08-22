from __future__ import annotations

import datetime as dt
from unittest import mock

from sentinal import cloudflare


def _response(status=200, json_body=None):
    response = mock.Mock()
    response.status_code = status
    response.json.return_value = json_body or {}
    response.raise_for_status = mock.Mock()
    if status >= 400:
        response.raise_for_status.side_effect = Exception(f"HTTP {status}")
    return response


def _payload(groups):
    return {
        "data": {
            "viewer": {
                "zones": [
                    {
                        "httpRequestsAdaptiveGroups": [
                            {
                                "count": count,
                                "dimensions": {
                                    "clientIP": ip,
                                    "clientRequestHTTPHost": host,
                                    "clientRequestPath": path,
                                    "edgeResponseStatus": status,
                                    "datetimeMinute": minute,
                                },
                            }
                            for (ip, host, path, status, minute, count) in groups
                        ]
                    }
                ]
            }
        }
    }


def test_fetch_traffic_parses_groups():
    session = mock.Mock()
    session.post.return_value = _response(
        json_body=_payload(
            [("203.0.113.5", "nextcloud.example.com", "/login", 401, "2026-08-22T10:00:00Z", 6)]
        )
    )

    groups = cloudflare.fetch_traffic(
        api_token="tok",
        zone_id="zone",
        hostnames=["nextcloud.example.com"],
        since=dt.datetime(2026, 8, 22, 9, 55),
        until=dt.datetime(2026, 8, 22, 10, 5),
        session=session,
    )

    assert groups == [
        cloudflare.TrafficGroup(
            hostname="nextcloud.example.com",
            client_ip="203.0.113.5",
            path="/login",
            status_code=401,
            request_count=6,
            minute=dt.datetime(2026, 8, 22, 10, 0),
        )
    ]
    call = session.post.call_args
    assert call.args[0] == cloudflare._API_URL
    assert call.kwargs["headers"] == {"Authorization": "Bearer tok"}
    variables = call.kwargs["json"]["variables"]
    assert variables["zoneTag"] == "zone"
    assert variables["hostnames"] == ["nextcloud.example.com"]
    assert variables["since"] == "2026-08-22T09:55:00Z"


def test_fetch_traffic_returns_empty_on_http_error():
    session = mock.Mock()
    session.post.return_value = _response(status=500)

    groups = cloudflare.fetch_traffic(
        api_token="tok",
        zone_id="zone",
        hostnames=["example.com"],
        since=dt.datetime(2026, 8, 22),
        until=dt.datetime(2026, 8, 22, 0, 5),
        session=session,
    )

    assert groups == []


def test_fetch_traffic_returns_empty_on_graphql_errors():
    session = mock.Mock()
    session.post.return_value = _response(json_body={"errors": [{"message": "bad token"}]})

    groups = cloudflare.fetch_traffic(
        api_token="tok",
        zone_id="zone",
        hostnames=["example.com"],
        since=dt.datetime(2026, 8, 22),
        until=dt.datetime(2026, 8, 22, 0, 5),
        session=session,
    )

    assert groups == []


def test_fetch_traffic_skips_rows_with_unparseable_fields():
    session = mock.Mock()
    good = ("203.0.113.5", "example.com", "/login", 401, "2026-08-22T10:00:00Z", 3)
    session.post.return_value = _response(
        json_body=_payload(
            [
                good,
                ("203.0.113.6", "example.com", "/x", "not-a-status", "2026-08-22T10:01:00Z", 1),
            ]
        )
    )

    groups = cloudflare.fetch_traffic(
        api_token="tok",
        zone_id="zone",
        hostnames=["example.com"],
        since=dt.datetime(2026, 8, 22),
        until=dt.datetime(2026, 8, 22, 0, 5),
        session=session,
    )

    assert len(groups) == 1
    assert groups[0].client_ip == "203.0.113.5"
