from __future__ import annotations

from unittest import mock

import pytest

from sentinal import registry


# --- parse_image_ref -------------------------------------------------------


@pytest.mark.parametrize(
    ("image", "expected_registry", "expected_repository", "expected_tag"),
    [
        ("postgres:14.2", registry.DOCKER_HUB_REGISTRY, "library/postgres", "14.2"),
        ("n8nio/n8n:1.123.0", registry.DOCKER_HUB_REGISTRY, "n8nio/n8n", "1.123.0"),
        ("nginx", registry.DOCKER_HUB_REGISTRY, "library/nginx", "latest"),
        ("ghcr.io/immich-app/immich-server:v2.7.5", "ghcr.io", "immich-app/immich-server", "v2.7.5"),
        ("docker.io/pihole/pihole:2025.08.0", registry.DOCKER_HUB_REGISTRY, "pihole/pihole", "2025.08.0"),
    ],
)
def test_parse_image_ref(image, expected_registry, expected_repository, expected_tag):
    ref = registry.parse_image_ref(image)
    assert ref.registry == expected_registry
    assert ref.repository == expected_repository
    assert ref.tag == expected_tag


# --- pick_upgrade_candidate -------------------------------------------------


def test_pick_newest_same_major():
    tags = ["14.1", "14.3", "14.19", "15.1", "16", "latest", "14.19-alpine"]
    assert registry.pick_upgrade_candidate("14.2", tags) == "14.19"


def test_pick_respects_suffix_flavor():
    tags = ["16.1", "16.9", "16.9-alpine", "16.4-alpine"]
    assert registry.pick_upgrade_candidate("16.2-alpine", tags) == "16.9-alpine"


def test_pick_respects_v_prefix():
    tags = ["2.8.0", "v2.8.1", "v2.9.0"]
    assert registry.pick_upgrade_candidate("v2.7.5", tags) == "v2.9.0"


def test_pick_never_crosses_major():
    assert registry.pick_upgrade_candidate("14.2", ["15.1", "16.0"]) is None


def test_pick_requires_same_component_count_and_major():
    # "16" and "16.1" are different tag conventions; don't mix them. And a
    # single-component bump (16 -> 17) is by definition a major bump: refused.
    assert registry.pick_upgrade_candidate("16", ["16.1", "17"]) is None
    assert registry.pick_upgrade_candidate("16.1", ["17"]) is None


def test_pick_returns_none_for_non_version_tags():
    assert registry.pick_upgrade_candidate("latest", ["1.0", "2.0"]) is None
    assert registry.pick_upgrade_candidate("stable", ["1.0"]) is None


def test_pick_returns_none_when_already_newest():
    assert registry.pick_upgrade_candidate("1.123.0", ["1.122.0", "1.123.0"]) is None


# --- list_tags --------------------------------------------------------------


def _response(status=200, json_body=None, headers=None, links=None):
    response = mock.Mock()
    response.status_code = status
    response.json.return_value = json_body or {}
    response.headers = headers or {}
    response.links = links or {}
    response.raise_for_status = mock.Mock()
    return response


def test_list_tags_follows_anonymous_token_challenge():
    ref = registry.parse_image_ref("n8nio/n8n:1.123.0")
    session = mock.Mock()
    challenge = _response(
        status=401,
        headers={
            "WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'
        },
    )
    token_response = _response(json_body={"token": "anon-token"})
    tags_response = _response(json_body={"tags": ["1.123.0", "1.124.2"]})
    session.get.side_effect = [challenge, token_response, tags_response]

    assert registry.list_tags(ref, session=session) == ["1.123.0", "1.124.2"]

    token_call = session.get.call_args_list[1]
    assert token_call.args[0] == "https://auth.docker.io/token"
    assert token_call.kwargs["params"]["scope"] == "repository:n8nio/n8n:pull"
    tags_call = session.get.call_args_list[2]
    assert tags_call.kwargs["headers"] == {"Authorization": "Bearer anon-token"}
