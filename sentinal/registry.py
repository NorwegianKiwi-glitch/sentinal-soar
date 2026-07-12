"""Query an image's registry for newer tags worth upgrading to.

Re-pulling the tag a container already runs only patches anything when that
tag is mutable (`:latest`-style); pinned tags like `postgres:14.2` never
change, so a real patch means moving to a newer tag. This module speaks the
Docker Registry HTTP API v2 (Docker Hub, GHCR, and most other registries) to
list a repository's tags anonymously, then picks the newest tag that looks
like the same flavor of what's running: same `v` prefix, same suffix
(`-alpine`, …), same number of version components, and the same leading
version number — a deliberately conservative "safe bump". Callers are
expected to Trivy-scan the candidate before proposing it to a human.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

import requests

DOCKER_HUB_REGISTRY = "registry-1.docker.io"
_PAGE_SIZE = 1000
_MAX_PAGES = 10
# The seeded rescue pass may page much further: repos like immich-machine-learning
# publish several flavor tags per commit, so tens of thousands of tags can sit
# between the running release and the next one. It exits early once a newer
# same-flavor release has shown up (see list_tags_for_upgrade).
_MAX_SEEK_PAGES = 60
_SEEK_GRACE_PAGES = 2
_TIMEOUT = 30

_VERSION_TAG_RE = re.compile(r"^(v?)(\d+(?:\.\d+)*)(.*)$")


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    tag: str


@dataclass(frozen=True)
class VersionTag:
    prefix: str
    numbers: tuple[int, ...]
    suffix: str


def parse_image_ref(image: str) -> ImageRef:
    """Split an image reference into registry host, repository path, and tag."""
    name, tag = image, "latest"
    if ":" in image.rsplit("/", 1)[-1]:
        name, _, tag = image.rpartition(":")
    head, slash, rest = name.partition("/")
    # A first path segment with a dot or port is a registry host; anything else
    # (including single-segment names like "postgres") lives on Docker Hub.
    if slash and ("." in head or ":" in head or head == "localhost"):
        registry, repository = head, rest
    else:
        registry, repository = DOCKER_HUB_REGISTRY, name
    if registry in ("docker.io", "index.docker.io"):
        registry = DOCKER_HUB_REGISTRY
    if registry == DOCKER_HUB_REGISTRY and "/" not in repository:
        repository = f"library/{repository}"
    return ImageRef(registry=registry, repository=repository, tag=tag)


def parse_version_tag(tag: str) -> VersionTag | None:
    """Parse "v2.7.5" / "14.2" / "16-alpine" style tags; None if non-numeric."""
    match = _VERSION_TAG_RE.match(tag)
    if match is None:
        return None
    prefix, numbers, suffix = match.groups()
    return VersionTag(prefix=prefix, numbers=tuple(int(n) for n in numbers.split(".")), suffix=suffix)


def pick_upgrade_candidate(current_tag: str, tags: list[str]) -> str | None:
    """Newest tag strictly newer than `current_tag` with the same shape.

    "Same shape" means same prefix/suffix, same component count, and the same
    leading number, so `14.2` can become `14.19` but never `15.1`, and
    `16-alpine` never degrades to plain `16`. Returns None for non-version
    tags like `latest` — there is nothing meaningful to compare.
    """
    current = parse_version_tag(current_tag)
    if current is None:
        return None
    best: tuple[tuple[int, ...], str] | None = None
    for tag in tags:
        parsed = parse_version_tag(tag)
        if (
            parsed is None
            or parsed.prefix != current.prefix
            or parsed.suffix != current.suffix
            or len(parsed.numbers) != len(current.numbers)
            or parsed.numbers[0] != current.numbers[0]
            or parsed.numbers <= current.numbers
        ):
            continue
        if best is None or parsed.numbers > best[0]:
            best = (parsed.numbers, tag)
    return best[1] if best else None


def newest_release(current_tag: str, tags: list[str]) -> str | None:
    """Newest same-flavor release regardless of major version.

    For informing a human when no safe same-major bump exists (e.g. the
    project abandoned the old major) — never something to auto-patch to.
    Same prefix and suffix rules as pick_upgrade_candidate, which also keeps
    prerelease suffixes like `-rc.3` out.
    """
    current = parse_version_tag(current_tag)
    if current is None:
        return None
    best: tuple[tuple[int, ...], str] | None = None
    for tag in tags:
        parsed = parse_version_tag(tag)
        if (
            parsed is None
            or parsed.prefix != current.prefix
            or parsed.suffix != current.suffix
            or parsed.numbers <= current.numbers
        ):
            continue
        if best is None or parsed.numbers > best[0]:
            best = (parsed.numbers, tag)
    return best[1] if best else None


def list_tags(ref: ImageRef, session: requests.Session | None = None) -> list[str]:
    tags, _ = _capped_listing(session or requests.Session(), ref)
    return tags


def list_tags_for_upgrade(ref: ImageRef, session: requests.Session | None = None) -> list[str]:
    """Tag listing tuned for finding something newer than `ref.tag`.

    Mega-repositories (immich publishes several tags per commit) blow past the
    page cap long before their release tags appear, because registries like
    GHCR list tags in insertion order — newest last. When the plain listing
    comes back truncated, a second listing seeded with `last=<current tag>`
    resumes from the very tag the container is running, which in insertion
    order means "everything published since this release". That pass pages
    until a newer same-flavor release has been seen (plus a small grace so a
    slightly newer one right behind it isn't missed), bounded by
    _MAX_SEEK_PAGES. On lexically-ordered registries the seeded slice is less
    complete, but those rarely truncate at all.
    """
    session = session or requests.Session()
    tags, truncated = _capped_listing(session, ref)
    if not truncated or ref.tag == "latest":
        return tags

    current = parse_version_tag(ref.tag)
    seen = set(tags)
    stop_after: int | None = None
    for page_index, page in enumerate(_iter_tag_pages(session, ref, last=ref.tag)):
        tags += [tag for tag in page if tag not in seen]
        seen.update(page)
        if stop_after is None and current and any(_is_newer_same_flavor(tag, current) for tag in page):
            stop_after = page_index + _SEEK_GRACE_PAGES
        if (stop_after is not None and page_index >= stop_after) or page_index + 1 >= _MAX_SEEK_PAGES:
            break
    return tags


def _is_newer_same_flavor(tag: str, current: VersionTag) -> bool:
    parsed = parse_version_tag(tag)
    return (
        parsed is not None
        and parsed.prefix == current.prefix
        and parsed.suffix == current.suffix
        and parsed.numbers > current.numbers
    )


def _capped_listing(
    session: requests.Session, ref: ImageRef, last: str | None = None
) -> tuple[list[str], bool]:
    """Up to _MAX_PAGES of tags (optionally resuming after `last`), plus
    whether the registry still had more pages when we stopped."""
    tags: list[str] = []
    pages = _iter_tag_pages(session, ref, last=last)
    for page_index, page in enumerate(pages):
        tags.extend(page)
        if page_index + 1 >= _MAX_PAGES:
            return tags, True
    return tags, False


def _iter_tag_pages(session: requests.Session, ref: ImageRef, last: str | None = None):
    """Yield tag pages, following pagination links until the registry runs out."""
    url = f"https://{ref.registry}/v2/{ref.repository}/tags/list?n={_PAGE_SIZE}"
    if last:
        url += f"&last={quote(last)}"
    token: str | None = None
    while True:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = session.get(url, headers=headers, timeout=_TIMEOUT)
        if response.status_code == 401 and token is None:
            token = _anonymous_pull_token(session, response.headers.get("WWW-Authenticate", ""), ref)
            headers = {"Authorization": f"Bearer {token}"}
            response = session.get(url, headers=headers, timeout=_TIMEOUT)
        response.raise_for_status()
        yield response.json().get("tags") or []
        next_url = response.links.get("next", {}).get("url")
        if not next_url:
            return
        url = next_url if next_url.startswith("http") else f"https://{ref.registry}{next_url}"


def _anonymous_pull_token(session: requests.Session, challenge: str, ref: ImageRef) -> str:
    """Follow the registry's Bearer challenge to get an anonymous pull token."""
    if not challenge.lower().startswith("bearer"):
        raise RuntimeError(f"{ref.registry} sent an unsupported auth challenge: {challenge!r}")
    fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = fields.get("realm")
    if not realm:
        raise RuntimeError(f"{ref.registry} sent a Bearer challenge without a realm: {challenge!r}")
    params = {"scope": f"repository:{ref.repository}:pull"}
    if "service" in fields:
        params["service"] = fields["service"]
    response = session.get(realm, params=params, timeout=_TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    return payload.get("token") or payload["access_token"]
