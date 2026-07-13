"""Decide whether "Apply Patch" (pull + recreate) can achieve anything.

Both the Discord alert and the web console show the patch button only when a
pull could actually change what runs, and otherwise state what the user should
do instead. Centralizing that judgement here keeps the two UIs — and the alert
body text — from drifting apart.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import registry

_DATABASE_ENGINES = ("postgres", "mariadb", "mysql", "mongo")
# Moving tags whose content changes under a fixed name, so a re-pull can fetch
# a newer build even without a version bump. Pinned version tags cannot.
_MUTABLE_TAGS = frozenset({"latest", "stable", "edge", "main", "nightly", "dev"})


def is_database_image(repository: str) -> bool:
    name = repository.rsplit("/", 1)[-1]
    return any(engine in name for engine in _DATABASE_ENGINES)


@dataclass(frozen=True)
class Patchability:
    can_patch: bool
    target: str | None
    advice: str


def describe_patch(
    image: str, proposed_image: str | None, proposed_major_image: str | None
) -> Patchability:
    """Whether a pull-based patch is worth offering for `image`, and if not, why."""
    if image.startswith("sha256:") or "@sha256:" in image:
        return Patchability(
            False,
            None,
            "This image is pinned by digest, so pulling can never fetch anything newer — "
            "rebuild or retag the image to update it.",
        )
    if proposed_image:
        return Patchability(
            True, proposed_image, f"A newer, Trivy-verified image is available: {proposed_image}."
        )
    ref = registry.parse_image_ref(image)
    if ref.tag in _MUTABLE_TAGS:
        return Patchability(
            True, image, f"`{image}` uses a moving tag; re-pulling may fetch a newer build."
        )
    if proposed_major_image:
        if is_database_image(ref.repository):
            return Patchability(
                False,
                None,
                f"Only a new major exists (`{proposed_major_image}`), and a database engine cannot "
                "be image-swapped across majors — upgrade it with a dump/restore (see BACKUPS.md).",
            )
        return Patchability(
            False,
            None,
            f"No same-major fix; a newer major exists (`{proposed_major_image}`). Use the "
            "Major Upgrade action, or upgrade via CasaOS.",
        )
    return Patchability(
        False,
        None,
        "No pull-based fix is available yet — you are already on the newest same-major tag. "
        "Snooze to revisit later, or Refuse to accept the risk with a review date.",
    )
