from __future__ import annotations

from sentinal import container_selection


def test_excluded_names_is_empty_by_default():
    assert container_selection.excluded_names() == set()


def test_set_excluded_roundtrips_through_excluded_names():
    saved = container_selection.set_excluded(["redis", "immich"])

    assert saved == {"redis", "immich"}
    assert container_selection.excluded_names() == {"redis", "immich"}


def test_set_excluded_replaces_rather_than_merges():
    container_selection.set_excluded(["redis", "immich"])
    container_selection.set_excluded(["postgres"])

    assert container_selection.excluded_names() == {"postgres"}


def test_set_excluded_drops_blank_and_whitespace_entries():
    saved = container_selection.set_excluded(["redis", "  ", "", "  immich  ".strip()])

    assert saved == {"redis", "immich"}


def test_set_excluded_with_empty_list_clears_all():
    container_selection.set_excluded(["redis"])
    container_selection.set_excluded([])

    assert container_selection.excluded_names() == set()
