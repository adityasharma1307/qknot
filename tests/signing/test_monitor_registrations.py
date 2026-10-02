"""A registration walk that cannot finish is NOT ESTABLISHED."""
from __future__ import annotations

import pytest

from qknot.signing.revocation_search import walk_identity
from qknot.signing.sigstore_clients import SigstoreClientError


class _Client:
    def __init__(self, entries=None, error: str | None = None):
        self._entries = entries or []
        self._error = error

    def search_by_identity(self, identity: str):
        if self._error:
            raise SigstoreClientError(self._error)
        return self._entries


def test_a_finished_walk_lists_entries_and_does_not_claim_completeness():
    entries, error = walk_identity(
        _Client([{"logIndex": 7, "integratedTime": 10}]), "a@b.c",
    )
    assert error is None
    assert entries[0]["logIndex"] == 7


@pytest.mark.allow_network
def test_a_live_rekor_walk_of_an_unused_identity_finishes():
    """Production log. An empty finished list is not 'no rogue keys exist'."""
    from qknot.signing.sigstore_clients import RekorRevocationSearchClient

    entries, error = walk_identity(
        RekorRevocationSearchClient(max_entries=5),
        "nobody-qknot-s8@example.com",
    )
    assert error is None
    assert entries == []


def test_an_unfinished_walk_is_not_established():
    entries, error = walk_identity(
        _Client(error="above the max_entries=512 bound"), "a@b.c",
    )
    assert entries == []
    assert error is not None
    assert "NOT evidence" in error or "max_entries" in error
