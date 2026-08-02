"""Transparency inclusion (spec step 6), against a Merkle tree built in the test.

A reference RFC 6962 tree is constructed locally, an inclusion proof generated
for a leaf, and the verifier checked against it -- so the proof math and the
signed-tree-head check are exercised with real proofs, not mocks.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qresp.signing.rekor import (
    InclusionError,
    LogEntry,
    leaf_hash,
    verify_inclusion_root,
    verify_log_entry,
)


def _h(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


class RefTree:
    """A minimal RFC 6962 tree that can emit inclusion proofs, for testing."""

    def __init__(self, entries):
        self.leaves = [leaf_hash(e) for e in entries]

    def _root(self, lo, hi):
        if hi - lo == 1:
            return self.leaves[lo]
        k = 1
        while k * 2 < (hi - lo):
            k *= 2
        split = lo + k
        return _h(self._root(lo, split), self._root(split, hi))

    def root(self):
        return self._root(0, len(self.leaves))

    def proof(self, index):
        return self._proof(index, 0, len(self.leaves))

    def _proof(self, index, lo, hi):
        if hi - lo == 1:
            return []
        k = 1
        while k * 2 < (hi - lo):
            k *= 2
        split = lo + k
        if index < split:
            return self._proof(index, lo, split) + [self._root(split, hi)]
        return self._proof(index, split, hi) + [self._root(lo, split)]


@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 13])
@pytest.mark.parametrize("index", [0, 1, 2, 4, 7, 12])
def test_reference_proofs_verify_for_every_valid_index(size, index):
    if index >= size:
        pytest.skip("index outside tree")
    entries = [f"entry-{i}".encode() for i in range(size)]
    tree = RefTree(entries)
    computed = verify_inclusion_root(index, size, leaf_hash(entries[index]),
                                     tree.proof(index))
    assert computed == tree.root()


def test_a_tampered_proof_reconstructs_a_different_root():
    entries = [f"e{i}".encode() for i in range(8)]
    tree = RefTree(entries)
    proof = tree.proof(3)
    proof[0] = bytes(32)                       # corrupt one sibling
    assert verify_inclusion_root(3, 8, leaf_hash(entries[3]), proof) != tree.root()


def test_an_index_outside_the_tree_is_refused():
    with pytest.raises(InclusionError, match="outside a tree"):
        verify_inclusion_root(9, 8, leaf_hash(b"x"), [])


def _log_entry(preimage, entries, index, log_key, integrated=None):
    tree = RefTree(entries)
    root = tree.root()
    tree_size = len(entries)
    sth = LogEntry.signed_tree_head(root, tree_size)
    sig = log_key.sign(sth, ec.ECDSA(hashes.SHA256()))
    return LogEntry(
        body_sha256=preimage,
        entry_leaf=entries[index],
        log_index=index, tree_size=tree_size,
        inclusion_proof=tree.proof(index), root_hash=root,
        integrated_time=int((integrated or datetime.now(timezone.utc)
                             - timedelta(days=1)).timestamp()),
        tree_head_signature=sig)


class TestFullEntryVerification:
    def setup_method(self):
        self.log_key = ec.generate_private_key(ec.SECP256R1())
        self.log_pub = self.log_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def test_a_valid_entry_returns_the_upper_bound_time(self):
        preimage = hashlib.sha256(b"registration").digest()
        entries = [preimage if i == 2 else f"e{i}".encode() for i in range(5)]
        entry = _log_entry(preimage, entries, 2, self.log_key)
        t = verify_log_entry(entry, preimage, self.log_pub)
        assert isinstance(t, datetime) and t.tzinfo is not None

    def test_an_entry_for_a_different_registration_is_refused(self):
        entries = [f"e{i}".encode() for i in range(5)]
        entry = _log_entry(b"a" * 32, entries, 2, self.log_key)
        with pytest.raises(InclusionError, match="different entry"):
            verify_log_entry(entry, b"b" * 32, self.log_pub)

    def test_a_tree_head_signed_by_the_wrong_key_is_refused(self):
        preimage = hashlib.sha256(b"r").digest()
        entries = [preimage if i == 1 else f"e{i}".encode() for i in range(4)]
        entry = _log_entry(preimage, entries, 1, self.log_key)
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(InclusionError, match="log's public key"):
            verify_log_entry(entry, preimage, other)

    def test_an_empty_log_key_is_a_config_error(self):
        preimage = hashlib.sha256(b"r").digest()
        entries = [preimage, b"x"]
        entry = _log_entry(preimage, entries, 0, self.log_key)
        with pytest.raises(InclusionError, match="Configuration error"):
            verify_log_entry(entry, preimage, b"")

    def test_a_future_integrated_time_is_refused(self):
        preimage = hashlib.sha256(b"r").digest()
        entries = [preimage, b"x"]
        future = datetime.now(timezone.utc) + timedelta(days=3650)
        entry = _log_entry(preimage, entries, 0, self.log_key, integrated=future)
        with pytest.raises(InclusionError, match="future"):
            verify_log_entry(entry, preimage, self.log_pub)
