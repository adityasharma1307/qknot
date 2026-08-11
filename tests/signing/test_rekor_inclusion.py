"""Transparency inclusion (spec step 6), against a Merkle tree built in the test.

A reference RFC 6962 tree is constructed locally, an inclusion proof generated
for a leaf, and the verifier checked against it -- so the proof math, the signed
checkpoint (STH) and the signed entry timestamp (SET) are exercised with real
proofs and REAL Rekor formats (signed by a test key), not mocks. The very same
formats are verified against production bytes in test_sigstore_fixture.py.
"""
from __future__ import annotations

import dataclasses
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qknot.signing.rekor import (
    InclusionError,
    hashedrekord_body,
    leaf_hash,
    verify_inclusion_root,
    verify_log_entry,
)

from ._rekor_doubles import make_log_entry


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


def _log_entry(entries, index, log_key, integrated=None):
    """A LogEntry with a real-format checkpoint + SET over a locally built tree.

    `entries` are entry BODIES; the checkpoint names the tree's real root, so an
    honest entry verifies and any tamper fails the reconstruction-vs-checkpoint
    or SET check.
    """
    tree = RefTree(entries)
    when = integrated or (datetime.now(timezone.utc) - timedelta(days=1))
    return make_log_entry(
        entry_body=entries[index],
        log_index=index,
        tree_size=len(entries),
        root_hash=tree.root(),
        inclusion_proof=tree.proof(index),
        integrated_time=int(when.timestamp()),
        key=log_key)


class TestFullEntryVerification:
    def setup_method(self):
        self.log_key = ec.generate_private_key(ec.SECP256R1())
        self.log_pub = self.log_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def test_a_valid_entry_returns_the_upper_bound_time(self):
        preimage = hashlib.sha256(b"registration").digest()
        entries = [hashedrekord_body(preimage) if i == 2 else f"e{i}".encode()
                   for i in range(5)]
        entry = _log_entry(entries, 2, self.log_key)
        t = verify_log_entry(entry, preimage, self.log_pub)
        assert isinstance(t, datetime) and t.tzinfo is not None

    def test_the_digest_is_bound_to_the_proven_leaf(self):
        """Bug 2: a REAL inclusion proof for one registration cannot be rebound
        to a different registration. The digest is parsed from the proven body,
        so claiming a different expected preimage simply fails the match."""
        real = hashlib.sha256(b"alice-registration").digest()
        entries = [hashedrekord_body(real) if i == 1 else f"e{i}".encode()
                   for i in range(4)]
        entry = _log_entry(entries, 1, self.log_key)         # honest proof
        attacker = hashlib.sha256(b"mallory-registration").digest()
        with pytest.raises(InclusionError, match="different digest|another entry"):
            verify_log_entry(entry, attacker, self.log_pub)

    def test_an_entry_body_not_matching_its_leaf_fails_inclusion(self):
        """Swap the body for a different hashedrekord after the proof was built:
        the leaf hash changes, so inclusion no longer reconstructs the signed
        checkpoint root."""
        real = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(real) if i == 0 else f"e{i}".encode()
                   for i in range(4)]
        entry = _log_entry(entries, 0, self.log_key)
        swapped = dataclasses.replace(
            entry, entry_body=hashedrekord_body(hashlib.sha256(b"other").digest()))
        with pytest.raises(InclusionError, match="reconstruct"):
            verify_log_entry(swapped, hashlib.sha256(b"other").digest(), self.log_pub)

    def test_a_checkpoint_root_the_proof_does_not_reach_is_refused(self):
        """A real inclusion proof for one entry cannot be presented under a
        checkpoint that signs a different root: reconstruction won't match."""
        real = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(real) if i == 2 else f"e{i}".encode()
                   for i in range(5)]
        entry = _log_entry(entries, 2, self.log_key)
        # a checkpoint over an unrelated root, validly signed by the same log
        from ._rekor_doubles import signed_checkpoint
        foreign = signed_checkpoint(5, hashlib.sha256(b"nope").digest(), self.log_key)
        tampered = dataclasses.replace(entry, checkpoint=foreign)
        with pytest.raises(InclusionError, match="reconstruct"):
            verify_log_entry(tampered, real, self.log_pub)

    def test_a_non_hashedrekord_body_is_refused(self):
        entries = [b"not-a-hashedrekord" for _ in range(3)]
        entry = _log_entry(entries, 0, self.log_key)
        with pytest.raises(InclusionError, match="not a parseable hashedrekord"):
            verify_log_entry(entry, b"x" * 32, self.log_pub)

    def test_a_checkpoint_signed_by_the_wrong_key_is_refused(self):
        preimage = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(preimage) if i == 1 else f"e{i}".encode()
                   for i in range(4)]
        entry = _log_entry(entries, 1, self.log_key)
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(InclusionError, match="log's public key"):
            verify_log_entry(entry, preimage, other)

    def test_a_set_for_a_different_time_is_refused(self):
        """The SET authenticates integratedTime: rewriting the claimed time
        without re-signing breaks the SET signature."""
        preimage = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(preimage) if i == 1 else f"e{i}".encode()
                   for i in range(4)]
        entry = _log_entry(entries, 1, self.log_key)
        moved = dataclasses.replace(entry, integrated_time=entry.integrated_time - 99999)
        with pytest.raises(InclusionError, match="log's public key|log signature"):
            verify_log_entry(moved, preimage, self.log_pub)

    def test_an_entry_from_a_different_log_is_refused(self):
        """logID must be SHA-256 of the trusted log key; an entry whose SET was
        signed by another log cannot be presented under this verifier's key."""
        preimage = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(preimage) if i == 1 else f"e{i}".encode()
                   for i in range(4)]
        other_key = ec.generate_private_key(ec.SECP256R1())
        entry = _log_entry(entries, 1, other_key)            # signed by other log
        with pytest.raises(InclusionError, match="different log|log's public key"):
            verify_log_entry(entry, preimage, self.log_pub)

    def test_an_empty_log_key_is_a_config_error(self):
        preimage = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(preimage), b"x"]
        entry = _log_entry(entries, 0, self.log_key)
        with pytest.raises(InclusionError, match="Configuration error"):
            verify_log_entry(entry, preimage, b"")

    def test_a_far_future_integrated_time_is_refused(self):
        preimage = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(preimage), b"x"]
        future = datetime.now(timezone.utc) + timedelta(days=3650)
        entry = _log_entry(entries, 0, self.log_key, integrated=future)
        with pytest.raises(InclusionError, match="future"):
            verify_log_entry(entry, preimage, self.log_pub)

    def test_a_few_seconds_of_clock_skew_is_tolerated(self):
        """A real log's integratedTime can land a moment ahead of the verifier's
        clock; a small skew must be tolerated, unlike a far-future timestamp."""
        preimage = hashlib.sha256(b"r").digest()
        entries = [hashedrekord_body(preimage), b"x"]
        soon = datetime.now(timezone.utc) + timedelta(seconds=10)
        entry = _log_entry(entries, 0, self.log_key, integrated=soon)
        t = verify_log_entry(entry, preimage, self.log_pub)
        assert isinstance(t, datetime)
