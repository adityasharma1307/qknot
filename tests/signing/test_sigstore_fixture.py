"""Production-parity: run the verifiers against REAL Sigstore bytes.

The bytes in tests/signing/fixtures/ are a genuine Fulcio leaf, the Fulcio CA
pool, a real Rekor inclusion proof + checkpoint, and the Rekor public key,
captured once with `sigstore sign` (scripts/verify/check_sigstore_fixture.py).
Every OTHER registration test mints its own trust stack; this one proves the
same modules accept production bytes -- a real leaf with EKU/SCT extensions, and
a real 2.2-billion-entry Merkle tree.

Skips cleanly when the fixture is absent, so CI without it still passes; the
fixture is small and committed so a reviewer can run it without signing.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509

from qresp.signing.fulcio import verify_chain
from qresp.signing.rekor import (
    hashedrekord_digest,
    leaf_hash,
    log_entry_from_rekor,
    verify_checkpoint,
    verify_inclusion_root,
    verify_log_entry,
)

FIXTURES = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.skipif(
    not (FIXTURES / "leaf.der").exists(),
    reason="no captured Sigstore fixture (run scripts/verify/check_sigstore_fixture.py)")


def _b64(v: str) -> bytes:
    return base64.b64decode(v + "=" * (-len(v) % 4))


@pytest.fixture
def leaf():
    return (FIXTURES / "leaf.der").read_bytes()


@pytest.fixture
def ca_pool():
    return [p.read_bytes() for p in sorted(FIXTURES.glob("fulcio_root_*.der"))]


@pytest.fixture
def tlog():
    return json.loads((FIXTURES / "tlog_entry.json").read_text(encoding="utf-8"))


class TestFulcioChainOnRealBytes:
    def test_a_real_fulcio_leaf_validates_from_an_unordered_pool(self, leaf, ca_pool):
        """verify_chain now does path discovery: the real CA pool is passed
        UNORDERED (as a TUF trusted_root.json presents it), and the verifier
        finds leaf -> intermediate(s) -> root itself -- no harness pre-sorting."""
        cert = x509.load_der_x509_certificate(leaf)
        at = cert.not_valid_before_utc
        identity = verify_chain(leaf, [], ca_pool, at_time=at)
        assert "@" in identity.identity          # a real OIDC subject
        assert identity.issuer.startswith("https://")


class TestRekorInclusionOnRealBytes:
    def test_a_real_inclusion_proof_reconstructs_the_checkpoint_root(self, tlog):
        proof = tlog["inclusionProof"]
        body = _b64(tlog["canonicalizedBody"])
        computed = verify_inclusion_root(
            int(proof["logIndex"]), int(proof["treeSize"]),
            leaf_hash(body), [_b64(h) for h in proof["hashes"]])
        assert computed == _b64(proof["rootHash"])

    def test_our_digest_parser_reads_a_real_rekor_body(self, tlog):
        body = _b64(tlog["canonicalizedBody"])
        digest = hashedrekord_digest(body)
        assert len(digest) == 32                 # a sha256 the real body committed to

    def test_our_verify_checkpoint_reads_a_real_signed_tree_head(self, tlog):
        """The production verify_checkpoint parses and verifies a REAL Rekor
        checkpoint, returning the tree size and root the log actually signed."""
        key_path = FIXTURES / "rekor_key.der"
        if not key_path.exists():
            pytest.skip("no rekor key in fixture")
        note = tlog["inclusionProof"]["checkpoint"]["envelope"]
        tree_size, root = verify_checkpoint(note, key_path.read_bytes())
        assert tree_size == int(tlog["inclusionProof"]["treeSize"])
        assert root == _b64(tlog["inclusionProof"]["rootHash"])


class TestComposedVerifyLogEntryOnRealBytes:
    """The composed API on production bytes: verify_log_entry authenticates the
    digest, the checkpoint root, the SET time, and the log identity end-to-end
    against a real Rekor entry -- no test double anywhere in the path."""

    def test_verify_log_entry_authenticates_a_real_entry_end_to_end(self, tlog):
        key_path = FIXTURES / "rekor_key.der"
        if not key_path.exists():
            pytest.skip("no rekor key in fixture")
        # The SHARED mapper turns the raw Rekor response into a LogEntry -- the
        # same helper qresp register uses -- so this proves the mapper on real
        # bytes and the composed verification in one shot.
        entry = log_entry_from_rekor(tlog)
        body = _b64(tlog["canonicalizedBody"])
        # expected_preimage is what a verifier already holds: the digest the
        # proven body commits to. On a real registration this equals
        # rekord_preimage(payloadType, payload); here the body is an artefact's.
        expected = hashedrekord_digest(body)
        after = datetime.fromtimestamp(
            int(tlog["integratedTime"]), tz=timezone.utc) + timedelta(days=1)
        t = verify_log_entry(entry, expected, key_path.read_bytes(), at_time=after)
        assert t == datetime.fromtimestamp(
            int(tlog["integratedTime"]), tz=timezone.utc)
        assert t.tzinfo is not None

    def test_the_mapper_carries_both_indices_from_a_sharded_response(self, tlog):
        """The global logIndex (SET) and the shard-local inclusionProof.logIndex
        (Merkle) are distinct on real Rekor; the mapper must keep them apart."""
        entry = log_entry_from_rekor(tlog)
        assert entry.log_index == int(tlog["logIndex"])
        assert entry.proof_index == int(tlog["inclusionProof"]["logIndex"])

    def test_a_wrong_preimage_is_rejected_on_real_bytes(self, tlog):
        key_path = FIXTURES / "rekor_key.der"
        if not key_path.exists():
            pytest.skip("no rekor key in fixture")
        entry = log_entry_from_rekor(tlog)
        after = datetime.fromtimestamp(
            int(tlog["integratedTime"]), tz=timezone.utc) + timedelta(days=1)
        with pytest.raises(Exception, match="different digest|another entry"):
            verify_log_entry(entry, b"\x11" * 32, key_path.read_bytes(), at_time=after)
