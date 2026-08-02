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
from pathlib import Path

import pytest
from cryptography import x509

from qresp.signing.fulcio import verify_chain
from qresp.signing.rekor import (
    hashedrekord_digest,
    leaf_hash,
    verify_inclusion_root,
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


def _ordered_path(leaf_der, pool):
    """Build leaf -> intermediate(s) -> root from the unordered CA pool, the way
    a production verifier must. That verify_chain needs this done for it is a
    known limitation, recorded in docs/REGISTRATION-SPEC.md section 9."""
    pool_by_subject = {
        x509.load_der_x509_certificate(d).subject.rfc4514_string():
        (d, x509.load_der_x509_certificate(d)) for d in pool}
    node = x509.load_der_x509_certificate(leaf_der)
    intermediates, root = [], None
    for _ in range(8):
        parent = pool_by_subject.get(node.issuer.rfc4514_string())
        if parent is None:
            break
        der, cert = parent
        if cert.subject == cert.issuer:
            root = der
            break
        intermediates.append(der)
        node = cert
    return intermediates, root


class TestFulcioChainOnRealBytes:
    def test_a_real_fulcio_leaf_validates_and_yields_the_identity(self, leaf, ca_pool):
        intermediates, root = _ordered_path(leaf, ca_pool)
        assert root is not None, "no self-signed root in the captured CA pool"
        cert = x509.load_der_x509_certificate(leaf)
        at = cert.not_valid_before_utc
        identity = verify_chain(leaf, intermediates, [root], at_time=at)
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

    def test_the_real_checkpoint_signature_verifies(self, tlog):
        key_path = FIXTURES / "rekor_key.der"
        if not key_path.exists():
            pytest.skip("no rekor key in fixture")
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        note = tlog["inclusionProof"]["checkpoint"]["envelope"]
        text, _, sigblock = note.partition("\n\n")
        signed = (text + "\n").encode("utf-8")
        sigline = next(ln for ln in sigblock.splitlines()
                       if ln.startswith("— ") or ln.startswith("- "))
        signature = base64.b64decode(sigline.split(" ", 2)[2])[4:]
        key = load_der_public_key(key_path.read_bytes())
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed)
        else:
            pytest.skip(f"unhandled rekor key type {type(key).__name__}")
