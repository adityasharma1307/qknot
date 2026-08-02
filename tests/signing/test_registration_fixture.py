"""Residual-3 lock: a REAL registration bundle through the full section-4 chain.

The offline `test_register.py` proves the orchestration against fakes. This proves
the emitted bundle format against PRODUCTION bytes: a real Fulcio cert over a real
P-256 key, a real Rekor entry (checkpoint + SET), the whole thing run through
`verify_registration_chain` with no special cases -- the same call a third party
makes.

Capture it once on a machine with network + browser OIDC:

    python scripts/register/capture_registration.py --save tests/signing/fixtures/registration

which writes `bundle.json` (and reuses the Fulcio roots + Rekor key already in
tests/signing/fixtures/). This test skips cleanly until that file exists, so CI
without it still passes and a reviewer can run it after one capture.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from qresp.signing.registration import RegistrationError
from qresp.signing.registration_chain import (
    RegistrationBundle,
    verify_registration_chain,
)
from qresp.signing.temporal import BindingBasis

FIXTURES = Path(__file__).parent / "fixtures"
REGISTRATION = FIXTURES / "registration" / "bundle.json"

pytestmark = pytest.mark.skipif(
    not REGISTRATION.exists(),
    reason="no captured registration bundle (run "
           "scripts/register/capture_registration.py --save "
           "tests/signing/fixtures/registration)")


def _load_der_pool(*globs: str) -> list[bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    out: list[bytes] = []
    for pattern in globs:
        for path in sorted(FIXTURES.glob(pattern)):
            raw = path.read_bytes()
            try:
                out.extend(c.public_bytes(Encoding.DER)
                           for c in x509.load_pem_x509_certificates(raw))
            except (ValueError, TypeError):
                out.append(raw)
    return out


@pytest.fixture
def bundle() -> RegistrationBundle:
    return RegistrationBundle.from_dict(
        json.loads(REGISTRATION.read_text(encoding="utf-8")))


@pytest.fixture
def fulcio_roots() -> list[bytes]:
    # the same public Sigstore CA pool captured for the artefact fixture
    return _load_der_pool("fulcio_root_*.der", "registration/fulcio_root_*.der")


@pytest.fixture
def log_key() -> bytes:
    for candidate in (FIXTURES / "registration" / "rekor_key.der",
                      FIXTURES / "rekor_key.der"):
        if candidate.exists():
            return candidate.read_bytes()
    pytest.skip("no rekor key alongside the registration fixture")


class TestARealRegistrationVerifies:
    def test_full_section_4_yields_a_trusted_binding(self, bundle, fulcio_roots, log_key):
        binding = verify_registration_chain(
            bundle, fulcio_roots=fulcio_roots, log_public_key=log_key)
        assert "@" in binding.identity          # a real OIDC subject
        assert binding.issuer.startswith("https://")
        assert binding.pqc_algorithm.startswith("ml-dsa")
        assert binding.basis in (BindingBasis.DIRECT, BindingBasis.RESCUED)
        assert binding.valid_as_of.tzinfo is not None

    def test_a_tampered_pqc_key_claim_is_rejected(self, bundle, fulcio_roots, log_key):
        """Flip one byte of the registered PQC key in the payload: proof of
        possession (the PQC signature over the PAE) no longer holds."""
        import base64
        import dataclasses

        env = bundle.envelope
        broken_payload = bytearray(env.payload)
        # corrupt a byte well inside the JSON so it stays parseable-ish; the
        # signature check is what must fail, not JSON parsing.
        broken_payload[len(broken_payload) // 2] ^= 0x01
        tampered = RegistrationBundle(
            envelope=dataclasses.replace(env, payload=bytes(broken_payload)),
            intermediate_certificates=bundle.intermediate_certificates,
            log_entry=bundle.log_entry)
        _ = base64  # keep import meaningful if refactored
        with pytest.raises(RegistrationError):
            verify_registration_chain(
                tampered, fulcio_roots=fulcio_roots, log_public_key=log_key)


class TestARealRegistrationRescues:
    def test_it_is_rescued_after_the_classical_algorithm_is_disallowed(
            self, bundle, fulcio_roots, log_key):
        """The point of the whole design, on real bytes: verified years from now,
        past the classical algorithm's disallow date, the binding still holds
        because the log timestamp proves it predates the break. Skips if the real
        registration happens to be logged after the disallow date."""
        binding = verify_registration_chain(
            bundle, fulcio_roots=fulcio_roots, log_public_key=log_key)
        disallow = datetime(2031, 12, 31, tzinfo=timezone.utc)   # p256/ed25519, M-26-15
        if binding.valid_as_of >= disallow:
            pytest.skip("registration logged after the classical disallow date")
        future = disallow + timedelta(days=365)
        rescued = verify_registration_chain(
            bundle, fulcio_roots=fulcio_roots, log_public_key=log_key, now=future)
        assert rescued.basis is BindingBasis.RESCUED
