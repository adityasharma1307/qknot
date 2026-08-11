"""Adversarial tests for identity registration.

Matching the standard set in test_digest.py and test_payload_coverage.py: every
test names an attack and asserts it fails, rather than asserting the happy path
twice.

Certificates here are minted locally with `cryptography`. They are not Fulcio
certificates and are not pretending to be -- what is under test is the binding
between a certificate and a statement, which is independent of who issued the
certificate. Chain validation is deliberately not this module's job; see
`verify_registration`'s docstring.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from qknot.signing.algorithms import REGISTRY
from qknot.signing.registration import (
    REGISTRATION_PAYLOAD_TYPE,
    KeyRegistration,
    RegistrationError,
    SignedRegistration,
    assess_registration,
    sign_registration,
    verify_registration,
)
from qknot.signing.temporal import TimeEvidence

IDENTITY = "https://github.com/qknot/release-bot"
ISSUER = "https://token.actions.githubusercontent.com"
PQ_KEY = bytes(range(32)) * 4          # stand-in for an ML-DSA public key


def _certificate(private_key, identity: str = IDENTITY) -> bytes:
    """A self-signed cert carrying `identity` in the SAN, like Fulcio's."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qknot-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


@pytest.fixture
def key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def registration():
    return KeyRegistration(
        identity=IDENTITY, issuer=ISSUER, algorithm="ml-dsa-87",
        public_key=PQ_KEY, created="2026-07-30T12:00:00Z",
    )


@pytest.fixture
def signed(key, registration):
    return sign_registration(registration, key, _certificate(key))


class TestTheHappyPath:
    def test_a_registration_round_trips(self, signed, registration):
        assert verify_registration(signed) == registration

    def test_the_envelope_serialises(self, signed):
        assert SignedRegistration.from_dict(signed.to_dict()) == signed

    def test_the_signature_covers_the_dsse_pae_not_the_raw_payload(self, signed):
        """Type confusion is the attack the PAE prevents.

        Signing the bare payload would let the same bytes be reinterpreted as a
        different document type. The PAE binds the type in, so a registration
        cannot be replayed as an in-toto statement or vice versa.
        """
        assert REGISTRATION_PAYLOAD_TYPE.encode() in signed.signed_bytes
        assert signed.signed_bytes != signed.payload


class TestForgery:
    def test_a_tampered_payload_is_rejected(self, signed):
        """Swap the vouched-for key and the signature must fail.

        This is the attack the whole mechanism exists to stop: an adversary
        pointing a legitimate identity at a key they control.
        """
        data = json.loads(signed.payload)
        data["publicKey"] = base64.b64encode(b"attacker-key" * 8).decode()
        forged = SignedRegistration(
            payload=json.dumps(data, sort_keys=True, separators=(",", ":")).encode(),
            signature=signed.signature,
            certificate_der=signed.certificate_der,
        )
        with pytest.raises(RegistrationError, match="does not verify"):
            verify_registration(forged)

    def test_a_signature_from_another_key_is_rejected(self, registration, key):
        other = ec.generate_private_key(ec.SECP256R1())
        mismatched = SignedRegistration(
            payload=registration.to_payload(),
            signature=sign_registration(registration, other, _certificate(other)).signature,
            certificate_der=_certificate(key),
        )
        with pytest.raises(RegistrationError, match="does not verify"):
            verify_registration(mismatched)

    def test_the_certificate_identity_must_match_the_claim(self, key, registration):
        """A valid certificate for one identity must not vouch in another's name.

        Without this check, anyone able to obtain any Fulcio certificate could
        write someone else's identity into the payload and have it verify --
        the signature would be sound and the claim a lie.
        """
        signed = sign_registration(
            registration, key, _certificate(key, identity="https://example.com/mallory")
        )
        with pytest.raises(RegistrationError, match="but the statement claims"):
            verify_registration(signed)

    def test_an_unexpected_identity_is_refused_when_pinned(self, signed):
        with pytest.raises(RegistrationError, match="expected"):
            verify_registration(signed, expected_identity="https://example.com/someone")

    def test_an_unexpected_issuer_is_refused_when_pinned(self, signed):
        with pytest.raises(RegistrationError, match="expected"):
            verify_registration(signed, expected_issuer="https://evil.example")


class TestMalformedInput:
    def test_a_non_ecdsa_signing_key_is_refused(self, registration):
        """Ed25519 cannot be logged by Rekor v2; refuse it at signing time.

        Catching this here rather than at submission means the failure names
        the real reason instead of surfacing as an opaque rejection later.
        """
        key = ed25519.Ed25519PrivateKey.generate()
        with pytest.raises(RegistrationError, match="ECDSA P-256"):
            sign_registration(registration, key, b"")

    def test_a_classical_key_cannot_be_registered(self):
        """The mechanism binds identity to a LONG-TERM post-quantum key.

        Registering a classical one would produce the appearance of
        post-quantum identity with none of the substance.
        """
        with pytest.raises(RegistrationError, match="Shor"):
            KeyRegistration(identity=IDENTITY, issuer=ISSUER, algorithm="ed25519",
                            public_key=PQ_KEY, created="2026-07-30T12:00:00Z")

    def test_an_unknown_algorithm_is_refused(self):
        with pytest.raises(RegistrationError, match="unknown algorithm"):
            KeyRegistration(identity=IDENTITY, issuer=ISSUER, algorithm="ml-dsa-99",
                            public_key=PQ_KEY, created="2026-07-30T12:00:00Z")

    def test_an_empty_key_is_refused(self):
        with pytest.raises(RegistrationError, match="empty public key"):
            KeyRegistration(identity=IDENTITY, issuer=ISSUER, algorithm="ml-dsa-87",
                            public_key=b"", created="2026-07-30T12:00:00Z")

    def test_a_foreign_payload_type_is_refused(self, signed):
        data = signed.to_dict()
        data["payloadType"] = "application/vnd.in-toto+json"
        with pytest.raises(RegistrationError, match="unexpected payloadType"):
            SignedRegistration.from_dict(data)

    def test_a_document_of_another_shape_is_refused(self, key):
        payload = json.dumps({"_type": "something-else"}).encode()
        with pytest.raises(RegistrationError, match="unexpected payload type"):
            KeyRegistration.from_payload(payload)


class TestTheTemporalPolicyIsShared:
    """One abstraction, two applications -- asserted, not asserted-to-be."""

    def test_a_forged_post_deadline_registration_trips_the_same_warning(self):
        """The acceptance criterion, stated as a test.

        A registration signed after P-256's deprecation deadline must produce
        exactly the finding a post-deadline artefact signature would. If the two
        paths ever diverge, an attacker gains a window in the identity layer
        that does not exist in the artefact layer.
        """
        deadline = REGISTRY["ecdsa-p256"].disallowed_after_date
        assert deadline is not None
        after = deadline + timedelta(days=30)
        evidence = TimeEvidence.from_beacon(after.strftime("%Y-%m-%dT%H:%M:%SZ"))

        from qknot.signing.temporal import assess

        registration_verdict = assess_registration(evidence=evidence, now=after)
        artefact_verdict = assess(["ecdsa-p256"], evidence=evidence, now=after)

        assert registration_verdict.has_critical
        assert registration_verdict.messages() == artefact_verdict.messages(), (
            "the registration path and the artefact path must produce identical "
            "findings for identical evidence; divergence means the policy was "
            "reimplemented rather than reused"
        )

    def test_a_registration_before_the_deadline_is_accepted(self):
        deadline = REGISTRY["ecdsa-p256"].disallowed_after_date
        assert deadline is not None
        before = deadline - timedelta(days=365)
        verdict = assess_registration(
            evidence=TimeEvidence.from_beacon(before.strftime("%Y-%m-%dT%H:%M:%SZ")),
            now=before,
        )
        assert not verdict.has_critical

    def test_it_assesses_the_signing_algorithm_not_the_vouched_for_key(self):
        """Assessing ML-DSA here would report the reassuring answer, not the true one.

        The statement is signed with P-256. That it vouches for a post-quantum
        key does not make the act of vouching post-quantum secure, and a policy
        check that looked at the registered algorithm would say "fine" forever.
        """
        deadline = REGISTRY["ecdsa-p256"].disallowed_after_date
        assert deadline is not None
        after = deadline + timedelta(days=1)
        verdict = assess_registration(
            evidence=TimeEvidence.from_beacon(after.strftime("%Y-%m-%dT%H:%M:%SZ")),
            now=after,
        )
        assert verdict.has_critical, (
            "a registration signed after P-256's deadline must be flagged even "
            "though the key it registers is post-quantum"
        )
