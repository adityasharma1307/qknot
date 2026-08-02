"""Dual-key registration: statement, dual signing, proof of possession, notAfter.

The classical anchor is ecdsa-p256 (Fulcio's default) with a REAL leaf
certificate over the classical key. Proof of possession binds the classical
signature to the certificate's key and requires the payload's classicalKey to
be byte-equal to the leaf's SPKI, so a fake certificate or a renamed key no
longer passes -- the hole an expert review found.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from qresp.signing.backends import get_backend
from qresp.signing.dsse import pae
from qresp.signing.registration import (
    HybridRegistration,
    HybridSignedRegistration,
    KeyRef,
    NotYetRegistered,
    RegistrationError,
    check_not_after,
    verify_proof_of_possession,
)

TYPE = "application/vnd.qresp.hybrid-key-registration+json"


def _ec_leaf():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    spki = key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return key, spki, cert.public_bytes(Encoding.DER)


def _pqc():
    backend = get_backend("ml-dsa-87")
    pub, sk = backend.keygen()
    return backend, pub, sk


def _envelope(classical_key, classical_spki, cert_der, pqc, pqc_pub, pqc_sk,
              identity="alice@example.com", not_after=None, recovery=None):
    reg = HybridRegistration(
        identity, "https://issuer", KeyRef("ecdsa-p256", classical_spki),
        KeyRef("ml-dsa-87", pqc_pub), "2026-08-01T00:00:00Z",
        not_after=not_after, recovery_key=recovery)
    signed = pae(TYPE, reg.to_payload())
    return HybridSignedRegistration(
        payload=reg.to_payload(),
        classical_signature=classical_key.sign(signed, ec.ECDSA(hashes.SHA256())),
        classical_certificate_der=cert_der,
        pqc_signature=pqc.sign(pqc_sk, signed)), reg


class TestTheStatement:
    def test_canonical_payload_round_trips(self):
        _, spki, _ = _ec_leaf()
        _, pqpk, _ = _pqc()
        reg = HybridRegistration("a@b.com", "https://i", KeyRef("ecdsa-p256", spki),
                                 KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z")
        assert HybridRegistration.from_payload(reg.to_payload()).to_payload() \
            == reg.to_payload()

    def test_a_classical_pqc_key_is_refused(self):
        with pytest.raises(RegistrationError, match="does not resist Shor"):
            HybridRegistration("a", "i", KeyRef("ecdsa-p256", b"x"),
                               KeyRef("ecdsa-p256", b"y"), "2026-08-01T00:00:00Z")

    def test_a_pqc_classical_anchor_is_refused(self):
        _, pqpk, _ = _pqc()
        with pytest.raises(RegistrationError, match="roles are confused"):
            HybridRegistration("a", "i", KeyRef("ml-dsa-87", pqpk),
                               KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z")


class TestProofOfPossession:
    def test_a_correctly_dual_signed_envelope_verifies(self):
        key, spki, cert = _ec_leaf()
        pqc, pqpk, pqsk = _pqc()
        env, _ = _envelope(key, spki, cert, pqc, pqpk, pqsk)
        assert verify_proof_of_possession(env).identity == "alice@example.com"

    def test_a_classical_key_the_cert_does_not_attest_is_rejected(self):
        """Bug 1: a real cert for key B, payload names a different key A signed
        with A. Possession would 'pass' on A while Fulcio only ever attested B."""
        cert_key, cert_spki, cert = _ec_leaf()
        other_key, other_spki, _ = _ec_leaf()
        pqc, pqpk, pqsk = _pqc()
        reg = HybridRegistration(
            "alice@example.com", "https://issuer",
            KeyRef("ecdsa-p256", other_spki),
            KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z")
        signed = pae(TYPE, reg.to_payload())
        env = HybridSignedRegistration(
            payload=reg.to_payload(),
            classical_signature=other_key.sign(signed, ec.ECDSA(hashes.SHA256())),
            classical_certificate_der=cert,
            pqc_signature=pqc.sign(pqsk, signed))
        with pytest.raises(RegistrationError, match="not the key the certificate"):
            verify_proof_of_possession(env)

    def test_a_fake_certificate_is_rejected(self):
        key, spki, _ = _ec_leaf()
        pqc, pqpk, pqsk = _pqc()
        env, _ = _envelope(key, spki, b"not-a-certificate", pqc, pqpk, pqsk)
        with pytest.raises(RegistrationError, match="does not parse"):
            verify_proof_of_possession(env)

    def test_a_missing_pqc_signature_fails_possession(self):
        key, spki, cert = _ec_leaf()
        pqc, pqpk, pqsk = _pqc()
        _, _, other_pqsk = _pqc()
        env, _ = _envelope(key, spki, cert, pqc, pqpk, pqsk)
        forged = HybridSignedRegistration(
            payload=env.payload, classical_signature=env.classical_signature,
            classical_certificate_der=env.classical_certificate_der,
            pqc_signature=pqc.sign(other_pqsk, env.signed_bytes))
        with pytest.raises(RegistrationError, match="possession side"):
            verify_proof_of_possession(forged)

    def test_a_tampered_payload_breaks_the_classical_signature(self):
        key, spki, cert = _ec_leaf()
        pqc, pqpk, pqsk = _pqc()
        env, _ = _envelope(key, spki, cert, pqc, pqpk, pqsk)
        tampered = HybridSignedRegistration(
            payload=env.payload.replace(b"alice", b"mallory"),
            classical_signature=env.classical_signature,
            classical_certificate_der=env.classical_certificate_der,
            pqc_signature=env.pqc_signature)
        with pytest.raises(RegistrationError):
            verify_proof_of_possession(tampered)

    def test_a_spliced_recovery_key_breaks_the_signature(self):
        key, spki, cert = _ec_leaf()
        pqc, pqpk, pqsk = _pqc()
        _, rk, _ = _pqc()
        env, _ = _envelope(key, spki, cert, pqc, pqpk, pqsk)
        with_recovery = HybridRegistration(
            "alice@example.com", "https://issuer", KeyRef("ecdsa-p256", spki),
            KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z",
            recovery_key=KeyRef("ml-dsa-87", rk))
        spliced = HybridSignedRegistration(
            payload=with_recovery.to_payload(),
            classical_signature=env.classical_signature,
            classical_certificate_der=cert, pqc_signature=env.pqc_signature)
        with pytest.raises(RegistrationError):
            verify_proof_of_possession(spliced)


class TestNotAfter:
    def _reg(self, not_after):
        _, spki, _ = _ec_leaf()
        _, pqpk, _ = _pqc()
        return HybridRegistration(
            "a@b.com", "https://i", KeyRef("ecdsa-p256", spki),
            KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z", not_after=not_after)

    def test_an_artefact_signed_after_notafter_is_rejected(self):
        with pytest.raises(NotYetRegistered):
            check_not_after(self._reg("2027-01-01T00:00:00Z"),
                            datetime.datetime(2028, 6, 1, tzinfo=datetime.timezone.utc))

    def test_it_uses_signing_time_not_the_verifier_clock(self):
        check_not_after(self._reg("2027-01-01T00:00:00Z"),
                        datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc))

    def test_no_notafter_means_no_limit(self):
        check_not_after(self._reg(None),
                        datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))

    def test_it_is_ruled_inapplicable_not_corrupt(self):
        assert issubclass(NotYetRegistered, RegistrationError)
        try:
            check_not_after(self._reg("2020-01-01T00:00:00Z"),
                            datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        except NotYetRegistered as exc:
            assert "inspectable" in str(exc)
