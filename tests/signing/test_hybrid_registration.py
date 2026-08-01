"""Dual-key registration: the statement, dual signing, proof of possession,
and notAfter (spec Fixes for the dual-key build).

Uses real backends -- Ed25519 for the classical anchor, ML-DSA for the PQC key.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from qresp.signing.backends import get_backend
from qresp.signing.registration import (
    HybridRegistration,
    HybridSignedRegistration,
    KeyRef,
    NotYetRegistered,
    RegistrationError,
    check_not_after,
    sign_hybrid_registration,
    verify_proof_of_possession,
)


def _keys():
    cl = get_backend("ed25519")
    pq = get_backend("ml-dsa-87")
    clpk, clsk = cl.keygen()
    pqpk, pqsk = pq.keygen()
    return (clpk, clsk), (pqpk, pqsk)


def _registration(not_after=None, recovery=None):
    (clpk, _), (pqpk, _) = _keys()
    return HybridRegistration(
        identity="alice@example.com", issuer="https://accounts.google.com",
        classical_key=KeyRef("ed25519", clpk), pqc_key=KeyRef("ml-dsa-87", pqpk),
        created="2026-08-01T00:00:00Z", not_after=not_after, recovery_key=recovery)


class TestTheStatement:
    def test_canonical_payload_round_trips(self):
        reg = _registration()
        assert HybridRegistration.from_payload(reg.to_payload()).to_payload() \
            == reg.to_payload()

    def test_a_classical_pqc_key_is_refused(self):
        (clpk, _), (pqpk, _) = _keys()
        with pytest.raises(RegistrationError, match="does not resist Shor"):
            HybridRegistration("a", "i", KeyRef("ed25519", clpk),
                               KeyRef("ed25519", clpk), "2026-08-01T00:00:00Z")

    def test_a_pqc_classical_anchor_is_refused(self):
        """The classical anchor must be the deprecating one, not the PQC key."""
        (clpk, _), (pqpk, _) = _keys()
        with pytest.raises(RegistrationError, match="roles are confused"):
            HybridRegistration("a", "i", KeyRef("ml-dsa-87", pqpk),
                               KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z")

    def test_a_garbled_timestamp_is_refused(self):
        (clpk, _), (pqpk, _) = _keys()
        with pytest.raises(RegistrationError, match="RFC 3339"):
            HybridRegistration("a", "i", KeyRef("ed25519", clpk),
                               KeyRef("ml-dsa-87", pqpk), "not-a-date")


class TestProofOfPossession:
    def test_a_correctly_dual_signed_envelope_verifies(self):
        (clpk, clsk), (pqpk, pqsk) = _keys()
        reg = HybridRegistration("alice@example.com", "https://issuer",
                                 KeyRef("ed25519", clpk), KeyRef("ml-dsa-87", pqpk),
                                 "2026-08-01T00:00:00Z")
        env = sign_hybrid_registration(reg, clsk, pqsk, b"fake-cert")
        got = verify_proof_of_possession(env)
        assert got.identity == "alice@example.com"

    def test_a_missing_pqc_signature_fails_possession(self):
        """An attacker who knows the PQC public key but not the private one."""
        (clpk, clsk), (pqpk, pqsk) = _keys()
        (_, _), (other_pqpk, other_pqsk) = _keys()
        reg = HybridRegistration("a", "i", KeyRef("ed25519", clpk),
                                 KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z")
        env = sign_hybrid_registration(reg, clsk, pqsk, b"cert")
        # replace the PQC signature with one made by a DIFFERENT key
        forged = HybridSignedRegistration(
            payload=env.payload, classical_signature=env.classical_signature,
            classical_certificate_der=env.classical_certificate_der,
            pqc_signature=get_backend("ml-dsa-87").sign(other_pqsk, env.signed_bytes))
        with pytest.raises(RegistrationError, match="possession side"):
            verify_proof_of_possession(forged)

    def test_a_tampered_payload_breaks_the_classical_signature(self):
        (clpk, clsk), (pqpk, pqsk) = _keys()
        reg = HybridRegistration("alice@example.com", "https://issuer",
                                 KeyRef("ed25519", clpk), KeyRef("ml-dsa-87", pqpk),
                                 "2026-08-01T00:00:00Z")
        env = sign_hybrid_registration(reg, clsk, pqsk, b"cert")
        tampered = HybridSignedRegistration(
            payload=env.payload.replace(b"alice", b"mallory"),
            classical_signature=env.classical_signature,
            classical_certificate_der=env.classical_certificate_der,
            pqc_signature=env.pqc_signature)
        with pytest.raises(RegistrationError, match="identity side|not JSON|missing"):
            verify_proof_of_possession(tampered)

    def test_a_spliced_recovery_key_breaks_the_signature(self):
        """Fix 3 adversarial: adding recoveryKey after signing must fail,
        because it is inside the PAE-covered payload. Confirmed, not assumed."""
        (clpk, clsk), (pqpk, pqsk) = _keys()
        (rk, _), _ = _keys()
        reg = HybridRegistration("alice@example.com", "https://issuer",
                                 KeyRef("ed25519", clpk), KeyRef("ml-dsa-87", pqpk),
                                 "2026-08-01T00:00:00Z")
        env = sign_hybrid_registration(reg, clsk, pqsk, b"cert")
        with_recovery = HybridRegistration(
            "alice@example.com", "https://issuer", KeyRef("ed25519", clpk),
            KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z",
            recovery_key=KeyRef("ml-dsa-87", rk))
        spliced = HybridSignedRegistration(
            payload=with_recovery.to_payload(),          # different bytes now
            classical_signature=env.classical_signature,  # old signature
            classical_certificate_der=env.classical_certificate_der,
            pqc_signature=env.pqc_signature)
        with pytest.raises(RegistrationError):
            verify_proof_of_possession(spliced)


class TestNotAfter:
    def test_an_artefact_signed_after_notafter_is_rejected(self):
        reg = _registration(not_after="2027-01-01T00:00:00Z")
        with pytest.raises(NotYetRegistered):
            check_not_after(reg, datetime(2028, 6, 1, tzinfo=timezone.utc))

    def test_an_artefact_signed_before_notafter_is_accepted(self):
        reg = _registration(not_after="2027-01-01T00:00:00Z")
        check_not_after(reg, datetime(2026, 6, 1, tzinfo=timezone.utc))

    def test_it_uses_signing_time_not_the_verifier_clock(self):
        """S <= notAfter < now must ACCEPT: the verifier's `now` is irrelevant.
        The registration lapsed, but the artefact was signed while it held."""
        reg = _registration(not_after="2027-01-01T00:00:00Z")
        signing_time = datetime(2026, 6, 1, tzinfo=timezone.utc)   # before lapse
        check_not_after(reg, signing_time)          # accepts, regardless of now

    def test_no_notafter_means_no_limit(self):
        check_not_after(_registration(not_after=None),
                        datetime(2099, 1, 1, tzinfo=timezone.utc))

    def test_it_is_ruled_inapplicable_not_corrupt(self):
        """NotYetRegistered is a RegistrationError subtype but distinct, so a
        caller tells 'does not apply' from 'malformed'."""
        assert issubclass(NotYetRegistered, RegistrationError)
        reg = _registration(not_after="2020-01-01T00:00:00Z")
        try:
            check_not_after(reg, datetime(2026, 1, 1, tzinfo=timezone.utc))
        except NotYetRegistered as exc:
            assert "inspectable" in str(exc)
