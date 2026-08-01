"""Recovery-key revocation (spec Fix 3, section 5.1).

The asymmetry: a legitimate signer whose PQC key is compromised after their
classical anchor's algorithm is disallowed must still be able to revoke. A
pre-authorised recovery key on an independently-timed family lets them, with two
mandatory verifier checks -- the key was actually designated, and its own
algorithm is judged on its own date.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from qresp.signing.algorithms import REGISTRY
from qresp.signing.backends import get_backend
from qresp.signing.registration import (
    HybridRegistration,
    KeyRef,
    RegistrationError,
    Revocation,
    SignedRevocation,
    _key_fingerprint,
    verify_revocation,
)

# A recovery algorithm with NO disallow date, so it survives the classical
# break. ml-dsa-87 is the natural choice (the spec's corrected recommendation).
RECOVERY_ALG = "ml-dsa-87"
CLASSICAL_ALG = "ed25519"
CLASSICAL_D = REGISTRY[CLASSICAL_ALG].disallowed_after_date
AFTER_D = datetime(2040, 1, 1, tzinfo=timezone.utc)
BEFORE_D = datetime(2028, 1, 1, tzinfo=timezone.utc)
REG_LOGGED = datetime(2026, 8, 1, tzinfo=timezone.utc)   # before any deadline


def _setup(with_recovery=True):
    cl, pq, rk = (get_backend(CLASSICAL_ALG), get_backend("ml-dsa-87"),
                  get_backend(RECOVERY_ALG))
    clpk, clsk = cl.keygen()
    pqpk, pqsk = pq.keygen()
    rkpk, rksk = rk.keygen()
    reg = HybridRegistration(
        "alice@example.com", "https://issuer", KeyRef(CLASSICAL_ALG, clpk),
        KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z",
        recovery_key=KeyRef(RECOVERY_ALG, rkpk) if with_recovery else None)
    return reg, (clpk, clsk), (pqpk, pqsk), (rkpk, rksk)


def _revocation(reg, signer_alg, signer_sk, revoked_at="2040-06-01T00:00:00Z"):
    rev = Revocation("alice@example.com",
                     _key_fingerprint(reg.pqc_key.public_key),
                     "pqc key compromised", revoked_at)
    signed = SignedRevocation(payload=rev.to_payload(), signature=b"")
    sig = get_backend(signer_alg).sign(signer_sk, signed.signed_bytes)
    return SignedRevocation(payload=rev.to_payload(), signature=sig)


class TestClassicalRevocation:
    def test_classical_revocation_before_the_deadline_is_honoured(self):
        reg, (clpk, clsk), _, _ = _setup()
        signed = _revocation(reg, CLASSICAL_ALG, clsk, "2028-06-01T00:00:00Z")
        rev = verify_revocation(signed, reg, registration_log_time=REG_LOGGED,
                                now=BEFORE_D)
        assert rev.reason == "pqc key compromised"

    def test_classical_revocation_after_deadline_needs_rescue(self):
        """Reg logged before D, so binding_trust rescues the classical signer."""
        reg, (clpk, clsk), _, _ = _setup()
        signed = _revocation(reg, CLASSICAL_ALG, clsk)
        rev = verify_revocation(signed, reg, registration_log_time=REG_LOGGED,
                                now=AFTER_D)
        assert rev is not None


class TestRecoveryRevocation:
    def test_recovery_revocation_after_primary_deadline_is_honoured(self):
        """The core case: primary anchor disallowed, recovery key still live."""
        reg, _, _, (rkpk, rksk) = _setup()
        signed = _revocation(reg, RECOVERY_ALG, rksk)
        rev = verify_revocation(signed, reg, registration_log_time=REG_LOGGED,
                                now=AFTER_D)
        assert rev.identity == "alice@example.com"

    def test_recovery_revocation_with_no_designated_key_is_rejected(self):
        """A recovery signature is worthless if no recovery key was registered."""
        reg, _, _, (rkpk, rksk) = _setup(with_recovery=False)
        signed = _revocation(reg, RECOVERY_ALG, rksk)
        with pytest.raises(RegistrationError, match="no recoveryKey was ever"):
            verify_revocation(signed, reg, registration_log_time=REG_LOGGED,
                              now=AFTER_D)

    def test_a_different_recovery_key_is_rejected(self):
        """Must match the DESIGNATED key, not any signature that verifies."""
        reg, _, _, _ = _setup()
        other = get_backend(RECOVERY_ALG)
        _, other_sk = other.keygen()
        signed = _revocation(reg, RECOVERY_ALG, other_sk)
        with pytest.raises(RegistrationError, match="neither the classicalKey"):
            verify_revocation(signed, reg, registration_log_time=REG_LOGGED,
                              now=AFTER_D)

    def test_recovery_key_on_a_broken_family_is_rejected(self):
        """If the recovery algorithm is ALSO past its own date with no rescue,
        it provides no recovery -- judged on ITS OWN date, not the primary's."""
        # recovery key on ed25519 (disallowed 2031), registration logged AFTER
        # that date so there is no rescuing timestamp for the recovery key.
        cl, pq, rk = (get_backend(CLASSICAL_ALG), get_backend("ml-dsa-87"),
                      get_backend("ed25519"))
        clpk, clsk = cl.keygen()
        pqpk, pqsk = pq.keygen()
        rkpk, rksk = rk.keygen()
        reg = HybridRegistration(
            "alice@example.com", "https://issuer", KeyRef(CLASSICAL_ALG, clpk),
            KeyRef("ml-dsa-87", pqpk), "2026-08-01T00:00:00Z",
            recovery_key=KeyRef("ed25519", rkpk))
        signed = _revocation(reg, "ed25519", rksk)
        logged_after_break = datetime(2036, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(RegistrationError, match="already-broken family"):
            verify_revocation(signed, reg,
                              registration_log_time=logged_after_break, now=AFTER_D)


class TestTargeting:
    def test_a_revocation_for_a_different_identity_is_rejected(self):
        reg, _, _, (rkpk, rksk) = _setup()
        rev = Revocation("mallory@evil.com",
                         _key_fingerprint(reg.pqc_key.public_key), "x",
                         "2040-01-01T00:00:00Z")
        signed = SignedRevocation(rev.to_payload(),
            get_backend(RECOVERY_ALG).sign(rksk, SignedRevocation(rev.to_payload(), b"").signed_bytes))
        with pytest.raises(RegistrationError, match="names"):
            verify_revocation(signed, reg, registration_log_time=REG_LOGGED, now=AFTER_D)

    def test_a_revocation_for_a_different_key_is_rejected(self):
        reg, _, _, (rkpk, rksk) = _setup()
        rev = Revocation("alice@example.com", "0" * 32, "x", "2040-01-01T00:00:00Z")
        signed = SignedRevocation(rev.to_payload(),
            get_backend(RECOVERY_ALG).sign(rksk, SignedRevocation(rev.to_payload(), b"").signed_bytes))
        with pytest.raises(RegistrationError, match="different key"):
            verify_revocation(signed, reg, registration_log_time=REG_LOGGED, now=AFTER_D)
