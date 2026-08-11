"""The composed verdict: a valid artefact, signed by a key an identity vouched for.

The join these tests exist to defend is the one that is easy to fake by holding
two true statements at once: "the signature is valid" and "alice registered a
key" do NOT add up to "alice signed this" unless the key is the SAME key. The
adversarial cases below are mostly about that.
"""
from __future__ import annotations

import datetime

import pytest

pytest.importorskip("cryptography", reason="needs `cryptography`")
pytest.importorskip("dilithium_py", reason="needs `dilithium-py`")

from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402

from qknot.signing.composed import (  # noqa: E402
    SigningTimeSource,
    verify_artefact_against_registration,
)
from qknot.signing.registration import RegistrationError  # noqa: E402
from qknot.signing.sign import keygen, sign  # noqa: E402
from qknot.signing.temporal import BindingBasis  # noqa: E402

from .test_registration_chain import Harness  # noqa: E402

SUITE = ["ed25519", "ml-dsa-87"]
ARTEFACT = b"the model weights"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _root(harness):
    """The harness's CA root, as the verifier's trust store."""
    return harness.root.public_bytes(Encoding.DER)


def _signed_artefact(pqc_public=None, pqc_secret=None):
    """A real signed artefact. If a PQC key pair is given, the artefact is
    signed with THAT key -- so a registration can name it (or fail to)."""
    keys = keygen(suite=SUITE)
    if pqc_public is not None:
        from qknot.signing.sign import KeyPair, key_fingerprint

        keys.keys["ml-dsa-87"] = KeyPair(
            algorithm="ml-dsa-87", public_key=pqc_public, secret_key=pqc_secret,
            fingerprint=key_fingerprint(pqc_public))
    return sign(ARTEFACT, keys), keys


def _registration_for(harness):
    bundle, _ = harness.bundle()
    return bundle


class TestTheHappyPath:
    def test_a_valid_artefact_signed_by_a_registered_key_is_attributed(self):
        """The product sentence: this artefact is valid AND alice vouched for
        the key that signed it, on a named basis, as of the log's time."""
        h = Harness()
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        verdict = verify_artefact_against_registration(
            ARTEFACT, artefact, _registration_for(h),
            fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now())
        assert verdict.identity == "alice@example.com"
        assert verdict.basis is BindingBasis.DIRECT
        assert verdict.pqc_algorithm == "ml-dsa-87"
        assert verdict.registration_logged_at is not None
        # no notAfter, no revocations -> the coverage checks are vacuous, and
        # the verdict says so rather than claiming they passed.
        assert verdict.coverage_checked is False
        assert verdict.signing_time_source is SigningTimeSource.UNESTABLISHED

    def test_the_rescued_basis_is_reported_after_the_deadline(self):
        logged = datetime.datetime(2028, 1, 1, tzinfo=datetime.timezone.utc)
        h = Harness(log_time=logged)
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        future = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
        verdict = verify_artefact_against_registration(
            ARTEFACT, artefact, _registration_for(h),
            fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=future)
        assert verdict.basis is BindingBasis.RESCUED


class TestTheJoin:
    """Without this, the command would report two unrelated true facts."""

    def test_an_artefact_signed_by_an_unregistered_key_is_refused(self):
        """Both halves verify individually: the artefact's signature is valid,
        and alice's registration is valid. They are about DIFFERENT keys, so
        the artefact is not attributable to alice."""
        h = Harness()
        artefact, _ = _signed_artefact()          # a fresh, unregistered PQC key
        with pytest.raises(RegistrationError, match="does not authorise"):
            verify_artefact_against_registration(
                ARTEFACT, artefact, _registration_for(h),
                fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now())

    def test_an_artefact_without_the_registered_algorithm_is_refused(self):
        """The registration vouches for ml-dsa-87; an artefact signed only with
        ml-dsa-44 cannot be what it is talking about."""
        h = Harness()
        artefact = sign(ARTEFACT, keygen(suite=["ed25519", "ml-dsa-44"]))
        with pytest.raises(RegistrationError, match="carries no ml-dsa-87"):
            verify_artefact_against_registration(
                ARTEFACT, artefact, _registration_for(h),
                fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now())

    def test_a_tampered_artefact_fails_before_any_attribution(self):
        """The artefact's own signature is checked first: there is no point
        asking who vouched for a key if the signature does not hold."""
        from qknot.signing.sign import VerificationFailed

        h = Harness()
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        with pytest.raises(VerificationFailed):
            verify_artefact_against_registration(
                b"different bytes entirely", artefact, _registration_for(h),
                fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now())


class TestSigningTimeDiscipline:
    """An unanswerable coverage question is not a pass."""

    def test_notafter_cannot_be_ruled_on_without_a_signing_time(self):
        h = Harness()
        bundle, _ = h.bundle(not_after="2027-01-01T00:00:00Z")
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        with pytest.raises(RegistrationError, match="cannot be decided"):
            verify_artefact_against_registration(
                ARTEFACT, artefact, bundle,
                fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now())

    def test_a_supplied_signing_time_inside_notafter_is_covered(self):
        h = Harness()
        bundle, _ = h.bundle(not_after="2027-01-01T00:00:00Z")
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        verdict = verify_artefact_against_registration(
            ARTEFACT, artefact, bundle,
            fulcio_roots=[_root(h)], log_public_key=h.log_pub,
            artefact_signed_at=datetime.datetime(
                2026, 6, 1, tzinfo=datetime.timezone.utc),
            now=_now())
        assert verdict.coverage_checked is True
        assert verdict.signing_time_source is SigningTimeSource.SUPPLIED

    def test_a_supplied_signing_time_after_notafter_is_refused(self):
        from qknot.signing.registration import NotYetRegistered

        h = Harness()
        bundle, _ = h.bundle(not_after="2027-01-01T00:00:00Z")
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        with pytest.raises(NotYetRegistered):
            verify_artefact_against_registration(
                ARTEFACT, artefact, bundle,
                fulcio_roots=[_root(h)], log_public_key=h.log_pub,
                artefact_signed_at=datetime.datetime(
                    2028, 6, 1, tzinfo=datetime.timezone.utc),
                now=_now())


class TestRevocationIsNeverAssumedAway:
    """A verdict must distinguish "the log says this key is live" from
    "nobody looked". The second must not read as the first."""

    def _search(self, outcome, revocations=()):
        from qknot.signing.revocation_search import RevocationSearch

        return RevocationSearch(outcome, revocations=list(revocations),
                                detail="test")

    def test_by_default_the_revocation_status_is_not_conclusive(self):
        h = Harness()
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        verdict = verify_artefact_against_registration(
            ARTEFACT, artefact, _registration_for(h),
            fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now())
        assert verdict.revocation_status_is_conclusive is False

    def test_a_completed_search_finding_nothing_is_conclusive(self):
        from qknot.signing.revocation_search import RevocationSearchOutcome

        h = Harness()
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        verdict = verify_artefact_against_registration(
            ARTEFACT, artefact, _registration_for(h),
            fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now(),
            revocation_search=self._search(RevocationSearchOutcome.NONE_FOUND))
        assert verdict.revocation_status_is_conclusive is True

    def test_a_failed_search_is_carried_into_the_verdict_not_dropped(self):
        from qknot.signing.revocation_search import RevocationSearchOutcome

        h = Harness()
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        verdict = verify_artefact_against_registration(
            ARTEFACT, artefact, _registration_for(h),
            fulcio_roots=[_root(h)], log_public_key=h.log_pub, now=_now(),
            revocation_search=self._search(RevocationSearchOutcome.FAILED))
        assert verdict.revocation_search.outcome is RevocationSearchOutcome.FAILED
        assert verdict.revocation_status_is_conclusive is False

    def test_a_found_revocation_kills_a_later_artefact(self):
        """The point of searching: a revocation dated before the artefact was
        signed means the signature is not trusted."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        from qknot.signing.dsse import pae
        from qknot.signing.registration import (
            REVOCATION_PAYLOAD_TYPE,
            Revocation,
            SignedRevocation,
            _key_fingerprint,
        )
        from qknot.signing.revocation_search import RevocationSearchOutcome

        h = Harness()
        artefact, _ = _signed_artefact(h.pqc_pub, h.pqc_sk)
        revocation = Revocation(
            identity="alice@example.com",
            pqc_key_fingerprint=_key_fingerprint(h.pqc_pub),
            reason="key compromised", revoked_at="2026-01-01T00:00:00Z")
        payload = revocation.to_payload()
        # signed by the registration's classical anchor -- the ordinary path
        signature = h.classical_priv.sign(
            pae(REVOCATION_PAYLOAD_TYPE, payload),
            ec.ECDSA(hashes.SHA256()))
        search = self._search(
            RevocationSearchOutcome.FOUND,
            [(SignedRevocation(payload=payload, signature=signature),
              h.log_time)])
        with pytest.raises(RegistrationError, match="revoked"):
            verify_artefact_against_registration(
                ARTEFACT, artefact, _registration_for(h),
                fulcio_roots=[_root(h)], log_public_key=h.log_pub,
                revocation_search=search,
                artefact_signed_at=datetime.datetime(
                    2026, 6, 1, tzinfo=datetime.timezone.utc),
                now=_now())
