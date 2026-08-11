"""Tests for the temporal trust boundary.

The interesting property is not "does it warn about old algorithms" but the
distinction between the two questions in temporal.py: whether the *signer* was
negligent, and whether the *signature* is still evidence. Those have different
answers and different remedies, and conflating them is the common mistake.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from qknot.signing.algorithms import REGISTRY
from qknot.signing.temporal import (
    ALGORITHM_POLICIES,
    Bound,
    TimeEvidence,
    TrustStatus,
    assess,
    evidence_from_attestation,
)

BEFORE = datetime(2026, 7, 26, tzinfo=timezone.utc)

# Derived, not hardcoded. These tests check the *semantics* of the deadline
# comparison, not the value of the deadline -- so when policy moves (2030 ->
# 2031 when the regime was fixed to OMB M-26-15) they should keep testing the
# same thing rather than needing a sweep of literals. test_algorithms.py pins
# the value; this file pins the behaviour around it.
DEADLINE = REGISTRY["ed25519"].disallowed_after_date
assert DEADLINE is not None, "ed25519 must carry a deadline for these tests"
AFTER = DEADLINE + timedelta(days=180)              # comfortably past it
HYBRID = ["ed25519", "ml-dsa-44"]


class TestTheDeadlineIsInclusive:
    """"Unacceptable after <date>" means the whole of that day is fine.

    Parsing the date to midnight made a signature at noon on the deadline read
    as past it -- a whole day of false positives at exactly the moment the
    check starts mattering.
    """

    def test_noon_on_the_deadline_is_still_inside_it(self):
        noon = DEADLINE.replace(hour=12, minute=0, second=0, microsecond=0)
        assert not assess(["ed25519"], now=noon).has_critical

    def test_the_last_second_of_the_deadline_day_is_inside_it(self):
        last = DEADLINE.replace(microsecond=0)
        assert not assess(["ed25519"], now=last).has_critical

    def test_the_last_instant_of_the_deadline_day_is_inside_it(self):
        """The boundary itself, to the microsecond."""
        assert not assess(["ed25519"], now=DEADLINE).has_critical

    def test_the_next_microsecond_is_outside_it(self):
        assert assess(["ed25519"],
                      now=DEADLINE + timedelta(microseconds=1)).has_critical

    def test_a_signature_made_on_the_deadline_day_is_not_convicted(self):
        noon = DEADLINE.replace(hour=12, minute=0, second=0, microsecond=0)
        evidence = TimeEvidence.from_beacon(
            noon.strftime("%Y-%m-%dT%H:%M:%SZ"))
        result = assess(["ed25519"], evidence=evidence, now=BEFORE)
        assert not any("disallowed algorithm" in m for m in result.messages())


class TestTheRegistryIsCoherent:
    def test_every_classical_algorithm_has_a_deadline(self):
        for name, policy in ALGORITHM_POLICIES.items():
            if policy.status is TrustStatus.DEPRECATED:
                assert policy.disallowed_after, f"{name} is deprecated with no deadline"

    def test_every_policy_cites_a_source(self):
        """A date with no provenance is a magic constant."""
        for name, policy in ALGORITHM_POLICIES.items():
            assert policy.source, f"{name} has no cited source"

    def test_post_quantum_algorithms_have_no_deadline(self):
        for name in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-128s"):
            assert ALGORITHM_POLICIES[name].status is TrustStatus.CURRENT
            assert ALGORITHM_POLICIES[name].disallowed_after is None

    def test_no_classical_algorithm_is_marked_current(self):
        for name in ("ed25519", "ecdsa-p256", "rsa-2048", "rsa-4096"):
            assert ALGORITHM_POLICIES[name].status is not TrustStatus.CURRENT

    def test_dates_parse(self):
        for policy in ALGORITHM_POLICIES.values():
            if policy.disallowed_after:
                assert policy.disallowed_after_date is not None


class TestBeforeAnyDeadline:
    def test_hybrid_today_raises_nothing_critical(self):
        result = assess(HYBRID, now=BEFORE)
        assert not result.has_critical

    def test_classical_today_is_informational_only(self):
        result = assess(["ed25519"], now=BEFORE)
        assert not result.has_critical
        assert any("deprecated" in m for m in result.messages())


class TestAfterTheDeadline:
    def test_classical_alone_becomes_critical(self):
        """The signature is no longer evidence: a forgery made today would be
        indistinguishable from a genuine old signature."""
        result = assess(["ed25519"], now=AFTER)
        assert result.has_critical
        assert any("indistinguishable" in m for m in result.messages())

    def test_a_hybrid_is_not_critical_because_the_pq_member_holds(self):
        """The entire point of signing with both."""
        result = assess(HYBRID, now=AFTER)
        assert not result.has_critical
        assert any("hybrid is doing its job" in m for m in result.messages())

    def test_an_upper_bound_rescues_a_classical_signature(self):
        """Independent proof that the signature ALREADY EXISTED before the
        break means it still means something: the attacker cannot produce that
        proof retroactively.

        Only a transparency-log inclusion proof gives this direction.
        """
        evidence = TimeEvidence.from_transparency_log("2026-07-26T09:00:00Z")
        result = assess(["ed25519"], evidence=evidence, now=AFTER)
        assert not result.has_critical
        assert any("The signature stands" in m for m in result.messages())

    def test_a_beacon_lower_bound_must_not_rescue(self):
        """The correction that motivated the Bound enum.

        A beacon pulse proves the signature was made no EARLIER than the pulse.
        Rescuing a signature requires proving it was made no LATER than the
        break. "No earlier than 2026" is equally true of a forgery made this
        morning, so it establishes nothing about age.

        An earlier version treated any `trusted` evidence as rescuing, which
        made the entire temporal argument rest on a bound pointing the wrong
        way -- and, because entropy attestations only ever carry beacon pulses,
        made the rescue branch unreachable from any real bundle.
        """
        evidence = TimeEvidence.from_beacon("2026-07-26T09:00:00Z")
        result = assess(["ed25519"], evidence=evidence, now=AFTER)
        assert result.has_critical, "a lower bound must not rescue a signature"
        messages = " ".join(result.messages())
        assert "lower bound" in messages
        assert "transparency-log" in messages, "must name the evidence that would work"

    def test_the_two_bounds_are_not_interchangeable(self):
        """Same timestamp, same algorithm, same clock -- opposite verdicts,
        decided purely by which direction the evidence constrains."""
        stamp = "2026-07-26T09:00:00Z"
        upper = assess(["ed25519"], evidence=TimeEvidence.from_transparency_log(stamp),
                       now=AFTER)
        lower = assess(["ed25519"], evidence=TimeEvidence.from_beacon(stamp), now=AFTER)
        assert not upper.has_critical
        assert lower.has_critical

    def test_self_asserted_time_does_not_rescue_it(self):
        """A timestamp the signer wrote is not evidence -- a forger writes one
        too. This is the distinction the whole module turns on."""
        evidence = TimeEvidence.self_asserted("2026-07-26T09:00:00Z")
        result = assess(["ed25519"], evidence=evidence, now=AFTER)
        assert result.has_critical

    def test_signing_after_the_deadline_flags_the_signer(self):
        """A different failure: not 'is this still evidence' but 'should they
        have used this algorithm at all'.

        Both are true here -- signed after the deadline AND now past it -- so
        the finding must say so rather than claim there is no evidence. An
        earlier version reported "no trusted evidence of when this signature
        was made" while holding trusted evidence that it was made too late,
        which would have sent a reader looking for the wrong problem.
        """
        past = DEADLINE + timedelta(days=5)
        evidence = TimeEvidence.from_beacon(past.strftime("%Y-%m-%dT%H:%M:%SZ"))
        result = assess(["ed25519"], evidence=evidence,
                        now=DEADLINE + timedelta(days=32))
        messages = " ".join(result.messages())
        assert "used a disallowed algorithm" in messages
        assert "no trusted evidence" not in messages, (
            "must not claim absence of evidence while holding it"
        )
        assert result.has_critical

    def test_a_future_dated_signature_before_the_deadline_warns(self):
        """Deadline not yet reached, but the signature claims to postdate it:
        a clock problem or a fabricated timestamp."""
        past = DEADLINE + timedelta(days=5)
        evidence = TimeEvidence.from_beacon(past.strftime("%Y-%m-%dT%H:%M:%SZ"))
        result = assess(["ed25519"], evidence=evidence, now=BEFORE)
        assert any("used a disallowed algorithm" in m for m in result.messages())


class TestEvidenceHandling:
    def test_unknown_algorithm_is_flagged_not_ignored(self):
        result = assess(["homebrew-sig"], now=BEFORE)
        assert any("cannot be assessed" in m for m in result.messages())

    def test_missing_evidence_is_noted_as_information(self):
        result = assess(HYBRID, now=BEFORE)
        assert any("no independent evidence" in m for m in result.messages())

    def test_self_asserted_evidence_is_called_out(self):
        result = assess(HYBRID, evidence=TimeEvidence.self_asserted("2026-01-01T00:00:00Z"),
                        now=BEFORE)
        assert any("not evidence" in m for m in result.messages())

    def test_beacon_evidence_is_trusted(self):
        assert TimeEvidence.from_beacon("2026-07-26T09:00:00Z").trusted

    def test_transparency_log_evidence_is_trusted(self):
        assert TimeEvidence.from_transparency_log("2026-07-26T09:00:00Z").trusted

    def test_self_asserted_evidence_is_not_trusted(self):
        assert not TimeEvidence.self_asserted("2026-07-26T09:00:00Z").trusted

    def test_a_beacon_gives_a_lower_bound_only(self):
        evidence = TimeEvidence.from_beacon("2026-07-26T09:00:00Z")
        assert evidence.bound is Bound.LOWER
        assert evidence.proves_not_before is not None
        assert evidence.proves_not_after is None, (
            "a beacon cannot establish that a signature already existed"
        )

    def test_a_transparency_log_gives_an_upper_bound(self):
        evidence = TimeEvidence.from_transparency_log("2026-07-26T09:00:00Z")
        assert evidence.bound is Bound.UPPER
        assert evidence.proves_not_after is not None
        assert evidence.proves_not_before is None

    def test_untrusted_evidence_proves_neither_bound(self):
        evidence = TimeEvidence.self_asserted("2026-07-26T09:00:00Z")
        assert evidence.proves_not_after is None
        assert evidence.proves_not_before is None

    def test_evidence_extracted_from_a_beacon_attestation(self):
        attestation = {
            "not_before": "2026-07-26T09:00:00Z",
            "contributions": [
                {"role": "secret", "backend": "system", "reference": None},
                {"role": "public", "backend": "nist-beacon",
                 "reference": {"pulse_index": 1547823}},
            ],
        }
        evidence = evidence_from_attestation(attestation)
        assert evidence is not None
        assert evidence.trusted
        assert evidence.reference["pulse_index"] == 1547823

    def test_a_real_attestation_yields_only_a_lower_bound(self):
        """The honest consequence, asserted so it cannot be forgotten.

        Entropy attestations carry beacon pulses, so a bundle produced by this
        package can never rescue its own classical signature. Obtaining an upper
        bound means publishing to a transparency log -- a step this package does
        not perform. Recording that here keeps the limitation visible in the
        paper rather than discovering it during review.
        """
        evidence = evidence_from_attestation({"not_before": "2026-07-26T09:00:00Z"})
        assert evidence.bound is Bound.LOWER
        assert evidence.proves_not_after is None

    def test_an_inclusion_proof_outranks_the_beacon(self):
        """When a caller does record a log entry, take the stronger direction."""
        attestation = {
            "not_before": "2026-07-26T09:00:00Z",
            "transparency_log": {"integrated_time": "2026-07-26T09:05:00Z",
                                 "log_index": 4471},
        }
        evidence = evidence_from_attestation(attestation)
        assert evidence.bound is Bound.UPPER
        assert evidence.kind == "transparency-log"

    def test_an_attestation_without_a_beacon_yields_no_evidence(self):
        assert evidence_from_attestation({"contributions": []}) is None

    def test_none_attestation_is_handled(self):
        assert evidence_from_attestation(None) is None


class TestSoftWarnVersusHardFail:
    """The locked decision: soft-warn globally, hard-fail only under STRICT."""

    def test_assess_never_raises(self):
        """The policy layer reports; the verifier decides. Keeping the decision
        out of here is what allows the same assessment to be a warning in one
        mode and a failure in another."""
        for algorithms in (["ed25519"], ["unknown-alg"], HYBRID, []):
            assess(algorithms, now=AFTER)

    def test_critical_is_distinguishable_from_warning(self):
        critical = assess(["ed25519"], now=AFTER)
        informational = assess(HYBRID, now=BEFORE)
        assert critical.has_critical
        assert not informational.has_critical

    def test_findings_carry_their_policy_source(self):
        result = assess(["ed25519"], now=AFTER)
        sourced = [f for f in result.findings if f.policy_source]
        assert sourced, "a critical finding must say which policy it rests on"


class TestIntegrationWithVerify:
    """The behaviour the memo's checkpoint asks for, end to end."""

    @pytest.fixture(scope="class")
    @classmethod
    def artefact_and_signature(cls, tmp_path_factory):
        # Ed25519 only -- deliberately no dilithium_py skip here. These four
        # tests ARE the temporal checkpoint, and gating them on a dependency
        # they never touch made them vanish silently on any machine without
        # ML-DSA installed, which is exactly where a classical-only signature
        # is most likely to be produced.
        pytest.importorskip("cryptography")
        from qknot.signing.backends import Exposure
        from qknot.signing.sign import keygen, sign

        root = tmp_path_factory.mktemp("m")
        (root / "w.bin").write_bytes(b"w" * 128)
        keys = keygen(suite=["ed25519"], seed=b"\x33" * 32)
        return root, sign(root, keys, exposure=Exposure.OFFLINE)

    def test_soft_warns_by_default_after_the_deadline(self, artefact_and_signature):
        from qknot.signing.sign import VerifyMode, verify

        root, signed = artefact_and_signature
        report = verify(root, signed, mode=VerifyMode.CLASSICAL, now=AFTER)
        assert report["verified"], "default posture is soft-warn, not failure"
        assert report["temporal"]["critical"]

    def test_hard_fails_in_strict_after_the_deadline(self, artefact_and_signature):
        from qknot.signing.sign import VerificationFailed, VerifyMode, verify

        root, signed = artefact_and_signature
        with pytest.raises(VerificationFailed, match="temporal trust boundary"):
            verify(root, signed, mode=VerifyMode.STRICT, now=AFTER)

    def test_strict_passes_before_the_deadline(self, artefact_and_signature):
        from qknot.signing.sign import VerifyMode, verify

        root, signed = artefact_and_signature
        assert verify(root, signed, mode=VerifyMode.STRICT, now=BEFORE)["verified"]

    def test_the_failure_message_names_the_escape_hatch(self, artefact_and_signature):
        from qknot.signing.sign import VerificationFailed, VerifyMode, verify

        root, signed = artefact_and_signature
        with pytest.raises(VerificationFailed) as excinfo:
            verify(root, signed, mode=VerifyMode.STRICT, now=AFTER)
        assert "CLASSICAL or PQC" in str(excinfo.value)
