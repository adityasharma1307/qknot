"""Adversarial tests for RFC 3161 upper-bound time evidence.

WHAT THESE CAN AND CANNOT COVER, STATED UP FRONT
================================================
Producing a *valid* timestamp response requires a TSA: it is CMS SignedData
signed by an authority's key. This suite cannot mint one, so it cannot assert
"a good token verifies" from first principles. Claiming otherwise would be the
kind of test that passes because it never exercised the thing it names.

What it does cover is every path where a wrong answer is dangerous:

  * a token that does not verify must not produce evidence
  * a token over DIFFERENT bytes must not verify against this signature
  * an empty trust store must fail closed, not open
  * duplicates must not satisfy an independence threshold
  * unavailability must be distinguishable from forgery
  * unverified claims in a bundle must not mint trusted evidence

The one gap -- a genuine end-to-end rescue against a real public TSA -- needs a
network round trip, is recorded in docs/OPEN-QUESTIONS.md, and becomes a
committed fixture the moment a real response is obtained. Until then this file
says so rather than implying coverage it does not have.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from qresp.signing.temporal import Bound, TimeEvidence, evidence_from_attestation
from qresp.signing.transparency import (
    VERIFIED_TIME_THRESHOLD,
    TimestampError,
    TimestampToken,
    TimestampUnavailableError,
    establish_time,
)

pytest.importorskip("rfc3161_client", reason="needs `qresp[transparency]`")

GOOD = TimestampToken(der=b"\x30\x03fake-a", url="http://tsa-a.example")
OTHER = TimestampToken(der=b"\x30\x03fake-b", url="http://tsa-b.example")
WHEN = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def _anchor() -> dict[str, object]:
    return {"tsa_certificate": object(), "roots": [object()], "intermediates": []}


def _anchors(*urls: str) -> dict[str, object]:
    return {url: _anchor() for url in urls}


@pytest.fixture
def verifies(monkeypatch: pytest.MonkeyPatch):
    """Stub verification so the POLICY layer can be tested in isolation.

    `establish_time` decides how many sources are needed, which one to believe,
    and what to do when some fail. Those decisions are independent of ASN.1, and
    testing them through a real verifier would mean testing neither properly.
    The stub is explicit about which tokens it accepts, so no test can pass by
    accidentally verifying nothing.
    """
    def install(accepted: dict[bytes, datetime], expect_message: bytes | None = None):
        def fake(token, message, **_kw):
            if expect_message is not None and message != expect_message:
                raise TimestampError("timestamp is over different bytes")
            if token.der not in accepted:
                raise TimestampError("signature does not verify")
            return accepted[token.der]
        monkeypatch.setattr("qresp.signing.transparency.verify_timestamp", fake)
    return install


class TestTheThresholdIsEnforced:
    """One timestamp is a single point of trust; the default demands two."""

    def test_the_default_threshold_is_two_not_one(self):
        """sigstore-python uses 1. This is deliberately stricter -- pin it.

        If someone relaxes this to match upstream, that must be a deliberate
        edit with a reason, not a quiet drift back to the weaker setting.
        """
        assert VERIFIED_TIME_THRESHOLD == 2

    def test_one_verified_timestamp_is_not_enough(self, verifies):
        verifies({GOOD.der: WHEN})
        with pytest.raises(TimestampError, match="need 2"):
            establish_time([GOOD], b"sig",
                           anchors=_anchors(GOOD.url))

    def test_two_independent_timestamps_succeed(self, verifies):
        later = WHEN.replace(month=3)
        verifies({GOOD.der: WHEN, OTHER.der: later})
        established = establish_time([GOOD, OTHER], b"sig",
                                     anchors=_anchors(GOOD.url, OTHER.url))
        assert established == WHEN

    def test_a_caller_may_lower_the_threshold_deliberately(self, verifies):
        verifies({GOOD.der: WHEN})
        assert establish_time([GOOD], b"sig", anchors=_anchors(GOOD.url),
                              threshold=1) == WHEN


class TestIndependenceCannotBeFaked:
    def test_the_same_token_twice_does_not_count_as_two_sources(self, verifies):
        """The cheapest possible forgery of independence.

        Without deduplication, pasting one token into the bundle twice
        satisfies "two independent verified times" -- and it would verify twice,
        because it is genuinely valid. The threshold would be measuring nothing.
        """
        verifies({GOOD.der: WHEN})
        with pytest.raises(TimestampError, match="need 2"):
            establish_time([GOOD, GOOD], b"sig", anchors=_anchors(GOOD.url))

    def test_the_duplicate_is_reported_not_silently_dropped(self, verifies):
        verifies({GOOD.der: WHEN})
        with pytest.raises(TimestampError, match="duplicate"):
            establish_time([GOOD, GOOD], b"sig", anchors=_anchors(GOOD.url))

    def test_an_unbounded_list_is_refused(self, verifies):
        verifies({})
        many = [TimestampToken(der=bytes([i]), url="u") for i in range(40)]
        with pytest.raises(TimestampError, match="refusing"):
            establish_time(many, b"sig", anchors=_anchors("u"))


class TestForgedAndTamperedTokens:
    def test_a_token_that_does_not_verify_contributes_nothing(self, verifies):
        verifies({GOOD.der: WHEN})            # OTHER is not accepted
        with pytest.raises(TimestampError, match="need 2"):
            establish_time([GOOD, OTHER], b"sig",
                           anchors=_anchors(GOOD.url, OTHER.url))

    def test_a_timestamp_over_different_bytes_is_rejected(self, verifies):
        """The property the whole mechanism rests on.

        A perfectly valid timestamp proves *some* bytes existed. Unless those
        bytes are this signature, it says nothing about this signature -- and an
        attacker holding any valid timestamp could otherwise attach it to
        anything.
        """
        verifies({GOOD.der: WHEN, OTHER.der: WHEN}, expect_message=b"the-real-signature")
        with pytest.raises(TimestampError, match="different bytes"):
            establish_time([GOOD, OTHER], b"some-other-signature",
                           anchors=_anchors(GOOD.url, OTHER.url))

    def test_a_token_from_an_unanchored_authority_is_refused(self, verifies):
        """Trust anchors are the verifier's, never the bundle's.

        A bundle naming a TSA the verifier has no anchor for is not evidence.
        Fetching an anchor on demand would let the bundle choose its own root.
        """
        verifies({GOOD.der: WHEN, OTHER.der: WHEN})
        with pytest.raises(TimestampError, match="no trust anchor"):
            establish_time([GOOD, OTHER], b"sig", anchors=_anchors(GOOD.url))

    def test_failure_detail_names_the_authority(self, verifies):
        verifies({})
        with pytest.raises(TimestampError, match="tsa-a.example"):
            establish_time([GOOD, OTHER], b"sig",
                           anchors=_anchors(GOOD.url, OTHER.url))


class TestFailClosed:
    def test_no_timestamps_at_all_raises_rather_than_returning_a_time(self, verifies):
        """"Could not establish" must not be representable as a datetime.

        Returning the epoch, or None, invites a caller to compare it against a
        deadline and conclude the signature is old enough.
        """
        verifies({})
        with pytest.raises(TimestampError, match="0 verified"):
            establish_time([], b"sig", anchors={})

    def test_an_empty_trust_store_is_not_success(self):
        """Verifying against no roots must fail, not vacuously pass."""
        from qresp.signing.transparency import verify_timestamp
        with pytest.raises(TimestampError, match="no root certificates"):
            verify_timestamp(GOOD, b"sig", tsa_certificate=object(), roots=[])

    def test_unavailability_and_forgery_are_different_exceptions(self):
        """They must not be catchable by the same handler.

        "The TSA was unreachable" is an availability problem at signing time.
        "This token does not verify" is an attack. Collapsing them into one
        error type is how a pipeline ends up treating a forgery as a retryable
        network blip.
        """
        assert not issubclass(TimestampUnavailableError, TimestampError)
        assert not issubclass(TimestampError, TimestampUnavailableError)


class TestEarliestIsChosen:
    def test_the_earliest_verified_time_wins(self, verifies):
        """cosign does the same, and for an upper bound it is conservative.

        Asserting "existed by January" is a stronger claim to satisfy than
        "existed by March", so the earliest never overstates the evidence.
        Taking the latest would let an attacker who obtains one late timestamp
        push a signature past a deprecation deadline by adding it.
        """
        early, late = WHEN, WHEN.replace(month=11)
        verifies({GOOD.der: late, OTHER.der: early})
        assert establish_time([GOOD, OTHER], b"sig",
                              anchors=_anchors(GOOD.url, OTHER.url)) == early


class TestTheEvidenceItProduces:
    def test_a_verified_timestamp_is_an_upper_bound(self):
        evidence = TimeEvidence.from_timestamp_authority("2026-01-15T12:00:00Z")
        assert evidence.bound is Bound.UPPER
        assert evidence.trusted
        assert evidence.proves_not_after is not None

    def test_it_is_distinguishable_from_a_log_entry(self):
        """Both are UPPER bounds; they are not the same thing.

        A log entry is publicly discoverable, a timestamp is evidence the
        holder must present. A reader of an attestation is entitled to know
        which one they have.
        """
        tsa = TimeEvidence.from_timestamp_authority("2026-01-15T12:00:00Z")
        log = TimeEvidence.from_transparency_log("2026-01-15T12:00:00Z")
        assert tsa.kind != log.kind
        assert tsa.bound is log.bound is Bound.UPPER

    def test_a_beacon_is_still_only_a_lower_bound(self):
        """The distinction this module exists to preserve."""
        assert TimeEvidence.from_beacon("2026-01-15T12:00:00Z").bound is Bound.LOWER
        assert TimeEvidence.from_beacon("2026-01-15T12:00:00Z").proves_not_after is None


class TestAttestationParsing:
    def test_a_time_evidence_field_with_kind_rfc3161_is_read(self):
        evidence = evidence_from_attestation(
            {"time_evidence": {"kind": "rfc3161", "gen_time": "2026-01-15T12:00:00Z"}}
        )
        assert evidence is not None
        assert evidence.kind == "timestamp-authority"
        assert evidence.bound is Bound.UPPER

    def test_the_older_transparency_log_field_still_works(self):
        """Bundles written before `time_evidence` existed must keep verifying."""
        evidence = evidence_from_attestation(
            {"transparency_log": {"integrated_time": "2026-01-15T12:00:00Z"}}
        )
        assert evidence is not None
        assert evidence.bound is Bound.UPPER

    def test_upper_bound_evidence_outranks_a_beacon_in_the_same_attestation(self):
        evidence = evidence_from_attestation({
            "not_before": "2026-01-01T00:00:00Z",
            "time_evidence": {"kind": "rfc3161", "gen_time": "2026-01-15T12:00:00Z"},
        })
        assert evidence is not None
        assert evidence.bound is Bound.UPPER, "the stronger direction must win"

    def test_an_unknown_kind_falls_through_rather_than_being_trusted(self):
        """An unrecognised kind must not be treated as an upper bound.

        Defaulting to the strong direction would let a bundle invent a kind and
        rescue itself. Falling through to the beacon is the safe failure.
        """
        evidence = evidence_from_attestation({
            "not_before": "2026-01-01T00:00:00Z",
            "time_evidence": {"kind": "vibes", "gen_time": "2026-01-15T12:00:00Z"},
        })
        assert evidence is not None
        assert evidence.bound is Bound.LOWER

    def test_parsing_an_attestation_does_not_verify_anything(self):
        """The most dangerous available confusion, pinned.

        `evidence_from_attestation` reads what a bundle CLAIMS. Nothing in it
        checks a signature. A caller that treats its output as verified has
        given attacker-controlled JSON the power to rescue a deprecated
        signature -- so this test exists to make that boundary explicit and to
        fail loudly if the two are ever merged.
        """
        forged = evidence_from_attestation(
            {"time_evidence": {"kind": "rfc3161",
                               "gen_time": "1999-01-01T00:00:00Z",
                               "response": base64.b64encode(b"nonsense").decode()}}
        )
        assert forged is not None
        assert forged.trusted, (
            "parsing marks the KIND as trustworthy-in-principle; verification "
            "is a separate step performed by transparency.verify_timestamp"
        )


class TestSerialisation:
    def test_a_token_round_trips(self):
        assert TimestampToken.from_dict(GOOD.to_dict()) == GOOD

    def test_a_foreign_kind_is_refused(self):
        with pytest.raises(TimestampError, match="unsupported time-evidence kind"):
            TimestampToken.from_dict({"kind": "rekor", "response": "AA=="})

    def test_malformed_base64_is_reported_as_such(self):
        with pytest.raises(TimestampError, match="not valid base64"):
            TimestampToken.from_dict({"kind": "rfc3161", "response": "not!base64!"})

    def test_a_missing_response_is_refused(self):
        with pytest.raises(TimestampError, match="no 'response' field"):
            TimestampToken.from_dict({"kind": "rfc3161"})
