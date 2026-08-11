"""Side-channel status as three states, and what ASSERTED has to carry.

The same shape as the Fulcio bug, one level up: that one inferred an algorithm
from issuer convention instead of parsing it; a `(version, platform)` allowlist
would infer a build property from metadata that does not contain it. Both are
inference from convention where measurement was available.
"""
from __future__ import annotations

import pytest

from qknot.signing.backends import (
    BackendUnsuitable,
    Exposure,
    attest_constant_time,
    check_exposure,
    get_backend,
)
from qknot.signing.sidechannel import SideChannelEvidence, SideChannelStatus

GOOD = dict(tool="dudect", tool_version="0.1.0",
            performed="2026-07-30T09:00:00+00:00",
            subject="liboqs 0.14.0, OQS_OPT_TARGET=generic, gcc 11.4",
            report_sha256="a" * 64, asserted_by="Aditya Sharma")


class TestTheThirdStateChangesNoGate:
    """Introducing UNKNOWN must not loosen anything; it records why, not what."""

    @pytest.mark.parametrize("status,online", [
        (SideChannelStatus.KNOWN_LEAKY, False),
        (SideChannelStatus.UNKNOWN, False),
        (SideChannelStatus.ASSERTED, True),
    ])
    def test_only_asserted_permits_online(self, status, online):
        assert status.permits_online is online

    def test_measured_leakage_is_refused_with_a_measured_reason(self):
        backend = get_backend("ml-dsa-87")
        assert backend.side_channel_status is SideChannelStatus.KNOWN_LEAKY
        with pytest.raises(BackendUnsuitable, match="MEASURED to leak"):
            check_exposure(backend, Exposure.ONLINE)

    def test_unknown_is_refused_as_firmly_as_leakage(self):
        """An unverified claim is not a weaker guarantee. It is none."""
        backend = get_backend("ml-dsa-87")
        backend.side_channel_status = SideChannelStatus.UNKNOWN
        backend.side_channel_resistant = False
        with pytest.raises(BackendUnsuitable, match="HAS NOT BEEN ESTABLISHED"):
            check_exposure(backend, Exposure.ONLINE)

    def test_the_unknown_refusal_says_no_mechanism_exists(self):
        """Probed: liboqs exposes name, version, claimed_nist_level, lengths --
        and no constant-time or build flag at all."""
        backend = get_backend("ml-dsa-87")
        backend.side_channel_status = SideChannelStatus.UNKNOWN
        backend.side_channel_resistant = False
        with pytest.raises(BackendUnsuitable) as caught:
            check_exposure(backend, Exposure.ONLINE)
        assert "no runtime mechanism" in str(caught.value)


class TestAssertedMustCarryEvaluableEvidence:
    """Otherwise ASSERTED is a more honest place to put an unverified claim."""

    def test_a_complete_assertion_is_accepted(self):
        evidence = SideChannelEvidence(**GOOD)
        assert evidence.tool_is_recognised
        assert evidence.to_dict()["reportSha256"] == "a" * 64

    @pytest.mark.parametrize("field", sorted(
        set(GOOD) - {"report_uri"}))
    def test_every_field_is_required(self, field):
        with pytest.raises(ValueError, match=field):
            SideChannelEvidence(**{**GOOD, field: "   "})

    def test_the_report_must_be_bound_by_digest(self):
        with pytest.raises(ValueError, match="64 lowercase hex"):
            SideChannelEvidence(**{**GOOD, "report_sha256": "not-a-digest"})

    def test_a_naive_timestamp_is_refused(self):
        """This field orders the analysis against the build it describes."""
        with pytest.raises(ValueError, match="timezone"):
            SideChannelEvidence(**{**GOOD, "performed": "2026-07-30T09:00:00"})

    def test_an_analysis_from_the_future_is_refused(self):
        with pytest.raises(ValueError, match="future"):
            SideChannelEvidence(**{**GOOD, "performed": "2099-01-01T00:00:00Z"})

    def test_an_unrecognised_tool_is_recorded_not_refused(self):
        """Silently dropping the name would leave a reader unable to judge."""
        evidence = SideChannelEvidence(**{**GOOD, "tool": "homegrown-timer"})
        assert evidence.tool == "homegrown-timer"
        assert evidence.tool_is_recognised is False
        assert evidence.to_dict()["toolRecognised"] is False


class TestRaisingABackendToAsserted:
    def test_a_free_string_is_refused(self):
        backend = get_backend("ml-dsa-87")
        backend.side_channel_status = SideChannelStatus.UNKNOWN
        with pytest.raises(TypeError, match="free string"):
            attest_constant_time(backend, "we checked it, it's fine")

    def test_measured_leakage_cannot_be_asserted_away(self):
        """The variance is a property of the implementation, not of a build."""
        with pytest.raises(BackendUnsuitable, match="MEASURED to leak"):
            attest_constant_time(get_backend("ml-dsa-87"),
                                 SideChannelEvidence(**GOOD))

    def test_unknown_can_be_raised_and_then_signs_online(self):
        backend = get_backend("ml-dsa-87")
        backend.side_channel_status = SideChannelStatus.UNKNOWN
        backend.side_channel_resistant = False
        attest_constant_time(backend, SideChannelEvidence(**GOOD))
        assert backend.side_channel_status is SideChannelStatus.ASSERTED
        check_exposure(backend, Exposure.ONLINE)
        assert backend.side_channel_evidence.asserted_by == "Aditya Sharma"
