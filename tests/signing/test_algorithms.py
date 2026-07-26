"""The registry is the single source, and the derived views agree with it.

These tests exist because the three tables this file replaced had already
drifted: `slh-dsa-128f` was bindable by the combiner, unimplemented by the
backend factory, and absent from the policy registry, so one algorithm got
three different answers depending on which module was asked. Structural tests
are the only thing that keeps that from happening again -- nobody notices
divergence by reading.
"""
from __future__ import annotations

import pytest

from qresp.signing import algorithms
from qresp.signing.algorithms import REGISTRY, TrustStatus, implemented, is_known
from qresp.signing.backends import _BACKENDS, get_backend
from qresp.signing.combiner import KNOWN_ALGORITHMS
from qresp.signing.temporal import ALGORITHM_POLICIES


class TestTheViewsCannotDisagree:
    def test_the_combiner_view_is_the_registry(self):
        derived = {n: s.resists_shor for n, s in REGISTRY.items()}
        assert derived == KNOWN_ALGORITHMS

    def test_the_policy_view_is_the_registry(self):
        assert ALGORITHM_POLICIES is REGISTRY

    def test_every_backend_has_a_registry_entry(self):
        for name in _BACKENDS:
            assert name in REGISTRY, f"backend {name} is not in the registry"

    def test_every_claimed_backend_exists(self):
        for name, spec in REGISTRY.items():
            if spec.has_backend:
                assert name in _BACKENDS, f"registry claims a backend for {name}"

    def test_the_specific_drift_that_motivated_this(self):
        """slh-dsa-128f was known to one table and invisible to another."""
        for name in ("slh-dsa-128f", "slh-dsa-128s", "ecdsa-p384"):
            assert name in KNOWN_ALGORITHMS
            assert name in ALGORITHM_POLICIES
            assert not REGISTRY[name].has_backend


class TestTheRegistryIsInternallyCoherent:
    def test_nothing_resisting_shor_carries_a_deadline(self):
        for name, spec in REGISTRY.items():
            if spec.resists_shor:
                assert spec.disallowed_after is None, f"{name}"
                assert spec.status is TrustStatus.CURRENT

    def test_nothing_vulnerable_to_shor_is_current(self):
        for name, spec in REGISTRY.items():
            if not spec.resists_shor:
                assert spec.status is not TrustStatus.CURRENT, f"{name}"
                assert spec.disallowed_after, f"{name} is deprecated with no deadline"

    def test_every_entry_cites_a_source(self):
        for name, spec in REGISTRY.items():
            assert spec.source, f"{name} has no cited source"

    def test_the_key_matches_the_algorithm_field(self):
        for name, spec in REGISTRY.items():
            assert name == spec.algorithm

    def test_unknown_algorithms_do_not_resist_shor(self):
        """The safe direction: an unrecognised name is never counted as
        quantum protection."""
        assert not algorithms.resists_shor("homebrew-pq")
        assert not is_known("homebrew-pq")


class TestDeadlineInclusivity:
    def test_the_deadline_runs_to_the_end_of_its_day(self):
        spec = REGISTRY["ed25519"]
        end = spec.disallowed_after_date
        assert end.year == 2030 and end.month == 12 and end.day == 31
        assert (end.hour, end.minute) == (23, 59), (
            "midnight would exclude the whole of the final day"
        )

    def test_current_algorithms_have_no_deadline_date(self):
        assert REGISTRY["ml-dsa-44"].disallowed_after_date is None


class TestBackendErrorsDistinguishTwoCases:
    def test_a_known_but_unimplemented_algorithm_says_so(self):
        """SLH-DSA is a FIPS 205 standard. Reporting it as 'unknown' invited
        the reading that it was suspect rather than merely absent here."""
        with pytest.raises(ValueError, match="recognised algorithm"):
            get_backend("slh-dsa-128s")

    def test_a_genuinely_unknown_algorithm_says_unknown(self):
        with pytest.raises(ValueError, match="unknown algorithm"):
            get_backend("homebrew-sig")

    def test_the_error_names_what_is_available(self):
        with pytest.raises(ValueError) as excinfo:
            get_backend("slh-dsa-128s")
        assert "ml-dsa-44" in str(excinfo.value)

    def test_implemented_lists_only_backed_algorithms(self):
        assert set(implemented()) == set(_BACKENDS)
