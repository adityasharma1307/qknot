"""The three-way binding decision (spec step 7), reused for primary and recovery.

DIRECT / RESCUED / REJECTED, keyed to when the act happened vs the algorithm's
disallow date -- the temporal upper-bound rescue applied to a key binding.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from qknot.signing.algorithms import REGISTRY
from qknot.signing.temporal import BindingBasis, binding_trust

ALG = "ecdsa-p256"
D = REGISTRY[ALG].disallowed_after_date
BEFORE = datetime(2030, 1, 1, tzinfo=timezone.utc)
AFTER = datetime(2040, 1, 1, tzinfo=timezone.utc)


class TestTheThreeOutcomes:
    def test_before_the_deadline_is_direct(self):
        assert binding_trust(ALG, None, now=BEFORE) is BindingBasis.DIRECT

    def test_after_the_deadline_with_an_earlier_timestamp_is_rescued(self):
        assert binding_trust(ALG, BEFORE, now=AFTER) is BindingBasis.RESCUED

    def test_after_the_deadline_with_no_timestamp_is_rejected(self):
        assert binding_trust(ALG, None, now=AFTER) is BindingBasis.REJECTED

    def test_after_the_deadline_with_a_later_timestamp_is_rejected(self):
        """A timestamp AFTER the deadline cannot prove the act predates it --
        it may be a forgery made once the algorithm was already broken."""
        assert binding_trust(ALG, AFTER, now=AFTER) is BindingBasis.REJECTED

    def test_the_boundary_day_itself_is_still_direct(self):
        """disallowed_after is the last allowed day; its final instant is in."""
        assert binding_trust(ALG, None, now=D) is BindingBasis.DIRECT


class TestOnlyAnUpperBoundRescues:
    def test_a_timestamp_exactly_at_the_deadline_rescues(self):
        assert binding_trust(ALG, D, now=AFTER) is BindingBasis.RESCUED


class TestItRefusesToGuess:
    def test_an_algorithm_with_no_policy_raises_rather_than_trusting(self):
        with pytest.raises(ValueError, match="no policy"):
            binding_trust("nonesuch-42", None, now=BEFORE)

    def test_a_pqc_algorithm_with_no_deadline_is_always_direct(self):
        """ml-dsa-87 has no disallow date, so it never needs rescue."""
        assert REGISTRY["ml-dsa-87"].disallowed_after_date is None
        assert binding_trust("ml-dsa-87", None, now=AFTER) is BindingBasis.DIRECT
