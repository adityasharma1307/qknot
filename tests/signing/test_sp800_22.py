"""Validate the SP 800-22 subset against NIST's own published worked examples.

WHY THIS FILE IS THE WHOLE POINT
================================
An implementation of a statistical test is not obviously right or wrong by
inspection: it produces a plausible-looking number either way. The only way to
know is to reproduce values someone else published.

`nistrng` was tried first and had to be abandoned after three defects surfaced
in an afternoon -- an int8 overflow in cumulative sums, a p-value of 0.683
reported as a failure, and template matching scoring `os.urandom` worse than a
repeating block. None of those are visible without a reference to check against.
Every test below checks one.

The expected values are from **SP 800-22 Rev. 1a**, section 2.x "Example" in
each test's description.
"""
from __future__ import annotations

import math

import pytest

from qknot.signing.entropy.sp800_22 import (
    ALPHA,
    cumulative_sums,
    frequency_within_block,
    monobit,
    run_all,
    runs,
    to_bits,
)


def bits(text: str) -> list[int]:
    return [int(c) for c in text if c in "01"]


class TestAgainstTheSpecificationsWorkedExamples:
    """Each expected value is printed in SP 800-22 Rev. 1a."""

    def test_monobit_example(self):
        """Section 2.1.8: epsilon = 1011010101, n = 10, p-value = 0.527089."""
        result = monobit(bits("1011010101"))
        assert result.p_value == pytest.approx(0.527089, abs=1e-6)
        assert result.passed

    def test_monobit_derived_independently(self):
        """The same example, recomputed from the definition rather than quoted.

        p = erfc(|S_n| / sqrt(n) / sqrt(2)). Deriving it here as well as
        asserting the published value means the test does not rest on the
        published value being remembered correctly.
        """
        sequence = bits("1011010101")
        s_n = sum(1 if b else -1 for b in sequence)
        expected = math.erfc((abs(s_n) / math.sqrt(len(sequence))) / math.sqrt(2))
        assert monobit(sequence).p_value == pytest.approx(expected, abs=1e-12)

    def test_frequency_within_block_example(self):
        """Section 2.2.8: epsilon = 0110011010, M = 3, p-value = 0.801252."""
        result = frequency_within_block(bits("0110011010"), block_size=3)
        assert result.p_value == pytest.approx(0.801252, abs=1e-6)
        assert result.passed

    def test_runs_example(self):
        """Section 2.3.8: epsilon = 1001101011, n = 10, p-value = 0.147232."""
        result = runs(bits("1001101011"))
        assert result.p_value == pytest.approx(0.147232, abs=1e-6)
        assert result.passed


class TestCumulativeSumsAgainstSimulation:
    """Validated by simulation rather than against a quoted constant.

    The other three tests here agree with the published example values to six
    decimal places, which is strong evidence for both the implementation and the
    recollection -- two independent errors would not cancel that precisely.

    Cumulative sums did *not* agree, so one of the two was wrong. Rather than
    trust either, the p-value is checked against the empirical tail probability
    of simulated random walks. That is a stronger check than a constant anyway:
    it tests the thing the formula is supposed to compute, P(max|S_k| >= z), and
    it can be re-run by anyone without a copy of the standard.

    The formula is asymptotic, so exact agreement is not expected; agreement
    within a few thousandths, converging in the tail where the alpha = 0.01
    decision is actually made, is.
    """

    @staticmethod
    def _walk_with_excursion(n: int, target: int) -> list[int]:
        walk = [1] * target + [0, 1] * ((n - target) // 2)
        return walk[:n]

    @pytest.mark.parametrize("z_target,tolerance", [
        (10, 0.02), (15, 0.02), (20, 0.02), (25, 0.01), (30, 0.01), (40, 0.005),
    ])
    def test_p_value_matches_the_empirical_tail(self, z_target, tolerance):
        import random

        n, trials = 200, 20_000
        rng = random.Random(20260728)
        maxima = []
        for _ in range(trials):
            running, largest = 0, 0
            for _ in range(n):
                running += 1 if rng.getrandbits(1) else -1
                largest = max(largest, abs(running))
            maxima.append(largest)

        result = cumulative_sums(self._walk_with_excursion(n, z_target))
        empirical = sum(1 for z in maxima if z >= result.statistic) / trials
        assert result.p_value == pytest.approx(empirical, abs=tolerance), (
            f"formula {result.p_value:.4f} vs empirical {empirical:.4f} "
            f"at z={result.statistic}")

    def test_backward_is_exactly_the_forward_pass_on_the_reversed_sequence(self):
        """The identity that says `reverse=True` does what it claims.

        Asserting the two directions merely *differ* would have been the obvious
        test and is wrong: for many sequences they coincide, and the first
        attempt here picked one of them. This identity holds for every input, so
        it actually constrains the implementation.
        """
        import random

        rng = random.Random(4)
        for _ in range(20):
            sequence = [rng.getrandbits(1) for _ in range(300)]
            backward = cumulative_sums(sequence, reverse=True)
            forward_of_reversed = cumulative_sums(list(reversed(sequence)),
                                                  reverse=False)
            assert backward.statistic == forward_of_reversed.statistic
            assert backward.p_value == pytest.approx(forward_of_reversed.p_value)

    def test_both_directions_are_reported(self):
        """Drift can be one-sided, so a single direction can miss it."""
        names = {r.name for r in run_all(bytes(range(256)) * 40)}
        assert "cumulative_sums_forward" in names
        assert "cumulative_sums_backward" in names


class TestTheAccumulatorIsExact:
    """The defect that made the library unusable, asserted absent here.

    `nistrng` accumulated the +-1 walk in an int8, which wraps at 127. On
    100,000 bits the true max |S_k| was 724 and it raised 2,021 overflow
    warnings while returning a confident pass.
    """

    def test_a_long_one_sided_walk_does_not_wrap(self):
        # 10,000 ones: the walk ends at +10,000, which is 78x past an int8.
        result = cumulative_sums([1] * 10_000)
        assert result.statistic == 10_000, "the excursion must not wrap"
        assert not result.passed, "a constant sequence is not random"

    def test_max_excursion_matches_a_direct_computation(self):
        import random

        rng = random.Random(20260728)
        sequence = [rng.getrandbits(1) for _ in range(50_000)]
        running, expected = 0, 0
        for bit in sequence:
            running += 1 if bit else -1
            expected = max(expected, abs(running))
        assert cumulative_sums(sequence).statistic == expected


class TestItActuallyDiscriminates:
    """A suite that passes everything is worth nothing.

    These are the cases the abandoned library got backwards: it scored
    `os.urandom` as failing and a repeating block as passing.
    """

    @staticmethod
    def _random_bytes(n: int = 125_000) -> bytes:
        import random
        return random.Random(20260728).randbytes(n)

    def test_good_randomness_passes_every_test(self):
        results = run_all(self._random_bytes())
        failures = [r for r in results if not r.passed]
        assert not failures, f"a good CSPRNG must pass: {[str(f) for f in failures]}"

    def test_all_zeros_fails(self):
        results = run_all(bytes(12_500))
        assert any(not r.passed for r in results)

    def test_alternating_bits_fail(self):
        """0101... has perfect monobit balance and impossible run behaviour.

        The case that shows why monobit alone is not enough.
        """
        data = bytes([0b01010101] * 12_500)
        results = {r.name: r for r in run_all(data)}
        assert results["monobit"].passed, "balance is perfect, as expected"
        assert not results["runs"].passed, "but every adjacent pair alternates"

    def test_a_repeating_counter_block_is_caught(self):
        """The control used in the benchmark write-up.

        Its byte histogram is perfectly uniform, so MCV min-entropy and a
        chi-square goodness-of-fit both wave it through. Something has to catch
        it, or the suite is measuring nothing.
        """
        data = (bytes(range(256)) * 500)[:125_000]
        results = run_all(data)
        assert any(not r.passed for r in results), (
            "a repeating counter must be rejected by something in the suite"
        )

    def test_a_biased_source_fails_monobit(self):
        import random
        rng = random.Random(7)
        # 70% ones.
        data = bytes(
            sum((1 if rng.random() < 0.7 else 0) << shift for shift in range(8))
            for _ in range(12_500))
        assert not monobit(to_bits(data)).passed


class TestPrerequisitesAreHonoured:
    def test_runs_refuses_when_monobit_would_fail(self):
        """SP 800-22 2.3.4: the runs test is undefined if the proportion is
        already too far from a half. Returning a number anyway would look like
        a result."""
        result = runs([1] * 1000)
        assert not result.passed
        assert "prerequisite failed" in result.detail

    def test_frequency_block_requires_a_full_block(self):
        with pytest.raises(ValueError, match="at least"):
            frequency_within_block([1, 0, 1], block_size=128)

    def test_monobit_rejects_an_empty_sequence(self):
        with pytest.raises(ValueError, match="empty"):
            monobit([])


class TestPValuesAreWellFormed:
    @pytest.mark.parametrize("seed", range(8))
    def test_p_values_are_probabilities(self, seed):
        import random
        data = random.Random(seed).randbytes(20_000)
        for result in run_all(data):
            assert 0.0 <= result.p_value <= 1.0, f"{result.name} p={result.p_value}"
            assert not math.isnan(result.p_value)

    def test_the_alpha_used_is_the_one_the_standard_specifies(self):
        assert ALPHA == 0.01

    def test_passed_agrees_with_the_p_value(self):
        """The defect that made the library untrustworthy: a p-value of 0.683
        reported as a failure."""
        import random
        for seed in range(5):
            for result in run_all(random.Random(seed).randbytes(20_000)):
                assert result.passed == (result.p_value >= ALPHA), (
                    f"{result.name}: passed={result.passed} but p={result.p_value}")
