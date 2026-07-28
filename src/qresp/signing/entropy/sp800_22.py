"""A verified subset of the NIST SP 800-22 statistical test suite.

WHY THESE ARE IMPLEMENTED HERE RATHER THAN TAKEN FROM A LIBRARY
===============================================================
The obvious move is to use an existing package. `nistrng` was tried and cannot
be relied on. Three defects were found in an afternoon, each of which would have
put a wrong number in the results table:

  1. **Cumulative sums overflows.** The +-1 random walk is accumulated in the
     int8 array its `pack_sequence` returns, so the running total wraps at 127.
     On 100,000 bits the correct max |S_k| was 724; computing it raised 2,021
     overflow warnings and returned `passed=True` from wrapped arithmetic.

  2. **A passing p-value reported as a failure.** Random Excursion returned
     score 0.683 -- comfortably above any sensible alpha -- and was flagged
     failed.

  3. **Results inverted on structured input.** Non-Overlapping Template Matching
     scored 0.0 on `os.urandom` and 0.34 on a deliberately repeating block, the
     opposite of what the test is for.

A test suite whose job is detecting broken randomness, which itself reports
`os.urandom` as failing four of ten tests, cannot be used to make claims about
anything. So this module implements the subset that can be **validated against
the worked examples printed in SP 800-22 Rev. 1a**, and reports only those.

Four tests rather than fifteen is a smaller claim. It is also a true one, and
every value below is checked against NIST's own published numbers in
`tests/signing/test_sp800_22.py`.

WHAT THE SUBSET COVERS
======================
    monobit           are there as many ones as zeros?              (2.1)
    frequency_block   is that true *locally* as well as globally?   (2.2)
    runs              do ones and zeros alternate at the right rate? (2.3)
    cumulative_sums   does the +-1 walk stray further than it should? (2.13)

Between them these catch bias, local clustering, wrong alternation rate, and
drift -- the failure modes an HTTP transport or a stuck source actually produces.
They do not catch everything: a counter, for instance, has ideal monobit and
runs behaviour. That is exactly why a structured control is analysed alongside
the real samples, and why this module claims to be a smoke test rather than a
validation.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# SP 800-22 uses alpha = 0.01 throughout: a sequence is called non-random when
# the p-value falls below it. At that threshold a good generator is wrongly
# rejected about one time in a hundred, which is why a single failure in a
# battery is not evidence of anything much.
ALPHA = 0.01


@dataclass(frozen=True)
class TestResult:
    name: str
    p_value: float
    passed: bool
    statistic: float
    detail: str = ""

    def __str__(self) -> str:
        verdict = "PASS" if self.passed else "FAIL"
        return f"{verdict}  {self.name:22} p={self.p_value:.6f}  {self.detail}"


def _erfc(x: float) -> float:
    return math.erfc(x)


def _igamc(a: float, x: float) -> float:
    """Regularised upper incomplete gamma Q(a, x), for the chi-square p-values.

    Implemented rather than imported so this module stays dependency-free: it
    is used by two tests below and pulling in scipy for it would make the
    entropy package heavier than the signing package it supports.

    Continued fraction for x > a + 1, series otherwise; the standard split, and
    accurate to well past the precision anything here reports.
    """
    if x < 0 or a <= 0:
        raise ValueError("igamc requires a > 0 and x >= 0")
    if x == 0:
        return 1.0
    if x < a + 1:
        # Series expansion for the lower incomplete gamma, then complement.
        term = 1.0 / a
        total = term
        n = a
        for _ in range(1000):
            n += 1
            term *= x / n
            total += term
            if abs(term) < abs(total) * 1e-16:
                break
        return 1.0 - total * math.exp(-x + a * math.log(x) - math.lgamma(a))

    # Lentz's algorithm on the continued fraction.
    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-16:
            break
    return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


def to_bits(data: bytes) -> list[int]:
    """Most significant bit first, which is the order SP 800-22 assumes."""
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


# ---------------------------------------------------------------------------
# 2.1 Frequency (monobit)
# ---------------------------------------------------------------------------
def monobit(bits: list[int]) -> TestResult:
    """Are there roughly as many ones as zeros?

    The most basic test there is, and the one every other test assumes has
    already passed: a sequence that fails monobit will fail most of the rest
    for the same reason, so reporting them all as independent failures
    overstates the evidence.
    """
    n = len(bits)
    if n == 0:
        raise ValueError("empty sequence")
    s = sum(1 if b else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    p = _erfc(s_obs / math.sqrt(2))
    return TestResult("monobit", p, p >= ALPHA, s_obs,
                      f"|S_n|={abs(s)}, n={n}")


# ---------------------------------------------------------------------------
# 2.2 Frequency within a block
# ---------------------------------------------------------------------------
def frequency_within_block(bits: list[int], block_size: int = 128) -> TestResult:
    """Monobit, but locally.

    A sequence can have a perfect global balance while being all ones in its
    first half and all zeros in its second. This catches that; monobit cannot.
    """
    n = len(bits)
    blocks = n // block_size
    if blocks < 1:
        raise ValueError(f"need at least {block_size} bits")
    chi_sq = 0.0
    for i in range(blocks):
        block = bits[i * block_size:(i + 1) * block_size]
        pi = sum(block) / block_size
        chi_sq += (pi - 0.5) ** 2
    chi_sq *= 4 * block_size
    p = _igamc(blocks / 2, chi_sq / 2)
    return TestResult("frequency_block", p, p >= ALPHA, chi_sq,
                      f"{blocks} blocks of {block_size}")


# ---------------------------------------------------------------------------
# 2.3 Runs
# ---------------------------------------------------------------------------
def runs(bits: list[int]) -> TestResult:
    """Do ones and zeros alternate at the rate chance would produce?

    Detects the failure monobit is blind to: `0101...` and `0000...1111` have
    identical monobit statistics and wildly different run counts.

    The prerequisite matters. If the proportion of ones is already too far from
    a half, this test is not defined -- SP 800-22 says so explicitly, and
    running it anyway produces a number that looks like a result.
    """
    n = len(bits)
    pi = sum(bits) / n
    tau = 2 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return TestResult("runs", 0.0, False, float("nan"),
                          f"prerequisite failed: |pi-0.5|={abs(pi - 0.5):.4f} >= "
                          f"tau={tau:.4f}; monobit must pass first")
    observed = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    numerator = abs(observed - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = _erfc(numerator / denominator)
    return TestResult("runs", p, p >= ALPHA, float(observed),
                      f"{observed} runs, pi={pi:.4f}")


# ---------------------------------------------------------------------------
# 2.13 Cumulative sums
# ---------------------------------------------------------------------------
def cumulative_sums(bits: list[int], reverse: bool = False) -> TestResult:
    """How far does the +-1 walk stray from the origin?

    Catches slow drift that leaves the global proportion intact -- a source
    that is slightly biased for the first half and compensates in the second
    passes monobit and fails here.

    Python's arbitrary-precision integers make the accumulator exact. That
    sounds too obvious to state, except that it is precisely where the library
    this replaced went wrong.
    """
    n = len(bits)
    sequence = list(reversed(bits)) if reverse else bits
    running = 0
    z = 0
    for bit in sequence:
        running += 1 if bit else -1
        z = max(z, abs(running))
    if z == 0:
        return TestResult("cumulative_sums", 1.0, True, 0.0, "walk never moved")

    root_n = math.sqrt(n)

    def phi(x: float) -> float:
        return 0.5 * math.erfc(-x / math.sqrt(2))

    total = 1.0
    lower = int((-n / z + 1) // 4)
    upper = int((n / z - 1) // 4)
    for k in range(lower, upper + 1):
        total -= phi((4 * k + 1) * z / root_n) - phi((4 * k - 1) * z / root_n)
    for k in range(int((-n / z - 3) // 4), upper + 1):
        total += phi((4 * k + 3) * z / root_n) - phi((4 * k + 1) * z / root_n)

    p = max(0.0, min(1.0, total))
    direction = "backward" if reverse else "forward"
    return TestResult(f"cumulative_sums_{direction}", p, p >= ALPHA, float(z),
                      f"max |S_k|={z}")


def run_all(data: bytes) -> list[TestResult]:
    """The verified subset, in the order SP 800-22 presents them."""
    bits = to_bits(data)
    return [
        monobit(bits),
        frequency_within_block(bits),
        runs(bits),
        cumulative_sums(bits, reverse=False),
        cumulative_sums(bits, reverse=True),
    ]


__all__ = [
    "ALPHA",
    "TestResult",
    "cumulative_sums",
    "frequency_within_block",
    "monobit",
    "run_all",
    "runs",
    "to_bits",
]
