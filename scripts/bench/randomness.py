"""Statistical analysis of the collected entropy samples.

Task 8 of the Phase II memo.

READ THIS BEFORE QUOTING ANY NUMBER BELOW
=========================================
These tests cannot validate an entropy source, and this file will not pretend
otherwise.

SP 800-90B assesses a **raw noise source**. Every sample available here is
*conditioned*:

    os.urandom     a CSPRNG, seeded from the OS pool
    ANU            post-processed detector counts, not raw measurements
    NIST beacon    the output of a hash chain

Running an entropy estimator on conditioned output measures the conditioning.
A good hash produces output indistinguishable from random regardless of how
much entropy went in, so a high score here is guaranteed and means nothing about
the underlying physics. The same applies to SP 800-22, which is a randomness
test with no pretence of assessing a source.

What they *can* do is detect gross failure -- a stuck source, a truncated
transfer, a transport that silently returned the same block twice, a decoder
that mangled the bytes. That is a genuinely useful smoke test for a pipeline
which fetches randomness over HTTP from two third parties, and it is the claim
this file supports. Nothing stronger.

To make that concrete rather than assertive, a **broken control** is analysed
alongside the real sources: a stream with deliberate structure. If the battery
did not reject it, the battery would be telling us nothing about anything.

WHAT IS IMPLEMENTED, AND WHAT IS NOT
====================================
SP 800-22 is a **verified four-test subset**, implemented in
`qknot.signing.entropy.sp800_22` and validated in `tests/signing/test_sp800_22.py`.
The obvious choice, `nistrng`, was tried and dropped: it overflows an int8 in
cumulative sums, reports a p-value of 0.683 as a failure, and scores `os.urandom`
worse than a repeating block. It called the system CSPRNG a failure on four of
ten tests. Four tests that reproduce the standard's own worked examples are worth
more than fifteen that cannot recognise `os.urandom`.

SP 800-90B is *not* fully implemented here. Its non-IID track defines ten
estimators and takes the minimum; a faithful implementation is a project in
itself, and the NIST reference tool exists. What is computed instead is the
**Most Common Value** estimate (SP 800-90B section 6.3.1), which is the
simplest of the ten and is reported as what it is: since 90B takes the minimum
over all estimators, MCV alone is an **upper bound** on what the full suite
would report. An upper bound is a real, checkable statement; presenting it as
"the min-entropy" would not be.

USAGE
=====
    python scripts/bench/randomness.py                     # everything found
    python scripts/bench/randomness.py --sample data/entropy/anu_2026-07-28.bin
    python scripts/bench/randomness.py --skip-sp800-22     # fast, estimators only
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))       # runnable from a checkout without install
DEFAULT_DIR = ROOT / "data" / "entropy"

# 99% two-sided normal quantile, as specified in SP 800-90B 6.3.1.
Z_ALPHA = 2.576

# SP 800-22 section 2.x: each test states a minimum n for its asymptotic
# approximations to hold. The battery's recommended sequence length is 10^6
# bits. Below that the p-values are still *computed*, but the distributional
# assumptions behind them weaken, and a row reading "5 passed, 0 failed" on
# 8,192 bits looks exactly like a row reading the same on 10^6 -- which is how a
# short sample ends up quoted as though it meant something.
SP800_22_RECOMMENDED_BITS = 1_000_000
SP800_22_ABSOLUTE_MINIMUM_BITS = 100  # monobit's own floor


# ---------------------------------------------------------------------------
# SP 800-90B: Most Common Value estimate (section 6.3.1)
# ---------------------------------------------------------------------------
def most_common_value_min_entropy(symbols: list[int], alphabet_bits: int) -> dict[str, Any]:
    """The MCV min-entropy estimate, with its upper confidence bound.

    SP 800-90B 6.3.1: find the most frequent symbol, take the upper 99% bound on
    its probability, and report -log2 of that. The confidence bound is what makes
    this conservative -- using the raw frequency would overstate the entropy of a
    short sample.

    Reported per symbol *and* normalised per bit, because comparing a bytewise
    estimate against a bitwise one without normalising is a common way to produce
    a number that looks alarming and is not.
    """
    n = len(symbols)
    if n < 2:
        raise ValueError("need at least two symbols")

    counts = Counter(symbols)
    mode_count = max(counts.values())
    p_hat = mode_count / n
    # Upper bound on the mode's probability at 99% confidence.
    p_upper = min(1.0, p_hat + Z_ALPHA * math.sqrt(p_hat * (1 - p_hat) / (n - 1)))
    min_entropy = -math.log2(p_upper)

    return {
        "n_symbols": n,
        "alphabet_bits": alphabet_bits,
        "distinct_symbols": len(counts),
        "mode_count": mode_count,
        "p_hat": round(p_hat, 8),
        "p_upper_99": round(p_upper, 8),
        "min_entropy_per_symbol": round(min_entropy, 4),
        "min_entropy_per_bit": round(min_entropy / alphabet_bits, 4),
        "ideal_per_symbol": alphabet_bits,
    }


def chi_square_uniformity(symbols: list[int], alphabet_size: int) -> dict[str, Any]:
    """A goodness-of-fit check against the uniform distribution.

    Not part of 90B, included because it answers a different question from the
    MCV estimate: MCV looks only at the *most frequent* symbol, so a source with
    a flat-but-wrong distribution passes it. This looks at the whole histogram.
    """
    n = len(symbols)
    expected = n / alphabet_size
    counts = Counter(symbols)
    statistic = sum((counts.get(s, 0) - expected) ** 2 / expected
                    for s in range(alphabet_size))
    dof = alphabet_size - 1
    # Wilson-Hilferty normal approximation: exact for the sample sizes here and
    # avoids a scipy dependency in a script that is otherwise pure stdlib.
    z = ((statistic / dof) ** (1 / 3) - (1 - 2 / (9 * dof))) / math.sqrt(2 / (9 * dof))
    p_value = 0.5 * math.erfc(z / math.sqrt(2))
    return {
        "chi_square": round(statistic, 2),
        "dof": dof,
        "p_value": round(p_value, 6),
        "uniform_at_0.01": p_value > 0.01,
    }


# ---------------------------------------------------------------------------
# SP 800-22, from qknot's own verified implementation
# ---------------------------------------------------------------------------
# `nistrng` was used here first and had to be dropped. Three defects surfaced:
#
#   1. cumulative sums accumulated the +-1 walk in an int8, wrapping at 127.
#      On 100,000 bits the true max |S_k| was 724; it raised 2,021 overflow
#      warnings and returned `passed=True` from wrapped arithmetic.
#   2. Random Excursion returned p = 0.683 and reported it as a failure.
#   3. Non-Overlapping Template Matching scored `os.urandom` at 0.0 and a
#      deliberately repeating block at 0.34 -- the wrong way round.
#
# It reported `os.urandom` as failing four of ten tests. A suite that cannot
# recognise the system CSPRNG cannot support a claim about anything else.
#
# `qknot.signing.entropy.sp800_22` implements four of the fifteen tests, each
# checked against the worked example printed in the standard or, where the
# recalled constant proved unreliable, against simulation. Four verified tests
# beat fifteen unverified ones.
def sp800_22(data: bytes) -> dict[str, Any]:
    from qknot.signing.entropy.sp800_22 import ALPHA, run_all

    bits = len(data) * 8
    if bits < SP800_22_ABSOLUTE_MINIMUM_BITS:
        return {"error": f"only {bits} bits; below the floor for any test"}

    started = time.perf_counter()
    results = run_all(data)
    tests = {
        r.name: {"passed": r.passed, "p_value": round(r.p_value, 6),
                 "statistic": r.statistic, "detail": r.detail}
        for r in results
    }
    passed = sum(1 for t in tests.values() if t["passed"])
    undersized = bits < SP800_22_RECOMMENDED_BITS
    return {
        "bits": bits,
        "undersized": undersized,
        "recommended_bits": SP800_22_RECOMMENDED_BITS,
        "alpha": ALPHA,
        "tests_run": len(tests),
        "tests_passed": passed,
        "tests_failed": len(tests) - passed,
        "wall_seconds": round(time.perf_counter() - started, 2),
        "implementation": "qknot.signing.entropy.sp800_22 (verified subset)",
        "not_implemented": [
            "binary_matrix_rank", "dft", "non_overlapping_template",
            "overlapping_template", "maurers_universal", "linear_complexity",
            "serial", "approximate_entropy", "random_excursions",
            "random_excursions_variant", "longest_run_of_ones",
        ],
        "tests": tests,
    }


# ---------------------------------------------------------------------------
def analyse(name: str, data: bytes, skip_sp800_22: bool) -> dict[str, Any]:
    as_bytes = list(data)
    as_bits = [(b >> i) & 1 for b in data for i in range(7, -1, -1)]

    result: dict[str, Any] = {
        "source": name,
        "bytes": len(data),
        "bits": len(as_bits),
        "sp800_90b_mcv_bitwise": most_common_value_min_entropy(as_bits, 1),
        "sp800_90b_mcv_bytewise": most_common_value_min_entropy(as_bytes, 8),
        "chi_square_bytewise": chi_square_uniformity(as_bytes, 256),
    }
    if not skip_sp800_22:
        result["sp800_22"] = sp800_22(data)
    return result


def broken_control(n_bytes: int) -> tuple[str, bytes]:
    """A source that must fail, so a pass elsewhere means something.

    Deliberately crude: a repeating block with a slow-moving counter. It has
    plenty of distinct byte values, so a naive "are all 256 symbols present"
    check would wave it through -- the point is that the *battery* catches
    structure that a casual glance does not.
    """
    block = bytes(range(256))
    repeats = -(-n_bytes // len(block))
    return "BROKEN CONTROL (repeating block)", (block * repeats)[:n_bytes]


def report(results: list[dict[str, Any]]) -> None:
    print("=" * 78)
    print("Entropy sample analysis")
    print("=" * 78)
    print("These tests detect gross failure. They cannot validate an entropy")
    print("source: every sample here is conditioned output, so a high score is")
    print("expected and says nothing about the underlying physics.")
    print()

    print("SP 800-90B MOST COMMON VALUE  (upper bound on the full suite)")
    print("-" * 78)
    print(f"{'source':34} {'H_min/bit':>10} {'H_min/byte':>12} {'chi2 p':>10} {'uniform':>9}")
    for r in results:
        bit = r["sp800_90b_mcv_bitwise"]["min_entropy_per_bit"]
        byte = r["sp800_90b_mcv_bytewise"]["min_entropy_per_symbol"]
        chi = r["chi_square_bytewise"]
        print(f"{r['source'][:34]:34} {bit:>10.4f} {byte:>12.4f} "
              f"{chi['p_value']:>10.4f} {str(chi['uniform_at_0.01']):>9}")
    print()
    print("  ideal: 1.0000 per bit, 8.0000 per byte")
    print("  90B takes the MINIMUM over ten estimators, so the full suite would")
    print("  report a value no higher than these.")
    print()

    if any("sp800_22" in r for r in results):
        print("SP 800-22 BATTERY")
        print("-" * 78)
        print(f"{'source':34} {'passed':>9} {'failed':>8} {'run':>6} {'seconds':>9}")
        for r in results:
            block = r.get("sp800_22")
            if not block or "error" in block:
                print(f"{r['source'][:34]:34} {(block or {}).get('error', 'not run')}")
                continue
            flag = "  UNDERSIZED" if block.get("undersized") else ""
            print(f"{r['source'][:34]:34} {block['tests_passed']:>9} "
                  f"{block['tests_failed']:>8} {block['tests_run']:>6} "
                  f"{block['wall_seconds']:>9.2f}{flag}")
        print()

        undersized = [(r["source"], r["sp800_22"]["bits"]) for r in results
                      if r.get("sp800_22", {}).get("undersized")]
        if undersized:
            print("  UNDERSIZED SAMPLES -- these rows are not results")
            for name, bits in undersized:
                short_by = SP800_22_RECOMMENDED_BITS / bits
                print(f"    {name:32} {bits:>10,} bits "
                      f"({short_by:.0f}x short of the recommended 1,000,000)")
            print("    A pass on a short sample is not evidence of randomness:")
            print("    the tests have far less power to detect a defect, so")
            print("    passing is close to guaranteed. Collect more before")
            print("    quoting these.")
            print()
        print("  per-test p-values")
        for r in results:
            block = r.get("sp800_22")
            if not block or "error" in block:
                continue
            print(f"    {r['source'][:40]}")
            for name, t in block["tests"].items():
                mark = "PASS" if t["passed"] else "FAIL"
                print(f"      {mark}  {name:26} p={t['p_value']:.6f}  {t['detail']}")
        print()
        first = next((r.get("sp800_22") for r in results if r.get("sp800_22")), None)
        if first:
            print(f"  {len(first['not_implemented'])} of the fifteen SP 800-22 "
                  f"tests are NOT implemented here. This is a verified subset,")
            print("  not the full battery; see the module docstring for why that "
                  "trade was made.")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR,
                        help="Directory of collected .bin samples.")
    parser.add_argument("--sample", type=Path, nargs="*",
                        help="Specific sample files, instead of scanning --dir.")
    parser.add_argument("--skip-sp800-22", action="store_true",
                        help="Estimators only. The battery is slow on 10^6 bits.")
    parser.add_argument("--no-control", action="store_true",
                        help="Omit the deliberately broken control sample.")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    paths = args.sample or sorted(args.dir.glob("*.bin"))
    paths = [p for p in paths if not p.name.endswith(".partial.bin")]
    if not paths:
        print(f"No samples in {args.dir}. Run scripts/bench/collect_entropy.py first.")
        return 2

    results = []
    for path in paths:
        data = path.read_bytes()
        print(f"analysing {path.name} ({len(data):,} bytes)...")
        results.append(analyse(path.stem, data, args.skip_sp800_22))

    if not args.no_control:
        # Match the largest real sample. Sizing it to `paths[0]` -- which is
        # alphabetical, so `anu` -- gave a 1 KB control against a 125 KB sample,
        # comparing two different things.
        largest = max(len(p.read_bytes()) for p in paths)
        name, data = broken_control(largest)
        print(f"analysing the control ({len(data):,} bytes)...")
        results.append(analyse(name, data, args.skip_sp800_22))

    print()
    report(results)

    control = next((r for r in results if "CONTROL" in r["source"]), None)
    if control and "sp800_22" in control and "error" not in control["sp800_22"]:
        if control["sp800_22"]["tests_failed"] == 0:
            print("WARNING: the broken control PASSED every test. The battery is")
            print("not discriminating, so no conclusion should be drawn from the")
            print("real sources passing either.")
        else:
            print(f"The broken control failed "
                  f"{control['sp800_22']['tests_failed']} test(s), so the battery")
            print("does discriminate. That is what makes the other rows meaningful.")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nfull results -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
