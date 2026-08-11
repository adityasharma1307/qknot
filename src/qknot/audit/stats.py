#!/usr/bin/env python3
"""Statistical inference for the QKnot audit.

Two modes.

SINGLE DATASET
    python -m qknot.audit.stats data/full_2026-07-06.jsonl

    Wilson intervals and the power analysis for one scan. This is the Phase I
    analysis and reproduces the published figures.

STRATIFIED
    python -m qknot.audit.stats --head data/head_10k.jsonl --tail data/longtail_10k.jsonl \
        --manifest data/longtail_manifest_2026-07-25.json

    Three blocks, per the two-stratum design:
      1. Head stratum (top 10,000 by downloads)
      2. Long-tail stratum (uniform random draw from everything else)
      3. Combined weighted estimate for the registry as a whole

    Plus the head-versus-tail contrast, which is the actual finding. Two
    separate percentages side by side do not make a claim; the difference
    between them, with an interval and a test, does.

A NOTE ON THE COMBINED ESTIMATE
    The head stratum is a *census*, not a sample: we audit all 10,000 of the
    top 10,000. Its proportion is therefore known exactly and contributes no
    sampling variance. All uncertainty in the combined estimate comes from the
    long-tail stratum, scaled by that stratum's weight, which is why the
    combined interval is wider than the head interval despite resting on 20,000
    observations. This is a property of the design, not a defect.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from math import ceil, lgamma
from pathlib import Path
from typing import Any

# 95% two-sided normal quantile. The exact value is 1.9599639845400545; 1.96 is
# kept because it is what the published Phase I intervals were computed with,
# and changing it would silently perturb every previously reported figure.
#
# The cost is bounded and negligible: verified against
# statsmodels.stats.proportion.proportion_confint(method='wilson'), the largest
# disagreement across the reported proportions is 1.5e-5 percentage points,
# invisible at the three-decimal precision used in the tables. Substituting the
# exact quantile reproduces statsmodels to 1.7e-18, confirming the formula
# itself is right and only the constant differs.
Z = 1.96

DEFAULT_DATASET = Path("data/full_2026-07-06.jsonl")
HEAD_POPULATION = 10_000  # Stratum A is defined as exactly the top 10,000


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load(path: Path) -> list[dict]:
    """Load a JSONL audit output, deduplicated to the latest record per model.

    The dedupe defends against a historical run_audit() bug in which a
    resume=False rerun appended a second copy of every row instead of
    truncating, corrupting an output to n=2000 with every label count doubled.
    """
    if not path.exists():
        sys.exit(
            f"Dataset not found: {path}\n"
            f"Available datasets are listed in docs/DATASETS.md"
        )
    raw = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    latest: dict[str, dict] = {}
    for rec in raw:
        # HuggingFace records key on `model_id`; PyPI and npm on `project`.
        # Keying on model_id alone raised KeyError on the package ecosystems,
        # which means this loader had NEVER successfully run on the PyPI or npm
        # data -- the cross-ecosystem comparison the paper is built on could
        # not have been produced through it. One identifier, whichever is
        # present.
        key = rec.get("model_id") or rec.get("project")
        if key is None:
            raise KeyError(
                f"record has neither model_id nor project: {sorted(rec)[:6]}")
        if key not in latest or rec["audit_ts"] > latest[key]["audit_ts"]:
            latest[key] = rec
    if len(raw) != len(latest):
        print(f"NOTE: {path} had {len(raw)} rows but {len(latest)} unique "
              f"identifiers; deduped to the latest record each.\n")
    return list(latest.values())


def counts(records: list[dict]) -> dict[str, int]:
    """Tally the labels, splitting `error` by whether a signature was present.

    The `error` label covers two situations that must not be pooled:

      * A repo carrying a signature this tool cannot parse. It IS signed; we
        just cannot say with what. Belongs under the signed subtotal.
      * A repo that could not be retrieved at all -- deleted, renamed, gated.
        It is neither signed nor unsigned, because we never saw its files.
        Belongs outside both, as coverage loss.

    Pooling them makes the signed subtotal stop summing, and would let missing
    coverage be read as a statement about signing. `has_signature` is what
    distinguishes the two.
    """
    err = [r for r in records if r["q_label"] == "error"]
    return {
        "n": len(records),
        "signed": sum(1 for r in records if r["has_signature"]),
        "unsigned": sum(1 for r in records if r["q_label"] == "unsigned"),
        "vulnerable": sum(1 for r in records if r["q_label"] == "vulnerable"),
        "safe": sum(1 for r in records if r["q_label"] == "safe"),
        "mixed": sum(1 for r in records if r["q_label"] == "mixed"),
        "error": len(err),
        # signature present, algorithm indeterminate
        "unparseable": sum(1 for r in err if r["has_signature"]),
        # repo never observed: coverage loss, not a finding about signing
        "unavailable": sum(1 for r in err if not r["has_signature"]),
    }


# ---------------------------------------------------------------------------
# Intervals
# ---------------------------------------------------------------------------
def wilson_ci(k: int, n: int, z: float = Z) -> tuple[float, float]:
    """Wilson score interval. Preferred over Wald here because the proportions
    of interest are near zero, where Wald produces intervals that include
    negative values or collapse to a point."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return max(0.0, centre - margin), min(1.0, centre + margin)


def newcombe_diff_ci(k1: int, n1: int, k2: int, n2: int, z: float = Z) -> tuple[float, float]:
    """Newcombe's score interval for the difference of two proportions.

    Built from the two Wilson intervals rather than from a pooled normal
    approximation, so it stays sensible when one or both counts are zero --
    which is the expected case for post-quantum adoption.
    """
    p1, p2 = (k1 / n1 if n1 else 0.0), (k2 / n2 if n2 else 0.0)
    l1, u1 = wilson_ci(k1, n1, z)
    l2, u2 = wilson_ci(k2, n2, z)
    lower = (p1 - p2) - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    upper = (p1 - p2) + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return max(-1.0, lower), min(1.0, upper)


# ---------------------------------------------------------------------------
# Fisher's exact test, two-sided
# ---------------------------------------------------------------------------
def _log_choose(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)


def fisher_exact_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p-value for the 2x2 table [[a, b], [c, d]].

    Computed in log space via lgamma. The counts here are tiny relative to the
    sample sizes, which is exactly the regime where a chi-square approximation
    is unreliable and an exact test is the right choice. Summing the
    hypergeometric probabilities no greater than the observed one is the
    conventional two-sided construction.
    """
    row1, row2 = a + b, c + d
    col1, total = a + c, a + b + c + d
    if total == 0 or row1 == 0 or row2 == 0 or col1 == 0 or col1 == total:
        return 1.0

    def log_p(x: int) -> float:
        return (
            _log_choose(row1, x)
            + _log_choose(row2, col1 - x)
            - _log_choose(total, col1)
        )

    observed = log_p(a)
    lo, hi = max(0, col1 - row2), min(row1, col1)
    # Small tolerance so floating point does not exclude the mirror-image table.
    total_p = sum(
        math.exp(lp)
        for lp in (log_p(x) for x in range(lo, hi + 1))
        if lp <= observed + 1e-9
    )
    return min(1.0, total_p)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def pct(x: float) -> str:
    return f"{100 * x:.3f}%"


def print_block(title: str, c: dict[str, int], population: int | None = None) -> None:
    print(f"{title}")
    print("-" * len(title))
    n = c["n"]
    if population:
        frac = n / population
        kind = "census" if frac >= 0.999 else f"sample, {100 * frac:.4f}% of {population:,}"
        print(f"n = {n:,}   ({kind})")
    else:
        print(f"n = {n:,}")
    print()

    def line(label: str, k: int, indent: str = "  ") -> None:
        lo, hi = wilson_ci(k, n)
        print(f"{indent}{label:<14} {k:>7,} {pct(k / n) if n else 'n/a':>9}   "
              f"[{pct(lo):>8}, {pct(hi):>8}]")

    # `signed` is not a peer of the q_labels, it is their union minus
    # `unsigned`. Printing it in a flat list invites the reading that a repo
    # could be counted as both signed and vulnerable, or that signed and safe
    # are alternatives. Indent the breakdown so the hierarchy is unambiguous.
    print(f"  {'':<14} {'count':>7} {'share':>9}   {'95% Wilson CI':>22}")
    line("unsigned", c["unsigned"])
    line("signed", c["signed"])
    print("                 of which:")
    line("vulnerable", c["vulnerable"], indent="      ")
    line("safe (PQC)", c["safe"], indent="      ")
    line("mixed", c["mixed"], indent="      ")
    line("unparseable", c["unparseable"], indent="      ")
    if c["unavailable"]:
        line("unavailable", c["unavailable"])

    breakdown = c["vulnerable"] + c["safe"] + c["mixed"] + c["unparseable"]
    if breakdown != c["signed"]:
        print(f"\n  WARNING: signed={c['signed']} but the breakdown sums to "
              f"{breakdown}. The labels should partition the signed repos.")
    if c["signed"] + c["unsigned"] + c["unavailable"] != n:
        print(f"\n  WARNING: signed+unsigned+unavailable != n "
              f"({c['signed']}+{c['unsigned']}+{c['unavailable']} != {n}).")

    if c["unparseable"]:
        print(f"\n  Note: {c['unparseable']} signed repo(s) carry a signature this "
              f"tool cannot parse.\n  They are counted as signed but their algorithm "
              f"is unknown, so they are\n  neither evidence for nor against "
              f"post-quantum adoption.")
    if c["unavailable"]:
        obs = n - c["unavailable"]
        print(f"\n  Note: {c['unavailable']} repo(s) could not be retrieved (deleted, "
              f"renamed or gated\n  between the frame being built and the scan). They "
              f"are coverage loss, not\n  a finding about signing. Rates above are over "
              f"n={n:,}; over the {obs:,}\n  actually observed, signed is "
              f"{100 * c['signed'] / obs:.3f}%.")
    print()


def print_combined(head: dict, tail: dict, tail_population: int) -> None:
    """Stratified estimate for the whole registry."""
    # Uppercase N denotes population size and lowercase n sample size, as in
    # every standard treatment of stratified sampling. Renaming these to
    # satisfy a linter would make the code harder to check against the
    # textbook formulae it implements.
    n_h, n_t = head["n"], tail["n"]
    # `tail_population` is the FULL frame size from the manifest, but the tail
    # was drawn from `frame - head` (see run_*_audit.py). So the tail stratum's
    # population is the frame minus the head, and the head and tail PARTITION
    # the registry: N = frame_size, not frame_size + head. Using the raw frame
    # size as N_t double-counts the head's 10,000 in both strata -- a 0.23%
    # error in the weights and in the reported N, which is small but wrong, and
    # a measurement paper states these as exact.
    N_h = HEAD_POPULATION  # noqa: N806
    N = tail_population  # noqa: N806  -- the whole registry
    N_t = N - N_h  # noqa: N806
    w_h, w_t = N_h / N, N_t / N

    if n_h != N_h:
        print(f"  WARNING: the head stratum is defined as a census of "
              f"{N_h:,} but the head file holds {n_h:,}. The 'no sampling "
              f"variance' claim below assumes a full census; with {n_h:,} it "
              f"is a partial one and the head DOES carry variance the "
              f"finite-population correction here understates. Re-audit the "
              f"head to a full {N_h:,} before quoting these intervals.\n")

    title = "BLOCK 3 -- COMBINED WEIGHTED ESTIMATE (whole registry)"
    print(title)
    print("-" * len(title))
    print(f"Stratum weights: head {w_h:.6f} (N={N_h:,}), tail {w_t:.6f} (N={N_t:,})")
    print(f"Registry population N = {N:,}")
    print()
    print("  The head stratum is a census, so it contributes no sampling")
    print("  variance. All uncertainty below comes from the long-tail draw.")
    print()
    print(f"  {'label':<12} {'estimate':>10}   {'95% CI':>24}")
    for label in ("signed", "unsigned", "vulnerable", "safe"):
        p_h = head[label] / n_h if n_h else 0.0
        p_t = tail[label] / n_t if n_t else 0.0
        p = w_h * p_h + w_t * p_t

        # Finite-population-corrected variance, head term vanishes at census.
        fpc_h = max(0.0, 1 - n_h / N_h) if N_h else 0.0
        fpc_t = max(0.0, 1 - n_t / N_t) if N_t else 0.0
        var = (
            (w_h**2) * (p_h * (1 - p_h) / n_h) * fpc_h if n_h else 0.0
        ) + (
            (w_t**2) * (p_t * (1 - p_t) / n_t) * fpc_t if n_t else 0.0
        )
        se = math.sqrt(var)

        if head[label] + tail[label] == 0:
            # A normal interval around zero is meaningless. Fall back to the
            # weighted combination of per-stratum Wilson upper bounds, which is
            # conservative and honest about being one-sided.
            _, hi_h = wilson_ci(0, n_h)
            _, hi_t = wilson_ci(0, n_t)
            hi = w_h * hi_h + w_t * hi_t
            print(f"  {label:<12} {pct(p):>10}   [   0.000%, {pct(hi):>8}]  one-sided")
        else:
            print(f"  {label:<12} {pct(p):>10}   "
                  f"[{pct(max(0.0, p - Z * se)):>8}, {pct(min(1.0, p + Z * se)):>8}]")
    print()


def print_contrast(head: dict, tail: dict) -> None:
    title = "HEAD VERSUS TAIL -- the contrast"
    print(title)
    print("-" * len(title))
    n_h, n_t = head["n"], tail["n"]

    for label in ("signed", "vulnerable", "safe"):
        k_h, k_t = head[label], tail[label]
        p_h = k_h / n_h if n_h else 0.0
        p_t = k_t / n_t if n_t else 0.0
        lo, hi = newcombe_diff_ci(k_h, n_h, k_t, n_t)
        p_value = fisher_exact_two_sided(k_h, n_h - k_h, k_t, n_t - k_t)

        ratio = (f"{p_h / p_t:.1f}x" if p_t > 0 else
                 ("inf" if p_h > 0 else "n/a"))

        print(f"  {label}")
        print(f"    head {k_h:>6,}/{n_h:,} = {pct(p_h):<9}   "
              f"tail {k_t:>6,}/{n_t:,} = {pct(p_t):<9}")
        print(f"    difference {pct(p_h - p_t)}  95% CI [{pct(lo)}, {pct(hi)}]  "
              f"ratio {ratio}")
        print(f"    Fisher exact p = {p_value:.4g}"
              f"{'  (significant at 0.05)' if p_value < 0.05 else '  (not significant)'}")
        print()

    if head["safe"] == 0 and tail["safe"] == 0:
        print("  No post-quantum signatures in either stratum. The null result")
        print("  holds across both the most-downloaded models and a uniform")
        print("  draw from the registry as a whole, so it is not an artefact")
        print("  of sampling only popular models.")
        print()


def print_power(n: int) -> None:
    title = "POWER"
    print(title)
    print("-" * len(title))
    p0, p1 = 0.0, 0.01
    z_alpha, z_beta = 1.645, 0.842  # one-tailed alpha=0.05, power=0.80
    p_bar = (p0 + p1) / 2
    n_needed = ceil(
        (z_alpha * math.sqrt(2 * p_bar * (1 - p_bar))
         + z_beta * math.sqrt(p0 * (1 - p0) + p1 * (1 - p1))) ** 2
        / (p1 - p0) ** 2
    )
    print(f"To detect 1% post-quantum adoption (vs 0%) at 80% power: "
          f"minimum n = {n_needed}")
    if n >= n_needed:
        print(f"n = {n:,} is sufficient to rule out even 1% adoption.")
    else:
        print(f"WARNING: n = {n:,} is BELOW {n_needed}; the null result is underpowered.")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dataset", nargs="?", type=Path, default=None,
                        help="Single audit output to analyse.")
    parser.add_argument("--head", type=Path, help="Stratum A audit output.")
    parser.add_argument("--tail", type=Path, help="Stratum B audit output.")
    parser.add_argument("--manifest", type=Path,
                        help="Sampling manifest from sample_longtail.py, read for "
                             "the long-tail population size used as the stratum weight.")
    parser.add_argument("--tail-population", type=int, default=None,
                        help="Long-tail population size, if no manifest is available.")
    parser.add_argument("--stratified", type=Path, default=None,
                        help="A single audit output whose records carry a "
                             "`stratum` field of 'head' or 'tail'. This is what "
                             "run_pypi_audit.py and run_npm_audit.py write -- "
                             "one file, both strata -- so it is split here "
                             "rather than requiring two separate files.")
    args = parser.parse_args(argv)

    if args.stratified:
        records = load(args.stratified)
        strata = {str(r.get("stratum")) for r in records}
        if strata - {"head", "tail"}:
            parser.error(
                f"{args.stratified} has strata {sorted(strata)}; a stratified "
                f"file must label every record 'head' or 'tail'")
        head_recs = [r for r in records if r.get("stratum") == "head"]
        tail_recs = [r for r in records if r.get("stratum") == "tail"]
        if not head_recs or not tail_recs:
            parser.error(
                f"{args.stratified} has {len(head_recs)} head and "
                f"{len(tail_recs)} tail records; both strata must be present")
        head, tail = counts(head_recs), counts(tail_recs)
        return _report_stratified(head, tail, args, parser, str(args.stratified),
                                  str(args.stratified))

    stratified = bool(args.head or args.tail)
    if stratified and not (args.head and args.tail):
        parser.error("--head and --tail must be given together")

    if not stratified:
        dataset = args.dataset or DEFAULT_DATASET
        records = load(dataset)
        print(f"dataset = {dataset}\n")
        print_block("SINGLE-STRATUM ANALYSIS", counts(records))
        print_power(len(records))
        return 0

    head = counts(load(args.head))
    tail = counts(load(args.tail))
    return _report_stratified(head, tail, args, parser,
                              str(args.head), str(args.tail))


def _report_stratified(head: dict, tail: dict, args: Any, parser: Any,
                        head_label: str, tail_label: str) -> int:
    tail_population = args.tail_population
    if tail_population is None and args.manifest:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        tail_population = manifest.get("frame_size")
        print(f"manifest = {args.manifest}  (seed {manifest.get('seed')}, "
              f"frame {tail_population:,})\n")
    if tail_population is None:
        parser.error(
            "the long-tail population size is required to weight the strata; "
            "pass --manifest or --tail-population"
        )

    print(f"head = {head_label}")
    print(f"tail = {tail_label}\n")
    print_block("BLOCK 1 -- HEAD STRATUM (top 10,000 by downloads)", head,
                population=HEAD_POPULATION)
    print_block("BLOCK 2 -- LONG-TAIL STRATUM (uniform random draw)", tail,
                population=tail_population)
    print_combined(head, tail, tail_population)
    print_contrast(head, tail)
    print_power(head["n"] + tail["n"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
