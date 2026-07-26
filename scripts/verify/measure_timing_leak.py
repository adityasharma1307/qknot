#!/usr/bin/env python3
"""Measure the ML-DSA timing side channel, and show that noise does not close it.

This produces the evidence cited in docs/THREAT-MODEL.md. It exists so the
claim "random delay is not a countermeasure" is a measurement in this
repository rather than a citation to folklore.

TWO EXPERIMENTS
===============
1. **The leak.** Sign repeatedly with one key, then with another, and compare
   the distributions. ML-DSA uses rejection sampling, so the iteration count --
   and therefore the duration -- depends on secret key material.

2. **Whether noise helps.** Add uniform random delay and ask how many traces an
   attacker needs to tell the two keys apart by comparing mean durations.
   Averaging suppresses zero-mean noise as 1/sqrt(N) while the secret-dependent
   signal stays fixed, so accuracy should climb with trace count regardless of
   how much noise is added. If it does, noise injection is a speed bump rather
   than a countermeasure.

    python scripts/verify/measure_timing_leak.py
    python scripts/verify/measure_timing_leak.py --samples 100 --noise-ms 200
"""
from __future__ import annotations

import argparse
import random
import statistics
import sys
import time


def collect(sign, secret_key, n: int) -> list[float]:
    """Time n signatures in milliseconds."""
    timings = []
    for i in range(n):
        message = i.to_bytes(8, "big")
        start = time.perf_counter()
        sign(secret_key, message)
        timings.append((time.perf_counter() - start) * 1000)
    return timings


def attack_accuracy(a: list[float], b: list[float], traces: int,
                    noise_ms: float, trials: int, rng: random.Random) -> float:
    """How often an attacker correctly tells key A from key B.

    The attacker draws `traces` timings per key, adds the defender's random
    delay, and guesses by comparing means. 50% is chance.
    """
    truth = statistics.median(a) < statistics.median(b)
    correct = 0
    for _ in range(trials):
        mean_a = statistics.mean(
            t + rng.uniform(0, noise_ms) for t in rng.choices(a, k=traces))
        mean_b = statistics.mean(
            t + rng.uniform(0, noise_ms) for t in rng.choices(b, k=traces))
        if (mean_a < mean_b) == truth:
            correct += 1
    return 100 * correct / trials


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", type=int, default=40,
                        help="Signatures timed per key (pure-Python ML-DSA is slow).")
    parser.add_argument("--noise-ms", type=float, default=50.0,
                        help="Uniform random delay the defender adds, in ms.")
    parser.add_argument("--trials", type=int, default=200,
                        help="Repetitions per trace count when estimating accuracy.")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)

    try:
        from dilithium_py.ml_dsa import ML_DSA_44
    except ImportError:
        raise SystemExit(
            "dilithium-py is required: pip install dilithium-py"
        ) from None

    rng = random.Random(args.seed)

    print("ML-DSA-44 timing side channel")
    print("=" * 72)
    print(f"{args.samples} signatures per key, pure-Python dilithium-py\n")

    pk_a, sk_a = ML_DSA_44.keygen()
    pk_b, sk_b = ML_DSA_44.keygen()
    a = collect(ML_DSA_44.sign, sk_a, args.samples)
    b = collect(ML_DSA_44.sign, sk_b, args.samples)

    print("1. Is there a leak?")
    print("-" * 72)
    for name, samples in (("key A", a), ("key B", b)):
        ordered = sorted(samples)
        print(f"  {name}: min {ordered[0]:6.1f} | median "
              f"{statistics.median(samples):6.1f} | max {ordered[-1]:6.1f} ms")
    separation = abs(statistics.median(a) - statistics.median(b))
    spread = sorted(a)[-1] / sorted(a)[0]
    print(f"\n  within-key spread : {spread:.1f}x  (rejection sampling)")
    print(f"  between-key gap   : {separation:.1f} ms  <- the signal")

    print(f"\n2. Does adding {args.noise_ms:.0f} ms of random delay close it?")
    print("-" * 72)
    print(f"  noise is ~{args.noise_ms / max(separation, 0.01):.0f}x the signal\n")
    print(f"  {'traces/key':>11}   attacker identifies the key correctly")
    trend = []
    for traces in (1, 10, 50, 200, 800, 3200):
        accuracy = attack_accuracy(a, b, traces, args.noise_ms, args.trials, rng)
        trend.append(accuracy)
        bar = "#" * int((accuracy - 50) / 2.5) if accuracy > 50 else ""
        print(f"  {traces:>11}   {accuracy:5.1f}%  {bar}")

    print("\n" + "=" * 72)
    if trend[-1] > trend[0] + 5:
        print("Accuracy rises with the number of traces. The noise is being")
        print("averaged away while the secret-dependent signal remains.")
        print()
        print("Random delay raises the attacker's cost by a constant factor.")
        print("It does not close the channel, and claiming otherwise would be")
        print("worse than claiming nothing. The countermeasure is to bound the")
        print("exposure: see docs/THREAT-MODEL.md.")
        return 0
    print("Accuracy did not rise measurably. Increase --samples or --trials;")
    print("with too few samples the estimate is dominated by its own noise.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
