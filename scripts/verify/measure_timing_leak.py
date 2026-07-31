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
import math
import random
import statistics
import sys
import time


def collect(sign, secret_key, n: int) -> list[float]:
    """Time n signatures in milliseconds, measured at nanosecond resolution.

    `perf_counter_ns` rather than `perf_counter`: liboqs signs ML-DSA-44 in
    roughly 0.1 ms, so a float-seconds clock reports medians of `0.0` and a
    between-key gap of `0.0`. That is the measurement hitting its own floor,
    not evidence of constant-time behaviour, and reporting it as the latter
    would be exactly the inference-from-insufficient-evidence this project
    keeps finding elsewhere.
    """
    timings = []
    for i in range(n):
        message = i.to_bytes(8, "big")
        start = time.perf_counter_ns()
        sign(secret_key, message)
        timings.append((time.perf_counter_ns() - start) / 1e6)
    return timings


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson interval, as used throughout the ecosystem audits.

    An accuracy without an interval cannot distinguish "no leak" from "not
    enough trials to see one". 56.5% at 3,200 traces looks like a signal and is
    indistinguishable from chance at this sample size; the interval says so.
    """
    if n == 0:
        return (0.0, 1.0)
    phat = successes / n
    denominator = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


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
    low, high = wilson(correct, trials)
    return 100 * correct / trials, 100 * low, 100 * high


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
    parser.add_argument("--backend", default="dilithium-py",
                        choices=("dilithium-py", "liboqs"),
                        help="Which implementation to measure. The protocol, "
                             "trace counts and statistics are identical for "
                             "both, so the two runs are directly comparable -- "
                             "which is the entire point: a paired result is "
                             "stronger than either measurement alone.")
    args = parser.parse_args(argv)

    if args.backend == "liboqs":
        try:
            import oqs
        except Exception as exc:                        # noqa: BLE001
            raise SystemExit(
                f"liboqs is not available here: {exc}\n\n"
                f"That is a reportable outcome, not a failure of this script. "
                f"See docs/TASK-D.md: no runtime mechanism exists to establish "
                f"liboqs' constant-time status either, so 'we could not "
                f"establish this' is the finding."
            ) from None

        class _Signer:
            """Adapter so both backends present the same sign(sk, msg) shape."""

            def __init__(self) -> None:
                self.mech = "ML-DSA-44"

            def keygen(self) -> tuple[bytes, object]:
                signer = oqs.Signature(self.mech)
                return signer.generate_keypair(), signer

            @staticmethod
            def sign(signer: object, message: bytes) -> bytes:
                return signer.sign(message)          # type: ignore[attr-defined]

        impl = _Signer()
        keygen, sign_fn = impl.keygen, impl.sign
        label = f"liboqs {getattr(oqs, 'oqs_version', lambda: '?')()}"
    else:
        try:
            from dilithium_py.ml_dsa import ML_DSA_44
        except ImportError:
            raise SystemExit(
                "dilithium-py is required: pip install dilithium-py"
            ) from None
        keygen, sign_fn = ML_DSA_44.keygen, ML_DSA_44.sign
        label = "pure-Python dilithium-py"

    rng = random.Random(args.seed)

    print("ML-DSA-44 timing side channel")
    print("=" * 72)
    print(f"{args.samples} signatures per key, {label}\n")

    _, sk_a = keygen()
    _, sk_b = keygen()
    a = collect(sign_fn, sk_a, args.samples)
    b = collect(sign_fn, sk_b, args.samples)

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
    print(f"  {'traces/key':>11}   attacker accuracy (95% Wilson interval)")
    trend = []
    separated = None
    for traces in (1, 10, 50, 200, 800, 3200):
        accuracy, low, high = attack_accuracy(a, b, traces, args.noise_ms,
                                              args.trials, rng)
        trend.append(accuracy)
        # "Above chance" means the INTERVAL clears 50%, not the point estimate.
        # 56.5% with 200 trials does not; reading it as a signal is how a
        # null result gets written up as a positive one.
        above = low > 50.0
        if above and separated is None:
            separated = traces
        bar = "#" * int((accuracy - 50) / 2.5) if accuracy > 50 else ""
        flag = "  <- above chance" if above else ""
        print(f"  {traces:>11}   {accuracy:5.1f}%  [{low:4.1f}, {high:4.1f}]"
              f"  {bar}{flag}")

    print("\n" + "=" * 72)
    if separated is not None:
        print(f"The attacker is above chance from {separated:,} traces per key,")
        print("with the interval clear of 50%. Noise is averaged away while the")
        print("secret-dependent signal remains.")
        print()
        print("Random delay raises the attacker's cost by a constant factor.")
        print("It does not close the channel, and claiming otherwise would be")
        print("worse than claiming nothing. Bound the exposure instead:")
        print("see docs/THREAT-MODEL.md.")
        return 0

    print("NO SEPARATION DETECTED at any tested trace count: every interval")
    print("includes 50%. Two readings are consistent with this and they are")
    print("not the same claim:")
    print()
    print("  * the implementation does not leak through this channel, or")
    print("  * the leak is below what this measurement can resolve.")
    print()
    print(f"Signing took a median of {statistics.median(a):.4f} ms. A black-box")
    print("timing test bounds the leak; it does not prove its absence, and it")
    print("is not a constant-time analysis. Per docs/TASK-D.md this result")
    print("does NOT raise a backend to ASSERTED -- that needs dudect, ctgrind")
    print("or Binsec/Rel against the specific build, recorded as")
    print("SideChannelEvidence. The status stays UNKNOWN, which is the")
    print("distinction the three states exist to keep.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
