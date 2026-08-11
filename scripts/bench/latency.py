"""Latency and signature-size benchmarks for the hybrid signing pipeline.

Task 8 of the Phase II memo.

WHAT THIS MEASURES, AND WHY EACH PART EARNS ITS PLACE
=====================================================
    primitives      keygen / sign / verify, per algorithm
    scaling         how cost grows with artefact size
    hybrid overhead what adopting this costs over Ed25519 alone
    cli             what a user experiences, including interpreter startup

The third is the number a reader actually wants. "ML-DSA signs in 23 ms" is
uninterpretable on its own; "the hybrid costs 24 ms more than Ed25519, and that
is 3% of the time spent hashing a 1 GB model" is a decision they can act on.

EVERY REPETITION USES A DIFFERENT INPUT, AND THAT IS NOT OPTIONAL
=================================================================
ML-DSA signing uses rejection sampling, and in *deterministic* mode the number
of iterations is a fixed function of (key, message). Signing one fixed message a
thousand times therefore performs the identical computation a thousand times: it
measures how lucky that message was, not what the algorithm costs.

The luck is large. Measured here, one key over eight different messages:

    10.2  10.6  15.4  20.1  20.7  35.0  38.4  57.7  ms      5.7x spread

The first version of this file signed a fixed artefact and produced an
impossible result -- the hybrid appeared *four times faster* than ML-DSA alone,
which cannot be, since the hybrid computes that same ML-DSA signature and an
Ed25519 one besides. The explanation was that the two configurations sign
different payloads (the algorithm binding differs, so the statement differs) and
the ML-DSA-only payload happened to be an unlucky one.

So `measure` passes the repetition index to the callable, and every benchmark
below varies its input with it. What is reported is then a sample of the
distribution over messages, which is the thing worth knowing.

MEDIAN AND IQR, NOT MEAN
========================
ML-DSA signing uses rejection sampling: it loops until a candidate falls within
bounds, and the iteration count varies. The distribution is therefore skewed
with a long right tail, and a mean is dragged around by outliers that a single
GC pause can produce. The median says what usually happens; the IQR says how
much it varies; reporting n lets a reader judge both.

That spread is not noise to be averaged away -- it is the same secret-dependent
variation that makes this backend unsuitable for an online signing service
(docs/THREAT-MODEL.md). Showing it is part of the point.

WHAT THIS CANNOT TELL YOU
=========================
These are pure-Python numbers on one machine. They characterise *this
implementation*, not ML-DSA. A constant-time C implementation such as liboqs is
one to two orders of magnitude faster, so nothing here should be read as the
cost of post-quantum signing in general -- only as the cost of this reference
implementation, which is the artefact under discussion.

USAGE
=====
    python scripts/bench/latency.py                    # everything
    python scripts/bench/latency.py --quick            # fewer reps, for a smoke test
    python scripts/bench/latency.py --skip scaling cli # subsets
    python scripts/bench/latency.py --out results/bench.json
"""
from __future__ import annotations

import argparse
import json
import math
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

ALGORITHMS = ["ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]

# The hybrid section measures ONE parameter set, and which one is a choice that
# has to travel with the numbers. It used to be hardcoded to ml-dsa-44 while the
# shipped default moved to ml-dsa-87, which left docs/BENCHMARKS.md describing a
# configuration nobody ships -- the numbers were right and the label was wrong,
# and check_docs.py could not catch it because it compares figures, not meaning.
# So: default to whatever the package actually ships, and record the choice in
# the output.
DEFAULT_HYBRID_LEVEL = "ml-dsa-87"


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------
@dataclass
class Timing:
    """A distribution, not a number.

    `mean` is recorded but deliberately not the headline: see the module
    docstring on why a skewed distribution needs its median.
    """

    label: str
    n: int
    median_ms: float
    p25_ms: float
    p75_ms: float
    min_ms: float
    max_ms: float
    mean_ms: float
    stdev_ms: float

    @classmethod
    def of(cls, label: str, samples: list[float]) -> Timing:
        ordered = sorted(samples)
        quartiles = (statistics.quantiles(ordered, n=4)
                     if len(ordered) >= 4 else [ordered[0], ordered[0], ordered[-1]])
        return cls(
            label=label,
            n=len(ordered),
            median_ms=statistics.median(ordered),
            p25_ms=quartiles[0],
            p75_ms=quartiles[2],
            min_ms=ordered[0],
            max_ms=ordered[-1],
            mean_ms=statistics.fmean(ordered),
            stdev_ms=statistics.stdev(ordered) if len(ordered) > 1 else 0.0,
        )

    @property
    def spread(self) -> float:
        """max/min. A proxy for how much the operation's cost varies."""
        return self.max_ms / self.min_ms if self.min_ms else float("nan")


def measure(fn: Callable[[int], Any], reps: int, warmup: int = 3) -> list[float]:
    """Time `fn(i)` for i in range(reps), in milliseconds.

    **The index is passed so callers can vary the input.** For ML-DSA in
    deterministic mode the cost is a fixed function of (key, message), so
    repeating one input measures that input rather than the algorithm -- see the
    module docstring for the impossible result this produced before it was
    fixed. Every caller below uses `i` to perturb what it signs.

    Warmup runs are discarded: the first call to a pure-Python routine pays for
    module-level lazy imports and cold caches, which is a real cost but not the
    steady-state one being reported.

    `perf_counter` rather than `process_time` because wall clock is what a user
    waits for, and because the GC pauses that process_time hides are part of why
    this implementation's timing varies.
    """
    # Warmup reuses the first few indices rather than inventing new ones, so a
    # caller precomputing per-index inputs needs only range(reps). The results
    # are discarded, and for ML-DSA the cost is determined by the input rather
    # than by cache state, so reusing an index does not flatter the measurement.
    for i in range(warmup):
        fn(i % max(reps, 1))
    samples = []
    for i in range(reps):
        start = time.perf_counter()
        fn(i)
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


# ---------------------------------------------------------------------------
# Environment, recorded so the numbers mean something later
# ---------------------------------------------------------------------------
def environment() -> dict[str, Any]:
    """Everything needed to interpret, or fail to reproduce, these numbers."""
    info: dict[str, Any] = {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "(not reported)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    try:
        import dilithium_py
        info["dilithium_py"] = getattr(dilithium_py, "__version__", "(unknown)")
    except ImportError:                                     # pragma: no cover
        info["dilithium_py"] = "(not installed)"
    try:
        import cryptography
        info["cryptography"] = cryptography.__version__
    except ImportError:                                     # pragma: no cover
        info["cryptography"] = "(not installed)"

    # Physical core count matters for interpreting variance, and on Linux the
    # governor tells you whether the CPU was free to clock down mid-run.
    try:
        import os
        info["cpu_count"] = os.cpu_count()
        gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        if gov.is_file():
            info["cpu_governor"] = gov.read_text().strip()
    except Exception:                                       # pragma: no cover
        pass
    return info


# ---------------------------------------------------------------------------
# 1. Primitives
# ---------------------------------------------------------------------------
def bench_primitives(reps: int) -> dict[str, Any]:
    from qknot.signing.backends import get_backend

    seed = bytes(range(32))

    def message_for(i: int) -> bytes:
        # A distinct message per repetition, so rejection-sampling cost is
        # sampled rather than fixed. Sixteen bytes of counter is enough to
        # decorrelate; the payload length is held constant so length is not a
        # confounder.
        return b"qknot-bench-" + i.to_bytes(16, "big", signed=True) + b"-pad"

    results: dict[str, Any] = {}

    for algorithm in ALGORITHMS:
        backend = get_backend(algorithm, deterministic=False)
        public, secret = backend.keygen(seed)
        signatures = {i: backend.sign(secret, message_for(i)) for i in range(reps)}

        results[algorithm] = {
            "keygen": asdict(Timing.of("keygen", measure(
                lambda i, b=backend: b.keygen(seed), reps))),
            "sign": asdict(Timing.of("sign", measure(
                lambda i, b=backend, k=secret: b.sign(k, message_for(i)), reps))),
            "verify": asdict(Timing.of("verify", measure(
                lambda i, b=backend, k=public, sg=signatures: b.verify(
                    k, message_for(i), sg[i]), reps))),
            "signature_bytes": len(signatures[0]),
            "public_key_bytes": len(public),
            "secret_key_bytes": len(secret),
            "quantum_resistant": backend.quantum_resistant,
        }
    return results


# ---------------------------------------------------------------------------
# 2. Scaling with artefact size
# ---------------------------------------------------------------------------
def _make_tree(root: Path, total_bytes: int, files: int = 8) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    per_file = max(1, total_bytes // files)
    chunk = b"\xa5" * min(per_file, 1 << 20)
    for i in range(files):
        written = 0
        with (root / f"shard-{i:03d}.bin").open("wb") as handle:
            while written < per_file:
                block = chunk[: min(len(chunk), per_file - written)]
                handle.write(block)
                written += len(block)
    return root


def bench_scaling(reps: int, sizes_mb: list[int],
                  level: str = DEFAULT_HYBRID_LEVEL) -> dict[str, Any]:
    """Separate the digest cost from the signature cost.

    Signs with the same parameter set as the hybrid section so the two are
    comparable; `level` is recorded in the output for the same reason it is
    there.

    For a real model the digest dominates by orders of magnitude, which is the
    single most useful fact in this whole file: the post-quantum signature is
    essentially free next to hashing the weights.
    """
    from qknot.signing.backends import Exposure
    from qknot.signing.digest import digest_artefact
    from qknot.signing.sign import keygen, sign

    keys = keygen(suite=["ed25519", level], seed=bytes(range(32)))
    results: dict[str, Any] = {"signed_with": level}

    with tempfile.TemporaryDirectory() as tmp:
        for size_mb in sizes_mb:
            root = _make_tree(Path(tmp) / f"tree-{size_mb}mb", size_mb * (1 << 20))
            n = max(3, reps // 4) if size_mb >= 100 else reps

            digest_only = measure(lambda i, r=root: digest_artefact(r), n, warmup=1)
            full = measure(
                lambda i, r=root: sign(r, keys, exposure=Exposure.OFFLINE,
                                       subject_name="bench",
                                       context=str(i).encode(), deterministic=True),
                n, warmup=1)

            digest_median = statistics.median(digest_only)
            full_median = statistics.median(full)
            results[f"{size_mb}MB"] = {
                "digest": asdict(Timing.of("digest", digest_only)),
                "sign_total": asdict(Timing.of("sign_total", full)),
                "signature_only_ms": round(full_median - digest_median, 3),
                "digest_share_pct": round(100 * digest_median / full_median, 1),
                "throughput_mb_s": round(size_mb / (digest_median / 1000), 1),
            }
    return results


# ---------------------------------------------------------------------------
# 3. Hybrid overhead
# ---------------------------------------------------------------------------
def bench_hybrid_overhead(reps: int, level: str = DEFAULT_HYBRID_LEVEL) -> dict[str, Any]:
    """What does adopting the hybrid actually cost over Ed25519 today?

    `level` selects the ML-DSA parameter set for both the hybrid and the
    ML-DSA-only comparison row, so the two stay comparable. It is recorded in
    the result so a reader never has to infer it from the signature size.
    """
    from qknot.signing.backends import Exposure
    from qknot.signing.sign import VerifyMode, keygen, sign, verify

    with tempfile.TemporaryDirectory() as tmp:
        root = _make_tree(Path(tmp) / "artefact", 1 << 20, files=4)   # 1 MiB
        out: dict[str, Any] = {}

        for label, suite in (("ed25519_only", ["ed25519"]),
                             ("hybrid", ["ed25519", level]),
                             ("ml_dsa_only", [level])):
            keys = keygen(suite=suite, seed=bytes(range(32)))
            signed = sign(root, keys, exposure=Exposure.OFFLINE,
                          subject_name="bench", deterministic=True)
            out[label] = {
                "sign": asdict(Timing.of("sign", measure(
                    lambda i, k=keys: sign(root, k, exposure=Exposure.OFFLINE,
                                           subject_name="bench",
                                           context=str(i).encode(),
                                           deterministic=True),
                    reps))),
                "verify": asdict(Timing.of("verify", measure(
                    lambda i, g=signed: verify(root, g, mode=VerifyMode.STRICT),
                    reps))),
                "total_signature_bytes": signed.total_signature_bytes,
            }

        classical = out["ed25519_only"]["sign"]["median_ms"]
        hybrid = out["hybrid"]["sign"]["median_ms"]
        out["overhead"] = {
            "absolute_ms": round(hybrid - classical, 3),
            "multiple": round(hybrid / classical, 1) if classical else None,
            "extra_signature_bytes": (out["hybrid"]["total_signature_bytes"]
                                      - out["ed25519_only"]["total_signature_bytes"]),
            "note": "over a 1 MiB artefact; the digest is common to both, so the "
                    "difference is the ML-DSA signature and nothing else",
        }
        out["hybrid_level"] = level
        out["overhead"]["hybrid_level"] = level
    return out


# ---------------------------------------------------------------------------
# 4. End-to-end CLI
# ---------------------------------------------------------------------------
def bench_cli(reps: int) -> dict[str, Any]:
    """What a user waits for, which is not what the library costs.

    Interpreter startup and imports usually dominate a single invocation. That
    is worth measuring precisely because it is invisible from inside the
    library, and because it is the number someone scripting a release will
    actually feel.
    """
    import os

    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONIOENCODING="utf-8")
    seed = "2a" * 32

    with tempfile.TemporaryDirectory() as tmp:
        root = _make_tree(Path(tmp) / "artefact", 1 << 20, files=4)
        bundle = Path(tmp) / "bench.bundle.json"

        def run(args: list[str]) -> None:
            subprocess.run([sys.executable, "-m", "qknot", *args],
                           capture_output=True, env=env, check=False,
                           text=True, encoding="utf-8", errors="replace")

        sign_args = ["sign", str(root), "--out", str(bundle),
                     "--seed", seed, "--deterministic", "--name", "bench"]
        run(sign_args)
        verify_args = ["verify", str(root), "--bundle", str(bundle)]

        n = max(3, reps // 10)          # each invocation is a process spawn
        baseline = measure(lambda i: subprocess.run(
            [sys.executable, "-c", "pass"], capture_output=True, check=False), n)

        return {
            "interpreter_startup": asdict(Timing.of("python -c pass", baseline)),
            "sign": asdict(Timing.of("qknot sign",
                                     measure(lambda i: run(sign_args), n))),
            "verify": asdict(Timing.of("qknot verify",
                                       measure(lambda i: run(verify_args), n))),
            "note": "interpreter startup is measured separately because it is "
                    "typically the majority of a single invocation and is not a "
                    "cost of the signing scheme",
        }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _row(timing: dict[str, Any]) -> str:
    return (f"{timing['median_ms']:>9.3f} "
            f"{timing['p25_ms']:>8.3f} {timing['p75_ms']:>8.3f} "
            f"{timing['max_ms'] / timing['min_ms']:>7.1f}x {timing['n']:>5}")


def report(results: dict[str, Any]) -> None:
    env = results["environment"]
    print("=" * 78)
    print("QKnot latency benchmarks")
    print("=" * 78)
    print(f"  {env['platform']}")
    print(f"  Python {env['python']} ({env['implementation']})  "
          f"dilithium-py {env['dilithium_py']}")
    print(f"  {env['timestamp']}")
    print()

    if "primitives" in results:
        print("PRIMITIVES")
        print("-" * 78)
        print(f"{'algorithm':12} {'op':8} {'median':>9} {'p25':>8} {'p75':>8} "
              f"{'spread':>8} {'n':>5}")
        for algorithm, data in results["primitives"].items():
            for op in ("keygen", "sign", "verify"):
                print(f"{algorithm:12} {op:8} {_row(data[op])}")
        print()
        print(f"{'algorithm':12} {'signature':>10} {'public key':>12} {'secret key':>12}")
        for algorithm, data in results["primitives"].items():
            print(f"{algorithm:12} {data['signature_bytes']:>10,} "
                  f"{data['public_key_bytes']:>12,} {data['secret_key_bytes']:>12,}")
        print()

    if "scaling" in results:
        print("SCALING WITH ARTEFACT SIZE")
        print("-" * 78)
        print(f"{'size':>8} {'digest ms':>12} {'total ms':>12} {'signature ms':>14} "
              f"{'digest %':>10} {'MB/s':>8}")
        for size, data in results["scaling"].items():
            if not isinstance(data, dict):      # e.g. "signed_with"
                continue
            print(f"{size:>8} {data['digest']['median_ms']:>12.1f} "
                  f"{data['sign_total']['median_ms']:>12.1f} "
                  f"{data['signature_only_ms']:>14.1f} "
                  f"{data['digest_share_pct']:>9.1f}% {data['throughput_mb_s']:>8.1f}")
        print()

    if "hybrid_overhead" in results:
        h = results["hybrid_overhead"]
        print("HYBRID OVERHEAD  (1 MiB artefact)")
        print("-" * 78)
        for label in ("ed25519_only", "hybrid", "ml_dsa_only"):
            data = h[label]
            print(f"{label:14} sign {data['sign']['median_ms']:>8.2f} ms   "
                  f"verify {data['verify']['median_ms']:>8.2f} ms   "
                  f"{data['total_signature_bytes']:>6,} B")
        o = h["overhead"]
        print(f"\n  adopting the hybrid costs {o['absolute_ms']} ms "
              f"({o['multiple']}x) and {o['extra_signature_bytes']:,} extra bytes")
        print()

    if "cli" in results:
        c = results["cli"]
        print("END-TO-END CLI")
        print("-" * 78)
        for key in ("interpreter_startup", "sign", "verify"):
            print(f"{c[key]['label']:22} {c[key]['median_ms']:>9.1f} ms   n={c[key]['n']}")
        startup = c["interpreter_startup"]["median_ms"]
        total = c["sign"]["median_ms"]
        print(f"\n  interpreter startup is {100 * startup / total:.0f}% of one "
              f"`qknot sign` invocation")
        print()


def check_invariants(results: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Physical facts the numbers must satisfy, checked rather than eyeballed.

    A benchmark that reports an impossible result and is believed is worse than
    no benchmark. This one did: before `measure` varied its input, the hybrid
    appeared four times faster than ML-DSA alone. The ordering below would have
    caught it immediately instead of it being noticed by hand.
    """
    problems: list[str] = []
    notes: list[str] = []

    if "hybrid_overhead" in results:
        h = results["hybrid_overhead"]

        # Did we benchmark what the package actually ships? Measuring a
        # non-default parameter set is legitimate -- that is what
        # --hybrid-level is for -- but it must be visible, because the
        # resulting table is easy to read as describing the default when it
        # does not. That exact mismatch already reached docs/BENCHMARKS.md once.
        level = h.get("hybrid_level")
        try:
            from qknot.signing.backends import DEFAULT_SUITE
            shipped = [a for a in DEFAULT_SUITE if a.startswith("ml-dsa")]
            if level and shipped and level != shipped[0]:
                notes.append(
                    f"hybrid section measured {level}, but the shipped default "
                    f"suite uses {shipped[0]}. This is fine if deliberate -- "
                    f"label the table with the parameter set, do not call it "
                    f"'the default'."
                )
        except Exception:                        # pragma: no cover
            notes.append("could not import DEFAULT_SUITE to confirm the "
                         "benchmarked hybrid level matches the shipped one")

        hybrid = h["hybrid"]["sign"]
        for weaker in ("ed25519_only", "ml_dsa_only"):
            other = h[weaker]["sign"]
            if other["median_ms"] <= hybrid["median_ms"]:
                continue
            # Compare against the spread, not exactly. ML-DSA's rejection
            # sampling makes signing times enormously variable -- a standard
            # deviation of 40 ms around a 58 ms median is normal -- so two
            # medians differing by 3% carry no information about ordering.
            # Flagging that as a violation is a false positive, and a check that
            # cries wolf gets ignored on the day it is right.
            noise = max(hybrid["stdev_ms"], other["stdev_ms"]) / math.sqrt(hybrid["n"])
            gap = other["median_ms"] - hybrid["median_ms"]
            if gap > 3 * noise:
                problems.append(
                    f"{weaker} signs slower ({other['median_ms']:.2f} ms) than the "
                    f"hybrid ({hybrid['median_ms']:.2f} ms) by {gap:.2f} ms, which "
                    f"is {gap / noise:.1f} standard errors -- too large to be "
                    f"noise. The hybrid computes that signature and an Ed25519 "
                    f"one, so it cannot be faster. Check that the inputs are "
                    f"being varied per repetition.")
            else:
                notes.append(
                    f"{weaker} median is {gap:.2f} ms above the hybrid's, within "
                    f"{gap / noise:.1f} standard errors -- noise, not an ordering "
                    f"violation. ML-DSA signing times vary by a factor of six.")

    if "primitives" in results:
        prims = results["primitives"]
        # Larger ML-DSA parameter sets cannot be cheaper than smaller ones.
        ladder = [a for a in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87") if a in prims]
        for lower, higher in zip(ladder, ladder[1:], strict=False):
            for op in ("keygen", "verify"):      # sign is too noisy to order
                if prims[higher][op]["median_ms"] < prims[lower][op]["median_ms"]:
                    problems.append(
                        f"{higher} {op} is faster than {lower} {op}; the larger "
                        f"parameter set does strictly more work")

            # `sign` is excluded above because rejection sampling makes it too
            # variable to order reliably -- treating an inversion as a violation
            # would cry wolf. But silence is also wrong: the primitives TABLE is
            # what gets published, and a table showing ml-dsa-65 slower than
            # ml-dsa-87 is a physical impossibility a reviewer will spot even
            # though the underlying cause is only noise. Note it, so the author
            # knows not to present the ladder as if it held on this run.
            lo, hi = prims[lower]["sign"], prims[higher]["sign"]
            if hi["median_ms"] < lo["median_ms"]:
                se = math.sqrt(lo["stdev_ms"] ** 2 / lo["n"]
                               + hi["stdev_ms"] ** 2 / hi["n"])
                sigma = abs(lo["median_ms"] - hi["median_ms"]) / se if se else float("inf")
                notes.append(
                    f"{higher} sign median ({hi['median_ms']:.2f} ms) is BELOW "
                    f"{lower} ({lo['median_ms']:.2f} ms) -- physically impossible, "
                    f"and at {sigma:.2f} sigma it is noise, not a result. Do not "
                    f"publish this ordering: raise --reps until the ladder holds, "
                    f"or report the sign column with its spread and say so."
                )
        # Signature and key sizes are fixed by the standard.
        expected = {"ed25519": 64, "ml-dsa-44": 2420, "ml-dsa-65": 3309,
                    "ml-dsa-87": 4627}
        for algorithm, size in expected.items():
            if algorithm in prims and prims[algorithm]["signature_bytes"] != size:
                problems.append(
                    f"{algorithm} signature is {prims[algorithm]['signature_bytes']} "
                    f"bytes, expected {size} from the specification")

    if "scaling" in results:
        sizes = [(k, v) for k, v in results["scaling"].items()
                 if isinstance(v, dict)]
        for (label_a, a), (label_b, b) in zip(sizes, sizes[1:], strict=False):
            if b["digest"]["median_ms"] < a["digest"]["median_ms"]:
                problems.append(
                    f"digesting {label_b} is faster than {label_a}; hashing cost "
                    f"must grow with size")

    return problems, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reps", type=int, default=50,
                        help="Repetitions per measurement (default 50).")
    parser.add_argument("--quick", action="store_true",
                        help="Few reps and small sizes, for a smoke test.")
    parser.add_argument("--sizes", type=int, nargs="+", default=[1, 10, 100],
                        help="Artefact sizes in MiB for the scaling benchmark.")
    parser.add_argument("--skip", nargs="+", default=[],
                        choices=["primitives", "scaling", "hybrid", "cli"],
                        help="Benchmarks to omit.")
    parser.add_argument("--hybrid-level", default=DEFAULT_HYBRID_LEVEL,
                        choices=["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"],
                        help="ML-DSA parameter set for the hybrid section "
                             f"(default: {DEFAULT_HYBRID_LEVEL}, the shipped "
                             "default suite).")
    parser.add_argument("--out", type=Path, default=None,
                        help="Write the full results as JSON here.")
    args = parser.parse_args(argv)

    reps = 5 if args.quick else args.reps
    sizes = [1] if args.quick else args.sizes

    results: dict[str, Any] = {"environment": environment(), "reps": reps}
    if "primitives" not in args.skip:
        results["primitives"] = bench_primitives(reps)
    if "scaling" not in args.skip:
        results["scaling"] = bench_scaling(reps, sizes, args.hybrid_level)
    if "hybrid" not in args.skip:
        results["hybrid_overhead"] = bench_hybrid_overhead(reps, args.hybrid_level)
    if "cli" not in args.skip:
        results["cli"] = bench_cli(reps)

    report(results)

    problems, notes = check_invariants(results)
    for note in notes:
        print(f"  note: {note}")
    if notes:
        print()
    if problems:
        print("=" * 78)
        print("INVARIANT VIOLATIONS -- do not quote these numbers")
        print("=" * 78)
        for problem in problems:
            print(f"  * {problem}")
        print()
    else:
        print("All physical invariants hold (ordering, sizes, monotonic scaling).")
        print()

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        results["invariant_violations"] = problems
        args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"full results -> {args.out}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
