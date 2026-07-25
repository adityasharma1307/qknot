#!/usr/bin/env python3
"""Adversarial verification of the QResP audit artefacts.

Written to be hostile to its own project. Every check below is an attempt to
falsify a claim the paper will make, not to confirm it. A reviewer gets one
pass at this; better that it fails here.

    python scripts/redteam_check.py
    python scripts/redteam_check.py --skip-slow    # omit the frame re-draw

Exit code is non-zero if any check fails, so it can gate a commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

DATA = Path("data")
FAILURES: list[str] = []
WARNINGS: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    """`detail` describes what went wrong, so it is shown only on failure.

    Printing it beside a PASS makes the line contradict itself -- a passing
    check followed by "39+9961+0 != 10000" reads as a failure at a glance,
    which is the opposite of what a verification report should do.
    """
    if condition:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}" + (f"  -- {detail}" if detail else ""))
        FAILURES.append(f"{name}: {detail}" if detail else name)
    return condition


def warn(name: str, detail: str) -> None:
    print(f"  [WARN] {name}  -- {detail}")
    WARNINGS.append(f"{name}: {detail}")


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--head", type=Path, default=DATA / "head_10k_2026-07-25.jsonl")
    parser.add_argument("--tail", type=Path, default=DATA / "longtail_10k_2026-07-25.jsonl")
    parser.add_argument("--frame", type=Path, default=DATA / "longtail_frame_2026-07-25.txt")
    parser.add_argument("--sample", type=Path, default=DATA / "longtail_sample_2026-07-25.txt")
    parser.add_argument("--manifest", type=Path,
                        default=DATA / "longtail_manifest_2026-07-25.json")
    parser.add_argument("--skip-slow", action="store_true")
    args = parser.parse_args(argv)

    for p in (args.head, args.tail, args.sample, args.manifest):
        if not p.exists():
            sys.exit(f"Missing artefact: {p}")

    head = load_jsonl(args.head)
    tail = load_jsonl(args.tail)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    sample = [ln.strip() for ln in args.sample.read_text(encoding="utf-8").splitlines() if ln.strip()]

    head_ids = {r["model_id"] for r in head}
    tail_ids = {r["model_id"] for r in tail}

    # -- Sample integrity ---------------------------------------------------
    section("1. Sample integrity")
    check("head has exactly 10,000 rows", len(head) == 10_000, f"got {len(head):,}")
    check("head rows are unique", len(head_ids) == len(head),
          f"{len(head) - len(head_ids)} duplicates")
    check("tail has exactly 10,000 rows", len(tail) == 10_000, f"got {len(tail):,}")
    check("tail rows are unique", len(tail_ids) == len(tail),
          f"{len(tail) - len(tail_ids)} duplicates")
    check("strata are disjoint", not (head_ids & tail_ids),
          f"{len(head_ids & tail_ids)} repos in both")
    check("tail audited exactly the drawn sample", tail_ids == set(sample),
          f"drawn {len(set(sample)):,}, audited {len(tail_ids):,}, "
          f"symmetric difference {len(tail_ids ^ set(sample))}")
    check("sample has no duplicates", len(sample) == len(set(sample)),
          "a draw without replacement cannot repeat")

    # -- Manifest fidelity --------------------------------------------------
    section("2. Manifest fidelity")
    check("sample file matches manifest sha256",
          sha256(args.sample) == manifest["sample_sha256"], "sample was altered after drawing")
    if args.frame.exists():
        frame_hash = sha256(args.frame)
        check("frame file matches manifest sha256",
              frame_hash == manifest["frame_sha256"], "frame was altered after building")
    else:
        warn("frame file absent", f"{args.frame} not found; cannot verify the draw")
    check("manifest k matches sample size", manifest["k"] == len(sample))
    check("sampling fraction is consistent",
          abs(manifest["sampling_fraction"] - len(sample) / manifest["frame_size"]) < 1e-9)
    if manifest["stratum_a_size"] != len(head):
        warn("manifest stratum_a_size differs from head size",
             f"manifest {manifest['stratum_a_size']:,} vs head {len(head):,}; the frame was "
             f"built before the head was trimmed, so {manifest['stratum_a_size'] - len(head)} "
             f"repo(s) are excluded from both strata")

    # -- Reproducibility of the draw ---------------------------------------
    section("3. Reproducibility of the draw")
    if args.skip_slow or not args.frame.exists():
        warn("draw re-derivation skipped", "run without --skip-slow to verify")
    else:
        frame = [ln.strip() for ln in args.frame.read_text(encoding="utf-8").splitlines() if ln.strip()]
        check("frame size matches manifest", len(frame) == manifest["frame_size"],
              f"{len(frame):,} vs {manifest['frame_size']:,}")
        check("frame excludes the head stratum", not (set(frame) & head_ids),
              f"{len(set(frame) & head_ids)} head repos leaked into the frame")
        redrawn = random.Random(manifest["seed"]).sample(sorted(frame), manifest["k"])
        check("seed reproduces the sample byte for byte", redrawn == sample,
              "the recorded seed does not regenerate the published draw")

    # -- Label partition ----------------------------------------------------
    section("4. Label partition")
    for name, rows in (("head", head), ("tail", tail)):
        signed = [r for r in rows if r["has_signature"]]
        unsigned = [r for r in rows if r["q_label"] == "unsigned"]
        err = [r for r in rows if r["q_label"] == "error"]
        unparseable = [r for r in err if r["has_signature"]]
        unavailable = [r for r in err if not r["has_signature"]]
        buckets = ("vulnerable", "safe", "mixed")
        breakdown = sum(1 for r in rows if r["q_label"] in buckets) + len(unparseable)

        check(f"{name}: signed + unsigned + unavailable = n",
              len(signed) + len(unsigned) + len(unavailable) == len(rows),
              f"{len(signed)}+{len(unsigned)}+{len(unavailable)} != {len(rows)}")
        check(f"{name}: signed breakdown sums to signed",
              breakdown == len(signed), f"breakdown {breakdown} vs signed {len(signed)}")
        check(f"{name}: no unsigned row has zero files",
              not [r for r in unsigned if r["file_count"] == 0],
              "a repo with no files was never observed and cannot be called unsigned")
        check(f"{name}: every signed row lists candidate files",
              all(r["candidate_files"] for r in signed))
        check(f"{name}: no signed row is labelled unsigned",
              not [r for r in signed if r["q_label"] == "unsigned"])

    # -- Attribution honesty -----------------------------------------------
    section("5. Attribution honesty")
    # The invariant that matters is narrower than "every algorithm has a note".
    # A direct parse -- reading the public-key algorithm octet out of an OpenPGP
    # packet, say -- is its own provenance and needs no annotation. What must
    # never happen is an *inferred* attribution presented as though it were
    # parsed, which is precisely the Fulcio-convention defect that Task 1
    # existed to fix.
    #
    # An earlier version of this check demanded a note on every resolved
    # algorithm and flagged the nine directly-parsed Thireus signatures. That
    # was the check being wrong, not the data.
    for name, rows in (("head", head), ("tail", tail)):
        heuristic_algos = {"ecdsa_p256"}  # resolvable only by convention
        suspicious = [
            r for r in rows
            if r["sig_algorithm"] in heuristic_algos
            and "inferred" not in (r["notes"] or "")
        ]
        check(f"{name}: no inferred attribution is presented as a parse",
              not suspicious,
              f"{len(suspicious)} row(s) claim a convention-derived algorithm "
              f"without saying so")

        inferred = [r for r in rows if "inferred" in (r["notes"] or "")]
        parsed = [r for r in rows
                  if r["sig_algorithm"] not in ("none", "unknown")
                  and "inferred" not in (r["notes"] or "")]
        print(f"         {name}: {len(inferred)} inferred, {len(parsed)} directly parsed")

    warn("positive provenance notes not yet emitted",
         "a direct parse records no note at all, so 'parsed' and 'note lost' "
         "are indistinguishable in the data. Emitting e.g. "
         "parsed_from_openpgp_packet would make the dataset self-describing")

    # -- Unparsed signatures ------------------------------------------------
    section("6. Outstanding unparsed signatures")
    for name, rows in (("head", head), ("tail", tail)):
        stale = [r for r in rows
                 if r["has_signature"] and r["q_label"] == "error"]
        if stale:
            warn(f"{name}: {len(stale)} signed repo(s) still unclassified",
                 "re-scan with the current parser before quoting any "
                 "vulnerable-vs-safe contrast")
            for r in stale[:3]:
                print(f"         {r['model_id']}  {(r['notes'] or '')[:60]}")

    # -- Summary ------------------------------------------------------------
    section("Summary")
    print(f"  {len(FAILURES)} failure(s), {len(WARNINGS)} warning(s)")
    for f in FAILURES:
        print(f"    FAIL  {f}")
    for w in WARNINGS:
        print(f"    WARN  {w}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
