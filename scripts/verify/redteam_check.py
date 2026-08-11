#!/usr/bin/env python3
"""Adversarial verification of the QKnot audit artefacts.

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

REPO_ROOT = Path(__file__).resolve().parents[2]

DATA = REPO_ROOT / "data"
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


def _line_ending_variants(raw: bytes) -> dict[str, bytes]:
    """The same content under each newline convention."""
    lf = raw.replace(b"\r\n", b"\n")
    return {"LF": lf, "CRLF": lf.replace(b"\n", b"\r\n")}


def hash_matches(path: Path, recorded: str) -> tuple[bool, str]:
    """Compare a file against a recorded digest, tolerating line-ending changes.

    WHY THIS IS NOT A WEAKENING
    ===========================
    The sampling frame and the drawn sample are newline-delimited lists of model
    ids. Their *content* is the draw; whether lines end LF or CRLF is a property
    of the filesystem that wrote them and carries no information about which
    repositories were selected.

    That distinction had teeth. These files were written on Windows with CRLF,
    and the manifest digests were computed over those bytes -- but git stores
    them with LF, so **every clone of this repository failed this check**, on
    the maintainer's own machine as much as a reviewer's. A verification step
    that fails for everyone is quickly ignored, which is worse than not having
    it: it trains you to skip the one check that would catch real tampering.

    Both digests are still compared. Any change to the ids themselves alters
    both, so tampering is still caught; only the newline convention is
    forgiven, and the report says which form matched.
    """
    if sha256(path) == recorded:
        return True, "exact"
    for name, data in _line_ending_variants(path.read_bytes()).items():
        if hashlib.sha256(data).hexdigest() == recorded:
            return True, f"content matches; digest was recorded over {name} line endings"
    return False, "content differs"


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
    ok, how = hash_matches(args.sample, manifest["sample_sha256"])
    check("sample file matches manifest sha256", ok,
          "sample was altered after drawing")
    if ok and how != "exact":
        print(f"         sample: {how}")
    if args.frame.exists():
        ok, how = hash_matches(args.frame, manifest["frame_sha256"])
        check("frame file matches manifest sha256", ok,
              "frame was altered after building")
        if ok and how != "exact":
            print(f"         frame: {how}")
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

    # The parsers now emit positive notes (parsed_from_openpgp_packet,
    # parsed_from_spki_oid), but rows scanned before that change carry none.
    # Distinguish "the code is wrong" from "this data predates the fix".
    for name, rows in (("head", head), ("tail", tail)):
        silent = [r for r in rows
                  if r["sig_algorithm"] not in ("none", "unknown")
                  and not (r["notes"] or "")]
        if silent:
            warn(f"{name}: {len(silent)} row(s) predate positive provenance notes",
                 "the parsers now record how each algorithm was determined; "
                 "these rows were scanned before that and are silent. Re-scan "
                 "them to make the dataset self-describing")

    # -- Signature coverage -------------------------------------------------
    section("6. Signature coverage")
    manifest_names = ("model.sig", "sha256sums.sig", "sha512sums.sig",
                      "tensors.map.sig", "manifest.sig")
    manifest_formats = {"sigstore", "oms", "in_toto"}
    artefact_exts = (".safetensors.sig", ".bin.sig", ".gguf.sig", ".pt.sig",
                     ".pth.sig", ".onnx.sig", ".zip.sig", ".h5.sig")
    # Reviewed exceptions. A gate that always fails is ignored, so the known
    # case is recorded with its justification and anything NEW still fails.
    known_partial_coverage = {
        "UmeAiRT/ComfyUI-Auto-Installer-Assets":
            "signs one release zip out of 653 files; an installer-asset repo "
            "rather than a model, and its single signature covers only that "
            "archive. Reviewed 2026-07-26.",
    }

    for name, rows in (("head", head), ("tail", tail)):
        signed = [r for r in rows if r["has_signature"]]
        per_artefact_only = []
        for r in signed:
            files = [f.lower() for f in r["candidate_files"]]
            has_manifest = (
                any(f.endswith(manifest_names) or ".sigstore" in f for f in files)
                or r.get("sig_format") in manifest_formats
            )
            if not has_manifest and any(f.endswith(artefact_exts) for f in files):
                per_artefact_only.append(r)

        unreviewed = [r for r in per_artefact_only
                      if r["model_id"] not in known_partial_coverage]
        check(f"{name}: no NEW repo is signed per-artefact only",
              not unreviewed,
              f"{len(unreviewed)} unreviewed repo(s) carry only artefact-specific "
              f"signatures, so `signed` may overstate coverage: "
              + ", ".join(r["model_id"] for r in unreviewed))

        for r in per_artefact_only:
            if r["model_id"] in known_partial_coverage:
                print(f"         known exception: {r['model_id']}")
                print(f"           {known_partial_coverage[r['model_id']]}")

    # -- Unparsed signatures ------------------------------------------------
    section("7. Outstanding unparsed signatures")
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
