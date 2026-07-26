#!/usr/bin/env python3
"""Trim the head stratum to exactly the top N repos by download count.

WHY THIS EXISTS
===============
Stratum A is defined as "the top 10,000 repositories by all-time downloads".
A scan can end up with more rows than that, because `run_audit` resumes by
skipping model_ids already present in the output: if the head scan is run more
than once, the second pass adds any repo that climbed into the top 10,000
between the two runs, and the result is a union of two snapshots rather than
one census.

That is the same instability that makes a download-sorted crawl unsuitable for
building a sampling frame (see the METHODS SUMMARY in sample_longtail.py).
Download counts change continuously, so the membership of "the top 10,000" is
only well defined at an instant.

This script restores the definition deterministically rather than by rescanning,
which would merely produce a third snapshot.

ORDERING
========
Rows are ranked by download count descending, with model_id ascending as a
tiebreak. The tiebreak matters: without it, repos on equal download counts would
be ordered by whatever the JSONL happened to contain, and the trim would not be
reproducible from the same input.

SAFETY
======
The untrimmed input is preserved alongside the output with a `.raw.jsonl`
suffix, and the script reports exactly which repos were dropped and whether any
of them were signed. Silently discarding a signed repo would change the
headline finding, so that check is not optional.

    python scripts/trim_head_stratum.py data/head_10k_2026-07-25.jsonl
    python scripts/trim_head_stratum.py data/head_10k_2026-07-25.jsonl --n 10000
    python scripts/trim_head_stratum.py data/head_10k_2026-07-25.jsonl --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_rows(path: Path) -> list[dict]:
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    seen: dict[str, dict] = {}
    for row in rows:
        key = row["model_id"]
        if key not in seen or row["audit_ts"] > seen[key]["audit_ts"]:
            seen[key] = row
    if len(seen) != len(rows):
        print(f"NOTE: {len(rows)} rows, {len(seen)} unique model_ids; "
              f"kept the most recent record for each.")
    return list(seen.values())


def rank_key(row: dict) -> tuple[int, str]:
    """Descending downloads, ascending model_id. Negated downloads keeps the
    whole key ascending so a single sorted() call is enough."""
    return (-(row.get("downloads") or 0), row["model_id"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trim a head-stratum audit output to exactly the top N repos.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--n", type=int, default=10_000,
                        help="Target stratum size (default: 10000).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would be dropped without writing.")
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        sys.exit(f"Not found: {args.dataset}")

    rows = load_rows(args.dataset)
    print(f"input  : {args.dataset}  ({len(rows):,} unique repos)")

    if len(rows) == args.n:
        print(f"Already exactly {args.n:,} repos. Nothing to do.")
        return 0
    if len(rows) < args.n:
        sys.exit(
            f"Refusing to trim: {len(rows):,} repos is fewer than the target "
            f"{args.n:,}. The scan is incomplete; rerun it rather than trimming."
        )

    ordered = sorted(rows, key=rank_key)
    keep, drop = ordered[: args.n], ordered[args.n:]

    print(f"target : {args.n:,}")
    print(f"dropping {len(drop)} repo(s) ranked {args.n + 1}-{len(ordered)}:")
    for row in drop:
        flag = "  <-- SIGNED" if row.get("has_signature") else ""
        print(f"   rank {ordered.index(row) + 1:>6,}  "
              f"{row['downloads']:>12,} downloads  {row['model_id']}{flag}")

    dropped_signed = [r for r in drop if r.get("has_signature")]
    if dropped_signed:
        print()
        print("WARNING: the trim removes signed repos, which changes the headline")
        print("finding. Review before accepting:")
        for row in dropped_signed:
            print(f"   {row['model_id']}  {row.get('sig_algorithm')}")
        print()

    kept_signed = sum(1 for r in keep if r.get("has_signature"))
    print()
    print(f"signed after trim: {kept_signed} / {len(keep):,} "
          f"({100 * kept_signed / len(keep):.3f}%)")

    if args.dry_run:
        print("\n--dry-run: nothing written.")
        return 0

    raw_path = args.dataset.with_suffix(".raw.jsonl")
    if not raw_path.exists():
        raw_path.write_text(args.dataset.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"\npreserved untrimmed input : {raw_path}")
    else:
        print(f"\n{raw_path} already exists; leaving it untouched.")

    args.dataset.write_text(
        "\n".join(json.dumps(r) for r in keep) + "\n", encoding="utf-8"
    )
    print(f"wrote trimmed stratum     : {args.dataset}  ({len(keep):,} repos)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
