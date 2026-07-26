#!/usr/bin/env python3
"""Relabel repos that were unobservable at scan time from `unsigned` to `error`.

WHY
===
`run_audit_ids` originally routed a repo whose metadata could not be fetched
through the ordinary audit path with an empty file list. No candidate files
means the unsigned fast path, so every repo that had been deleted, renamed or
gated between the sampling frame being built and the scan running was recorded
as `unsigned`.

That is wrong in a way that matters. `unsigned` asserts that we looked and found
no signature. These are repos we could not look at. Counting them as unsigned
converts absence of evidence into evidence of absence, and does so in the
direction of the project's own conclusion, which is exactly the bias a reviewer
checks for.

`scanner.unavailable_record()` now labels them `error`. This script applies the
same correction to datasets already on disk, so they do not have to be
re-scanned against a registry that has moved on since.

IDENTIFICATION
==============
A row is treated as unobservable when it has zero files, no signature, and is
currently labelled unsigned. A real repo with genuinely zero files does not
occur in practice -- every HuggingFace repo carries at least `.gitattributes` --
so this is a safe signature for the failure rather than a heuristic.

    python scripts/relabel_vanished_repos.py data/longtail_10k_2026-07-25.jsonl --dry-run
    python scripts/relabel_vanished_repos.py data/longtail_10k_2026-07-25.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def is_unobservable(row: dict) -> bool:
    return (
        row.get("file_count") == 0
        and not row.get("has_signature")
        and row.get("q_label") == "unsigned"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        sys.exit(f"Not found: {args.dataset}")

    rows = [
        json.loads(line)
        for line in args.dataset.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    targets = [r for r in rows if is_unobservable(r)]

    print(f"dataset : {args.dataset}  ({len(rows):,} rows)")
    print(f"unobservable repos (0 files, labelled unsigned): {len(targets)}")
    if not targets:
        print("Nothing to relabel.")
        return 0

    for row in targets[:10]:
        print(f"   {row['model_id']}")
    if len(targets) > 10:
        print(f"   ... and {len(targets) - 10} more")

    before_unsigned = sum(1 for r in rows if r["q_label"] == "unsigned")
    before_error = sum(1 for r in rows if r["q_label"] == "error")

    for row in targets:
        row["q_label"] = "error"
        row["sig_algorithm"] = "unknown"
        note = "metadata_unavailable: repo not retrievable at scan time"
        row["notes"] = f"{row['notes']}; {note}" if row.get("notes") else note

    print()
    print(f"unsigned : {before_unsigned:,} -> {before_unsigned - len(targets):,}")
    print(f"error    : {before_error:,} -> {before_error + len(targets):,}")
    print(f"n        : {len(rows):,} (unchanged; denominator preserved)")

    if args.dry_run:
        print("\n--dry-run: nothing written.")
        return 0

    backup = args.dataset.with_suffix(".prerelabel.jsonl")
    if not backup.exists():
        backup.write_text(args.dataset.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"\nbacked up original : {backup}")

    args.dataset.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    print(f"wrote relabelled   : {args.dataset}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
