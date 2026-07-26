"""Re-scan the rows whose provenance the current parsers would now record.

WHY THESE ROWS AND NOT THE WHOLE DATASET
========================================
Two groups of rows are stale, for two different reasons, and both are standing
warnings in `scripts/verify/redteam_check.py`:

  1. **Silent rows.** Rows carrying a resolved `sig_algorithm` and no note at
     all. They were scanned before the parsers emitted positive provenance
     (`parsed_from_openpgp_packet`, `parsed_from_spki_oid`), so the dataset
     cannot say *how* those algorithms were determined. The classification is
     almost certainly right -- these were direct parses, which is why they have
     no "inferred" note -- but "probably right and unable to say why" is not a
     claim a paper should rest on.

  2. **Gated repositories.** Repos that returned HTTP 401 because access is
     restricted. These are only worth retrying if you now hold a token with
     access; without one they will fail again identically, which is itself a
     result worth recording rather than a reason not to run.

Re-scanning everything would be simpler and wrong: it would rewrite 20,000 rows
against a live registry that has moved on, silently mixing two scan dates into
one dataset. That exact mistake -- a July file quietly replacing a May one at
the same filename -- is documented in docs/DATASETS.md as the reason every
output here is date-stamped.

WHAT THIS SCRIPT DOES NOT DO
============================
It does not modify the published datasets. It writes a *separate* rescan file
and prints a comparison. Merging is a second, deliberate step (see --merge),
because a re-scan that silently overwrote the audit would destroy the ability
to show that the two agree.

USAGE
=====
    # 1. see what would be re-scanned, without touching the network
    python scripts/audit/rescan_silent_rows.py --dry-run

    # 2. re-scan (needs HF_TOKEN for the gated repos to have any chance)
    python scripts/audit/rescan_silent_rows.py --token $env:HF_TOKEN

    # 3. compare, then merge only if the labels agree
    python scripts/audit/rescan_silent_rows.py --merge
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

DATA = Path("data")
HEAD = DATA / "head_10k_2026-07-25.jsonl"
TAIL = DATA / "longtail_10k_2026-07-25.jsonl"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def silent_rows(rows: list[dict]) -> list[dict]:
    """Resolved an algorithm but recorded no provenance note."""
    return [r for r in rows
            if r["sig_algorithm"] not in ("none", "unknown")
            and not (r.get("notes") or "")]


def gated_rows(rows: list[dict]) -> list[dict]:
    """Signed repos we could not read. 401 means gated, not absent."""
    return [r for r in rows
            if r["q_label"] == "error"
            and r.get("has_signature")
            and "401" in (r.get("notes") or "")]


def collect() -> tuple[list[dict], list[dict]]:
    head, tail = load(HEAD), load(TAIL)
    silent = silent_rows(head) + silent_rows(tail)
    gated = gated_rows(head) + gated_rows(tail)
    return silent, gated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true",
                        help="List the targets and exit. No network.")
    parser.add_argument("--token", default=None,
                        help="HuggingFace token. Required for gated repos.")
    parser.add_argument("--out", type=Path, default=None,
                        help="Rescan output. Defaults to data/rescan_<today>.jsonl")
    parser.add_argument("--merge", action="store_true",
                        help="Compare an existing rescan against the datasets "
                             "and report. Never writes without --write.")
    parser.add_argument("--write", action="store_true",
                        help="With --merge, actually update the datasets.")
    args = parser.parse_args(argv)

    silent, gated = collect()
    out = args.out or DATA / f"rescan_{date.today().isoformat()}.jsonl"

    print("Rows the current parsers would describe better")
    print("=" * 72)
    print(f"  silent (no provenance note) : {len(silent)}")
    for row in silent:
        print(f"      {row['model_id']}  [{row['sig_algorithm']}] {row['q_label']}")
    print(f"  gated (HTTP 401)            : {len(gated)}")
    for row in gated:
        print(f"      {row['model_id']}")

    if args.dry_run:
        print("\n--dry-run: nothing fetched.")
        return 0

    if args.merge:
        return merge(out, write=args.write)

    if not args.token:
        print("\nNo --token given. The gated repos will fail again with 401.")
        print("That is a legitimate result -- it confirms they are still gated --")
        print("but pass a token if you have access and want them classified.")

    targets = [r["model_id"] for r in silent + gated]
    ids_file = DATA / f"rescan_targets_{date.today().isoformat()}.txt"
    ids_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    print(f"\n{len(targets)} id(s) -> {ids_file}")

    from qresp.audit.hf_client import HfClient
    from qresp.audit.scanner import run_audit_ids

    client = HfClient(token=args.token)
    scanned = 0
    # `run_audit_ids` streams to out_path itself -- that is where its resume and
    # crash-safety live. Passing None and writing here bypassed both and simply
    # crashed on `out_path.parent`.
    for record in run_audit_ids(client, targets, out_path=out, resume=False):
        scanned += 1
        print(f"  {record.model_id}  -> {record.q_label.value}  "
              f"{record.sig_algorithm.value}  {(record.notes or '')[:60]}")

    print(f"\n{scanned} row(s) -> {out}")
    if scanned < len(targets):
        print(f"WARNING: {len(targets) - scanned} target(s) produced no record. "
              f"Transient failures leave no row so they can be retried; rerun.")
    print("Now run with --merge to compare before changing anything.")
    return 0


def backfill(rescan_path: Path, rescanned: dict[str, dict]) -> int:
    """Write the recovered provenance notes into the published datasets.

    Only the `notes` field is touched, and only on rows that had none. The
    label, the algorithm and `audit_ts` are all left alone, because the *scan*
    that produced them happened on the original date -- what is new is the
    annotation, not the finding. Overwriting `audit_ts` would misdate the
    result; leaving the backfill unmarked would hide that two dates are now
    involved. So each backfilled note carries its own provenance suffix, and
    the dataset stays self-describing without needing a doc alongside it.

    A pre-backfill copy is written for anyone working outside git, and is
    gitignored: git already preserves the previous state of a tracked file, so
    committing a second copy is redundant. It is not merely redundant -- these
    datasets contain repository *names* shaped like credentials, and a fresh
    full-file blob would drag them through GitHub's secret scanning again for
    no gain. Recover the original with:

        git show <commit>:data/longtail_10k_2026-07-25.jsonl
    """
    stamp = rescan_path.stem.replace("rescan_", "")
    touched = 0
    for path in (HEAD, TAIL):
        rows = load(path)
        changed = False
        for row in rows:
            new = rescanned.get(row["model_id"])
            if new is None or (row.get("notes") or "") or not (new.get("notes") or ""):
                continue
            row["notes"] = f"{new['notes']} [provenance backfilled {stamp}]"
            changed = True
            touched += 1
        if not changed:
            continue
        backup = path.with_suffix(f".prebackfill-{stamp}.jsonl")
        if not backup.exists():
            backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            print(f"  preserved {path.name} -> {backup.name}")
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        print(f"  updated   {path.name}")
    print(f"\n{touched} row(s) backfilled.")
    return 0


def merge(rescan_path: Path, write: bool = False) -> int:
    """Compare a rescan against the datasets. Disagreement is the interesting case.

    Refuses to report on an incomplete rescan. An earlier version compared an
    empty file against the datasets, found nothing to disagree with, and
    announced "no label changed -- safe to merge". That is the worst possible
    failure for a verification step: it produced reassurance from an absence of
    data. Zero disagreements out of zero comparisons is not evidence of
    agreement, and the check now says so.
    """
    if not rescan_path.exists():
        print(f"No rescan file at {rescan_path}. Run without --merge first.")
        return 2

    rescanned = {r["model_id"]: r for r in load(rescan_path)}
    silent, gated = collect()
    expected = {r["model_id"] for r in silent + gated}
    missing = expected - set(rescanned)

    if not rescanned:
        print(f"\n{rescan_path} is empty. Nothing was re-scanned, so there is "
              f"nothing to compare.\nThis is NOT the same as 'the labels agree'.")
        return 2
    if missing:
        print(f"\nRescan covers {len(rescanned)}/{len(expected)} target(s). "
              f"Missing {len(missing)}:")
        for model_id in sorted(missing):
            print(f"      {model_id}")
        print("\nComparing a partial rescan would report agreement for rows that "
              "were never checked. Rerun the scan first.")
        return 2

    changed_label, gained_notes, still_silent = [], [], []

    for path in (HEAD, TAIL):
        for row in load(path):
            new = rescanned.get(row["model_id"])
            if new is None:
                continue
            if new["q_label"] != row["q_label"]:
                changed_label.append((row, new))
            elif (new.get("notes") or "") and not (row.get("notes") or ""):
                gained_notes.append((row, new))
            elif not (new.get("notes") or ""):
                still_silent.append(row)

    print(f"\nComparison  ({len(rescanned)} row(s) re-scanned)")
    print("=" * 72)
    print(f"  label changed        : {len(changed_label)}")
    for old, new in changed_label:
        print(f"      {old['model_id']}: {old['q_label']} -> {new['q_label']}")
    print(f"  gained provenance    : {len(gained_notes)}")
    for _, new in gained_notes:
        print(f"      {new['model_id']}: {(new.get('notes') or '')[:70]}")
    print(f"  still silent         : {len(still_silent)}")

    if changed_label:
        print("\nA changed label is NOT a formatting fix. Either the old parse was")
        print("wrong, or the repository changed since July. Establish which before")
        print("merging, and record the answer in docs/DATASETS.md.")
        return 1

    print("\nNo label changed: the re-scan confirms the published classification")
    print("and only adds provenance.")

    unreadable = [r for r in rescanned.values() if r["q_label"] == "error"]
    if unreadable:
        print(f"\n{len(unreadable)} repo(s) still unreadable. Re-checking them is "
              f"itself a result -- it confirms they remain gated rather than "
              f"having been fixed -- but note whether the run was authenticated:")
        for row in unreadable:
            print(f"      {row['model_id']}")
        print("  An UNAUTHENTICATED 401 cannot distinguish 'gated' from 'we did")
        print("  not present a token'. Only an authenticated attempt supports the")
        print("  stronger claim, and even then only for the token's access level.")

    if not write:
        print("\nNothing written. Re-run with --merge --write to backfill.")
        return 0

    print("\nBackfilling provenance notes:")
    return backfill(rescan_path, rescanned)


if __name__ == "__main__":
    sys.exit(main())
