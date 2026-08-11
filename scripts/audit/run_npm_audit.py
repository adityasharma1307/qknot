"""Two-stratum npm attestation scan, mirroring the PyPI and HuggingFace design.

    python scripts/audit/run_npm_audit.py \
        --ranking data/npm_ranking_2026-07-30.json \
        --frame   data/npm_frame_2026-07-30.txt \
        --out     data/npm_2026-07-30.jsonl

Equivalent to `qknot audit-npm` with the same options; both call the same
`qknot.audit.registry_scan.run_npm_audit`, so this script is kept for the
invocations already recorded in the dataset manifests.

The methodology -- two strata, a re-derivable seeded sample, a resumable
collector, and `error` never counted as `unsigned` -- is documented on the
module it now delegates to.

STRATA
======
head  top 10,000 by downloads, from scripts/audit/rank_npm.py
tail  10,000 sampled at random from the rest of the npm namespace

npm publishes no ranking, so unlike PyPI both inputs are produced locally and
passed in explicitly:

    --ranking  output of rank_npm.py (stage 2: real download counts)
    --frame    one package name per line, from the registry's _all_docs

Both are files rather than fetches, for the reason the PyPI ranking is cached:
a stratum is only reproducible if the exact inputs are preserved.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from qknot.audit.registry_scan import (  # noqa: E402, F401
    DEFAULT_HEAD_SIZE,
    DEFAULT_SEED,
    DEFAULT_TAIL_SIZE,
    already_done,
    run_npm_audit,
)

# `already_done` is re-exported deliberately: the resume rule -- an `error` row
# is NOT a recorded answer, so a re-run retries it -- is part of this runner's
# published contract, and stays importable from here regardless of which module
# implements it.
__all__ = ["already_done", "main", "run_npm_audit"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True,
                        help="JSONL output; re-running resumes into the same file.")
    parser.add_argument("--ranking", type=Path, required=True,
                        help="Output of scripts/audit/rank_npm.py.")
    parser.add_argument("--frame", type=Path, required=True,
                        help="One package name per line; the sampling frame.")
    parser.add_argument("--head", type=int, default=DEFAULT_HEAD_SIZE)
    parser.add_argument("--tail", type=int, default=DEFAULT_TAIL_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--workers", type=int, default=8,
                        help="Concurrent requests. Keep modest; this is a free "
                             "public service.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Stop after N projects. For a smoke test.")
    args = parser.parse_args(argv)

    run_npm_audit(
        out=args.out, ranking_path=args.ranking, frame_path=args.frame,
        head_size=args.head, tail_size=args.tail, seed=args.seed,
        workers=args.workers, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
