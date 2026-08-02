"""Two-stratum PyPI attestation scan, mirroring the HuggingFace design.

    python scripts/audit/run_pypi_audit.py --out data/pypi_2026-07-30.jsonl

Equivalent to `qresp audit-pypi` with the same options; both call the same
`qresp.audit.registry_scan.run_pypi_audit`, so this script is kept for the
invocations already recorded in the RUNBOOK and in the manifests.

The methodology -- two strata, a re-derivable seeded sample, a resumable
collector, and `error` never counted as `unsigned` -- is documented on the
module it now delegates to.

STRATA
======
head  top 10,000 by download count, from the published top-PyPI ranking
tail  10,000 sampled at random from the rest of the PyPI namespace

The ranking is fetched once and CACHED beside the output: re-fetching per run
would silently change the head stratum, making a resumed scan a scan of two
populations stitched together. The frame is the live index at scan time, and
its size and digest go into the manifest so the tail is re-derivable.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from qresp.audit.registry_scan import (  # noqa: E402, F401
    DEFAULT_HEAD_SIZE,
    DEFAULT_SEED,
    DEFAULT_TAIL_SIZE,
    PYPI_RANKING_URL,
    already_done,
    run_pypi_audit,
)

# `already_done` is re-exported deliberately: the resume rule -- an `error` row
# is NOT a recorded answer, so a re-run retries it -- is part of this runner's
# published contract, and stays importable from here regardless of which module
# implements it.
__all__ = ["already_done", "main", "run_pypi_audit"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True,
                        help="JSONL output; re-running resumes into the same file.")
    parser.add_argument("--ranking-url", default=PYPI_RANKING_URL)
    parser.add_argument("--ranking-cache", type=Path, default=None,
                        help="Default: <out>.ranking.json, beside the output.")
    parser.add_argument("--head", type=int, default=DEFAULT_HEAD_SIZE)
    parser.add_argument("--tail", type=int, default=DEFAULT_TAIL_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--workers", type=int, default=8,
                        help="Concurrent requests. Keep modest; this is a free "
                             "public service.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Stop after N projects. For a smoke test.")
    args = parser.parse_args(argv)

    run_pypi_audit(
        out=args.out, ranking_url=args.ranking_url,
        ranking_cache=args.ranking_cache, head_size=args.head,
        tail_size=args.tail, seed=args.seed, workers=args.workers,
        limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
