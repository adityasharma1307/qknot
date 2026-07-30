"""Stage 2 of the npm head ranking: real download counts over a candidate pool.

    python scripts/audit/rank_npm.py --candidates candidates.txt \
                                     --out data/npm_ranking_2026-07-30.json

WHY THIS IS TWO STAGES AND NOT ONE
==================================
npm publishes no downloads ranking. Ranking the whole ~3.5M frame is about
27,000 bulk requests -- roughly 23 minutes at the rate this project sustains,
so **volume is not the obstacle**. The obstacle is that npm's bulk downloads
endpoint **rejects scoped packages**, and `@babel/*`, `@types/*` and similar
are a large share of the most popular names. Ranking only what the bulk
endpoint accepts would bias the head towards unscoped packages rather than
towards popular ones.

So: a candidate pool comes in (stage 1, from any popularity-ish source), and
this script measures **real downloads** over it (stage 2) -- bulk for unscoped
names, individually for scoped ones.

WHAT STAGE 1 HAS TO GET RIGHT, AND WHAT IT DOES NOT
===================================================
The candidate source does **not** need to rank well. Stage 2 does the ranking.
Stage 1 only has to avoid *losing* genuinely popular packages, so it should err
large. A pool of 50,000 to rank a head of 10,000 leaves substantial slack.

The residual caveat, which belongs in the paper in one sentence: a package with
very high downloads and near-zero presence in the candidate source would be
missed. That is a real edge case rather than a systematic bias, which is what
distinguishes this from ranking a random subsample -- there, a 2.9% sample
would have missed roughly 97% of the true top 10,000, because sampling
probability is independent of popularity.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--candidates", type=Path, required=True,
                        help="One package name per line, or a JSON list.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args(argv)

    from qresp.audit.npm_client import BULK_LIMIT, NpmClient, is_scoped

    raw = args.candidates.read_text(encoding="utf-8").strip()
    if raw.startswith("["):
        names = json.loads(raw)
    else:
        names = [line.strip() for line in raw.splitlines() if line.strip()]
    names = list(dict.fromkeys(names))          # de-duplicate, keep order

    unscoped = [n for n in names if not is_scoped(n)]
    scoped = [n for n in names if is_scoped(n)]
    print(f"candidates: {len(names):,}  ({len(unscoped):,} unscoped, "
          f"{len(scoped):,} scoped)")
    print(f"  unscoped -> {(len(unscoped) + BULK_LIMIT - 1)//BULK_LIMIT:,} bulk requests")
    print(f"  scoped   -> {len(scoped):,} individual requests")

    client = NpmClient()
    counts: dict[str, int | None] = {}
    started = time.time()

    batches = [unscoped[i:i + BULK_LIMIT]
               for i in range(0, len(unscoped), BULK_LIMIT)]
    for index, batch in enumerate(batches, start=1):
        try:
            counts.update(client.bulk_downloads(batch))
        except Exception as exc:
            print(f"  batch {index} failed ({exc}); recording as unknown")
            counts.update({n: None for n in batch})
        if index % 20 == 0 or index == len(batches):
            rate = index / max(time.time() - started, 1e-9)
            print(f"  bulk {index:,}/{len(batches):,}  {rate:.1f} batches/s")

    from concurrent.futures import ThreadPoolExecutor

    if scoped:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for index, (name, value) in enumerate(
                    zip(scoped, pool.map(client.single_downloads, scoped),
                        strict=False), start=1):
                counts[name] = value
                if index % 500 == 0 or index == len(scoped):
                    print(f"  scoped {index:,}/{len(scoped):,}")

    # Packages with no measurement are EXCLUDED from the ranking rather than
    # sorted to the bottom. A missing count is not a count of zero, and treating
    # it as one would quietly demote every package the API declined to answer
    # for -- turning a collection failure into a claim about popularity.
    measured = {n: c for n, c in counts.items() if isinstance(c, int)}
    unknown = [n for n, c in counts.items() if not isinstance(c, int)]
    ranked = sorted(measured.items(), key=lambda kv: kv[1], reverse=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "metric": "npm downloads, last-month, api.npmjs.org",
        "candidate_count": len(names),
        "measured": len(measured),
        "unmeasured": len(unknown),
        "rows": [{"project": n, "download_count": c} for n, c in ranked],
    }, indent=2), encoding="utf-8")

    print(f"\n  measured {len(measured):,} / {len(names):,}")
    if unknown:
        print(f"  {len(unknown):,} had no count and are EXCLUDED, not ranked last "
              f"(e.g. {unknown[:3]})")
    print(f"  top 5: {[n for n, _ in ranked[:5]]}")
    print(f"  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
