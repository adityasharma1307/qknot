"""Sanity-check a ranking before anything is built on it.

    python scripts/audit/check_ranking.py --ranking data/npm_ranking_unscoped.json

WHY THIS EXISTS
===============
The first npm ranking looked entirely plausible and was badly wrong: 7,139
packages, a sensible-looking top 20, and 25 of 30 unmistakably top-tier packages
missing. Nothing about the file announced the problem. The second pool was wrong
for a different reason -- npm search returns `lodash._objecttypes` but not
`lodash` -- and again the output looked fine.

A ranking that omits `lodash` is not a ranking of npm, and that is cheap to
check and expensive to discover later. So this checks it explicitly, exits
non-zero when it fails, and prints the distribution that makes a hollow pool
obvious.

It also accepts a partial file, so a long run can be checked while in flight.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

# Unmistakably top-tier unscoped packages. Any ranking of npm that does not
# place these near the top is not measuring what it claims to.
BELLWETHERS = [
    "lodash", "chalk", "debug", "express", "ms", "semver", "tslib",
    "picocolors", "supports-color", "commander", "axios", "glob", "minimatch",
    "uuid", "react", "webpack", "eslint", "postcss", "typescript",
]


def load(path: Path) -> dict[str, int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "rows" in data:
        return {r["project"]: r["download_count"] for r in data["rows"]}
    return {k: v for k, v in data.items() if isinstance(v, int)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ranking", type=Path, required=True,
                        help="A ranking .json or a .partial.json.")
    parser.add_argument("--head", type=int, default=10_000,
                        help="Intended head size, for the threshold report.")
    parser.add_argument("--partial", action="store_true",
                        help="In flight: report only, never fail.")
    args = parser.parse_args(argv)

    counts = load(args.ranking)
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    order = {n: i + 1 for i, (n, _) in enumerate(ranked)}
    print(f"ranking: {len(counts):,} measured packages")

    print("\ndistribution:")
    for r in (1, 100, 1_000, 5_000, 10_000, 50_000, 100_000):
        if r <= len(ranked):
            print(f"   rank {r:>8,}: {ranked[r - 1][1]:>16,} downloads/month")

    if len(ranked) >= args.head:
        threshold = ranked[args.head - 1][1]
        print(f"\n   a {args.head:,}-package head requires "
              f"{threshold:,} downloads/month")
        if threshold < 10_000:
            print("   WARNING: that threshold is very low. A head whose last "
                  "member is\n            near-unused suggests the population "
                  "does not actually contain\n            enough popular "
                  "packages -- the failure mode of the search pool.")

    print("\nbellwethers:")
    missing = []
    for name in BELLWETHERS:
        if name in order:
            print(f"   ok      {name:16} rank {order[name]:>7,}  "
                  f"{counts[name]:>15,}")
        else:
            missing.append(name)
            print(f"   ABSENT  {name}")

    if missing:
        print(f"\n{len(missing)} of {len(BELLWETHERS)} bellwethers absent: "
              f"{missing}")
        if args.partial:
            print("(--partial: run still in flight, so absence is not yet a "
                  "verdict)")
            return 0
        print("A ranking of npm that omits these is not measuring npm. Do not "
              "build a head stratum on it.")
        return 1

    print(f"\nall {len(BELLWETHERS)} bellwethers present and ranked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
