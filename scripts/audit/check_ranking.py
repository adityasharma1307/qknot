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
    """Read a ranking or a partial, and say plainly when it is not there.

    The finished file only appears when the run completes, so pointing this at
    it mid-run is the ordinary mistake, not an exotic one. It used to raise a
    bare FileNotFoundError traceback, which says where the code failed and not
    what to do -- and a checking tool that reports its own failure badly is a
    poor advertisement for the checks it performs.
    """
    if not path.exists():
        partial = path.with_suffix(".partial.json")
        hint = ""
        if partial.exists():
            size = partial.stat().st_size / 1e6
            hint = (f"\n\nA partial IS present: {partial} ({size:.0f} MB).\n"
                    f"The finished file is written only when the run "
                    f"completes, so this most likely means it is still going. "
                    f"Check progress with:\n\n"
                    f"    python {Path(__file__).name} --ranking {partial} "
                    f"--partial")
        raise SystemExit(f"{path} does not exist.{hint}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path} is not valid JSON ({exc}).\n"
            f"A partial written while a run was killed mid-write can be "
            f"truncated; re-run the collector, which resumes."
        ) from None
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

    # The frame is sorted, so an in-flight run has an alphabetical frontier.
    # "Not reached yet" and "reached and missing" are different facts, and
    # only the second is a problem -- the same absent-versus-unchecked
    # distinction the scanners draw, applied to progress monitoring.
    frontier = max(counts, default="")

    print(f"\nbellwethers  (frontier: highest name measured is {frontier!r})")
    missing, unreached = [], []
    for name in BELLWETHERS:
        if name in order:
            print(f"   ok        {name:16} rank {order[name]:>7,}  "
                  f"{counts[name]:>15,}")
        elif name > frontier:
            unreached.append(name)
            print(f"   pending   {name:16} sorts after the frontier")
        else:
            missing.append(name)
            print(f"   MISSING   {name:16} sorts BEFORE the frontier "
                  f"-- should have been measured")

    if unreached:
        print(f"\n{len(unreached)} bellwether(s) not yet reached: {unreached}")

    if missing:
        print(f"\n{len(missing)} bellwether(s) MISSING despite sorting before "
              f"the frontier: {missing}")
        print("These should have been measured already. This is not a matter "
              "of waiting.")
        if args.partial:
            # Still fails: a name the run has passed and does not have is a
            # real gap whether or not the run is finished.
            return 1
        print("A ranking of npm that omits these is not measuring npm. Do not "
              "build a head stratum on it.")
        return 1

    if unreached and args.partial:
        print("\nHealthy so far: every absence sorts after the frontier, which "
              "is what a\nsorted frame in progress looks like. Re-check without "
              "--partial when done.")
        return 0
    if unreached:
        print(f"\nINCOMPLETE: {len(unreached)} bellwether(s) never reached. "
              f"The run did not finish.")
        return 1

    print(f"\nall {len(BELLWETHERS)} bellwethers present and ranked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
