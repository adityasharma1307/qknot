"""Stage 1, rebuilt: a scoped candidate pool from what popular packages depend on.

    python scripts/audit/build_scoped_pool.py \
        --ranking data/npm_ranking_unscoped.json --top 20000 \
        --out data/npm_scoped_candidates.txt

WHY THE SEARCH-BASED POOL WAS REPLACED
======================================
The first stage 1 swept npm's search API with letter and digram seeds. It
failed, and not by a little: **25 of 30 unmistakably top-tier packages were
absent** from the resulting pool -- lodash, chalk, debug, express, webpack,
eslint, @types/node, @babel/core among them. The pool's 10,000th-ranked package
had 157 downloads/month, which is not a head at all.

Two causes, both fatal:

1. `--target` stopped the sweep as soon as enough distinct names had been
   collected, at request ~1,400 of 2,848 -- partway through the seed list. Only
   seeds `a`..`ma` ever ran, which is also why the survivors skewed alphabetically.
2. More fundamentally, **npm search does not rank by downloads**. Probed
   directly: `text=lo&popularity=1.0` returns `lo`, `lodash._objecttypes`,
   `lodash._shimkeys`, `lodash._basebind` -- deprecated micro-packages -- and
   never returns `lodash` itself. It prefix-matches names and scores by a blend
   that popularity weighting does not dominate. Fixing the early stop would not
   have fixed this; the source was wrong.

WHAT REPLACES IT
================
Unscoped packages no longer need a pool at all: npm's bulk endpoint takes 128
names per request, so all ~2.69M unscoped names can be ranked exhaustively for
~21,000 requests (`rank_npm.py --frame`). Exact, not approximate.

Only scoped packages still need one, because they must be queried individually.
This script derives it from **the dependencies of the top-ranked unscoped
packages**: a scoped package that matters is, with few exceptions, one that
popular packages depend on. That is a genuine popularity signal rather than a
name-matching artefact, it uses only `registry.npmjs.org` (which tolerates a far
higher rate than the downloads API), and it is exactly reproducible from a
pinned ranking file.

The same rule as before still applies and is what makes this sound: stage 1 does
not rank. `rank_npm.py` measures real downloads over whatever comes out of here.
Stage 1 only has to avoid *losing* popular scoped packages.

RESIDUAL CAVEAT FOR THE PAPER
=============================
A scoped package with high download counts that no popular unscoped package
depends on -- a widely installed CLI or application scope, say -- would be
missed. Direct-dependency reach is a proxy for popularity, not popularity
itself. This is a stated limitation rather than a hidden one, and it is
bounded: the head it feeds is checked against the measured download threshold,
so the effect of any miss is visible as a gap in coverage rather than as a
silently wrong ranking.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ranking", type=Path, required=True,
                        help="Exhaustive unscoped ranking from rank_npm.py --frame.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--top", type=int, default=20_000,
                        help="How many top unscoped packages to read deps from.")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--frame", type=Path, default=None,
                        help="If given, keep only scoped names present in the "
                             "frame, so the pool cannot contain deleted packages.")
    args = parser.parse_args(argv)

    from qresp.audit.npm_client import NpmClient, NpmError, is_scoped

    ranking = json.loads(args.ranking.read_text(encoding="utf-8"))
    seeds = [r["project"] for r in ranking["rows"][:args.top]]
    print(f"reading dependencies of the top {len(seeds):,} unscoped packages")

    client = NpmClient()
    found: dict[str, int] = {}          # scoped name -> how many depend on it
    failures = 0

    def deps_of(name: str) -> list[str]:
        """Dependencies of the latest version, from the abbreviated packument."""
        from urllib.parse import quote
        data = client._get(
            f"https://registry.npmjs.org/{quote(name, safe='')}",
            "application/vnd.npm.install-v1+json")
        versions = data.get("versions") or {}
        if not versions:
            return []
        latest = (data.get("dist-tags") or {}).get("latest") or list(versions)[-1]
        meta = versions.get(latest) or {}
        out: list[str] = []
        for field in ("dependencies", "peerDependencies", "optionalDependencies"):
            out.extend((meta.get(field) or {}).keys())
        return out

    def safe_deps(name: str) -> list[str]:
        try:
            return deps_of(name)
        except NpmError:
            return []
        except Exception:
            return []

    started = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for index, deps in enumerate(pool.map(safe_deps, seeds), start=1):
            if not deps:
                failures += 1
            for dep in deps:
                if is_scoped(dep):
                    found[dep] = found.get(dep, 0) + 1
            if index % 1000 == 0 or index == len(seeds):
                rate = index / max(time.time() - started, 1e-9)
                eta = (len(seeds) - index) / max(rate, 1e-9) / 60
                print(f"  {index:,}/{len(seeds):,}  {rate:.0f}/s  ~{eta:.0f} min left  "
                      f"distinct scoped deps={len(found):,}")

    names = sorted(found, key=lambda n: (-found[n], n))

    if args.frame:
        frame = set(args.frame.read_text(encoding="utf-8").split())
        before = len(names)
        names = [n for n in names if n in frame]
        print(f"  frame filter: {before - len(names):,} name(s) not in the index")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(names) + "\n", encoding="utf-8")
    args.out.with_suffix(".manifest.json").write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source": "direct dependencies of top-ranked unscoped npm packages",
        "ranking": str(args.ranking),
        "seed_count": len(seeds),
        "seeds_with_no_readable_deps": failures,
        "scoped_candidates": len(names),
        "role": "stage 1 candidate pool only; rank_npm.py does the ranking",
        "replaces": "npm search seed sweep, which returned lodash._objecttypes "
                    "but not lodash and omitted 25 of 30 top-tier packages",
    }, indent=2), encoding="utf-8")

    print(f"\n  {len(names):,} scoped candidates")
    if failures:
        print(f"  {failures:,} seed(s) had no readable dependency list")
    print(f"  most depended-upon: {names[:6]}")
    print(f"  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
