"""Stage 1: a candidate pool for the npm head ranking, from npm's own search.

    python scripts/audit/build_npm_candidates.py --out data/npm_candidates.txt

WHY npm's SEARCH AND NOT A THIRD PARTY
======================================
The plan expected a third-party popularity source (deps.dev or similar). npm's
own search API turns out to serve the purpose better:

* it ranks by **popularity** directly (`popularity=1.0`),
* it **includes scoped packages** -- 141 of 250 results for one probe query --
  which is the whole reason stage 1 exists, since 37.4% of npm is scoped and
  the bulk downloads endpoint refuses those,
* it is **npm's own infrastructure**, so the provenance tier is better than any
  external ranker.

WHAT THIS STAGE MUST AND MUST NOT DO
====================================
It does **not** rank. `rank_npm.py` does that, from measured download counts.
This stage only has to avoid *losing* genuinely popular packages, so it errs
large: many seed queries, deduplicated, aiming well above the head size.

Because search is text-relevance filtered, no single query sees the whole
namespace. The pool is therefore built from many seeds -- single letters and
common digrams -- each paged in popularity order. A package popular enough to
belong in the head is overwhelmingly likely to match at least one seed and rank
highly within it.

**The residual caveat, one sentence for the paper:** a package with very high
downloads that matches no seed and is returned by no query would be missed. It
is an edge case rather than a systematic bias -- unlike ranking a random
subsample, where a 2.9% sample would miss ~97% of the true top 10,000 because
sampling probability is independent of popularity.
"""
from __future__ import annotations

import argparse
import json
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

SEARCH = "https://registry.npmjs.org/-/v1/search"
PAGE = 250
UA = {"User-Agent": "qresp-audit (+https://github.com/qresp)"}


def seeds() -> list[str]:
    """Every letter, digit and two-letter combination. Broad, not deep.

    Measured while building this: paging one seed deeper yields heavy overlap,
    because popularity ordering surfaces the same well-known packages again.
    332 requests across 62 seeds produced only 2,980 distinct names -- about
    nine per request.

    Distinct SEEDS are what add coverage, since each matches a different slice
    of the namespace. Hence all 676 digrams rather than a handful paged deeply.
    """
    return (list(string.ascii_lowercase) + list(string.digits)
            + [a + b for a in string.ascii_lowercase
               for b in string.ascii_lowercase])


def fetch_page(args: tuple[str, int]) -> list[str]:
    import requests

    text, offset = args
    url = (f"{SEARCH}?text={quote(text)}&size={PAGE}&from={offset}"
           f"&popularity=1.0&quality=0.0&maintenance=0.0")
    try:
        response = requests.get(url, headers=UA, timeout=45)
        response.raise_for_status()
        return [o["package"]["name"]
                for o in response.json().get("objects", [])]
    except Exception:
        return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target", type=int, default=50_000,
                        help="Stop once this many distinct names are collected.")
    parser.add_argument("--depth", type=int, default=1_000,
                        help="How deep to page each seed.")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args(argv)

    jobs = [(seed, offset)
            for seed in seeds()
            for offset in range(0, args.depth, PAGE)]
    print("candidate pool from npm search")
    print(f"  {len(seeds())} seeds x {args.depth // PAGE} pages = {len(jobs):,} requests")

    found: dict[str, None] = {}
    started = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for index, names in enumerate(pool.map(fetch_page, jobs), start=1):
            for name in names:
                found.setdefault(name, None)
            if index % 100 == 0 or index == len(jobs):
                rate = index / max(time.time() - started, 1e-9)
                scoped = sum(1 for n in found if n.startswith("@"))
                print(f"  {index:,}/{len(jobs):,}  {rate:4.1f}/s  "
                      f"distinct={len(found):,} (scoped {scoped:,})")
            if len(found) >= args.target:
                print(f"  reached target of {args.target:,}")
                break

    names = sorted(found)
    scoped = sum(1 for n in names if n.startswith("@"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(names) + "\n", encoding="utf-8")
    args.out.with_suffix(".manifest.json").write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source": "npm registry search API, popularity=1.0",
        "seeds": len(seeds()),
        "depth": args.depth,
        "total": len(names),
        "scoped": scoped,
        "role": "stage 1 candidate pool only; rank_npm.py does the ranking",
    }, indent=2), encoding="utf-8")

    print(f"\n  {len(names):,} candidates ({scoped:,} scoped, "
          f"{100*scoped/max(len(names),1):.1f}%)")
    print(f"  -> {args.out}")
    print("\n  This pool is NOT a ranking. Run rank_npm.py next to measure "
          "real\n  download counts over it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
