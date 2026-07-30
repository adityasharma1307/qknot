"""Enumerate the npm namespace into a sampling frame, one name per line.

    python scripts/audit/fetch_npm_frame.py --out data/npm_frame_2026-07-30.txt

UNTESTED FROM THE DEVELOPMENT SANDBOX
=====================================
`replicate.npmjs.com` is unreachable there, so response size, paging behaviour
and rate limits for ~3.5M names are unknown to this code's author. It is
written defensively as a result: it pages, it reports progress, and it can be
resumed from the last key rather than restarted.

If the registry turns out to serve the whole thing in one response, the paging
simply completes in one iteration. If it rate-limits, `--start-key` picks up
where the last run stopped.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

REPLICATE = "https://replicate.npmjs.com/_all_docs"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--page", type=int, default=50_000,
                        help="Names per request.")
    parser.add_argument("--start-key", default=None,
                        help="Resume from this package name.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Stop after N names. For a smoke test.")
    args = parser.parse_args(argv)

    import requests

    session = requests.Session()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.start_key else "w"
    start = args.start_key
    total = 0
    started = time.time()

    print(f"enumerating npm -> {args.out}")
    with args.out.open(mode, encoding="utf-8") as handle:
        while True:
            url = f"{REPLICATE}?limit={args.page}"
            if start:
                url += f"&start_key={quote(json.dumps(start))}"
            try:
                response = session.get(url, timeout=300,
                                       headers={"User-Agent": "qresp-audit"})
                response.raise_for_status()
                rows = response.json().get("rows", [])
            except Exception as exc:
                print(f"\n  FAILED after {total:,} names: {exc}")
                print(f"  resume with:  --start-key {start!r}")
                return 1

            if start and rows and rows[0].get("id") == start:
                rows = rows[1:]          # start_key is inclusive
            if not rows:
                break

            for row in rows:
                name = row.get("id")
                if name and not name.startswith("_"):
                    handle.write(name + "\n")
                    total += 1
            handle.flush()
            start = rows[-1].get("id")
            rate = total / max(time.time() - started, 1e-9)
            print(f"  {total:,} names  {rate:,.0f}/s  last={start}")

            if args.limit and total >= args.limit:
                break
            if len(rows) < args.page - 1:
                break

    print(f"\n  wrote {total:,} names -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
