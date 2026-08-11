"""Does npm's bulk downloads endpoint really stop at 128 names?

    python scripts/audit/probe_bulk_limit.py

BULK_LIMIT = 128 came from npm's documentation, not from measurement. Every
other constant in this audit was probed against the live service, because the
documentation has already been wrong once here: replicate.npmjs.org/_all_docs
is documented and returns HTTP 400.

The exhaustive unscoped ranking is 2,686,420 names, so the batch size divides
the entire cost. At 128 that is 20,988 requests; if 256 works it is 10,494, and
an eight-hour run becomes four. Worth thirty seconds to find out.

Prints the largest batch size that returns complete, correct data. It verifies
COMPLETENESS, not just HTTP 200 -- an endpoint that silently truncates to 128
while accepting 256 would otherwise look like a win and quietly halve coverage.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

API = "https://api.npmjs.org/downloads/point/last-month/"
UA = {"User-Agent": "qknot-audit (+https://github.com/qknot)"}


def sample_names(count: int) -> list[str]:
    """Real unscoped names from the frame, so the probe tests real conditions."""
    frame = ROOT / "data" / "npm_frame_2026-07-30.txt"
    if not frame.exists():
        raise SystemExit(f"{frame} not found; run fetch_npm_frame.py first")
    out: list[str] = []
    with frame.open(encoding="utf-8") as handle:
        for line in handle:
            name = line.strip()
            if name and not name.startswith("@") and "," not in name:
                out.append(name)
                if len(out) >= count:
                    break
    return out


def attempt(names: list[str]) -> tuple[bool, str]:
    url = API + ",".join(names)
    request = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, str(exc)[:60]

    if not isinstance(data, dict):
        return False, "response is not an object"
    # Completeness matters more than status: a truncating endpoint that returns
    # 200 for 256 names while answering for 128 would halve coverage silently.
    returned = sum(1 for n in names if n in data)
    if returned < len(names):
        return False, f"TRUNCATED: {returned}/{len(names)} names answered"
    return True, f"{returned}/{len(names)} answered"


def main() -> int:
    print("probing npm bulk downloads batch size")
    print(f"  current BULK_LIMIT is 128 -> "
          f"{(2_686_420 + 127) // 128:,} requests for the unscoped frame\n")
    best = 0
    for size in (128, 192, 256, 384, 512, 1024):
        names = sample_names(size)
        if len(names) < size:
            print(f"  {size:>5}: not enough names in the frame to test")
            continue
        ok, detail = attempt(names)
        print(f"  {size:>5}: {'ok  ' if ok else 'no  '} {detail}")
        if ok:
            best = size
        else:
            break
        time.sleep(2.0)          # do not start a 429 storm inside a probe

    print(f"\n  largest complete batch: {best}")
    if best > 128:
        print(f"  -> {(2_686_420 + best - 1) // best:,} requests instead of "
              f"{(2_686_420 + 127) // 128:,}: "
              f"{128 / best:.0%} of the current runtime")
        print(f"  -> set BULK_LIMIT = {best} in src/qknot/audit/npm_client.py")
    elif best == 128:
        print("  -> the documented limit is the real limit; the current run is "
              "already\n     as cheap as this endpoint allows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
