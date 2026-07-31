"""Two-stratum PyPI attestation scan, mirroring the HuggingFace design.

    python scripts/audit/run_pypi_audit.py --out data/pypi_2026-07-30.jsonl

One command. Resumable: interrupt it and re-run, and it picks up from the
records already written rather than starting over. A 20,000-project scan over a
public API will be interrupted at some point, and a collector that treats that
as fatal is one that never finishes -- the lesson from the entropy collection,
where an early version lost 99% and 53% of two samples to a single error each.

STRATA
======
head  top 10,000 by downloads, from a published ranking
tail  10,000 sampled at random from the rest of the PyPI namespace

The ranking is fetched once and **written to disk beside the output**. It is a
dated artefact: the head stratum is only reproducible if the exact ranking used
is preserved, because the live ranking changes every month. Same reasoning that
removed BigQuery from the plan (docs/DATASETS.md).

The sampling seed, the frame size and a digest of the frame are all recorded in
a manifest, so the tail is re-derivable rather than merely described.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_RANKING_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
)
HEAD_SIZE = 10_000
TAIL_SIZE = 10_000
DEFAULT_SEED = 20260730


def _fetch_json(url: str, timeout: float = 120.0) -> dict:
    import requests

    response = requests.get(url, timeout=timeout,
                            headers={"User-Agent": "qresp-audit"})
    response.raise_for_status()
    return response.json()


def load_or_fetch_ranking(path: Path, url: str) -> list[str]:
    """Use the cached ranking if present; otherwise fetch and cache it.

    Cached deliberately. Re-fetching on each run would silently change the head
    stratum between runs, which would make a resumed scan a scan of two
    different populations stitched together.
    """
    if path.exists():
        print(f"  ranking: reusing {path} (delete it to re-fetch)")
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        print(f"  ranking: fetching {url}")
        data = _fetch_json(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        print(f"  ranking: cached to {path}")

    rows = data.get("rows") if isinstance(data, dict) else data
    names = [r["project"] if isinstance(r, dict) else r for r in rows]
    print(f"  ranking: {len(names):,} projects")
    return names


def build_frame(client) -> list[str]:
    print("  frame: enumerating the PyPI namespace (one large request)...")
    names = client.list_projects()
    print(f"  frame: {len(names):,} projects")
    return names


def already_done(path: Path) -> set[str]:
    """Names already recorded, so a resumed run does not repeat work."""
    if not path.exists():
        return set()
    seen = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                seen.add(json.loads(line)["project"])
            except Exception:
                continue          # a truncated final line from a hard kill
    return seen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True,
                        help="JSONL output; re-running resumes into the same file.")
    parser.add_argument("--ranking-url", default=DEFAULT_RANKING_URL)
    parser.add_argument("--ranking-cache", type=Path, default=None,
                        help="Default: <out>.ranking.json, beside the output.")
    parser.add_argument("--head", type=int, default=HEAD_SIZE)
    parser.add_argument("--tail", type=int, default=TAIL_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--workers", type=int, default=8,
                        help="Concurrent requests. Keep modest; this is a free "
                             "public service.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Stop after N projects. For a smoke test.")
    args = parser.parse_args(argv)

    from qresp.audit.capability import scan_environment
    from qresp.audit.pypi_client import PyPiClient
    from qresp.audit.pypi_scanner import audit_project

    args.out.parent.mkdir(parents=True, exist_ok=True)
    ranking_cache = args.ranking_cache or args.out.with_suffix(".ranking.json")
    manifest_path = args.out.with_suffix(".manifest.json")

    print("PyPI attestation scan")
    print("=" * 70)

    ranking = load_or_fetch_ranking(ranking_cache, args.ranking_url)
    client = PyPiClient()
    frame = build_frame(client)

    # Head: top N of the ranking that actually exist in the frame. A ranked
    # project missing from the index has been deleted since the ranking was
    # published; dropping it silently would leave the head short without saying
    # so, so the count is reported.
    frame_set = set(frame)
    head = [name for name in ranking if name in frame_set][:args.head]
    dropped = len([n for n in ranking[:args.head] if n not in frame_set])
    if dropped:
        print(f"  head: {dropped} ranked project(s) no longer in the index")
    print(f"  head: {len(head):,}")

    # Tail: random from everything not in the head. Seeded and recorded.
    remainder = sorted(frame_set - set(head))
    rng = random.Random(args.seed)
    tail = rng.sample(remainder, min(args.tail, len(remainder)))
    print(f"  tail: {len(tail):,} sampled from {len(remainder):,} (seed {args.seed})")

    frame_digest = hashlib.sha256("\n".join(sorted(frame)).encode()).hexdigest()
    manifest_path.write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "frame_size": len(frame),
        "frame_sha256": frame_digest,
        "head_size": len(head),
        "tail_size": len(tail),
        "seed": args.seed,
        "ranking_url": args.ranking_url,
        "ranking_size": len(ranking),
        "environment": scan_environment(),
        "unit_of_analysis": "per-project, any release ever attested",
    }, indent=2), encoding="utf-8")
    print(f"  manifest -> {manifest_path}")

    targets = [(n, "head") for n in head] + [(n, "tail") for n in tail]
    done = already_done(args.out)
    if done:
        print(f"  resuming: {len(done):,} already recorded")
    todo = [(n, s) for n, s in targets if n not in done]
    if args.limit:
        todo = todo[:args.limit]
    print(f"  to scan: {len(todo):,}\n")

    started = time.time()
    counts = {"signed": 0, "unsigned": 0, "error": 0}

    def scan(item):
        name, stratum = item
        record = audit_project(client, name)
        record["stratum"] = stratum
        return record

    with (args.out.open("a", encoding="utf-8") as handle,
          ThreadPoolExecutor(max_workers=args.workers) as pool):
            for index, record in enumerate(pool.map(scan, todo), start=1):
                handle.write(json.dumps(record) + "\n")
                if index % 200 == 0:
                    handle.flush()
                if record["q_label"] == "error":
                    counts["error"] += 1
                elif record["has_signature"]:
                    counts["signed"] += 1
                else:
                    counts["unsigned"] += 1
                if index % 500 == 0 or index == len(todo):
                    rate = index / max(time.time() - started, 1e-9)
                    remaining = (len(todo) - index) / max(rate, 1e-9)
                    print(f"  {index:6,}/{len(todo):,}  {rate:5.1f}/s  "
                          f"~{remaining/60:5.1f} min left   "
                          f"signed={counts['signed']} "
                          f"unsigned={counts['unsigned']} "
                          f"error={counts['error']}")

    print(f"\n  wrote {args.out}")
    print(f"  signed={counts['signed']}  unsigned={counts['unsigned']}  "
          f"error={counts['error']}")
    print("\n  `error` is NOT `unsigned`: those are projects that could not be "
          "checked.\n  Re-run to retry them before quoting any rate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
