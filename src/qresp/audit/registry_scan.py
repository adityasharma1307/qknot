"""Two-stratum registry scans: the orchestration behind the npm and PyPI audits.

The npm and PyPI runners were two ~220-line scripts whose bodies were nearly
identical -- same strata, same seeded sampling, same manifest, same resume rule,
same thread pool, same progress reporting, and a `already_done` docstring
duplicated word for word. Only the source of the ranking and the frame really
differed. That is one procedure with two inputs, so it lives here once, and both
the scripts and `qresp audit-npm` / `qresp audit-pypi` call it.

THE METHODOLOGY THIS ENCODES
============================
* **Two strata.** `head` is the top N by downloads; `tail` is N sampled at
  random from everything else. Reporting only the head would describe the
  popular packages and call it the ecosystem.
* **The sample is re-derivable, not merely described.** The seed, the frame
  size and a SHA-256 of the frame go into a manifest beside the output, so the
  tail can be reconstructed rather than taken on trust.
* **Resumable, because a 20,000-project scan over a public API WILL be
  interrupted.** A collector that treats an interruption as fatal is one that
  never finishes.
* **`error` is not `unsigned`.** A project that could not be reached was not
  checked, and counting it as unsigned would inflate the very number the study
  reports. Error rows are therefore NOT treated as done on resume: re-running
  retries them, and the reader takes the latest record per project. This is the
  absent-versus-unchecked rule the whole project is built on, one level up.
"""
from __future__ import annotations

import hashlib
import json
import random
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_HEAD_SIZE",
    "DEFAULT_SEED",
    "DEFAULT_TAIL_SIZE",
    "PYPI_RANKING_URL",
    "already_done",
    "run_npm_audit",
    "run_pypi_audit",
    "run_registry_scan",
]

DEFAULT_HEAD_SIZE = 10_000
DEFAULT_TAIL_SIZE = 10_000
DEFAULT_SEED = 20260730
PYPI_RANKING_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
)

Echo = Callable[[str], None]


def _ranking_rows(data: Any, source: Path) -> list[Any]:
    """The ranking rows, or a clear error.

    A ranking that is a dict without `rows` used to fall through to iterating
    `None`, which surfaced as an opaque TypeError at the top of a long scan. A
    malformed ranking is a configuration problem and should say so.
    """
    rows = data.get("rows") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ValueError(
            f"{source} does not look like a ranking: expected a list of rows, "
            f"or an object with a 'rows' list, got {type(rows).__name__}")
    return rows


def already_done(path: Path) -> set[str]:
    """Names with a USABLE record, so a resume neither repeats work nor skips a
    retry.

    A record whose q_label is `error` is NOT done: it was reached and could not
    be classified, and the runner's closing message tells the user to re-run to
    retry those. That instruction was once false -- this function counted error
    rows as recorded, so a resume skipped exactly the records it claimed to
    retry. `error` is excluded, so re-running retries them and appends a fresh
    record; the reader dedups to the latest, so a later success supersedes the
    earlier error.

    "We have a record" is not "we have an answer".
    """
    if not path.exists():
        return set()
    seen: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:  # noqa: BLE001 -- a truncated line from a hard kill
                continue
            if record.get("q_label") == "error":
                continue          # reached but unclassified -- retry on resume
            seen.add(record["project"])
    return seen


def run_registry_scan(
    *,
    ecosystem: str,
    out: Path,
    ranking: Sequence[str],
    frame: Sequence[str],
    client: Any,
    audit_one: Callable[[Any, str], dict[str, Any]],
    head_size: int = DEFAULT_HEAD_SIZE,
    tail_size: int = DEFAULT_TAIL_SIZE,
    seed: int = DEFAULT_SEED,
    workers: int = 8,
    limit: int | None = None,
    manifest_extra: dict[str, Any] | None = None,
    echo: Echo = print,
) -> dict[str, int]:
    """Run a two-stratum scan and append JSONL records to `out`.

    Returns the counts, so a caller can report or assert on them rather than
    scraping stdout.
    """
    from .capability import scan_environment

    out.parent.mkdir(parents=True, exist_ok=True)
    manifest_path = out.with_suffix(".manifest.json")

    # Head: the top N of the ranking that actually exist in the frame. A ranked
    # project missing from the index has been deleted since the ranking was
    # published; dropping it silently would leave the head short without saying
    # so, so the count is reported.
    frame_set = set(frame)
    head = [name for name in ranking if name in frame_set][:head_size]
    dropped = len([n for n in ranking[:head_size] if n not in frame_set])
    if dropped:
        echo(f"  head: {dropped} ranked project(s) no longer in the index")
    echo(f"  head: {len(head):,}")

    # Tail: random from everything not in the head. Seeded and recorded.
    remainder = sorted(frame_set - set(head))
    rng = random.Random(seed)
    tail = rng.sample(remainder, min(tail_size, len(remainder)))
    echo(f"  tail: {len(tail):,} sampled from {len(remainder):,} (seed {seed})")

    frame_digest = hashlib.sha256("\n".join(sorted(frame)).encode()).hexdigest()
    manifest: dict[str, Any] = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "ecosystem": ecosystem,
        "frame_size": len(frame),
        "frame_sha256": frame_digest,
        "head_size": len(head),
        "tail_size": len(tail),
        "seed": seed,
        "ranking_size": len(ranking),
        "environment": scan_environment(),
        "unit_of_analysis": "per-project, any release ever attested",
    }
    manifest.update(manifest_extra or {})
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    echo(f"  manifest -> {manifest_path}")

    targets = [(n, "head") for n in head] + [(n, "tail") for n in tail]
    done = already_done(out)
    if done:
        echo(f"  resuming: {len(done):,} already recorded")
    todo = [(n, s) for n, s in targets if n not in done]
    if limit:
        todo = todo[:limit]
    echo(f"  to scan: {len(todo):,}\n")

    started = time.time()
    counts = {"signed": 0, "unsigned": 0, "error": 0}

    def scan(item: tuple[str, str]) -> dict[str, Any]:
        name, stratum = item
        record = audit_one(client, name)
        record["stratum"] = stratum
        return record

    with (out.open("a", encoding="utf-8") as handle,
          ThreadPoolExecutor(max_workers=workers) as pool):
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
                echo(f"  {index:6,}/{len(todo):,}  {rate:5.1f}/s  "
                     f"~{remaining / 60:5.1f} min left   "
                     f"signed={counts['signed']} "
                     f"unsigned={counts['unsigned']} "
                     f"error={counts['error']}")

    echo(f"\n  wrote {out}")
    echo(f"  signed={counts['signed']}  unsigned={counts['unsigned']}  "
         f"error={counts['error']}")
    echo("\n  `error` is NOT `unsigned`: those are projects that could not be "
         "checked.\n  Re-run to retry them before quoting any rate.")
    return counts


# ---------------------------------------------------------------------------
# npm: both inputs are files, because npm publishes no ranking.
# ---------------------------------------------------------------------------

def load_npm_ranking(path: Path, echo: Echo = print) -> list[str]:
    """The stage-2 ranking (scripts/audit/rank_npm.py). A file, never a fetch.

    npm has no published ranking to re-fetch, and even if it had, re-fetching
    per run would make a resumed scan a scan of two populations stitched
    together.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = _ranking_rows(data, path)
    names = [r["project"] if isinstance(r, dict) else r for r in rows]
    echo(f"  ranking: {len(names):,} packages ({path})")
    if isinstance(data, dict) and data.get("unmeasured"):
        echo(f"  ranking: {data['unmeasured']:,} candidate(s) had no download "
             f"count and were excluded rather than ranked last")
    return names


def load_frame(path: Path, echo: Echo = print) -> list[str]:
    """The sampling frame: one package name per line."""
    names = [line.strip() for line in
             path.read_text(encoding="utf-8").splitlines() if line.strip()]
    echo(f"  frame: {len(names):,} packages ({path})")
    return names


def run_npm_audit(
    *,
    out: Path,
    ranking_path: Path,
    frame_path: Path,
    head_size: int = DEFAULT_HEAD_SIZE,
    tail_size: int = DEFAULT_TAIL_SIZE,
    seed: int = DEFAULT_SEED,
    workers: int = 8,
    limit: int | None = None,
    echo: Echo = print,
) -> dict[str, int]:
    """The npm two-stratum attestation scan."""
    from .npm_client import NpmClient
    from .npm_scanner import audit_package

    echo("npm attestation scan")
    echo("=" * 70)
    ranking = load_npm_ranking(ranking_path, echo)
    frame = load_frame(frame_path, echo)
    return run_registry_scan(
        ecosystem="npm", out=out, ranking=ranking, frame=frame,
        client=NpmClient(), audit_one=audit_package,
        head_size=head_size, tail_size=tail_size, seed=seed, workers=workers,
        limit=limit, echo=echo,
        manifest_extra={
            "ranking_file": str(ranking_path),
            "ranking_metric": "npm downloads, last-month (two-stage: candidate "
                              "pool then measured counts)",
        })


# ---------------------------------------------------------------------------
# PyPI: the ranking is fetched once and CACHED; the frame is the live index.
# ---------------------------------------------------------------------------

def load_or_fetch_ranking(path: Path, url: str, echo: Echo = print) -> list[str]:
    """Use the cached ranking if present; otherwise fetch and cache it.

    Cached deliberately. Re-fetching on each run would silently change the head
    stratum between runs, which would make a resumed scan a scan of two
    different populations stitched together.
    """
    if path.exists():
        echo(f"  ranking: reusing {path} (delete it to re-fetch)")
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        import requests

        echo(f"  ranking: fetching {url}")
        response = requests.get(url, timeout=120.0,
                                headers={"User-Agent": "qresp-audit"})
        response.raise_for_status()
        data = response.json()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        echo(f"  ranking: cached to {path}")

    rows = _ranking_rows(data, path)
    names = [r["project"] if isinstance(r, dict) else r for r in rows]
    echo(f"  ranking: {len(names):,} projects")
    return names


def run_pypi_audit(
    *,
    out: Path,
    ranking_url: str = PYPI_RANKING_URL,
    ranking_cache: Path | None = None,
    head_size: int = DEFAULT_HEAD_SIZE,
    tail_size: int = DEFAULT_TAIL_SIZE,
    seed: int = DEFAULT_SEED,
    workers: int = 8,
    limit: int | None = None,
    echo: Echo = print,
) -> dict[str, int]:
    """The PyPI two-stratum attestation scan."""
    from .pypi_client import PyPiClient
    from .pypi_scanner import audit_project

    out.parent.mkdir(parents=True, exist_ok=True)
    cache = ranking_cache or out.with_suffix(".ranking.json")

    echo("PyPI attestation scan")
    echo("=" * 70)
    ranking = load_or_fetch_ranking(cache, ranking_url, echo)
    client = PyPiClient()
    echo("  frame: enumerating the PyPI namespace (one large request)...")
    frame = client.list_projects()
    echo(f"  frame: {len(frame):,} projects")
    return run_registry_scan(
        ecosystem="pypi", out=out, ranking=ranking, frame=frame,
        client=client, audit_one=audit_project,
        head_size=head_size, tail_size=tail_size, seed=seed, workers=workers,
        limit=limit, echo=echo,
        manifest_extra={"ranking_url": ranking_url})
