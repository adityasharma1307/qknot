#!/usr/bin/env python3
"""Draw the Stratum B (long-tail) sample for the QResP stratified audit.

METHODS SUMMARY
===============
The audit uses a two-stratum design over the HuggingFace model registry:

    Stratum A (head): the top 10,000 models by all-time download count.
    Stratum B (tail): 10,000 models drawn uniformly at random from every
                      model *outside* Stratum A.

Stratum B is a genuine random sample, not "the next 10,000 by downloads".
That distinction is the whole point of the design. Ranks 10,001-20,000 are
still popular models and would tell us about the head a second time; a
uniform draw from the remaining population is what licenses inference about
the registry as a whole, and it is what makes the head-versus-tail contrast
the paper's actual finding rather than a comparison of two shades of popular.

The HuggingFace API offers no random-sample endpoint, so a uniform draw
requires a sampling frame. This script builds one:

    1. ENUMERATE. Page through `GET /api/models` sorted by `createdAt` to
       collect the id of every model in the registry. Sorting by creation
       date (rather than by downloads) gives a stable, append-only ordering:
       new models enter at one end and never reshuffle the rest, so a frame
       built over several hours is not corrupted by models moving between
       pages mid-enumeration. Sorting by downloads would have exactly that
       defect, because download counts change continuously.

    2. EXCLUDE. Remove every id in Stratum A, so the two strata are disjoint
       and the weighted combination in stats.py is valid.

    3. DRAW. Take `random.sample(frame, 10_000)` from a `random.Random`
       seeded with an explicit, logged integer.

The frame itself is written to disk alongside the sample. This is deliberate.
A seed alone does not make the draw reproducible, because the population it
was drawn from changes daily as models are added and removed. Publishing the
frame lets a reviewer re-run the draw and get byte-identical output, and lets
them check the draw was uniform rather than taking our word for it.

REPRODUCIBILITY
===============
Every run writes a manifest recording the seed, the frame size, the exclusion
count, the API snapshot time, and a SHA-256 of the frame file. Re-running with
the same `--seed` against the same `--frame` reproduces the sample exactly.

    # full run: enumerate, then draw
    python scripts/sample_longtail.py --head-ids data/head_10k.jsonl --seed 20260725

    # re-draw from a published frame without touching the network
    python scripts/sample_longtail.py --frame data/longtail_frame_2026-07-25.txt \
        --head-ids data/head_10k.jsonl --seed 20260725

COST
====
Enumeration is the expensive phase: it touches the entire registry, not just
the 10,000 models we keep. At 1,000 ids per page this is roughly one request
per thousand models in the registry. See --estimate-only to measure the
population size and projected request count before committing to a full run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import sys
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("sample_longtail")

API_URL = "https://huggingface.co/api/models"
USER_AGENT = "qresp/0.2 (BITS Pilani CS F376 research audit)"

# The API caps page size. 1,000 is the documented maximum; the code does not
# assume the cap holds and simply follows whatever the server returns.
PAGE_LIMIT = 1000

# Enumeration asks for the smallest useful payload. `siblings` (the per-repo
# file list) is returned by default and is by far the largest field; we do not
# need it here because the scanner fetches file lists itself during the audit.
EXPAND_FIELDS = ["createdAt"]

LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

# How many times a single page may fail before the crawl gives up. Progress is
# checkpointed, so giving up is recoverable rather than catastrophic.
MAX_PAGE_ATTEMPTS = 6


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------
def _next_url(response: requests.Response) -> str | None:
    """Extract the cursor-pagination `next` link, if the server sent one."""
    link = response.headers.get("Link")
    if not link:
        return None
    match = LINK_NEXT_RE.search(link)
    return match.group(1) if match else None


def build_session(token: str | None = None) -> requests.Session:
    """A session that survives the ordinary hostility of a long enumeration.

    Transport-level retries are configured on the adapter so that a dropped
    TCP connection is retried inside urllib3 rather than surfacing as a
    ConnectionResetError that kills a run an hour in. `backoff_factor` gives
    exponential spacing, and `respect_retry_after_header` means a 429 is
    honoured on the server's terms rather than ours.
    """
    session = requests.Session()
    retry = Retry(
        total=8,
        connect=5,
        read=5,
        status=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=4)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = USER_AGENT
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    return session


def enumerate_population(
    session: requests.Session,
    token: str | None = None,
    max_pages: int | None = None,
    sleep: float = 0.0,
    start_url: str | None = None,
    on_page: Callable[[list[str], str | None, int], None] | None = None,
) -> Iterator[str]:
    """Yield the id of every model in the registry, oldest-created first.

    Pages via the `Link: rel="next"` cursor rather than by incrementing an
    offset. Offset pagination over a table that is being written to will skip
    or duplicate rows; cursor pagination will not.

    Args:
        start_url: resume from a previously saved cursor instead of the
            beginning. Safe precisely because the ordering is by creation date:
            new models are appended at the far end and never disturb pages
            already walked, so a resumed enumeration sees the same prefix it
            would have seen had it never stopped.
        on_page: called with (ids, next_cursor, page_number) after each page,
            for incremental checkpointing. Enumeration of a multi-million-row
            registry takes long enough that losing it to one dropped connection
            is not acceptable.
    """
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    resuming = start_url is not None
    url: str | None = start_url or API_URL
    params: dict | None = None if resuming else {
        "limit": PAGE_LIMIT,
        "sort": "createdAt",
        "direction": 1,  # ascending: oldest first, so the tail is append-only
        "expand[]": EXPAND_FIELDS,
    }

    page = 0
    seen = 0
    consecutive_failures = 0

    while url:
        if max_pages is not None and page >= max_pages:
            log.info("Stopping at --max-pages=%d", max_pages)
            return

        try:
            response = session.get(url, params=params, headers=headers, timeout=60)
        except requests.exceptions.RequestException as exc:
            # The adapter already retried at the transport level; reaching here
            # means those were exhausted. Back off further rather than losing
            # the whole enumeration.
            consecutive_failures += 1
            if consecutive_failures > MAX_PAGE_ATTEMPTS:
                raise RuntimeError(
                    f"Enumeration failed {consecutive_failures} times in a row on "
                    f"page {page} ({exc}). Progress is checkpointed; rerun to resume."
                ) from exc
            wait = min(60.0, 2.0 ** consecutive_failures)
            log.warning("Connection error on page %d (%s). Retrying in %.0fs [%d/%d].",
                        page, exc, wait, consecutive_failures, MAX_PAGE_ATTEMPTS)
            time.sleep(wait)
            continue

        if response.status_code == 429:
            consecutive_failures += 1
            if consecutive_failures > MAX_PAGE_ATTEMPTS:
                raise RuntimeError(
                    f"Still rate limited on page {page} after {consecutive_failures} "
                    f"attempts. Progress is checkpointed; rerun later to resume, "
                    f"or pass --sleep to slow the crawl."
                )
            # Honour Retry-After, but escalate if the server keeps saying no:
            # repeating the same wait forever is how a crawl livelocks.
            base = float(response.headers.get("Retry-After", "60"))
            wait = base * consecutive_failures
            log.warning("Rate limited on page %d. Sleeping %.0fs [%d/%d].",
                        page, wait, consecutive_failures, MAX_PAGE_ATTEMPTS)
            time.sleep(wait)
            continue

        response.raise_for_status()
        batch = response.json()
        if not batch:
            return

        consecutive_failures = 0
        ids = [e.get("id") or e.get("modelId") for e in batch]
        ids = [i for i in ids if i]

        next_url = _next_url(response)
        if on_page is not None:
            on_page(ids, next_url, page)

        for model_id in ids:
            yield model_id
            seen += 1

        page += 1
        if page % 100 == 0:
            log.info("Enumerated %d models across %d pages", seen, page)

        url = next_url
        params = None  # the cursor url already carries the query string
        if sleep:
            time.sleep(sleep)


# ---------------------------------------------------------------------------
# Stratum A ids
# ---------------------------------------------------------------------------
def load_head_ids(path: Path) -> set[str]:
    """Read Stratum A model ids from the head audit output (JSONL) or a
    plain newline-delimited id list."""
    ids: set[str] = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                ids.add(json.loads(line)["model_id"])
            else:
                ids.add(line)
    return ids


# ---------------------------------------------------------------------------
# Draw
# ---------------------------------------------------------------------------
def draw_sample(frame: list[str], k: int, seed: int) -> list[str]:
    """Uniform draw of k ids without replacement, reproducible from `seed`.

    The frame is sorted before drawing. `random.sample` is deterministic given
    a seed *and a fixed input ordering*, and enumeration order is not
    guaranteed stable across runs, so sorting is what actually makes the seed
    meaningful.
    """
    if k > len(frame):
        raise SystemExit(
            f"Cannot draw {k:,} from a frame of {len(frame):,}. "
            f"Check that enumeration completed and exclusions are correct."
        )
    ordered = sorted(frame)
    rng = random.Random(seed)
    return rng.sample(ordered, k)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    today = datetime.now(timezone.utc).date().isoformat()
    parser = argparse.ArgumentParser(
        description="Draw the Stratum B long-tail sample.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--seed", type=int, required=True,
                        help="Integer RNG seed. Recorded in the manifest. Required, "
                             "because an unrecorded seed is an unreproducible sample.")
    parser.add_argument("--k", type=int, default=10_000,
                        help="Sample size (default: 10000).")
    parser.add_argument("--head-ids", type=Path, default=None,
                        help="Stratum A ids to exclude: the head audit output or an "
                             "id list. Required except in --estimate-only mode.")
    parser.add_argument("--frame", type=Path, default=None,
                        help="Reuse an existing frame file instead of enumerating. "
                             "Use this to reproduce a published draw offline.")
    parser.add_argument("--out-dir", type=Path, default=Path("data"))
    parser.add_argument("--token", default=None,
                        help="HuggingFace token. Raises rate limits.")
    parser.add_argument("--sleep", type=float, default=0.0,
                        help="Seconds to sleep between pages, to stay polite.")
    parser.add_argument("--max-pages", type=int, default=None,
                        help="Cap pages enumerated. For dry runs.")
    parser.add_argument("--estimate-only", action="store_true",
                        help="Enumerate a few pages, project total cost, exit "
                             "without drawing. Run this before the real thing.")
    args = parser.parse_args(argv)

    # Log to stdout rather than the logging default of stderr. Progress
    # messages are not errors, and shells that treat native stderr as failure
    # (PowerShell with ErrorActionPreference = 'Stop') would otherwise abort on
    # the first INFO line.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    session = build_session(args.token)

    # -- Estimate mode ------------------------------------------------------
    if args.estimate_only:
        log.info("Estimate mode: sampling 5 pages to project total cost.")
        t0 = time.time()
        count = sum(1 for _ in enumerate_population(session, args.token, max_pages=5))
        elapsed = time.time() - t0
        if not count:
            log.error("No models returned. Check network and API availability.")
            return 1
        per_page = count / 5
        log.info("Observed %.0f models/page, %.2fs for 5 pages.", per_page, elapsed)
        log.info("Enumerating a registry of N models will take roughly "
                 "N/%.0f requests and N/%.0f * %.2fs.", per_page, per_page, elapsed / 5)
        for n in (1_000_000, 2_000_000, 3_000_000):
            pages = n / per_page
            log.info("  if N=%s: %.0f requests, ~%.1f min wall clock",
                     f"{n:,}", pages, pages * (elapsed / 5) / 60)
        return 0

    # -- Frame --------------------------------------------------------------
    if args.head_ids is None:
        parser.error("--head-ids is required unless --estimate-only is given")
    head_ids = load_head_ids(args.head_ids)
    log.info("Stratum A: %d ids to exclude", len(head_ids))

    frame_path = args.frame or args.out_dir / f"longtail_frame_{today}.txt"
    snapshot_started = datetime.now(timezone.utc).isoformat()

    if args.frame:
        log.info("Reusing frame %s (no network access)", frame_path)
        population = [ln.strip() for ln in frame_path.read_text().splitlines() if ln.strip()]
        n_enumerated = len(population)
        frame = [m for m in population if m not in head_ids]
    else:
        # Checkpointed enumeration. Ids are appended to a .partial file as each
        # page arrives and the cursor is saved beside it, so an interruption
        # costs one page rather than the entire crawl. A multi-million-row
        # enumeration is far too long to treat as atomic.
        partial_path = frame_path.with_suffix(frame_path.suffix + ".partial")
        cursor_path = frame_path.with_suffix(frame_path.suffix + ".cursor")

        start_url = None
        seen_ids: set[str] = set()
        if partial_path.exists() and cursor_path.exists():
            state = json.loads(cursor_path.read_text(encoding="utf-8"))
            start_url = state.get("next_url")
            seen_ids = {
                ln.strip()
                for ln in partial_path.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            }
            log.info("Resuming enumeration: %d ids already collected, from page %d.",
                     len(seen_ids), state.get("page", 0))
            if not start_url:
                log.info("Saved cursor is empty, meaning the previous run reached "
                         "the end of the registry. Nothing left to enumerate.")
        elif partial_path.exists():
            log.warning("Found %s without a cursor file. Starting over; delete the "
                        "partial file to silence this.", partial_path)

        n_enumerated = len(seen_ids)
        if start_url or not seen_ids:
            log.info("Enumerating registry. This is the slow part.")
            out_handle = partial_path.open("a", encoding="utf-8")

            def checkpoint(ids: list[str], next_url: str | None, page: int) -> None:
                for i in ids:
                    out_handle.write(i + "\n")
                out_handle.flush()
                os.fsync(out_handle.fileno())
                cursor_path.write_text(
                    json.dumps({"next_url": next_url, "page": page,
                                "saved_at": datetime.now(timezone.utc).isoformat()}),
                    encoding="utf-8",
                )

            try:
                for model_id in enumerate_population(
                    session, args.token,
                    max_pages=args.max_pages, sleep=args.sleep,
                    start_url=start_url, on_page=checkpoint,
                ):
                    n_enumerated += 1
                    seen_ids.add(model_id)
            finally:
                out_handle.close()

        # Deduplicate defensively: cursor pagination should not repeat, but a
        # server-side rebalance during a long run could, and a resumed run can
        # re-read the final partial page.
        if len(seen_ids) != n_enumerated:
            log.warning("Enumeration returned %d ids, %d unique. Deduplicated.",
                        n_enumerated, len(seen_ids))
        n_enumerated = len(seen_ids)
        frame = sorted(seen_ids - head_ids)
        frame_path.write_text("\n".join(frame) + "\n", encoding="utf-8")
        log.info("Frame written: %s (%d ids)", frame_path, len(frame))
        # The checkpoint files have served their purpose now that the frame is
        # complete. Leave them: they cost little and make it obvious the frame
        # was built incrementally if anyone audits the process.

    excluded = n_enumerated - len(frame)
    log.info("Population enumerated: %d | after exclusions: %d", n_enumerated, len(frame))

    # -- Draw ---------------------------------------------------------------
    sample = draw_sample(frame, args.k, args.seed)
    sample_path = args.out_dir / f"longtail_sample_{today}.txt"
    sample_path.write_text("\n".join(sample) + "\n", encoding="utf-8")

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_started": snapshot_started,
        "script": "scripts/sample_longtail.py",
        "procedure": "uniform random.sample without replacement from a "
                     "createdAt-ordered enumeration of the registry, "
                     "excluding Stratum A",
        "seed": args.seed,
        "k": args.k,
        "population_enumerated": n_enumerated,
        "stratum_a_size": len(head_ids),
        "excluded_as_stratum_a": excluded,
        "frame_size": len(frame),
        "sampling_fraction": len(sample) / len(frame) if frame else None,
        "frame_file": str(frame_path),
        "frame_sha256": sha256_file(frame_path),
        "sample_file": str(sample_path),
        "sample_sha256": sha256_file(sample_path),
        "authenticated": bool(args.token),
    }
    manifest_path = args.out_dir / f"longtail_manifest_{today}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    log.info("Sample written:   %s (%d ids)", sample_path, len(sample))
    log.info("Manifest written: %s", manifest_path)
    log.info("Sampling fraction: %.4f%%", 100 * manifest["sampling_fraction"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
