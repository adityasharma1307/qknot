"""Stage 2 of the npm head ranking: real download counts over a candidate pool.

    python scripts/audit/rank_npm.py --candidates data/npm_candidates.txt \
                                     --out data/npm_ranking_2026-07-30.json

WHY THIS IS TWO STAGES AND NOT ONE
==================================
npm publishes no downloads ranking, and its bulk downloads endpoint **rejects
scoped packages**. `@babel/*`, `@types/*` and similar are a large share of the
most popular names -- 37.4% of the whole namespace is scoped -- so ranking only
what the bulk endpoint accepts would bias the head towards unscoped packages
rather than towards popular ones. A candidate pool comes in (stage 1), and this
script measures real downloads over it: bulk for unscoped, individually for
scoped.

THE 429 STORM, AND WHAT IT TAUGHT
=================================
The first run of this script had no throttle and no retry. api.npmjs.org is far
stricter than registry.npmjs.org, and it began returning HTTP 429 at roughly
batch 49 of 239. The damage was not merely that 42,965 of 50,104 candidates
went unmeasured. It was that **the survivors were alphabetically biased**:
because the candidate pool is sorted, the batches that completed before the
rate limit engaged were the early-alphabet ones, so 84% of measured names began
with a, b or c, and only 228 of 19,527 scoped packages measured at all.

An incomplete ranking would have been merely weak. A ranking whose losses
correlate with the sort order is *worse than a random subsample*, because the
bias is invisible in the output -- the file looks like a clean ranking of 7,139
packages. Nothing in it says "this is the top of the alphabet, not the top of
npm."

Three changes follow from that:

* **Throttle** to a fixed request rate rather than firing as fast as possible.
* **Retry with exponential backoff**, so a 429 delays a batch instead of
  destroying it.
* **Persist partial results** after every batch, so an interrupted or
  rate-limited run resumes instead of restarting -- the same lesson the entropy
  collection and the PyPI scanner already learned.

And one that is about honesty rather than mechanism: the run **fails loudly**
if too large a share of candidates went unmeasured, rather than writing a
plausible-looking ranking built from whatever survived.

WHAT STAGE 1 HAS TO GET RIGHT, AND WHAT IT DOES NOT
===================================================
The candidate source does not need to rank well; stage 2 ranks. Stage 1 only
has to avoid *losing* genuinely popular packages, so it errs large.

Residual caveat for the paper, one sentence: a package with very high downloads
and near-zero presence in the candidate source would be missed. That is an edge
case rather than a systematic bias -- unlike ranking a random subsample, where
a 2.9% sample would miss ~97% of the true top 10,000 because sampling
probability is independent of popularity.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_RATE = 4.0          # starting pace; AIMD lowers it if npm pushes back
MAX_ATTEMPTS = 6
MIN_MEASURED_FRACTION = 0.80


class Throttle:
    """A shared request pace that SLOWS DOWN GLOBALLY when npm pushes back.

    The first throttled version paced requests but let each thread back off
    privately. That does not work: while one worker sleeps 32s on a 429, the
    other three keep issuing requests at the full rate, so the server sees no
    reduction and the 429s continue indefinitely. Backoff has to be a property
    of the shared pace, not of the individual request.

    So a 429 does two things here: it pauses *every* worker until the stated
    (or estimated) retry time, and it multiplicatively widens the interval for
    all future requests. Successes narrow it back gradually. This is ordinary
    AIMD congestion control, which is what a rate limit calls for.
    """

    def __init__(self, per_second: float, floor_per_second: float = 0.4) -> None:
        self._base = 1.0 / per_second if per_second > 0 else 0.0
        self._interval = self._base
        self._ceiling = 1.0 / floor_per_second if floor_per_second > 0 else 10.0
        self._lock = threading.Lock()
        self._next = 0.0
        self.penalties = 0

    def wait(self) -> None:
        with self._lock:
            if self._interval <= 0:
                return
            now = time.monotonic()
            due = max(now, self._next)
            self._next = due + self._interval
        delay = due - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    def penalise(self, seconds: float) -> None:
        """Pause every worker, and widen the interval for all future requests."""
        with self._lock:
            self.penalties += 1
            self._next = max(self._next, time.monotonic() + seconds)
            self._interval = min(self._interval * 1.5, self._ceiling)

    def relax(self) -> None:
        """Recover slowly after success, so one good reply is not a green light."""
        with self._lock:
            self._interval = max(self._base, self._interval * 0.999)

    @property
    def rate(self) -> float:
        return 1.0 / self._interval if self._interval > 0 else float("inf")


def with_retry(call, throttle: Throttle, describe: str,
               attempts: int = MAX_ATTEMPTS):
    """Run `call`, backing off on TRANSIENT failure only.

    A 404 from the downloads API is npm answering the question: there is no
    download record for this package. Retrying it five more times cannot change
    that, and on a rate-limited endpoint each pointless retry spends budget a
    genuinely transient 429 needed. Permanent failures raise immediately.
    """
    from qresp.audit.npm_client import NpmError

    delay = 4.0
    for attempt in range(1, attempts + 1):
        throttle.wait()
        try:
            result = call()
        except NpmError as exc:
            if exc.is_permanent:
                raise
            if attempt == attempts:
                raise
            pause = exc.retry_after if exc.retry_after else delay
            # No sleep here. penalise() pushes the SHARED next-allowed time
            # forward, and this thread's next throttle.wait() already blocks
            # until then. Sleeping as well waited out the same penalty twice,
            # which with six workers and a delay escalating to 120s is what
            # made the run appear to stall.
            throttle.penalise(pause)
            delay = min(delay * 2, 120.0)
        except Exception:
            if attempt == attempts:
                raise
            throttle.penalise(delay)
            delay = min(delay * 2, 120.0)
        else:
            throttle.relax()
            return result
    raise AssertionError("unreachable")


def load_partial(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if isinstance(v, int)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE,
                        help="Requests per second, shared across workers.")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--min-measured", type=float, default=MIN_MEASURED_FRACTION,
                        help="Fail rather than write a ranking built from less "
                             "than this fraction of candidates.")
    args = parser.parse_args(argv)

    from qresp.audit.npm_client import BULK_LIMIT, NpmClient, is_scoped

    raw = args.candidates.read_text(encoding="utf-8").strip()
    names = json.loads(raw) if raw.startswith("[") else [
        line.strip() for line in raw.splitlines() if line.strip()]
    names = list(dict.fromkeys(names))

    unscoped = [n for n in names if not is_scoped(n)]
    scoped = [n for n in names if is_scoped(n)]
    partial_path = args.out.with_suffix(".partial.json")
    counts: dict[str, int] = load_partial(partial_path)

    print(f"candidates: {len(names):,}  ({len(unscoped):,} unscoped, "
          f"{len(scoped):,} scoped)")
    if counts:
        print(f"  resuming: {len(counts):,} already measured ({partial_path})")
    print(f"  throttle: {args.rate:g} req/s across {args.workers} workers")

    client = NpmClient()
    throttle = Throttle(args.rate)
    started = time.time()
    failed: list[str] = []

    todo_unscoped = [n for n in unscoped if n not in counts]
    batches = [todo_unscoped[i:i + BULK_LIMIT]
               for i in range(0, len(todo_unscoped), BULK_LIMIT)]
    print(f"  unscoped -> {len(batches):,} bulk requests")

    for index, batch in enumerate(batches, start=1):
        try:
            result = with_retry(lambda b=batch: client.bulk_downloads(b),
                                throttle, f"bulk {index}")
            counts.update({n: c for n, c in result.items() if isinstance(c, int)})
        except Exception as exc:
            failed.extend(batch)
            print(f"  batch {index} exhausted retries: {str(exc)[:100]}")
        if index % 10 == 0 or index == len(batches):
            partial_path.write_text(json.dumps(counts), encoding="utf-8")
            rate = index / max(time.time() - started, 1e-9)
            eta = (len(batches) - index) / max(rate, 1e-9) / 60
            print(f"  bulk {index:,}/{len(batches):,}  {rate:.1f}/s  "
                  f"~{eta:.0f} min left  measured={len(counts):,}  "
                  f"pace={throttle.rate:.1f}/s throttled={throttle.penalties}")

    todo_scoped = [n for n in scoped if n not in counts]
    print(f"  scoped -> {len(todo_scoped):,} individual requests")

    from concurrent.futures import ThreadPoolExecutor

    from qresp.audit.npm_client import NpmError

    no_record = 0
    lock = threading.Lock()

    def measure(name: str) -> tuple[str, int | None]:
        nonlocal no_record
        try:
            return name, with_retry(lambda: client.single_downloads(name),
                                    throttle, name)
        except NpmError as exc:
            if exc.is_permanent:
                # npm answered: no download record. Not a collection failure,
                # and counted separately so the two are never conflated in the
                # summary the way they would be if both just vanished.
                with lock:
                    no_record += 1
            return name, None
        except Exception:
            return name, None

    scoped_started = time.time()
    if todo_scoped:
        from concurrent.futures import as_completed

        last_beat = time.time()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(measure, n) for n in todo_scoped]
            # as_completed, not map: map yields IN SUBMISSION ORDER, so one
            # package stuck in backoff hid the progress of every package that
            # had already finished behind it. The run looked stopped when it
            # was working.
            for index, future in enumerate(as_completed(futures), start=1):
                name, value = future.result()
                if isinstance(value, int):
                    counts[name] = value
                else:
                    failed.append(name)
                beat = time.time() - last_beat > 30
                if index % 100 == 0 or index == len(todo_scoped) or beat:
                    last_beat = time.time()
                    partial_path.write_text(json.dumps(counts), encoding="utf-8")
                    elapsed = max(time.time() - scoped_started, 1e-9)
                    eta = (len(todo_scoped) - index) / (index / elapsed) / 60
                    print(f"  scoped {index:,}/{len(todo_scoped):,}  "
                          f"~{eta:.0f} min left  measured={len(counts):,}  "
                          f"pace={throttle.rate:.1f}/s throttled={throttle.penalties}  "
                          f"no-record={no_record}")

    # Unmeasured candidates are EXCLUDED, not sorted to the bottom. A missing
    # count is not a count of zero, and ranking them last would convert a
    # collection failure into a claim about popularity.
    measured = {n: c for n, c in counts.items() if n in set(names)}
    fraction = len(measured) / max(len(names), 1)
    ranked = sorted(measured.items(), key=lambda kv: kv[1], reverse=True)

    print(f"\n  measured {len(measured):,} / {len(names):,} ({fraction:.1%})")
    if fraction < args.min_measured:
        print(f"\n  ABORTED: only {fraction:.1%} of candidates were measured, "
              f"below --min-measured {args.min_measured:.0%}.")
        print("  A ranking built from a rate-limited subset is not a ranking by")
        print("  popularity -- the previous run lost 86% of candidates and the")
        print("  survivors were 84% a/b/c, because losses tracked sort order.")
        print(f"  Partial results are kept in {partial_path}; re-run to resume,")
        print("  optionally with a lower --rate.")
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "metric": "npm downloads, last-month, api.npmjs.org",
        "candidate_count": len(names),
        "measured": len(measured),
        "unmeasured": len(names) - len(measured),
        "measured_fraction": round(fraction, 4),
        "rate_limit_req_per_s": args.rate,
        "rows": [{"project": n, "download_count": c} for n, c in ranked],
    }, indent=2), encoding="utf-8")

    if no_record:
        print(f"  {no_record:,} returned 404 -- npm has no download record for "
              f"them (answered, not failed)")
    if failed:
        print(f"  {len(set(failed)):,} exhausted retries and are EXCLUDED, "
              f"not ranked last")
    print(f"  final pace {throttle.rate:.2f}/s after {throttle.penalties:,} "
          f"throttle events")
    print(f"  top 5: {[n for n, _ in ranked[:5]]}")
    print(f"  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
