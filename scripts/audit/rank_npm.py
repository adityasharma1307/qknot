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

    def __init__(self, per_second: float, floor_per_second: float = 1.5) -> None:
        self._base = 1.0 / per_second if per_second > 0 else 0.0
        self._interval = self._base
        self._ceiling = 1.0 / floor_per_second if floor_per_second > 0 else 10.0
        self._lock = threading.Lock()
        self._next = 0.0
        self._penalty_until = 0.0
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
        """Pause every worker, and widen the interval -- once per congestion event.

        TWO BUGS LIVED HERE, AND TOGETHER THEY RATCHETED THE RUN TO A HALT.

        First: with six workers in flight, a single burst of rate limiting
        produces six near-simultaneous 429s. Widening on each of them treats one
        congestion event as six, so the interval grew by 1.5^6 -- about 11x --
        for what the server experienced as one push-back. Penalties that arrive
        while the pause they caused is still in effect are therefore counted but
        NOT compounded; the congestion is already being paid for.

        Second, and worse, is in relax(): recovery was multiplicative and tiny,
        so the pace could only ever ratchet downwards. Observed live: 12
        throttle events drove 8 req/s to the 0.4 req/s floor, where it stayed --
        an ETA of 403 minutes and climbing. Multiplicative decrease needs
        ADDITIVE increase to be a control loop rather than a one-way valve.
        """
        with self._lock:
            now = time.monotonic()
            self.penalties += 1
            # Compare against a dedicated penalty deadline, NOT against _next.
            # `wait()` always leaves _next a little in the future as ordinary
            # pacing, so testing `now < _next` read every penalty as concurrent
            # and disabled backoff altogether -- caught by the gate, which is
            # the first time it has been in a position to catch anything.
            concurrent = now < self._penalty_until
            self._penalty_until = max(self._penalty_until, now + seconds)
            self._next = max(self._next, now + seconds)
            if not concurrent:
                self._interval = min(self._interval * 1.5, self._ceiling)

    def relax(self) -> None:
        """Additive increase: give back a fixed slice of the base interval.

        Was `interval * 0.999`, which after a 1.5x penalty needed roughly 400
        consecutive successes to undo one event -- and at a throttled pace those
        successes arrive too slowly to ever catch up. A fixed step recovers in a
        bounded number of successes regardless of how far the pace has fallen,
        which is what makes this AIMD rather than a ratchet.
        """
        with self._lock:
            self._interval = max(self._base, self._interval - self._base * 0.05)

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


def load_no_record(path: Path) -> set[str]:
    """Names npm answered about, with the answer "no download record".

    Distinct from unmeasured, and persisted, because otherwise the run never
    converges: a name the API declines to report on stays absent from `counts`,
    so every resume recomputes it as outstanding, re-queries it, gets the same
    answer, and ends in the same place. Observed at 98.9% completion with
    30,244 such names -- 17,013 of them isolated singletons scattered through
    the frame, mostly junk or unpublished packages.

    "No record" is an ANSWER. Filing it as "not yet asked" is the same
    absent-versus-unchecked confusion the scanners exist to prevent, here
    turned inward on the collector's own bookkeeping.
    """
    if not path.exists():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--candidates", type=Path, default=None,
                        help="One name per line. Omit when using --frame.")
    parser.add_argument("--frame", type=Path, default=None,
                        help="Rank EVERY unscoped name in the frame, exhaustively. "
                             "No candidate pool and no stage 1: the bulk endpoint "
                             "takes 128 names per request, so all of unscoped npm "
                             "is ~21,000 requests. Scoped names are skipped -- they "
                             "cannot use the bulk endpoint and need --candidates.")
    parser.add_argument("--merge", type=Path, default=None,
                        help="A previously written ranking to fold in, so the "
                             "unscoped and scoped passes compose into one file.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE,
                        help="Requests per second, shared across workers.")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--min-measured", type=float, default=MIN_MEASURED_FRACTION,
                        help="Fail rather than write a ranking built from less "
                             "than this fraction of candidates.")
    args = parser.parse_args(argv)

    from qresp.audit.npm_client import BULK_LIMIT, NpmClient, is_scoped

    if args.frame:
        all_names = args.frame.read_text(encoding="utf-8").split()
        names = [n for n in all_names if not is_scoped(n)]
        print(f"frame: {len(all_names):,} names -> {len(names):,} unscoped "
              f"(exhaustive; no candidate pool involved)")
    elif args.candidates:
        raw = args.candidates.read_text(encoding="utf-8").strip()
        names = json.loads(raw) if raw.startswith("[") else [
            line.strip() for line in raw.splitlines() if line.strip()]
    else:
        parser.error("one of --frame or --candidates is required")
    names = list(dict.fromkeys(names))

    unscoped = [n for n in names if not is_scoped(n)]
    scoped = [n for n in names if is_scoped(n)]
    partial_path = args.out.with_suffix(".partial.json")
    no_record_path = args.out.with_suffix(".no-record.json")
    counts: dict[str, int] = load_partial(partial_path)
    no_record_names: set[str] = load_no_record(no_record_path)

    print(f"candidates: {len(names):,}  ({len(unscoped):,} unscoped, "
          f"{len(scoped):,} scoped)")
    if counts:
        print(f"  resuming: {len(counts):,} already measured ({partial_path})")
    print(f"  throttle: {args.rate:g} req/s across {args.workers} workers")

    client = NpmClient()
    throttle = Throttle(args.rate)
    started = time.time()
    failed: list[str] = []

    if no_record_names:
        print(f"  {len(no_record_names):,} name(s) previously answered "
              f"'no download record' -- not re-queried")
    todo_unscoped = [n for n in unscoped
                     if n not in counts and n not in no_record_names]
    batches = [todo_unscoped[i:i + BULK_LIMIT]
               for i in range(0, len(todo_unscoped), BULK_LIMIT)]
    print(f"  unscoped -> {len(batches):,} bulk requests")

    for index, batch in enumerate(batches, start=1):
        try:
            result = with_retry(lambda b=batch: client.bulk_downloads(b),
                                throttle, f"bulk {index}")
            counts.update({n: c for n, c in result.items() if isinstance(c, int)})
            # The API answered for the batch; any name it did not report on has
            # no download record. That is a result, so record it as one.
            no_record_names.update(
                n for n, c in result.items() if not isinstance(c, int))
        except Exception as exc:
            failed.extend(batch)
            print(f"  batch {index} exhausted retries: {str(exc)[:100]}")
        if index % 10 == 0 or index == len(batches):
            partial_path.write_text(json.dumps(counts), encoding="utf-8")
            no_record_path.write_text(json.dumps(sorted(no_record_names)),
                                      encoding="utf-8")
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
    merged: dict[str, int] = {}
    if args.merge and args.merge.exists():
        prior = json.loads(args.merge.read_text(encoding="utf-8"))
        merged = {r["project"]: r["download_count"] for r in prior.get("rows", [])}
        print(f"  merging {len(merged):,} rows from {args.merge}")

    # `set(names)` MUST be hoisted. Written inline in the condition it is
    # rebuilt on every iteration -- 2.65M passes each constructing a 2.68M
    # element set -- which is quadratic and, measured by extrapolation from
    # 20,000 items, roughly 60 hours. The run completed every request, printed
    # "scoped -> 0 individual requests", and then sat here looking like a hang
    # because it was one. It survived a 50,000-name candidate pool only because
    # quadratic on 50,000 is merely slow.
    name_set = set(names)
    measured = {n: c for n, c in counts.items() if n in name_set}
    # Names npm has no record for are ANSWERED, not outstanding, so they count
    # towards coverage. Excluding them from the denominator would make a run
    # that had asked about every single name look permanently incomplete.
    answered = len(measured) + len(no_record_names & name_set)
    fraction_own = answered / max(len(names), 1)
    measured = {**merged, **measured}
    fraction = fraction_own
    ranked = sorted(measured.items(), key=lambda kv: kv[1], reverse=True)

    print(f"\n  measured {len(measured):,} / {len(names):,}")
    if no_record_names:
        print(f"  {len(no_record_names & name_set):,} answered "
              f"'no download record' -- excluded from the ranking, not ranked "
              f"last")
    print(f"  coverage (measured + answered) {fraction:.2%}")
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

    # STREAMED, and compact for the rows. json.dumps(..., indent=2) over 2.65M
    # rows builds a single ~400 MB string in memory before writing one byte:
    # the run completed every request, printed "scoped -> 0", and then appeared
    # to hang here. The header stays readable; the rows are one per line, which
    # keeps the file greppable without paying for pretty-printing millions of
    # objects.
    header = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "metric": "npm downloads, last-month, api.npmjs.org",
        "candidate_count": len(names),
        "measured": len(measured),
        "no_download_record": len(no_record_names & name_set),
        "unmeasured": len(names) - answered,
        "coverage": round(fraction, 6),
        "rate_limit_req_per_s": args.rate,
    }
    with args.out.open("w", encoding="utf-8") as handle:
        handle.write("{\n")
        for key, value in header.items():
            handle.write(f"  {json.dumps(key)}: {json.dumps(value)},\n")
        handle.write('  "rows": [\n')
        last = len(ranked) - 1
        for index, (name, count) in enumerate(ranked):
            comma = "" if index == last else ","
            handle.write(
                f'    {{"project": {json.dumps(name)}, '
                f'"download_count": {count}}}{comma}\n')
        handle.write("  ]\n}\n")

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
