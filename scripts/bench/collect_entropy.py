"""Collect entropy samples for the SP 800-22 / SP 800-90B analyses.

Task 8 of the Phase II memo.

WHY THIS IS A SEPARATE STEP FROM THE ANALYSIS
=============================================
Collection takes minutes to hours and touches a free academic API and a
government service. The analysis is pure computation over a local file. Keeping
them apart means the statistics can be re-run, re-parameterised and debugged
without re-fetching anything, and means a failed analysis never costs someone
else's bandwidth twice.

HOW MUCH DATA, AND WHY IT IS AWKWARD
====================================
SP 800-22 wants at least 10^6 bits per sequence, and ideally 100 sequences.
What that costs from each source:

    ANU              1024 bytes/request      123 requests per sequence
    beacon (live)     512 bits/60 s          32.6 hours per sequence
    beacon (history)  512 bits/request      1954 requests per sequence

Live beacon collection is therefore not merely slow but infeasible: the full
100-sequence suite would need 136 days of output that does not exist yet. The
beacon's *history* is retrievable by pulse index, so the same 10^6 bits can be
had in about half an hour of polite requests. That is what this script does, and
the distinction is worth stating in the write-up rather than quietly collecting
whatever was convenient.

A NOTE ON POLITENESS
====================
Both services are free and neither owes us anything. Requests are rate-limited
by default, resumable so an interrupted run does not start over, and the
defaults collect one sequence rather than a hundred. Anyone wanting the full
suite should think about whether they need it before pointing 12,300 requests at
a university.

WHAT THE COLLECTED DATA IS AND IS NOT
=====================================
Both sources return **conditioned** output: ANU post-processes its raw detector
counts, and a beacon pulse is the output of a hash chain. Neither exposes a raw
noise source. Statistical tests over this data can detect gross failure -- a
stuck source, a broken transport, a truncated response -- but cannot validate an
entropy source, because they are measuring the conditioning. See
scripts/bench/randomness.py, which states the same thing where the results are
produced.

USAGE
=====
    python scripts/bench/collect_entropy.py --source system      # instant, offline
    python scripts/bench/collect_entropy.py --source anu
    python scripts/bench/collect_entropy.py --source beacon
    python scripts/bench/collect_entropy.py --source all --bits 1000000
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_BITS = 1_000_000
OUT_DIR = ROOT / "data" / "entropy"


@dataclass
class Collection:
    """A sample, with everything needed to judge or reproduce it."""

    source: str
    bits: int
    bytes_collected: int
    sha256: str
    started: str
    finished: str
    requests: int
    notes: list[str] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fetch_with_retries(call, attempts: int, backoff: float, label: str) -> Any:
    """Retry a transient network failure instead of abandoning the collection.

    The first version gave up on the first error, and both sources produced one:
    ANU returned HTTP 500 on request 2 of 123, and the beacon dropped the
    connection at pulse 912 of 1,954. Two isolated hiccups cost 99% and 53% of
    their respective samples.

    Free public services return 500s and reset connections; that is ordinary,
    not exceptional, and a collector that treats it as fatal will essentially
    never complete. Backoff is exponential so a service having a bad minute is
    given room rather than hammered.
    """
    delay = backoff
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return call()
        except Exception as exc:                       # noqa: BLE001
            last = exc
            if attempt < attempts:
                print(f"    {label} attempt {attempt}/{attempts} failed "
                      f"({type(exc).__name__}); retrying in {delay:.1f}s")
                time.sleep(delay)
                delay *= 2
    raise RuntimeError(f"{label} failed after {attempts} attempts: {last}") from last


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Stage then move: a truncated sample that looks complete would silently
    # corrupt every statistic computed from it, and this project has been bitten
    # by exactly that on a slow mount before (see docs/DATASETS.md).
    staging = path.with_suffix(path.suffix + ".partial")
    staging.write_bytes(data)
    staging.replace(path)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
def collect_system(n_bytes: int) -> tuple[bytes, Collection]:
    """os.urandom. Instant, offline, and the baseline everything else is read against.

    Included because a suite that only ever sees exotic sources cannot tell you
    whether it would notice a problem. If the CSPRNG and the QRNG score the
    same, that is informative about the tests, not about the sources.
    """
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    data = os.urandom(n_bytes)
    return data, Collection(
        source="system", bits=n_bytes * 8, bytes_collected=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        started=started, finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        requests=0,
        notes=["os.urandom: a CSPRNG, not an entropy source. Passing any "
               "statistical test here is expected and proves nothing about "
               "the underlying noise."],
    )


def collect_anu(n_bytes: int, api_key: str | None, delay: float,
                resume: Path | None, attempts: int = 5,
                backoff: float = 2.0) -> tuple[bytes, Collection]:
    """ANU Quantum Numbers, 1024 bytes per request."""
    import requests

    from qknot.signing.entropy.backends import ANU_KEYED_URL, ANU_LEGACY_URL

    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    collected = bytearray()
    if resume and resume.is_file():
        collected += resume.read_bytes()
        print(f"  resuming from {len(collected):,} bytes already collected")

    session = requests.Session()
    requests_made = 0
    notes: list[str] = []
    keyed = bool(api_key)
    if not keyed:
        notes.append("used the unauthenticated legacy endpoint, which ANU is "
                     "retiring; set ANU_API_KEY for the current service")

    while len(collected) < n_bytes:
        want = min(1024, n_bytes - len(collected))

        def one_request(want=want):
            url = ANU_KEYED_URL if keyed else ANU_LEGACY_URL
            headers = {"x-api-key": api_key} if keyed else {}
            response = session.get(url, timeout=30, headers=headers,
                                   params={"length": want, "type": "uint8"})
            if response.status_code != 200:
                raise RuntimeError(f"HTTP {response.status_code}")
            payload = response.json()
            if not payload.get("success", True):
                raise RuntimeError(f"ANU reported failure: {payload}")
            return bytes(payload["data"])

        try:
            collected += _fetch_with_retries(
                one_request, attempts, backoff, f"ANU request {requests_made + 1}")
            requests_made += 1
        except RuntimeError as exc:
            notes.append(str(exc))
            print(f"  giving up: {exc}")
            print(f"  have {len(collected):,}/{n_bytes:,} bytes; re-run to resume")
            if resume:
                _write(resume, bytes(collected))
            # A partial sample is recorded honestly. What must never happen is
            # padding it to length with something else.
            break

        if requests_made % 10 == 0:
            print(f"  {len(collected):,}/{n_bytes:,} bytes "
                  f"({requests_made} requests)")
            if resume:
                _write(resume, bytes(collected))
        time.sleep(delay)

    data = bytes(collected)
    return data, Collection(
        source="anu", bits=len(data) * 8, bytes_collected=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        started=started, finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        requests=requests_made, notes=notes,
    )


def collect_beacon(n_bytes: int, delay: float, resume: Path | None,
                   attempts: int = 5,
                   backoff: float = 2.0) -> tuple[bytes, Collection]:
    """NIST beacon *history*, 64 bytes per pulse, fetched by index.

    Live collection would take 32.6 hours for 10^6 bits. The history is the
    same data, already published, and every pulse index is recorded so a reader
    can re-fetch any of them and confirm the sample was not fabricated -- which
    is the property that makes the beacon worth using at all.
    """
    import requests

    from qknot.signing.entropy.beacon import NIST_BEACON_BASE

    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    session = requests.Session()

    # The anchoring fetch was outside the retry loop, so an offline runtime got
    # a raw ProxyError traceback rather than a sentence. Collection scripts are
    # run by people who are not this script's author; an unreachable service is
    # an expected condition, not a bug to be reported as a stack trace.
    try:
        latest = session.get(f"{NIST_BEACON_BASE}/pulse/last", timeout=30).json()
        last_index = int(latest["pulse"]["pulseIndex"])
        chain = int(latest["pulse"]["chainIndex"])
    except Exception as exc:
        print(f"  cannot reach the NIST beacon ({type(exc).__name__}): {exc}")
        print("  nothing collected. The beacon needs outbound HTTPS to "
              "beacon.nist.gov; there is no offline substitute, because the "
              "point of the beacon is that a third party can re-fetch it.")
        return b"", Collection(
            source="beacon", bits=0, bytes_collected=0,
            sha256=hashlib.sha256(b"").hexdigest(),
            started=started, finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            requests=0, notes=[f"unreachable: {exc}"])
    needed = -(-n_bytes // 64)
    first_index = max(1, last_index - needed + 1)
    print(f"  chain {chain}, pulses {first_index:,}..{last_index:,} "
          f"({needed:,} pulses for {n_bytes:,} bytes)")

    collected = bytearray()
    if resume and resume.is_file():
        collected += resume.read_bytes()
        print(f"  resuming from {len(collected):,} bytes already collected")
    references: list[dict[str, Any]] = []
    notes: list[str] = []
    requests_made = 0

    # Skip the pulses already held, so a resumed run continues rather than
    # re-fetching what is on disk.
    first_index += len(collected) // 64

    for index in range(first_index, last_index + 1):
        if len(collected) >= n_bytes:
            break
        def one_pulse(index=index):
            response = session.get(
                f"{NIST_BEACON_BASE}/chain/{chain}/pulse/{index}", timeout=30)
            if response.status_code != 200:
                raise RuntimeError(f"HTTP {response.status_code}")
            pulse = response.json()["pulse"]
            value = bytes.fromhex(pulse["outputValue"])
            if len(value) != 64:
                raise RuntimeError(f"pulse {index} carried {len(value)} bytes")
            return pulse, value

        try:
            pulse, value = _fetch_with_retries(
                one_pulse, attempts, backoff, f"pulse {index}")
            requests_made += 1
            collected += value
            # Record the first and last few so the sample is anchored without
            # writing two thousand references into the manifest.
            if len(references) < 5 or index > last_index - 5:
                references.append({"pulse_index": index,
                                   "timestamp": pulse["timeStamp"],
                                   "output_value": pulse["outputValue"]})
        except RuntimeError as exc:
            notes.append(str(exc))
            print(f"  giving up: {exc}")
            print(f"  have {len(collected):,}/{n_bytes:,} bytes; re-run to resume")
            if resume:
                _write(resume, bytes(collected))
            break

        if requests_made % 100 == 0:
            print(f"  {len(collected):,}/{n_bytes:,} bytes ({requests_made} pulses)")
            if resume:
                _write(resume, bytes(collected))
        time.sleep(delay)

    data = bytes(collected[:n_bytes])
    notes.append(f"fetched from beacon history, chain {chain}, "
                 f"pulses {first_index}..{first_index + requests_made - 1}")
    notes.append("beacon output is PUBLIC and hash-chained: it is verifiable, "
                 "not unpredictable, and must never be used as key material")
    return data, Collection(
        source="beacon", bits=len(data) * 8, bytes_collected=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        started=started, finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        requests=requests_made, notes=notes, references=references,
    )


# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", default="system",
                        choices=["system", "anu", "beacon", "all"])
    parser.add_argument("--bits", type=int, default=DEFAULT_BITS,
                        help=f"Bits to collect (default {DEFAULT_BITS:,}).")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Seconds between requests. Be polite (default 0.2).")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    parser.add_argument("--anu-key", default=os.environ.get("ANU_API_KEY"))
    parser.add_argument("--attempts", type=int, default=5,
                        help="Retries per request before giving up (default 5).")
    parser.add_argument("--backoff", type=float, default=2.0,
                        help="Initial retry delay in seconds; doubles each time.")
    args = parser.parse_args(argv)

    n_bytes = -(-args.bits // 8)
    sources = ["system", "anu", "beacon"] if args.source == "all" else [args.source]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d")

    for source in sources:
        print(f"\n{source}: collecting {n_bytes:,} bytes ({args.bits:,} bits)")
        path = args.out_dir / f"{source}_{stamp}.bin"
        partial = path.with_suffix(".partial.bin")

        if source == "system":
            data, record = collect_system(n_bytes)
        elif source == "anu":
            data, record = collect_anu(n_bytes, args.anu_key, args.delay, partial,
                                       args.attempts, args.backoff)
        else:
            data, record = collect_beacon(n_bytes, args.delay, partial,
                                          args.attempts, args.backoff)

        if not data:
            print("  nothing collected; skipping")
            continue

        _write(path, data)
        manifest = path.with_suffix(".json")
        manifest.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")

        short = record.bytes_collected < n_bytes
        if short:
            # Keep the partial so a re-run resumes. Deleting it on a short
            # collection -- which the first version did -- meant every retry
            # started from zero, which is the opposite of resumable.
            _write(partial, data)
        else:
            partial.unlink(missing_ok=True)

        print(f"  {record.bytes_collected:,} bytes -> {path.name}"
              f"{'  (SHORT of the target; re-run to continue)' if short else ''}")
        print(f"  sha256 {record.sha256[:32]}...")
        for note in record.notes[:3]:
            print(f"  note: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
