#!/usr/bin/env python3
"""Detect whether OpenSSF has changed the OMS spec under us.

WHY THIS EXISTS
===============
This project reports three gaps in OMS v1.0:

  1. `signature` is closed to new fields and `keyid` is explicitly not used for
     verification, so a bundle can carry an ML-DSA signature that no verifier
     can identify. Hybrid verification is structurally possible and
     semantically undefined.
  2. The hash enums (`serialization.hash_type`, `resources[].algorithm`) admit
     only sha256/blake2b/blake3. No SHA-3, so per-file digests cannot use a
     hash with margin against Grover.
  3. The algorithm registry names no post-quantum algorithm at all.

Every one of those is a claim about a *living document*. OpenSSF may close any
of them tomorrow, and if they do, three things in this project become wrong at
once: the spec proposal, the paper's motivation, and the compatibility tests
that assert OMS rejects what we need.

Discovering that from a reviewer is the bad outcome. This script fetches the
live spec, compares it to what we vendored, and says plainly what changed.

WHAT IT CHECKS
==============
  * byte-level drift in each vendored schema and in the registry
  * whether the three specific gaps above are still open
  * whether the registry has gained any post-quantum entry

EXIT CODES
==========
    0   no drift; the vendored copies still match upstream
    1   drift detected; read the report and update the paper
    2   could not reach upstream; nothing was checked

Exit 2 is deliberately distinct from 0. "I could not check" and "I checked and
all is well" are different states, and conflating them is how a stale claim
survives into a submission.

    python scripts/verify/check_oms_upstream.py
    python scripts/verify/check_oms_upstream.py --update   # refresh the vendored copies
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDORED = REPO_ROOT / "tests" / "signing" / "oms_schemas"

# The GitHub organisation is `ossf`, not `openssf`. The project is named
# "OpenSSF" everywhere in prose, which is exactly why this was wrong for a
# while and returned a flat 404 -- indistinguishable, at a glance, from the
# spec having been withdrawn.
ORG = "ossf"
REPO = "model-signing-spec"
RAW_BASE = f"https://raw.githubusercontent.com/{ORG}/{REPO}/main"
API_COMMITS = f"https://api.github.com/repos/{ORG}/{REPO}/commits/main"

TRACKED = {
    "algorithm-registry.md": f"{RAW_BASE}/algorithm-registry.md",
    "predicate.schema.json": f"{RAW_BASE}/schemas/v1.0/predicate.schema.json",
    "statement.schema.json": f"{RAW_BASE}/schemas/v1.0/statement.schema.json",
    "envelope.schema.json": f"{RAW_BASE}/schemas/v1.0/envelope.schema.json",
    "bundle.schema.json": f"{RAW_BASE}/schemas/v1.0/bundle.schema.json",
}

# Terms whose appearance in the registry would mean gap 3 has closed.
POST_QUANTUM_TERMS = ("ml-dsa", "dilithium", "slh-dsa", "sphincs", "falcon",
                      "post-quantum", "pqc", "lms", "xmss")

CHANGED: list[str] = []
UNREACHABLE: list[str] = []


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, timeout: float = 30.0) -> bytes | None:
    try:
        import requests
    except ImportError:
        print("  requests is not installed; cannot check upstream")
        return None
    try:
        response = requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "qresp-oms-drift-check/1.0",
                     "Accept": "application/vnd.github.raw"},
        )
    except Exception as exc:
        print(f"  unreachable: {url}\n    {exc}")
        return None
    if response.status_code != 200:
        print(f"  HTTP {response.status_code}: {url}")
        return None
    return response.content


def report_upstream_head() -> None:
    """Print the current upstream commit, for the record."""
    raw = fetch(API_COMMITS)
    if raw is None:
        print("  (could not read upstream commit metadata)")
        return
    try:
        commit = json.loads(raw)
        sha = commit.get("sha", "?")[:12]
        date = commit.get("commit", {}).get("committer", {}).get("date", "?")
        message = commit.get("commit", {}).get("message", "").splitlines()[0][:70]
        print(f"  upstream HEAD : {sha}  {date}")
        print(f"  subject       : {message}")
    except Exception:
        print("  (upstream commit metadata was not parseable)")


def check_file(name: str, url: str, update: bool) -> None:
    local_path = VENDORED / name
    if not local_path.exists():
        print(f"  [MISSING] {name} is not vendored")
        CHANGED.append(f"{name}: not vendored")
        return

    remote = fetch(url)
    if remote is None:
        UNREACHABLE.append(name)
        return

    local = local_path.read_bytes()
    # Normalise line endings; a checkout on Windows should not read as drift.
    if sha256(local.replace(b"\r\n", b"\n")) == sha256(remote.replace(b"\r\n", b"\n")):
        print(f"  [SAME]    {name}")
        return

    print(f"  [CHANGED] {name}")
    print(f"              vendored: {sha256(local)[:16]}")
    print(f"              upstream: {sha256(remote)[:16]}")
    CHANGED.append(name)
    if update:
        local_path.write_bytes(remote)
        print("              updated the vendored copy")


def check_gaps_still_open() -> None:
    """Test the three specific claims this project makes about OMS."""
    print("\nAre the reported gaps still open?")
    print("-" * 72)

    registry = fetch(TRACKED["algorithm-registry.md"])
    if registry is None:
        UNREACHABLE.append("gap analysis")
        print("  could not fetch the registry; gaps not assessed")
        return

    text = registry.decode("utf-8", errors="replace").lower()
    found = [t for t in POST_QUANTUM_TERMS if t in text]
    if found:
        print(f"  [CLOSED]  the registry now mentions: {found}")
        print("            Gap 3 is closed. The paper's claim that OMS has no")
        print("            post-quantum path must be revised, and the Phase I")
        print("            motivation restated as historical.")
        CHANGED.append(f"registry now mentions {found}")
    else:
        print("  [OPEN]    registry names no post-quantum algorithm")

    envelope_raw = fetch(TRACKED["envelope.schema.json"])
    if envelope_raw is None:
        UNREACHABLE.append("envelope gap analysis")
    else:
        envelope = json.loads(envelope_raw)
        signature = envelope.get("$defs", {}).get("signature", {})
        closed_to_extension = signature.get("additionalProperties") is False
        declares_algorithm = "algorithm" in signature.get("properties", {})
        if declares_algorithm or not closed_to_extension:
            print("  [CLOSED]  signatures can now declare an algorithm")
            print("            Gap 1 is closed. This was the central proposal;")
            print("            the contribution is now the reference")
            print("            implementation rather than the gap report.")
            CHANGED.append("signature can now carry an algorithm")
        else:
            print("  [OPEN]    signature is still closed to an algorithm field")

    predicate_raw = fetch(TRACKED["predicate.schema.json"])
    if predicate_raw is None:
        UNREACHABLE.append("predicate gap analysis")
    else:
        predicate = json.loads(predicate_raw)
        defs = predicate.get("$defs", {})
        enums = set()
        enums.update(
            defs.get("resource_descriptor", {})
            .get("properties", {}).get("algorithm", {}).get("enum", []))
        enums.update(
            defs.get("serialization", {})
            .get("properties", {}).get("hash_type", {}).get("enum", []))
        sha3 = {e for e in enums if "sha3" in e.lower() or "shake" in e.lower()}
        if sha3:
            print(f"  [CLOSED]  hash enums now include {sorted(sha3)}")
            print("            Gap 2 is closed; per-file SHA-3 digests are")
            print("            now expressible in a conformant bundle.")
            CHANGED.append(f"hash enums now include {sorted(sha3)}")
        else:
            print(f"  [OPEN]    hash enums remain {sorted(enums)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true",
                        help="Overwrite the vendored copies with upstream. Re-run "
                             "the test suite afterwards: TestSpecGapsWeAreReporting "
                             "is designed to fail when a gap closes.")
    args = parser.parse_args(argv)

    print("OMS upstream drift check")
    print("=" * 72)
    print(f"vendored at : {VENDORED.relative_to(REPO_ROOT)}")
    report_upstream_head()

    print("\nVendored files vs upstream")
    print("-" * 72)
    for name, url in TRACKED.items():
        check_file(name, url, args.update)

    check_gaps_still_open()

    print("\n" + "=" * 72)
    if UNREACHABLE and not CHANGED:
        print(f"COULD NOT CHECK: {len(UNREACHABLE)} item(s) unreachable.")
        print("Nothing was verified. This is not the same as 'no drift'.")
        return 2
    if CHANGED:
        print(f"DRIFT DETECTED in {len(CHANGED)} item(s):")
        for item in CHANGED:
            print(f"  - {item}")
        print("\nWhat to do, in order:")
        print("  1. Re-run: python -m pytest tests/signing/test_oms_compatibility.py")
        print("     Failures in TestSpecGapsWeAreReporting mean a gap has closed.")
        print("  2. Update docs/OMS-COMPATIBILITY.md with what changed and when.")
        print("  3. Revise the spec proposal and the paper's motivation.")
        print("  4. Re-vendor with --update once the paper reflects the new state.")
        return 1
    print("NO DRIFT. The vendored spec still matches upstream, and all three")
    print("reported gaps remain open.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
