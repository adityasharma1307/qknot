#!/usr/bin/env python3
"""Validate the ML-DSA backend against FIPS 204 known-answer tests.

WHAT THIS ESTABLISHES, AND WHAT IT DOES NOT
===========================================
KATs establish **functional correctness**: given a fixed seed and message, the
implementation produces the byte-exact key pair and signature that the standard
specifies. That rules out the failure mode where a signature verifies against
its own implementation and nothing else, which is the worst kind of wrong
because it looks like it works.

KATs say **nothing** about side-channel resistance. A perfectly correct
implementation can leak its secret key through timing on every signature, and
this one does. Correctness and constant-time behaviour are independent
properties, and conflating them is how "it passes the test vectors" becomes a
false assurance. See docs/THREAT-MODEL.md.

VECTOR SOURCE
=============
`dilithium-py` ships `assets/PQCsignKAT_Dilithium{2,3,5}.rsp`, the NIST
submission KAT files. Parameter sets map to ML-DSA levels as:

    Dilithium2 -> ML-DSA-44
    Dilithium3 -> ML-DSA-65
    Dilithium5 -> ML-DSA-87

    python scripts/verify/run_ml_dsa_kats.py
    python scripts/verify/run_ml_dsa_kats.py --assets /path/to/dilithium-py/assets
    python scripts/verify/run_ml_dsa_kats.py --limit 10
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

LEVELS = {
    "PQCsignKAT_Dilithium2.rsp": "Dilithium2",
    "PQCsignKAT_Dilithium3.rsp": "Dilithium3",
    "PQCsignKAT_Dilithium5.rsp": "Dilithium5",
}


def parse_rsp(path: Path) -> list[dict[str, str]]:
    """Parse a NIST .rsp KAT file into a list of records."""
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("count = "):
            if current:
                records.append(current)
            current = {"count": line.split(" = ", 1)[1]}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key.strip()] = value.strip()
    if current:
        records.append(current)
    return records


def run_file(path: Path, limit: int | None) -> tuple[int, int, list[str]]:
    """Run the vectors in one .rsp file. Returns (passed, total, failures)."""
    try:
        from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5
        from dilithium_py.drbg.aes256_ctr_drbg import AES256_CTR_DRBG
    except ImportError as exc:
        raise SystemExit(
            f"dilithium-py is not importable: {exc}\n"
            f"Install it, or point --assets at a source checkout and ensure "
            f"its `src` directory is on PYTHONPATH."
        ) from None

    impl = {"Dilithium2": Dilithium2, "Dilithium3": Dilithium3,
            "Dilithium5": Dilithium5}[LEVELS[path.name]]

    records = parse_rsp(path)
    if limit:
        records = records[:limit]

    passed = 0
    failures: list[str] = []

    for record in records:
        count = record.get("count", "?")
        try:
            # The KAT seeds an AES-256 CTR DRBG, which then drives keygen and
            # signing. Reproducing that exactly is the whole point: it removes
            # randomness so the output is deterministic and comparable.
            drbg = AES256_CTR_DRBG(bytes.fromhex(record["seed"]))
            impl.set_drbg_seed(bytes.fromhex(record["seed"]))

            pk, sk = impl.keygen()
            if pk.hex().upper() != record["pk"].upper():
                failures.append(f"{path.name} count={count}: public key mismatch")
                continue
            if sk.hex().upper() != record["sk"].upper():
                failures.append(f"{path.name} count={count}: secret key mismatch")
                continue

            message = bytes.fromhex(record["msg"])
            signed = impl.sign(sk, message)
            expected = bytes.fromhex(record["sm"])
            # NIST's `sm` is signature || message.
            if signed + message != expected:
                failures.append(f"{path.name} count={count}: signature mismatch")
                continue

            if not impl.verify(pk, message, signed):
                failures.append(f"{path.name} count={count}: own signature failed to verify")
                continue

            passed += 1
            del drbg
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{path.name} count={count}: raised {type(exc).__name__}: {exc}")

    return passed, len(records), failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--assets", type=Path, default=None,
                        help="Directory holding the PQCsignKAT_*.rsp files.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Run only the first N vectors per file (a full run "
                             "is slow: pure-Python ML-DSA signs in ~25 ms).")
    args = parser.parse_args(argv)

    assets = args.assets
    if assets is None:
        try:
            import dilithium_py
            assets = Path(dilithium_py.__file__).resolve().parents[2] / "assets"
        except ImportError:
            assets = None
    if assets is None or not assets.is_dir():
        raise SystemExit(
            "Could not locate the KAT assets.\n"
            "\n"
            "This is expected after `pip install dilithium-py`: the NIST\n"
            "PQCsignKAT_*.rsp vectors ship in the project's GitHub source tree,\n"
            "not in the published wheel. They are not redistributed here either,\n"
            "so reproducing this check needs a source checkout:\n"
            "\n"
            "    git clone https://github.com/GiacomoPope/dilithium-py\n"
            "    python scripts/verify/run_ml_dsa_kats.py \\\n"
            "        --assets dilithium-py/assets\n"
            "\n"
            "Or pass --assets at any directory holding PQCsignKAT_Dilithium{2,3,5}.rsp.\n"
            "\n"
            "The claim this script substantiates -- that the ML-DSA backend\n"
            "reproduces the FIPS 204 known-answer tests byte for byte -- is\n"
            "therefore reproducible, but not from a pip install alone. Stated\n"
            "here rather than left for a reader to discover."
        )

    print("ML-DSA / Dilithium known-answer tests")
    print("=" * 72)
    print(f"assets: {assets}")
    if args.limit:
        print(f"limit : first {args.limit} vectors per file")
    print()

    total_passed = total_run = 0
    all_failures: list[str] = []

    for name in sorted(LEVELS):
        path = assets / name
        if not path.exists():
            print(f"  [SKIP] {name} not found")
            continue
        passed, total, failures = run_file(path, args.limit)
        total_passed += passed
        total_run += total
        all_failures.extend(failures)
        mark = "PASS" if passed == total else "FAIL"
        print(f"  [{mark}] {name:<32} {passed}/{total}")

    print()
    print("=" * 72)
    if all_failures:
        print(f"{len(all_failures)} FAILURE(S):")
        for failure in all_failures[:20]:
            print(f"  {failure}")
        return 1

    print(f"All {total_passed}/{total_run} vectors reproduce byte for byte.")
    print()
    print("This establishes FUNCTIONAL CORRECTNESS only. It says nothing about")
    print("side-channel resistance, and this implementation is not constant-time.")
    print("See docs/THREAT-MODEL.md before signing anything that matters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
