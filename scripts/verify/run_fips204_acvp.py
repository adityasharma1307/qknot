"""Validate the ML-DSA backend against the NIST ACVP FIPS 204 test vectors.

WHY THIS REPLACES run_ml_dsa_kats.py
====================================
The previous script ran `PQCsignKAT_Dilithium{2,3,5}.rsp` against
`dilithium_py.dilithium.Dilithium{2,3,5}`. Both halves of that are the **round-3
Dilithium** submission, not **ML-DSA**, and the backend this project ships is
`dilithium_py.ml_dsa.ML_DSA_44`. So the evidence and the artefact were about
different algorithms, while the docs claimed FIPS 204 validation.

They are genuinely different, not a renaming. Measured on the installed library:

    Dilithium2 secret key   2528 bytes
    ML-DSA-44  secret key   2560 bytes
    a Dilithium2 signature does not verify under ML-DSA-44

FIPS 204 changed the message encoding (a domain-separating prefix
`0x00 || len(ctx) || ctx` before the message), the `tr` length, and added the
hedged/deterministic `rnd`. Round-3 KATs cannot detect a fault in any of that.

Passing the old vectors was therefore true and irrelevant: it validated a module
the signing path never calls. This script validates what is actually shipped.

WHAT THE ACVP VECTORS COVER
===========================
Three files, the standard ACVP decomposition, all three exercised here:

    keyGen   seed -> (pk, sk)              does key derivation match?
    sigGen   (sk, message) -> signature    does signing match, byte for byte?
    sigVer   (pk, message, sig) -> bool    are BAD signatures rejected?

`sigVer` is the one worth having and the one a naive test omits. Its vectors are
mostly *negative*: signatures mutated in specific ways that a correct verifier
must reject. An implementation that returns True unconditionally passes keyGen
and sigGen and fails only here.

EVERY sigGen VECTOR IS COMPARED BYTE FOR BYTE, INCLUDING THE HEDGED ONES
========================================================================
Hedged signing mixes 32 fresh random bytes, so a signature produced here can
never equal a recorded one -- except that ACVP *supplies* the `rnd` it used, so
byte-exact comparison is possible after all. Worth reaching for: a round-trip
"does it verify under its own key" check only proves self-consistency, whereas
this proves we agree with NIST on the hedged path too.

ONE THING TO KNOW ABOUT THESE VECTORS: THEY TARGET THE *INTERNAL* INTERFACE
==========================================================================
ACVP exercises `ML-DSA.Sign_internal` / `Verify_internal` (FIPS 204 Alg. 7/8),
which take the message exactly as given. The public `sign()` implements the
*external* interface and prepends `0x00 || len(ctx) || ctx` first. Feeding these
vectors through `sign()` makes all 60 of them fail -- which is what happened on
the first run here, and is a mistake worth recording because the failure looks
like a broken implementation rather than a wrong entry point.

The internal interface is the algorithm; the external one is a thin wrapper.
Both matter, so `test_fips204_acvp.py` additionally asserts that the wrapper
composes correctly: `sign(msg, ctx)` must equal
`_sign_internal(0x00 || len(ctx) || ctx || msg)`. Validating the core without
that link would leave the actually-called path unverified.

USAGE
=====
    python scripts/verify/run_fips204_acvp.py
    python scripts/verify/run_fips204_acvp.py --limit 5      # quick
    python scripts/verify/run_fips204_acvp.py --param ML-DSA-44

Exit codes: 0 all passed, 1 a vector failed, 2 could not run.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

VECTORS = Path(__file__).resolve().parents[2] / "tests" / "signing" / "fips204_vectors"

KEYGEN = "ML-DSA-keyGen-FIPS204"
SIGGEN = "ML-DSA-sigGen-FIPS204"
SIGVER = "ML-DSA-sigVer-FIPS204"


def load(directory: str, name: str) -> dict[str, Any]:
    path = VECTORS / directory / f"{name}.json"
    if not path.is_file():
        raise SystemExit(
            f"Missing vector file: {path}\n"
            f"The ACVP FIPS 204 vectors are vendored in tests/signing/fips204_vectors/. "
            f"See its PROVENANCE.md if they need re-fetching."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def implementations() -> dict[str, Any]:
    try:
        from dilithium_py import ml_dsa
    except ImportError as exc:
        raise SystemExit(f"dilithium-py is not importable: {exc}") from None
    return {
        "ML-DSA-44": ml_dsa.ML_DSA_44,
        "ML-DSA-65": ml_dsa.ML_DSA_65,
        "ML-DSA-87": ml_dsa.ML_DSA_87,
    }


def expected_index(payload: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Flatten expectedResults into {tcId: result}."""
    return {t["tcId"]: t for g in payload["testGroups"] for t in g["tests"]}


def run_keygen(impls, limit, only, report) -> tuple[int, int]:
    prompt, expected = load(KEYGEN, "prompt"), expected_index(load(KEYGEN, "expectedResults"))
    passed = failed = 0
    for group in prompt["testGroups"]:
        param = group["parameterSet"]
        if only and param != only:
            continue
        impl = impls[param]
        for test in group["tests"][:limit]:
            want = expected[test["tcId"]]
            pk, sk = impl.key_derive(bytes.fromhex(test["seed"]))
            ok = (pk.hex().upper() == want["pk"].upper()
                  and sk.hex().upper() == want["sk"].upper())
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
            if not ok:
                report.append(f"keyGen {param} tcId={test['tcId']}: derived key mismatch")
    return passed, failed


def run_siggen(impls, limit, only, report) -> tuple[int, int]:
    prompt, expected = load(SIGGEN, "prompt"), expected_index(load(SIGGEN, "expectedResults"))
    passed = failed = 0
    for group in prompt["testGroups"]:
        param = group["parameterSet"]
        if only and param != only:
            continue
        impl = impls[param]
        deterministic = bool(group.get("deterministic"))
        for test in group["tests"][:limit]:
            want = expected[test["tcId"]]
            sk = bytes.fromhex(test["sk"])
            message = bytes.fromhex(test["message"])
            # ACVP targets ML-DSA.Sign_internal (FIPS 204 Alg. 7): the message
            # is used as-is, with no context prefix. Passing it through the
            # public `sign()` -- which prepends 0x00 || len(ctx) || ctx -- makes
            # every vector fail, which is what happened first. Deterministic
            # mode is rnd = 32 zero bytes, per Alg. 2 step 5.
            rnd = bytes(32) if deterministic else bytes.fromhex(test["rnd"])
            signature = impl._sign_internal(sk, message, rnd)
            ok = signature.hex().upper() == want["signature"].upper()
            detail = ("signature bytes differ from the vector"
                      if deterministic else
                      "hedged signature differs from the vector at the given rnd")
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
            if not ok:
                report.append(f"sigGen {param} tcId={test['tcId']}: {detail}")
    return passed, failed


def run_sigver(impls, limit, only, report) -> tuple[int, int]:
    prompt, expected = load(SIGVER, "prompt"), expected_index(load(SIGVER, "expectedResults"))
    passed = failed = 0
    for group in prompt["testGroups"]:
        param = group["parameterSet"]
        if only and param != only:
            continue
        impl = impls[param]
        pk = bytes.fromhex(group["pk"])
        for test in group["tests"][:limit]:
            want = bool(expected[test["tcId"]]["testPassed"])
            got = bool(impl._verify_internal(pk, bytes.fromhex(test["message"]),
                                             bytes.fromhex(test["signature"])))
            ok = got == want
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
            if not ok:
                verdict = "accepted a signature it must reject" if got else \
                          "rejected a valid signature"
                report.append(f"sigVer {param} tcId={test['tcId']}: {verdict}")
    return passed, failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=None,
                        help="Only the first N tests per group.")
    parser.add_argument("--param", default=None,
                        help="Restrict to one parameter set, e.g. ML-DSA-44.")
    args = parser.parse_args(argv)

    impls = implementations()
    limit = args.limit
    report: list[str] = []

    print("ML-DSA / FIPS 204 ACVP test vectors")
    print("=" * 72)
    print(f"vectors    : {VECTORS}")
    print("validating : dilithium_py.ml_dsa  (the backend qknot actually signs with)")
    print()

    total_pass = total_fail = 0
    for label, runner in (("keyGen", run_keygen), ("sigGen", run_siggen),
                          ("sigVer", run_sigver)):
        p, f = runner(impls, limit, args.param, report)
        total_pass += p
        total_fail += f
        status = "PASS" if f == 0 else "FAIL"
        print(f"  [{status}] {label:7} {p:4} passed, {f} failed")

    print()
    if report:
        print("Failures")
        print("-" * 72)
        for line in report[:40]:
            print(f"  {line}")
        if len(report) > 40:
            print(f"  ... and {len(report) - 40} more")
        print()

    print("=" * 72)
    if total_fail:
        print(f"FAILED: {total_fail} of {total_pass + total_fail} vectors.")
        return 1
    print(f"ALL {total_pass} VECTORS PASS.")
    print("keyGen and deterministic sigGen are byte-exact against NIST's values;")
    print("sigVer confirms invalid signatures are rejected, which is the half a")
    print("positive-only test would miss.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
