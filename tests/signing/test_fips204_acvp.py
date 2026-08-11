"""FIPS 204 conformance, run as part of the ordinary test suite.

This used to live only in a script that needed a dilithium-py source checkout to
find its vectors, so in practice it was run once and cited thereafter. The
vectors are now vendored (see fips204_vectors/PROVENANCE.md) and the conformance
claim is re-checked on every `pytest` run.

WHAT CHANGED, AND WHY IT MATTERED
=================================
The previous evidence ran `PQCsignKAT_Dilithium*.rsp` against
`dilithium_py.dilithium.Dilithium2` -- the **round-3 Dilithium** submission. The
backend this project signs with is `dilithium_py.ml_dsa.ML_DSA_44`, which is
**ML-DSA (FIPS 204)**. Those are different algorithms: different secret key
sizes (2528 vs 2560 bytes), and signatures do not cross-verify. So the old check
passed, and validated a module the signing path never calls.

`test_the_two_schemes_are_not_the_same_algorithm` below pins that distinction so
nobody re-points this at the round-3 vectors on the assumption they are a
renaming.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("dilithium_py", reason="needs `dilithium-py`")

from dilithium_py import ml_dsa  # noqa: E402

VECTORS = Path(__file__).parent / "fips204_vectors"
IMPLS = {"ML-DSA-44": ml_dsa.ML_DSA_44,
         "ML-DSA-65": ml_dsa.ML_DSA_65,
         "ML-DSA-87": ml_dsa.ML_DSA_87}


def _load(directory: str, name: str) -> dict:
    return json.loads((VECTORS / directory / f"{name}.json").read_text(encoding="utf-8"))


def _expected(directory: str) -> dict[int, dict]:
    payload = _load(directory, "expectedResults")
    return {t["tcId"]: t for g in payload["testGroups"] for t in g["tests"]}


def _cases(directory: str):
    """Yield (param_set, group, test, expected) for every vector."""
    expected = _expected(directory)
    for group in _load(directory, "prompt")["testGroups"]:
        for test in group["tests"]:
            yield group["parameterSet"], group, test, expected[test["tcId"]]


def _ids(directory: str) -> list[str]:
    return [f"{p}-{t['tcId']}" for p, _, t, _ in _cases(directory)]


class TestKeyGeneration:
    """seed -> (pk, sk), byte-exact against NIST's recorded values."""

    @pytest.mark.parametrize("param,group,test,want", list(_cases("ML-DSA-keyGen-FIPS204")),
                             ids=_ids("ML-DSA-keyGen-FIPS204"))
    def test_derived_key_matches(self, param, group, test, want):
        pk, sk = IMPLS[param].key_derive(bytes.fromhex(test["seed"]))
        assert pk.hex().upper() == want["pk"].upper()
        assert sk.hex().upper() == want["sk"].upper()


class TestSignatureGeneration:
    """(sk, message, rnd) -> signature, byte-exact.

    ACVP targets `ML-DSA.Sign_internal` (FIPS 204 Alg. 7), which takes the
    message as-is. The public `sign()` implements the external interface and
    prepends a context prefix, so routing these through it fails all 60 vectors
    -- a failure that reads like a broken implementation rather than a wrong
    entry point. See TestTheExternalWrapper for the link to what we actually call.
    """

    @pytest.mark.parametrize("param,group,test,want", list(_cases("ML-DSA-sigGen-FIPS204")),
                             ids=_ids("ML-DSA-sigGen-FIPS204"))
    def test_signature_matches(self, param, group, test, want):
        rnd = bytes(32) if group.get("deterministic") else bytes.fromhex(test["rnd"])
        signature = IMPLS[param]._sign_internal(
            bytes.fromhex(test["sk"]), bytes.fromhex(test["message"]), rnd)
        assert signature.hex().upper() == want["signature"].upper()


class TestSignatureVerification:
    """The half a positive-only conformance test omits.

    Most of these vectors are *negative*: signatures mutated so that a correct
    verifier must reject them. An implementation whose `verify` returned True
    unconditionally would pass keyGen and sigGen and fail only here.
    """

    @pytest.mark.parametrize("param,group,test,want", list(_cases("ML-DSA-sigVer-FIPS204")),
                             ids=_ids("ML-DSA-sigVer-FIPS204"))
    def test_verdict_matches(self, param, group, test, want):
        got = IMPLS[param]._verify_internal(
            bytes.fromhex(group["pk"]), bytes.fromhex(test["message"]),
            bytes.fromhex(test["signature"]))
        assert bool(got) is bool(want["testPassed"])

    def test_the_vectors_actually_contain_negatives(self):
        """Otherwise the class above proves much less than it appears to."""
        verdicts = [bool(w["testPassed"]) for _, _, _, w in _cases("ML-DSA-sigVer-FIPS204")]
        assert any(verdicts) and not all(verdicts), (
            "sigVer vectors must include both valid and invalid signatures"
        )


class TestTheExternalWrapper:
    """Tie the validated core to the interface qknot actually calls.

    ACVP validates the internal algorithm. `qknot.signing` calls `sign()`, the
    external interface. Conformance of the former says nothing about the latter
    unless the composition is checked, and an error in the context encoding
    would be invisible to every vector above.
    """

    def test_sign_composes_internal_with_the_context_prefix(self):
        impl = ml_dsa.ML_DSA_44
        pk, sk = impl.key_derive(bytes(range(32)))
        message, ctx = b"artefact bytes", b"model-release"

        external = impl.sign(sk, message, ctx=ctx, deterministic=True)
        m_prime = bytes([0, len(ctx)]) + ctx + message
        internal = impl._sign_internal(sk, m_prime, bytes(32))
        assert external == internal, (
            "the external interface must be exactly the internal one over "
            "0x00 || len(ctx) || ctx || message"
        )

    def test_the_context_actually_separates(self):
        """Two contexts over one message must not yield one signature."""
        impl = ml_dsa.ML_DSA_44
        _pk, sk = impl.key_derive(bytes(range(32)))
        a = impl.sign(sk, b"m", ctx=b"release", deterministic=True)
        b = impl.sign(sk, b"m", ctx=b"staging", deterministic=True)
        assert a != b

    def test_qknot_backend_uses_the_validated_implementation(self):
        """Guard against the backend being re-pointed at round-3 Dilithium."""
        from qknot.signing.backends import MlDsaBackend

        assert MlDsaBackend("ml-dsa-44")._impl is ml_dsa.ML_DSA_44


class TestTheSchemesAreDistinct:
    def test_the_two_schemes_are_not_the_same_algorithm(self):
        """Round-3 Dilithium is not ML-DSA, and its KATs do not validate ML-DSA.

        The old conformance script conflated them. Both facts below are why the
        vectors had to be replaced rather than merely relocated.
        """
        from dilithium_py.dilithium import Dilithium2

        # Default entropy, not a seeded DRBG. `set_drbg_seed` needs
        # pycryptodome for its AES-CTR implementation, which this project does
        # not otherwise depend on -- and nothing here needs determinism. The
        # claim is about key sizes and cross-verification, both of which hold
        # for any key. Requiring a dependency a test does not need is how a
        # suite comes to fail on a clean install, which is exactly how this was
        # found.
        pk_d, sk_d = Dilithium2.keygen()
        _pk_m, sk_m = ml_dsa.ML_DSA_44.key_derive(bytes(32))

        assert len(sk_d) != len(sk_m), "secret key sizes differ (2528 vs 2560)"

        signature = Dilithium2.sign(sk_d, b"m")
        assert not ml_dsa.ML_DSA_44.verify(pk_d, b"m", signature), (
            "a round-3 Dilithium signature must not verify as ML-DSA"
        )
