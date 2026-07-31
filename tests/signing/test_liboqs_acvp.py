"""liboqs against NIST's ACVP key material, and the limit of what that can show.

WHY THE ACVP VECTORS CANNOT SIMPLY BE REPLAYED THROUGH liboqs
=============================================================
The FIPS 204 vectors in `fips204_vectors/` are **internal-interface**: the
group objects carry no `signatureInterface`, and `test_fips204_acvp.py`
exercises them through `_sign_internal` / `_verify_internal`. FIPS 204's
external `ML-DSA.Sign` prepends a domain separator and the context string to
the message before calling the internal routine, so a signature valid under one
interface is invalid under the other **by construction**.

liboqs-python exposes only the external API. Replaying internal vectors through
it would therefore fail, and the failure would say nothing about liboqs. Three
things follow, and the third is the useful one:

* **sigVer vectors: unusable.** Wrong interface.
* **sigGen vectors: unusable.** They pin byte-exact output for a supplied `rnd`,
  and liboqs signs in hedged mode with no way to inject it.
* **keyGen vectors: usable, and they close a real gap.** They give NIST-derived
  `(sk, pk)` pairs. Loading a foreign secret key into liboqs and signing with it
  exercises the key-import path -- which the cross-validation tests never touch,
  since there liboqs signs only with keys it generated itself. A private-key
  encoding mismatch would be invisible to every other test in this repository.

This is the scope stated exactly, rather than a claim of "validated against
FIPS 204 KATs" that would be true of the pure-Python backend and not of this
one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from qresp.signing.backends import BackendUnsuitable, LibOqsBackend, MlDsaBackend

VECTORS = Path(__file__).parent / "fips204_vectors"
LEVELS = {"ML-DSA-44": "ml-dsa-44", "ML-DSA-65": "ml-dsa-65",
          "ML-DSA-87": "ml-dsa-87"}


def _keygen_cases():
    """(parameter set, secret key, public key) from NIST's keyGen vectors."""
    prompt = json.loads(
        (VECTORS / "ML-DSA-keyGen-FIPS204" / "prompt.json").read_text())
    expected = json.loads(
        (VECTORS / "ML-DSA-keyGen-FIPS204" / "expectedResults.json").read_text())
    answers = {t["tcId"]: t for g in expected["testGroups"] for t in g["tests"]}
    for group in prompt["testGroups"]:
        for test in group["tests"]:
            want = answers[test["tcId"]]
            yield (group["parameterSet"], test["tcId"],
                   bytes.fromhex(want["sk"]), bytes.fromhex(want["pk"]))


ALL_CASES = list(_keygen_cases())


def _sample(per_set: int = 4):
    """The first `per_set` cases of EACH parameter set.

    `ALL_CASES[:12]` was the first attempt and it silently tested ML-DSA-44
    only: the vectors are grouped by parameter set, so a leading slice never
    reaches 65 or 87. Sampling has to be stratified when the source is ordered
    by the very thing being sampled across -- the same reason the npm ranking
    could not be built from whichever batches happened to finish first.
    """
    taken: dict[str, int] = {}
    out = []
    for case in ALL_CASES:
        param = case[0]
        if taken.get(param, 0) >= per_set:
            continue
        taken[param] = taken.get(param, 0) + 1
        out.append(case)
    return out


CASES = _sample()


def _liboqs(level: str):
    try:
        return LibOqsBackend(level)
    except (ImportError, BackendUnsuitable) as exc:
        pytest.skip(f"liboqs unavailable: {str(exc)[:60]}")


@pytest.mark.allow_network
class TestLiboqsAcceptsNistKeyMaterial:
    """The key-import path, which cross-validation never exercises."""

    @pytest.mark.parametrize("param,tc_id,sk,pk", CASES,
                             ids=[f"{p}-{t}" for p, t, _, _ in CASES])
    def test_liboqs_signs_with_a_nist_secret_key(self, param, tc_id, sk, pk):
        """A private-key encoding mismatch would be invisible elsewhere.

        Everywhere else liboqs signs with keys it generated itself, so an
        encoding disagreement would cancel out and never surface.
        """
        backend = _liboqs(LEVELS[param])
        message = f"acvp-{tc_id}".encode()
        signature = backend.sign(sk, message)
        assert backend.verify(pk, message, signature), (
            "liboqs could not verify its own signature made with a NIST key")
        assert MlDsaBackend(LEVELS[param]).verify(pk, message, signature), (
            "dilithium-py rejected a liboqs signature over NIST key material")

    @pytest.mark.parametrize("param,tc_id,sk,pk", CASES,
                             ids=[f"{p}-{t}" for p, t, _, _ in CASES])
    def test_the_key_pair_is_consistent_across_implementations(self, param,
                                                               tc_id, sk, pk):
        """dilithium-py signs with the NIST key; liboqs must accept it."""
        backend = _liboqs(LEVELS[param])
        pure = MlDsaBackend(LEVELS[param])
        message = f"acvp-reverse-{tc_id}".encode()
        assert backend.verify(pk, message, pure.sign(sk, message))

    def test_the_parametrised_cases_cover_every_parameter_set(self):
        """Asserts over CASES -- what the tests actually run.

        The first version of this checked the full vector list instead, so it
        passed while the parametrised tests, fed a leading slice, exercised
        ML-DSA-44 alone. A coverage assertion over a collection nothing uses is
        worse than none: it reports assurance that does not exist.
        """
        assert {p for p, _, _, _ in CASES} == set(LEVELS), (
            f"parametrised cases cover {sorted({p for p, _, _, _ in CASES})}, "
            f"not {sorted(LEVELS)}")

    def test_every_parameter_set_gets_more_than_one_case(self):
        counts = {p: sum(1 for c in CASES if c[0] == p) for p in LEVELS}
        assert all(n >= 2 for n in counts.values()), counts


@pytest.mark.allow_network
class TestTheInterfaceMismatchIsRealNotADefect:
    """Demonstrated, so nobody later "fixes" liboqs to pass internal vectors."""

    def test_liboqs_rejects_internal_interface_signatures(self):
        """FIPS 204 external Sign prepends a domain separator, so an
        internal-mode signature must NOT verify externally. If this ever starts
        passing, one of the two interfaces has been implemented wrongly.
        """
        prompt = json.loads(
            (VECTORS / "ML-DSA-sigVer-FIPS204" / "prompt.json").read_text())
        expected = json.loads(
            (VECTORS / "ML-DSA-sigVer-FIPS204" / "expectedResults.json").read_text())
        answers = {t["tcId"]: t for g in expected["testGroups"] for t in g["tests"]}

        checked = 0
        for group in prompt["testGroups"]:
            backend = _liboqs(LEVELS[group["parameterSet"]])
            for test in group["tests"]:
                if not answers[test["tcId"]]["testPassed"]:
                    continue          # already invalid; proves nothing here
                assert backend.verify(
                    bytes.fromhex(group["pk"]),
                    bytes.fromhex(test["message"]),
                    bytes.fromhex(test["signature"])) is False, (
                    f"tcId {test['tcId']}: an INTERNAL-interface signature "
                    f"verified under liboqs' EXTERNAL API. The two differ by a "
                    f"domain separator, so one of them is implemented wrongly.")
                checked += 1
                if checked >= 8:
                    return
        assert checked, "no valid sigVer vectors found to test against"
