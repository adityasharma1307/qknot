"""End-to-end: sign a real artefact, then attack the actual bundle.

Earlier tests attacked the combiner in isolation. These attack a serialised
bundle produced by the real pipeline, which is what an adversary would actually
have in hand. The distinction matters: a combiner can be correct while the
serialisation quietly drops the field that makes it work.
"""
from __future__ import annotations

import base64
import json

import pytest

pytest.importorskip("cryptography", reason="needs `cryptography`")
pytest.importorskip("dilithium_py", reason="needs `dilithium-py`")

from qresp.signing.backends import Exposure  # noqa: E402
from qresp.signing.bundle import (  # noqa: E402
    build_bundle,
    build_statement,
    parse_bundle,
)
from qresp.signing.sign import (  # noqa: E402
    VerificationFailed,
    VerifyMode,
    keygen,
    sign,
    verify,
)

SUITE = ["ed25519", "ml-dsa-44"]
SEED = b"\x2a" * 32


@pytest.fixture(scope="module")
def keys():
    return keygen(suite=SUITE, seed=SEED)


@pytest.fixture(scope="module")
def artefact(tmp_path_factory):
    root = tmp_path_factory.mktemp("model")
    (root / "model.safetensors").write_bytes(b"weights" * 100)
    (root / "config.json").write_bytes(b'{"arch": "test"}')
    (root / "tokenizer").mkdir()
    (root / "tokenizer" / "vocab.txt").write_bytes(b"hello\nworld\n")
    return root


@pytest.fixture(scope="module")
def signed(artefact, keys):
    # subject_name is fixed at signing time: it lives inside the payload the
    # signatures cover, so it cannot be chosen later when building the bundle.
    return sign(artefact, keys, exposure=Exposure.OFFLINE, context=b"model-release",
                subject_name="model")


# ===========================================================================
# The happy path
# ===========================================================================
class TestSigningWorks:
    def test_signs_a_directory_tree(self, signed):
        assert set(signed.signatures) == set(SUITE)
        assert len(signed.signatures["ed25519"]) == 64
        assert len(signed.signatures["ml-dsa-44"]) == 2420

    def test_verifies_strict(self, artefact, signed):
        report = verify(artefact, signed, mode=VerifyMode.STRICT, context=b"model-release")
        assert report["verified"]
        assert report["algorithms_checked"] == SUITE
        assert report["quantum_resistant"]
        assert report["binding_enforced"]

    def test_keygen_is_deterministic_from_a_seed(self):
        a = keygen(suite=SUITE, seed=SEED)
        b = keygen(suite=SUITE, seed=SEED)
        for algorithm in SUITE:
            assert a.keys[algorithm].public_key == b.keys[algorithm].public_key

    def test_keys_are_domain_separated_per_algorithm(self, keys):
        """One leaked key must not expose another derived from the same seed."""
        secrets = [k.secret_key for k in keys.keys.values()]
        assert secrets[0] != secrets[1]

    def test_signing_a_bytes_object_works_too(self, keys):
        result = sign(b"just some bytes", keys, exposure=Exposure.OFFLINE)
        assert verify(b"just some bytes", result)["verified"]

    def test_tampering_with_the_artefact_is_detected(self, artefact, signed, tmp_path):
        tampered = tmp_path / "tampered"
        tampered.mkdir()
        for src in artefact.rglob("*"):
            if src.is_file():
                dst = tampered / src.relative_to(artefact)
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
        (tampered / "model.safetensors").write_bytes(b"BACKDOORED")
        with pytest.raises(VerificationFailed, match="has been modified"):
            verify(tampered, signed, context=b"model-release")


# ===========================================================================
# Attacking the serialised bundle
# ===========================================================================
class TestBundleStripping:
    def test_stripping_ml_dsa_from_the_bundle_is_detected(self, artefact, signed):
        """The attack, performed on the real artefact an adversary would hold."""
        bundle = build_bundle(signed, subject_name="model")
        bundle["dsseEnvelope"]["signatures"] = [
            s for s in bundle["dsseEnvelope"]["signatures"] if s["keyid"] != "ml-dsa-44"
        ]
        stripped = parse_bundle(bundle)
        assert set(stripped.signatures) == {"ed25519"}

        with pytest.raises(VerificationFailed, match="stripped"):
            verify(artefact, stripped, mode=VerifyMode.STRICT, context=b"model-release")

    def test_stripping_survives_classical_mode_which_is_the_point(
        self, artefact, signed
    ):
        """CLASSICAL mode does not consult the binding, so it accepts the
        stripped bundle. This is correct behaviour and exactly why STRICT
        exists -- documented so nobody mistakes it for a bug."""
        bundle = build_bundle(signed, subject_name="model")
        bundle["dsseEnvelope"]["signatures"] = [
            s for s in bundle["dsseEnvelope"]["signatures"] if s["keyid"] != "ml-dsa-44"
        ]
        stripped = parse_bundle(bundle)
        report = verify(artefact, stripped, mode=VerifyMode.CLASSICAL,
                        context=b"model-release")
        assert report["verified"]
        assert not report["quantum_resistant"]
        assert any("does not enforce" in w for w in report["warnings"])

    def test_editing_the_binding_to_hide_the_strip_is_detected(self, artefact, signed):
        """The attacker's second move: strip, then rewrite the suite to match."""
        bundle = build_bundle(signed, subject_name="model")
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        statement["subject"][0]["algorithmBinding"]["algorithms"] = ["ed25519"]
        statement["subject"][0]["algorithmBinding"]["suite"] = "ed25519"
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        bundle["dsseEnvelope"]["signatures"] = [
            s for s in bundle["dsseEnvelope"]["signatures"] if s["keyid"] != "ml-dsa-44"
        ]
        forged = parse_bundle(bundle)
        with pytest.raises(VerificationFailed, match="does not recompute"):
            verify(artefact, forged, mode=VerifyMode.STRICT, context=b"model-release")

    def test_a_bundle_without_a_binding_is_refused(self, signed):
        bundle = build_bundle(signed, subject_name="model")
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        del statement["subject"][0]["algorithmBinding"]
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(statement).encode()).decode()
        with pytest.raises(ValueError, match="no algorithmBinding"):
            parse_bundle(bundle)

    def test_roundtrip_preserves_everything_needed(self, artefact, signed):
        parsed = parse_bundle(build_bundle(signed, subject_name="model"))
        assert verify(artefact, parsed, mode=VerifyMode.STRICT,
                      context=b"model-release")["verified"]

    def test_parse_reads_algorithms_from_the_binding_not_the_signatures(self, signed):
        """Trusting the signature list would let an attacker who strips one
        simply be believed."""
        bundle = build_bundle(signed, subject_name="model")
        bundle["dsseEnvelope"]["signatures"] = []
        parsed = parse_bundle(bundle)
        assert parsed.binding.algorithms == SUITE
        assert parsed.signatures == {}


# ===========================================================================
# Verification modes
# ===========================================================================
class TestVerifyModes:
    def test_pqc_mode_checks_only_the_post_quantum_signature(self, artefact, signed):
        report = verify(artefact, signed, mode=VerifyMode.PQC, context=b"model-release")
        assert report["algorithms_checked"] == ["ml-dsa-44"]
        assert report["quantum_resistant"]

    def test_classical_mode_warns_it_checked_nothing_quantum(self, artefact, signed):
        report = verify(artefact, signed, mode=VerifyMode.CLASSICAL,
                        context=b"model-release")
        assert report["algorithms_checked"] == ["ed25519"]
        assert not report["quantum_resistant"]
        assert any("not protected against a quantum adversary" in w
                   for w in report["warnings"])

    def test_only_strict_enforces_the_binding(self, artefact, signed):
        for mode in (VerifyMode.CLASSICAL, VerifyMode.PQC):
            assert not verify(artefact, signed, mode=mode,
                              context=b"model-release")["binding_enforced"]
        assert verify(artefact, signed, mode=VerifyMode.STRICT,
                      context=b"model-release")["binding_enforced"]

    def test_wrong_context_fails_strict(self, artefact, signed):
        with pytest.raises(VerificationFailed):
            verify(artefact, signed, mode=VerifyMode.STRICT, context=b"different")


# ===========================================================================
# Exposure gating reaches the signing entry point
# ===========================================================================
class TestExposureReachesSign:
    def test_online_signing_with_pure_python_ml_dsa_is_refused(self, artefact, keys):
        from qresp.signing.backends import BackendUnsuitable

        with pytest.raises(BackendUnsuitable, match="not constant-time"):
            sign(artefact, keys, exposure=Exposure.ONLINE)

    def test_the_refusal_happens_before_any_signing(self, artefact, keys):
        """An unsuitable configuration must not produce a partial result."""
        from qresp.signing.backends import BackendUnsuitable

        with pytest.raises(BackendUnsuitable):
            sign(artefact, keys, exposure=Exposure.ONLINE)

    def test_the_bundle_records_the_backend_caveats(self, signed):
        info = signed.backend_info["ml-dsa-44"]
        assert info["sideChannelResistant"] is False
        assert any("rejection sampling" in c for c in info["caveats"])

    def test_signing_notes_the_non_constant_time_backend(self, signed):
        assert any("non-constant-time" in n for n in signed.notes)


# ===========================================================================
# The bundle is real OMS
# ===========================================================================
class TestOmsShape:
    def test_bundle_has_the_sigstore_shape(self, signed):
        bundle = build_bundle(signed, subject_name="model")
        assert bundle["mediaType"].startswith("application/vnd.dev.sigstore.bundle")
        assert bundle["dsseEnvelope"]["payloadType"] == "application/vnd.in-toto+json"
        assert len(bundle["dsseEnvelope"]["signatures"]) == 2

    def test_statement_declares_the_oms_predicate_type(self, signed):
        statement = build_statement(signed, "model")
        assert statement["predicateType"] == "https://model_signing/signature/v1.0"
        assert statement["_type"] == "https://in-toto.io/Statement/v1"

    def test_subject_digest_carries_both_hashes(self, signed):
        statement = build_statement(signed, "model")
        digest_set = statement["subject"][0]["digest"]
        assert "sha256" in digest_set, "OMS requires sha256"
        assert "sha3-256" in digest_set, "our actual digest"

    def test_resources_declare_sha256_and_carry_sha3(self, signed):
        statement = build_statement(signed, "model")
        for resource in statement["predicate"]["resources"]:
            assert resource["algorithm"] == "sha256", "the only enum value permitted"
            assert "digestSha3_256" in resource, "SHA-3 rides as an extra field"

    def test_entropy_attestation_rides_inside_the_signed_payload(self, artefact):
        """An unsigned attestation is worthless; it must be covered.

        This docstring used to be false. The attestation was inside the payload
        but the signatures covered only the binding, so it was present and
        unprotected -- the worst combination, because it looked signed. Since
        signing moved to the DSSE PAE over the whole statement it is genuinely
        covered, and this test now checks that rather than mere presence.
        """
        from qresp.signing.entropy.backends import SystemEntropyBackend
        from qresp.signing.entropy.mixing import mix_entropy

        result = mix_entropy([SystemEntropyBackend()], n_bytes=32)
        keys = keygen(suite=SUITE, seed=result.seed)
        object.__setattr__(keys, "entropy_attestation", result.attestation)
        out = sign(artefact, keys, exposure=Exposure.OFFLINE, subject_name="model")

        statement = json.loads(out.payload)
        assert "entropyAttestation" in statement["subject"][0]

        # Present is not enough: prove it is inside what the signatures cover.
        tampered = json.loads(out.payload)
        tampered["subject"][0]["entropyAttestation"]["kdf"] = "rot13"
        forged = json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
        from qresp.signing.backends import get_backend
        from qresp.signing.dsse import DSSE_PAYLOAD_TYPE, pae

        assert not get_backend("ed25519").verify(
            out.public_keys["ed25519"], pae(DSSE_PAYLOAD_TYPE, forged),
            out.signatures["ed25519"],
        ), "editing the attestation must invalidate the signature"
