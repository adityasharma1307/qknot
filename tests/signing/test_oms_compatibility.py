"""Compatibility with the *unmodified* OpenSSF Model Signing v1.0 schemas.

WHY THIS FILE EXISTS
====================
"OMS-compatible extension" is a claim, and claims decay. These tests validate
against the real schemas, vendored verbatim from the ossf/model-signing-spec
repository, so the claim is checked on every run rather than asserted in a
docstring.

They also pin the *limits* of that compatibility. Several of the tests below
assert that OMS **rejects** something -- a post-quantum hash algorithm, an
`algorithm` field on a signature. Those are not bugs in our code; they are the
spec gaps this work reports, recorded as executable evidence so that if a
future OMS version closes them, the test fails and tells us to update the paper.

WHAT THE SCHEMAS PERMIT, ESTABLISHED HERE
=========================================
    multiple DSSE signatures        yes   -> the hybrid signature lives here
    subject[].digest["sha3-256"]    yes   -> SHA-3 artefact digest
    subject[] extra fields          yes   -> the algorithm binding lives here
    resources[] extra fields        yes   -> per-file SHA-3 digests
    signature.algorithm             NO    -> so hybrid verification is undefined
    predicate top-level fields      NO
    serialization.hash_type sha3    NO
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from qknot.signing.combiner import build_binding  # noqa: E402
from qknot.signing.digest import digest_bytes  # noqa: E402

SCHEMA_DIR = Path(__file__).parent / "oms_schemas"
VECTORS = SCHEMA_DIR / "vectors"


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def schemas():
    statement = _load("statement.schema.json")
    predicate = _load("predicate.schema.json")
    envelope = _load("envelope.schema.json")
    resolver = jsonschema.RefResolver.from_schema(
        statement, store={s["$id"]: s for s in (statement, predicate)}
    )
    return {"statement": statement, "predicate": predicate,
            "envelope": envelope, "resolver": resolver}


@pytest.fixture(scope="module")
def reference_bundle():
    return json.loads((VECTORS / "certificate.bundle.json").read_text(encoding="utf-8"))


@pytest.fixture
def reference_statement(reference_bundle):
    return json.loads(base64.b64decode(reference_bundle["dsseEnvelope"]["payload"]))


def _valid(obj, schema, resolver=None) -> bool:
    try:
        jsonschema.validate(obj, schema, resolver=resolver)
        return True
    except jsonschema.ValidationError:
        return False


# ===========================================================================
# The reference vectors must validate, or our reading of the spec is wrong
# ===========================================================================
class TestReferenceVectors:
    @pytest.mark.parametrize("name", ["certificate", "key", "sigstore"])
    def test_official_vectors_validate(self, name, schemas):
        bundle = json.loads((VECTORS / f"{name}.bundle.json").read_text(encoding="utf-8"))
        assert _valid(bundle["dsseEnvelope"], schemas["envelope"])
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        assert _valid(statement, schemas["statement"], schemas["resolver"])


# ===========================================================================
# What our extension needs, and whether OMS allows it
# ===========================================================================
class TestExtensionPointsThatWork:
    def test_a_second_signature_is_schema_valid(self, reference_bundle, schemas):
        """The hybrid signature goes here. DSSE natively supports an array."""
        envelope = copy.deepcopy(reference_bundle["dsseEnvelope"])
        envelope["signatures"].append(
            {"sig": base64.b64encode(b"\x00" * 2420).decode(), "keyid": "ml-dsa-44"}
        )
        assert _valid(envelope, schemas["envelope"]), (
            "if this fails, hybrid signing cannot use an unmodified OMS bundle"
        )

    def test_subject_digest_accepts_sha3_256(self, reference_statement, schemas):
        statement = copy.deepcopy(reference_statement)
        statement["subject"][0]["digest"]["sha3-256"] = digest_bytes(b"artefact")
        assert _valid(statement, schemas["statement"], schemas["resolver"])

    def test_subject_accepts_the_algorithm_binding(self, reference_statement, schemas):
        """The binding must live inside the signed payload. This is the
        extension point that makes non-separability possible within OMS."""
        statement = copy.deepcopy(reference_statement)
        binding = build_binding(["ed25519", "ml-dsa-44"], digest_bytes(b"artefact"))
        statement["subject"][0]["algorithmBinding"] = binding.to_dict()
        assert _valid(statement, schemas["statement"], schemas["resolver"])

    def test_resource_descriptors_accept_extra_digests(self, reference_statement, schemas):
        predicate = copy.deepcopy(reference_statement["predicate"])
        predicate["resources"][0]["sha3_256"] = digest_bytes(b"file")
        assert _valid(predicate, schemas["predicate"])


class TestSpecGapsWeAreReporting:
    """Each of these asserts OMS *rejects* something we need.

    They are the evidence behind the spec proposal. If OMS later permits any
    of them, the corresponding test fails and the paper needs updating -- which
    is the intended behaviour.
    """

    def test_a_signature_cannot_declare_its_algorithm(self, reference_bundle, schemas):
        """THE central gap. `signature` is additionalProperties:false and the
        spec says keyid 'is not used for verification', so a bundle can carry
        an ML-DSA signature that no verifier can identify."""
        envelope = copy.deepcopy(reference_bundle["dsseEnvelope"])
        envelope["signatures"][0]["algorithm"] = "ml-dsa-44"
        assert not _valid(envelope, schemas["envelope"]), (
            "OMS now permits per-signature algorithms -- update the spec "
            "proposal, this gap is closed"
        )

    def test_serialization_hash_type_rejects_sha3(self, reference_statement, schemas):
        """Per-file SHA-3 digests cannot be declared, because hash_type is an
        enum of sha256/blake2b/blake3."""
        predicate = copy.deepcopy(reference_statement["predicate"])
        predicate["serialization"]["hash_type"] = "sha3-256"
        assert not _valid(predicate, schemas["predicate"])

    def test_resource_algorithm_rejects_sha3(self, reference_statement, schemas):
        predicate = copy.deepcopy(reference_statement["predicate"])
        predicate["resources"][0]["algorithm"] = "sha3-256"
        assert not _valid(predicate, schemas["predicate"])

    def test_predicate_is_closed_to_new_fields(self, reference_statement, schemas):
        """So the entropy attestation cannot be a predicate field."""
        predicate = copy.deepcopy(reference_statement["predicate"])
        predicate["entropyAttestation"] = {"kdf": "HKDF-SHA3-256"}
        assert not _valid(predicate, schemas["predicate"])

    def test_statement_is_closed_to_new_fields(self, reference_statement, schemas):
        statement = copy.deepcopy(reference_statement)
        statement["hybridAlgorithms"] = ["ed25519", "ml-dsa-44"]
        assert not _valid(statement, schemas["statement"], schemas["resolver"])


class TestRegistryHasNoPostQuantumEntry:
    """The Phase I finding, re-checked against the vendored registry."""

    def test_registry_names_no_post_quantum_algorithm(self):
        text = (SCHEMA_DIR / "algorithm-registry.md").read_text(encoding="utf-8").lower()
        for term in ("ml-dsa", "dilithium", "slh-dsa", "sphincs", "post-quantum", "falcon"):
            assert term not in text, (
                f"the OMS registry now mentions {term!r} -- the paper's claim "
                f"that OMS has no post-quantum path needs revisiting"
            )

    def test_every_registry_key_type_is_shor_vulnerable(self):
        """P-256/384/521 are all elliptic curve, all broken by Shor."""
        text = (SCHEMA_DIR / "algorithm-registry.md").read_text(encoding="utf-8")
        assert "P-256" in text and "P-384" in text and "P-521" in text

    def test_hash_enum_matches_the_registry(self, schemas):
        """The registry says changes MUST be reflected in the schema. Confirm
        they currently agree, so a future divergence is caught."""
        enum = schemas["predicate"]["$defs"]["resource_descriptor"]["properties"]["algorithm"]["enum"]
        assert set(enum) == {"sha256", "blake2b", "blake3"}


class TestOurBundlesValidateAgainstRealOms:
    """The backward-compatibility claim, made checkable.

    A hybrid bundle produced by this project must validate against the
    unmodified OMS v1.0 schemas. If it does not, "OMS-compatible extension" is
    false and the whole framing collapses into a fork.
    """

    @pytest.fixture(scope="class")
    @classmethod
    def hybrid_bundle(cls, tmp_path_factory):
        pytest.importorskip("cryptography")
        pytest.importorskip("dilithium_py")
        from qknot.signing.backends import Exposure
        from qknot.signing.bundle import build_bundle
        from qknot.signing.sign import keygen, sign

        root = tmp_path_factory.mktemp("artefact")
        (root / "weights.bin").write_bytes(b"w" * 512)
        (root / "config.json").write_bytes(b"{}")

        keys = keygen(suite=["ed25519", "ml-dsa-44"], seed=b"\x11" * 32)
        signed = sign(root, keys, exposure=Exposure.OFFLINE,
                      subject_name="test-artefact")
        return build_bundle(signed)

    def test_envelope_validates(self, hybrid_bundle, schemas):
        assert _valid(hybrid_bundle["dsseEnvelope"], schemas["envelope"]), (
            "our hybrid envelope is not valid OMS -- the compatibility claim "
            "is false"
        )

    def test_statement_validates(self, hybrid_bundle, schemas):
        statement = json.loads(base64.b64decode(hybrid_bundle["dsseEnvelope"]["payload"]))
        assert _valid(statement, schemas["statement"], schemas["resolver"])

    def test_predicate_validates(self, hybrid_bundle, schemas):
        statement = json.loads(base64.b64decode(hybrid_bundle["dsseEnvelope"]["payload"]))
        assert _valid(statement["predicate"], schemas["predicate"])

    def test_it_really_carries_two_signatures(self, hybrid_bundle):
        assert len(hybrid_bundle["dsseEnvelope"]["signatures"]) == 2

    def test_the_binding_is_inside_the_signed_payload(self, hybrid_bundle):
        """Outside it, an attacker could edit the binding freely and the
        non-separability argument would collapse."""
        statement = json.loads(base64.b64decode(hybrid_bundle["dsseEnvelope"]["payload"]))
        assert "algorithmBinding" in statement["subject"][0]

    def test_a_legacy_verifier_still_finds_its_signature(self, hybrid_bundle):
        """Backward compatibility in practice: an OMS verifier that knows only
        Ed25519 must still find something it can check."""
        keyids = {s.get("keyid") for s in hybrid_bundle["dsseEnvelope"]["signatures"]}
        assert "ed25519" in keyids
