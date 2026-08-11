"""Attacks on the hybrid combiner.

The combiner exists to stop one specific attack: deleting the post-quantum
signature and presenting the classical one alone. Every test below is an
attempt to perform that attack, or a variant of it, and to have the result
accepted.

If any of these passes without raising, the hybrid scheme provides no more
protection than the classical signature alone, and the paper's central claim
is false.
"""
from __future__ import annotations

import hashlib

import pytest

from qknot.signing.combiner import (
    BINDING_DOMAIN,
    KNOWN_ALGORITHMS,
    BindingMismatch,
    HybridBinding,
    SuiteError,
    build_binding,
    canonical_suite,
    compute_binding,
    verify_binding,
)
from qknot.signing.digest import digest_bytes

DIGEST = digest_bytes(b"the artefact", "sha3-256")
HYBRID = ["ed25519", "ml-dsa-44"]


# ===========================================================================
# The attack the module exists to stop
# ===========================================================================
class TestSignatureStripping:
    def test_stripping_the_pq_signature_is_detected(self):
        binding = build_binding(HYBRID, DIGEST)
        with pytest.raises(BindingMismatch, match="stripped"):
            verify_binding(binding, present_algorithms=["ed25519"], digest=DIGEST)

    def test_stripping_the_classical_signature_is_detected(self):
        binding = build_binding(HYBRID, DIGEST)
        with pytest.raises(BindingMismatch, match="stripped"):
            verify_binding(binding, present_algorithms=["ml-dsa-44"], digest=DIGEST)

    def test_editing_the_suite_down_breaks_the_binding(self):
        """The attacker's obvious next move: strip the signature AND rewrite
        the suite so the counts agree. The binding no longer recomputes."""
        binding = build_binding(HYBRID, DIGEST)
        forged = HybridBinding(
            suite="ed25519", algorithms=["ed25519"],
            digest=binding.digest, digest_algorithm=binding.digest_algorithm,
            binding=binding.binding,          # kept from the hybrid bundle
        )
        with pytest.raises(BindingMismatch, match="does not recompute"):
            verify_binding(forged, present_algorithms=["ed25519"], digest=DIGEST)

    def test_recomputing_the_binding_for_the_reduced_suite_changes_it(self):
        """Proof that the two suites are genuinely distinguishable."""
        hybrid = build_binding(HYBRID, DIGEST)
        classical = build_binding(["ed25519"], DIGEST)
        assert hybrid.binding != classical.binding

    def test_an_unbound_extra_signature_is_rejected(self):
        """Adding a signature the suite does not name must not count as
        protection -- otherwise an attacker appends a signature under a key
        they control and a naive verifier counts it."""
        binding = build_binding(HYBRID, DIGEST)
        with pytest.raises(BindingMismatch, match="does not cover"):
            verify_binding(binding,
                           present_algorithms=["ed25519", "ml-dsa-44", "rsa-2048"],
                           digest=DIGEST)

    def test_a_complete_hybrid_bundle_verifies(self):
        binding = build_binding(HYBRID, DIGEST)
        verify_binding(binding, present_algorithms=HYBRID, digest=DIGEST)

    def test_algorithm_order_does_not_matter_to_a_verifier(self):
        binding = build_binding(HYBRID, DIGEST)
        verify_binding(binding, present_algorithms=["ml-dsa-44", "ed25519"],
                       digest=DIGEST)

    def test_case_differences_do_not_break_verification(self):
        binding = build_binding(HYBRID, DIGEST)
        verify_binding(binding, present_algorithms=["Ed25519", "ML-DSA-44"],
                       digest=DIGEST)


# ===========================================================================
# Substitution attacks
# ===========================================================================
class TestSubstitution:
    def test_swapping_the_artefact_digest_is_detected(self):
        binding = build_binding(HYBRID, DIGEST)
        other = digest_bytes(b"a different artefact", "sha3-256")
        with pytest.raises(BindingMismatch, match="does not recompute"):
            verify_binding(binding, present_algorithms=HYBRID, digest=other)

    def test_same_digest_under_a_different_hash_is_not_interchangeable(self):
        """A 64-hex-char SHA3-256 digest and a 64-hex-char SHA-256 digest are
        indistinguishable by shape. The binding names the algorithm so they
        cannot be swapped."""
        value = "ab" * 32
        a = compute_binding("ed25519+ml-dsa-44", value, "sha3-256")
        b = compute_binding("ed25519+ml-dsa-44", value, "sha256")
        assert a != b

    def test_context_separates_bindings(self):
        a = build_binding(HYBRID, DIGEST, context=b"model-release")
        b = build_binding(HYBRID, DIGEST, context=b"internal-build")
        assert a.binding != b.binding

    def test_a_binding_from_another_context_is_rejected(self):
        binding = build_binding(HYBRID, DIGEST, context=b"model-release")
        with pytest.raises(BindingMismatch):
            verify_binding(binding, present_algorithms=HYBRID, digest=DIGEST,
                           context=b"internal-build")

    def test_length_prefixing_prevents_field_confusion(self):
        """Without length prefixes, suite 'ed25519' + digest '+ml-dsa-44abcd'
        would serialise identically to suite 'ed25519+ml-dsa-44' + digest
        'abcd'. This is the classic manifest-concatenation collision."""
        a = compute_binding("ed25519", "ab" * 32, "sha3-256")
        b = compute_binding("ed25519+ml-dsa-44", "ab" * 32, "sha3-256")
        assert a != b

    def test_binding_is_domain_separated(self):
        """A bare hash of the same fields must not equal the binding, or the
        binding could be replayed from another protocol that hashes them."""
        suite, digest = "ed25519+ml-dsa-44", "ab" * 32
        naive = hashlib.sha3_256(
            suite.encode() + bytes.fromhex(digest)).digest()
        assert compute_binding(suite, digest, "sha3-256") != naive
        assert BINDING_DOMAIN not in naive


# ===========================================================================
# Suite handling
# ===========================================================================
class TestSuiteCanonicalisation:
    def test_order_and_case_are_normalised(self):
        assert (canonical_suite(["ML-DSA-44", "ed25519"])
                == canonical_suite(["ed25519", "ml-dsa-44"])
                == "ed25519+ml-dsa-44")

    def test_empty_suite_is_refused(self):
        with pytest.raises(SuiteError, match="cannot be empty"):
            canonical_suite([])

    def test_duplicates_are_refused(self):
        with pytest.raises(SuiteError, match="duplicate"):
            canonical_suite(["ed25519", "ed25519"])

    def test_separator_in_a_name_is_refused(self):
        """An algorithm called 'a+b' would make the suite string ambiguous."""
        with pytest.raises(SuiteError, match="separates"):
            canonical_suite(["ed25519", "ml+dsa"])

    def test_unknown_algorithms_are_refused(self):
        """Binding an algorithm whose quantum resistance we cannot assess
        would let a bundle claim protection we cannot justify."""
        with pytest.raises(SuiteError, match="unknown"):
            canonical_suite(["ed25519", "homebrew-sig-v2"])

    def test_empty_name_is_refused(self):
        with pytest.raises(SuiteError):
            canonical_suite(["ed25519", "  "])


# ===========================================================================
# What the binding claims about quantum resistance
# ===========================================================================
class TestQuantumClaims:
    def test_hybrid_survives_shor(self):
        binding = build_binding(HYBRID, DIGEST)
        assert binding.survives_shor
        assert binding.quantum_resistant_members == ["ml-dsa-44"]
        assert binding.classical_members == ["ed25519"]

    def test_classical_only_does_not_survive_shor(self):
        binding = build_binding(["ed25519"], DIGEST)
        assert not binding.survives_shor
        assert binding.is_hybrid is False

    @pytest.mark.parametrize("algorithm,resistant", sorted(KNOWN_ALGORITHMS.items()))
    def test_every_known_algorithm_is_classified(self, algorithm, resistant):
        binding = build_binding([algorithm], DIGEST)
        assert binding.survives_shor is resistant

    def test_no_classical_algorithm_is_marked_resistant(self):
        """The classification that everything else depends on."""
        for name in ("ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"):
            assert KNOWN_ALGORITHMS[name] is False

    @pytest.mark.parametrize("level", ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"])
    def test_all_ml_dsa_levels_are_bindable(self, level):
        """44 is the default; 65 and 87 must be available as options."""
        binding = build_binding(["ed25519", level], DIGEST)
        assert binding.survives_shor
        assert level in binding.suite


# ===========================================================================
# Malformed input
# ===========================================================================
class TestMalformedInput:
    def test_non_hex_digest_is_refused(self):
        with pytest.raises(SuiteError, match="hex"):
            compute_binding("ed25519", "not-a-digest", "sha3-256")

    def test_empty_digest_is_refused(self):
        with pytest.raises(SuiteError, match="empty"):
            compute_binding("ed25519", "", "sha3-256")

    def test_binding_is_deterministic(self):
        a = build_binding(HYBRID, DIGEST, context=b"x")
        b = build_binding(HYBRID, DIGEST, context=b"x")
        assert a.binding == b.binding

    def test_binding_is_immutable(self):
        import dataclasses
        binding = build_binding(HYBRID, DIGEST)
        with pytest.raises(dataclasses.FrozenInstanceError):
            binding.suite = "ed25519"

    def test_serialises_for_the_bundle(self):
        d = build_binding(HYBRID, DIGEST).to_dict()
        assert d["algorithms"] == ["ed25519", "ml-dsa-44"]
        assert d["bindingAlgorithm"] == "sha3-256"
        assert len(d["binding"]) == 64
