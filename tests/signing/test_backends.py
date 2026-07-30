"""Tests for the signature backends and exposure gating.

The property under test is that a backend cannot misrepresent what it protects.
The gating tests matter most: they are what stops a pure-Python ML-DSA
implementation being deployed behind an HTTP endpoint, which is the one
configuration where its timing leak is exploitable.
"""
from __future__ import annotations

import pytest

from qresp.signing.backends import (
    DEFAULT_SUITE,
    ML_DSA_SIGNATURE_SIZES,
    BackendUnsuitable,
    Ed25519Backend,
    Exposure,
    LibOqsBackend,
    MlDsaBackend,
    check_exposure,
    constant_time_compare,
    get_backend,
    key_fingerprint,
)

crypto = pytest.importorskip("cryptography", reason="Ed25519 needs `cryptography`")
dilithium = pytest.importorskip("dilithium_py", reason="ML-DSA needs `dilithium-py`")


@pytest.fixture(scope="module")
def ed25519():
    return Ed25519Backend()


@pytest.fixture(scope="module")
def ml_dsa():
    return MlDsaBackend("ml-dsa-44")


# ===========================================================================
# Exposure gating: the point of the module
# ===========================================================================
class TestExposureGating:
    def test_pure_python_ml_dsa_is_refused_online(self, ml_dsa):
        """The configuration where the timing leak becomes exploitable."""
        with pytest.raises(BackendUnsuitable, match="not constant-time"):
            check_exposure(ml_dsa, Exposure.ONLINE)

    def test_ml_dsa_is_permitted_offline(self, ml_dsa):
        """Release signing: nobody can observe the timings."""
        check_exposure(ml_dsa, Exposure.OFFLINE)

    def test_ed25519_is_permitted_everywhere(self, ed25519):
        for exposure in Exposure:
            check_exposure(ed25519, exposure)

    def test_the_refusal_names_the_alternative(self, ml_dsa):
        """An error that only says 'no' gets worked around."""
        with pytest.raises(BackendUnsuitable) as excinfo:
            check_exposure(ml_dsa, Exposure.ONLINE)
        message = str(excinfo.value)
        assert "liboqs" in message
        assert "OFFLINE" in message

    def test_the_refusal_pre_empts_the_noise_wrapper_idea(self, ml_dsa):
        """Random delay is the intuitive fix and does not work. Saying so at
        the point of failure is more useful than saying it in a document
        nobody reads."""
        with pytest.raises(BackendUnsuitable) as excinfo:
            check_exposure(ml_dsa, Exposure.ONLINE)
        assert "random delay does not fix this" in str(excinfo.value)

    def test_gating_is_an_error_not_a_warning(self, ml_dsa):
        """A warning would be scrolled past and the service would ship."""
        with pytest.raises(BackendUnsuitable):
            check_exposure(ml_dsa, Exposure.ONLINE)


# ===========================================================================
# Backends must not misrepresent themselves
# ===========================================================================
class TestHonestSelfDescription:
    def test_ml_dsa_admits_it_is_not_constant_time(self, ml_dsa):
        assert ml_dsa.side_channel_resistant is False
        described = ml_dsa.describe()
        assert described["sideChannelResistant"] is False
        assert described["suitableExposures"] == ["offline"]

    def test_ml_dsa_caveats_name_the_actual_mechanism(self, ml_dsa):
        """'Not constant-time' is vague. 'Rejection sampling makes duration
        depend on secret data' is checkable."""
        caveats = " ".join(ml_dsa.describe()["caveats"]).lower()
        assert "rejection sampling" in caveats
        assert "not side-channel" in caveats

    def test_ml_dsa_caveats_name_the_conformance_evidence_precisely(self, ml_dsa):
        """The caveat must say *which* vectors, not just "KATs".

        It previously said "FIPS 204 KATs" while the script behind that claim
        ran round-3 Dilithium vectors against the round-3 Dilithium module --
        a different algorithm from the one this backend signs with. Naming the
        specific vector suite is what makes the claim checkable rather than
        reassuring. See tests/signing/fips204_vectors/PROVENANCE.md.
        """
        caveats = " ".join(ml_dsa.describe()["caveats"]).lower()
        assert "acvp" in caveats and "fips 204" in caveats
        assert "correctness, not side-channel resistance" in caveats

    def test_ed25519_admits_it_is_shor_vulnerable(self, ed25519):
        assert ed25519.quantum_resistant is False
        assert "shor" in " ".join(ed25519.describe()["caveats"]).lower()

    def test_ml_dsa_claims_quantum_resistance(self, ml_dsa):
        assert ml_dsa.quantum_resistant is True

    def test_descriptions_are_serialisable(self, ml_dsa, ed25519):
        import json
        for backend in (ml_dsa, ed25519):
            assert json.loads(json.dumps(backend.describe()))


# ===========================================================================
# The primitives actually work
# ===========================================================================
class TestEd25519:
    def test_roundtrip(self, ed25519):
        pk, sk = ed25519.keygen()
        sig = ed25519.sign(sk, b"message")
        assert ed25519.verify(pk, b"message", sig)

    def test_signature_size(self, ed25519):
        pk, sk = ed25519.keygen()
        assert len(ed25519.sign(sk, b"m")) == ed25519.signature_size == 64

    def test_rejects_a_tampered_message(self, ed25519):
        pk, sk = ed25519.keygen()
        sig = ed25519.sign(sk, b"message")
        assert not ed25519.verify(pk, b"tampered", sig)

    def test_rejects_a_tampered_signature(self, ed25519):
        pk, sk = ed25519.keygen()
        sig = bytearray(ed25519.sign(sk, b"message"))
        sig[0] ^= 1
        assert not ed25519.verify(pk, b"message", bytes(sig))

    def test_rejects_a_foreign_key(self, ed25519):
        pk1, sk1 = ed25519.keygen()
        pk2, _ = ed25519.keygen()
        assert not ed25519.verify(pk2, b"m", ed25519.sign(sk1, b"m"))

    def test_seeded_keygen_is_deterministic(self, ed25519):
        seed = b"\x42" * 32
        assert ed25519.keygen(seed)[0] == ed25519.keygen(seed)[0]

    def test_verify_returns_false_rather_than_raising(self, ed25519):
        pk, _ = ed25519.keygen()
        assert ed25519.verify(pk, b"m", b"garbage") is False


class TestMlDsa:
    def test_roundtrip(self, ml_dsa):
        pk, sk = ml_dsa.keygen()
        sig = ml_dsa.sign(sk, b"message")
        assert ml_dsa.verify(pk, b"message", sig)

    @pytest.mark.parametrize("level,size", sorted(ML_DSA_SIGNATURE_SIZES.items()))
    def test_signature_sizes_match_fips_204(self, level, size):
        """2420 / 3309 / 4627. These are the values the audit's length-based
        classifier keys on, so a mismatch would break both halves at once."""
        backend = MlDsaBackend(level)
        assert backend.signature_size == size
        pk, sk = backend.keygen()
        assert len(backend.sign(sk, b"m")) == size

    def test_rejects_a_tampered_message(self, ml_dsa):
        pk, sk = ml_dsa.keygen()
        sig = ml_dsa.sign(sk, b"message")
        assert not ml_dsa.verify(pk, b"tampered", sig)

    def test_rejects_a_tampered_signature(self, ml_dsa):
        pk, sk = ml_dsa.keygen()
        sig = bytearray(ml_dsa.sign(sk, b"message"))
        sig[100] ^= 1
        assert not ml_dsa.verify(pk, b"message", bytes(sig))

    def test_rejects_a_foreign_key(self, ml_dsa):
        pk1, sk1 = ml_dsa.keygen()
        pk2, _ = ml_dsa.keygen()
        assert not ml_dsa.verify(pk2, b"m", ml_dsa.sign(sk1, b"m"))

    def test_seeded_keygen_is_deterministic(self, ml_dsa):
        """Required so that attested entropy actually reaches the key. Without
        it the entropy attestation would describe bytes that never got used."""
        seed = b"\x07" * 32
        assert ml_dsa.keygen(seed)[0] == ml_dsa.keygen(seed)[0]

    def test_different_seeds_give_different_keys(self, ml_dsa):
        assert ml_dsa.keygen(b"\x01" * 32)[0] != ml_dsa.keygen(b"\x02" * 32)[0]

    def test_short_seed_is_refused(self, ml_dsa):
        with pytest.raises(ValueError, match="at least 32 bytes"):
            ml_dsa.keygen(b"tooshort")

    def test_verify_returns_false_rather_than_raising(self, ml_dsa):
        pk, _ = ml_dsa.keygen()
        assert ml_dsa.verify(pk, b"m", b"garbage") is False

    def test_unknown_level_is_refused(self):
        with pytest.raises(ValueError, match="unknown level"):
            MlDsaBackend("ml-dsa-99")


# ===========================================================================
# Helpers
# ===========================================================================
class TestHelpers:
    def test_constant_time_compare_is_correct(self):
        assert constant_time_compare(b"abc", b"abc")
        assert not constant_time_compare(b"abc", b"abd")
        assert not constant_time_compare(b"abc", b"ab")

    def test_key_fingerprint_is_stable_and_domain_separated(self):
        import hashlib
        pk = b"\x01" * 32
        assert key_fingerprint(pk) == key_fingerprint(pk)
        assert key_fingerprint(pk) != hashlib.sha3_256(pk).hexdigest()[:32]

    def test_key_fingerprint_distinguishes_keys(self):
        assert key_fingerprint(b"\x01" * 32) != key_fingerprint(b"\x02" * 32)

    def test_liboqs_backend_is_an_honest_stub(self):
        """It must not silently behave as though it were constant-time."""
        with pytest.raises(NotImplementedError, match="documented contract"):
            LibOqsBackend()

    def test_registry_resolves_every_default_suite_member(self):
        for algorithm in DEFAULT_SUITE:
            assert get_backend(algorithm) is not None

    def test_default_suite_is_hybrid_at_cnsa_2_0_strength(self):
        """Pinned literally, not derived from DEFAULT_SUITE.

        Deriving the expected value from the thing under test would make this
        assertion vacuous. The point is that changing the shipped default is a
        deliberate act that has to update a test, because the default decides
        what every user who passes no flags actually gets.

        ML-DSA-87 because CNSA 2.0 names it specifically, and because software
        signing must be exclusively CNSA 2.0 for US National Security Systems
        from 2027-01-01. -44 and -65 remain selectable for bandwidth-sensitive
        deployments; see docs/OPEN-QUESTIONS.md 7.
        """
        assert DEFAULT_SUITE == ["ed25519", "ml-dsa-87"]

    def test_unknown_algorithm_lists_the_available_ones(self):
        with pytest.raises(ValueError, match="ed25519"):
            get_backend("rot13")

    @pytest.mark.parametrize("level", ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"])
    def test_all_three_security_levels_are_selectable(self, level):
        assert get_backend(level).algorithm == level


class TestTheLibOqsStubDefaultsToTheSafeValue:
    """The dangerous default is the permissive one.

    LibOqsBackend cannot be constructed today, so the class attribute is inert
    -- but whoever fills in __init__ inherits whatever is written here. A
    forgotten line would ship an unproven constant-time claim straight into an
    ONLINE exposure, which is precisely what check_exposure exists to prevent.
    """

    def test_side_channel_resistance_is_not_claimed_by_default(self):
        from qresp.signing.backends import LibOqsBackend

        assert LibOqsBackend.side_channel_resistant is False, (
            "an unimplemented backend must not inherit a constant-time claim"
        )

    def test_it_still_refuses_to_construct(self):
        from qresp.signing.backends import LibOqsBackend

        with pytest.raises(NotImplementedError, match="documented contract"):
            LibOqsBackend()

    def test_the_stub_would_be_gated_out_of_online_exposure(self):
        """With the safe default, the exposure check does the right thing even
        if someone wires the stub up without reading the docstring."""
        from qresp.signing.backends import (
            BackendUnsuitable,
            Exposure,
            LibOqsBackend,
            check_exposure,
        )

        with pytest.raises(BackendUnsuitable):
            check_exposure(LibOqsBackend, Exposure.ONLINE)
