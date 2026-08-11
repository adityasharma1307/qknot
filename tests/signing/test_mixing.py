"""Adversarial tests for entropy mixing and the public/secret boundary.

The catastrophic failure this design can have is deriving a key from public
randomness. It would look perfectly random and be computable by anyone reading
the beacon. Most of what follows is an attempt to cause exactly that.
"""
from __future__ import annotations

import hashlib
import hmac

import pytest

from qknot.signing.entropy.backends import QrngUnavailable, SystemEntropyBackend, commit
from qknot.signing.entropy.beacon import BEACON_PULSE_BYTES, BeaconPulse, NistBeaconBackend
from qknot.signing.entropy.mixing import (
    KDF_NAME,
    NoSecretEntropy,
    hkdf,
    mix_entropy,
)


class FakePublicBeacon:
    name = "nist-beacon"
    is_quantum = True
    is_public = True

    def __init__(self, value: bytes | None = None, fail: bool = False):
        self.value = value or bytes(range(64))
        self.fail = fail

    def get_bytes(self, n):
        if self.fail:
            raise QrngUnavailable("beacon down")
        return self.value[:n]

    def describe(self):
        return {
            "endpoint": "https://beacon.nist.gov/beacon/2.0",
            "is_public": True,
            "not_before": "2026-07-26T09:00:00.000Z",
            "pulse": {"pulse_index": 12345, "chain_index": 1,
                      "output_value": self.value.hex()},
        }


class FakeSecretQuantum:
    name = "anu"
    is_quantum = True
    is_public = False

    def __init__(self, fail: bool = False):
        self.fail = fail

    def get_bytes(self, n):
        if self.fail:
            raise QrngUnavailable("anu down")
        return b"\xa5" * n

    def describe(self):
        return {"endpoint": "https://api.quantumnumbers.anu.edu.au", "authenticated": True}


# ===========================================================================
# The catastrophic case
# ===========================================================================
class TestPublicRandomnessCannotBecomeAKey:
    def test_beacon_alone_is_refused(self):
        """The whole point. A seed from public values is public."""
        with pytest.raises(NoSecretEntropy, match="public"):
            mix_entropy([FakePublicBeacon()], n_bytes=32)

    def test_many_beacons_are_still_refused(self):
        """Stacking public sources adds no secrecy."""
        with pytest.raises(NoSecretEntropy):
            mix_entropy([FakePublicBeacon(bytes(range(64))),
                         FakePublicBeacon(bytes(range(64, 128)))], n_bytes=32)

    def test_refusal_when_every_secret_source_fails(self):
        with pytest.raises(NoSecretEntropy):
            mix_entropy([FakeSecretQuantum(fail=True), FakePublicBeacon()], n_bytes=32)

    def test_seed_is_not_derivable_from_public_material_alone(self):
        """An attacker holding the beacon value must not reach the seed."""
        beacon = FakePublicBeacon()
        result = mix_entropy([SystemEntropyBackend(), beacon], n_bytes=32)
        attacker_guess = hkdf(ikm=beacon.value, salt=beacon.value,
                              info=b"qknot-signing-seed-v1|", length=32)
        assert result.seed != attacker_guess

    def test_beacon_refuses_to_serve_key_sized_requests(self):
        """Asking a public beacon for 256 bytes means someone has
        misunderstood what it is for."""
        with pytest.raises(ValueError, match="HKDF salt"):
            NistBeaconBackend().get_bytes(256)


# ===========================================================================
# Mixing strengthens, never weakens
# ===========================================================================
class TestMixingNeverWeakens:
    def test_adding_a_compromised_source_does_not_reveal_the_seed(self):
        """A source returning constant bytes must not make the seed guessable
        while a good source is present."""
        class Compromised:
            name, is_quantum, is_public = "evil", True, False

            def get_bytes(self, n):
                return b"\x00" * n

            def describe(self):
                return {}

        seeds = {mix_entropy([SystemEntropyBackend(), Compromised()], n_bytes=32).seed
                 for _ in range(20)}
        assert len(seeds) == 20, "system entropy must still dominate unpredictability"

    def test_seed_changes_when_any_secret_input_changes(self):
        a = mix_entropy([SystemEntropyBackend()], n_bytes=32).seed
        b = mix_entropy([SystemEntropyBackend()], n_bytes=32).seed
        assert a != b

    def test_context_separates_seeds(self):
        """Same sources, different purpose, different seed."""
        class Fixed:
            name, is_quantum, is_public = "fixed", False, False

            def get_bytes(self, n):
                return b"\x11" * n

            def describe(self):
                return {}

        keygen = mix_entropy([Fixed()], n_bytes=32, context=b"ml-dsa-44-keygen").seed
        nonce = mix_entropy([Fixed()], n_bytes=32, context=b"nonce").seed
        assert keygen != nonce, (
            "one compromised seed must not compromise another purpose"
        )

    def test_unavailable_source_is_recorded_not_fatal(self):
        result = mix_entropy(
            [SystemEntropyBackend(), FakeSecretQuantum(fail=True)], n_bytes=32)
        assert any("anu_unavailable" in n for n in result.attestation.notes)
        assert len(result.seed) == 32


# ===========================================================================
# The attestation must describe what actually happened
# ===========================================================================
class TestAttestationHonesty:
    def test_public_source_is_not_counted_as_quantum_seeding(self):
        """A beacon is quantum and contributes no unpredictability. Counting it
        as quantum seeding would let a key claim physical randomness while
        every secret bit came from the system CSPRNG."""
        att = mix_entropy([SystemEntropyBackend(), FakePublicBeacon()],
                          n_bytes=32).attestation
        assert "nist-beacon" in att.quantum_contributors
        assert att.is_quantum_seeded is False, (
            "public quantum randomness must not count as quantum seeding"
        )

    def test_secret_quantum_source_does_count(self):
        att = mix_entropy([SystemEntropyBackend(), FakeSecretQuantum()],
                          n_bytes=32).attestation
        assert att.is_quantum_seeded is True

    def test_secret_contributions_never_publish_their_bytes(self):
        att = mix_entropy([SystemEntropyBackend(), FakeSecretQuantum()],
                          n_bytes=32).attestation
        for contribution in att.contributions:
            if contribution.role == "secret":
                assert contribution.public_value is None, (
                    "a secret source must never have its bytes recorded"
                )

    def test_public_contribution_publishes_its_value_for_checking(self):
        beacon = FakePublicBeacon()
        att = mix_entropy([SystemEntropyBackend(), beacon], n_bytes=32).attestation
        public = [c for c in att.contributions if c.role == "public"][0]
        assert public.public_value == beacon.value.hex()
        assert public.reference["pulse_index"] == 12345

    def test_only_public_sources_are_externally_verifiable(self):
        att = mix_entropy([SystemEntropyBackend(), FakeSecretQuantum(),
                           FakePublicBeacon()], n_bytes=32).attestation
        assert att.verifiable_contributors == ["nist-beacon"]
        assert "system" not in att.verifiable_contributors
        assert "anu" not in att.verifiable_contributors

    def test_beacon_supplies_a_timestamp_lower_bound(self):
        att = mix_entropy([SystemEntropyBackend(), FakePublicBeacon()],
                          n_bytes=32).attestation
        assert att.not_before == "2026-07-26T09:00:00.000Z", (
            "a key derived from pulse N cannot predate pulse N"
        )

    def test_no_beacon_means_no_timestamp_claim(self):
        att = mix_entropy([SystemEntropyBackend()], n_bytes=32).attestation
        assert att.not_before is None, (
            "without a beacon there is no evidence about creation time"
        )


class TestAttestExplicitSeed:
    """Registerable keys (sign --seed) still carry honest time evidence."""

    def test_without_beacon_still_commits_to_the_seed(self):
        from qknot.signing.entropy.mixing import attest_explicit_seed

        seed = b"\x5a" * 32
        att = attest_explicit_seed(seed, use_beacon=False)
        assert att.verify_commitment(seed)
        assert att.not_before is None
        assert att.contributions[0].backend == "explicit-seed"
        assert not att.is_quantum_seeded

    def test_key_material_is_not_mixed_with_public_witness(self):
        """Reproducibility: the same seed must produce the same keys whether
        or not a beacon pulse was recorded beside them."""
        from qknot.signing.entropy.mixing import attest_explicit_seed
        from qknot.signing.sign import keygen

        seed = b"\x42" * 32
        a = keygen(suite=["ed25519"], seed=seed,
                   entropy_attestation=attest_explicit_seed(seed, use_beacon=False))
        b = keygen(suite=["ed25519"], seed=seed, entropy_attestation=None)
        assert a.keys["ed25519"].public_key == b.keys["ed25519"].public_key
        assert a.entropy_attestation is not None
        assert b.entropy_attestation is None

    def test_fixed_ceremony_time_is_byte_stable(self):
        """--deterministic needs two attestations of the same seed to match."""
        from datetime import datetime, timezone

        from qknot.signing.entropy.mixing import attest_explicit_seed

        seed = b"\x11" * 32
        fixed = datetime(1970, 1, 1, tzinfo=timezone.utc)
        a = attest_explicit_seed(seed, use_beacon=False, ceremony_time=fixed)
        b = attest_explicit_seed(seed, use_beacon=False, ceremony_time=fixed)
        assert a.to_dict() == b.to_dict()

    def test_commitment_binds_the_derived_seed(self):
        result = mix_entropy([SystemEntropyBackend()], n_bytes=32)
        assert result.attestation.verify_commitment(result.seed)
        assert not result.attestation.verify_commitment(b"\x00" * 32)

    def test_attestation_serialises(self):
        import json
        att = mix_entropy([SystemEntropyBackend(), FakePublicBeacon()],
                          n_bytes=32).attestation
        assert json.loads(att.to_json())["kdf"] == KDF_NAME

    def test_attestation_is_immutable(self):
        import dataclasses
        att = mix_entropy([SystemEntropyBackend()], n_bytes=32).attestation
        with pytest.raises(dataclasses.FrozenInstanceError):
            att.commitment = "tampered"


# ===========================================================================
# HKDF correctness
# ===========================================================================
class TestHkdf:
    def test_matches_rfc5869_construction(self):
        ikm, salt, info = b"\x0b" * 22, b"\x00" * 13, b"\xf0\xf1"
        prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
        expected = hmac.new(prk, b"" + info + bytes([1]), hashlib.sha3_256).digest()[:16]
        assert hkdf(ikm, salt, info, 16) == expected

    def test_output_length_is_exact(self):
        for n in (1, 16, 32, 64, 255 * 32):
            assert len(hkdf(b"ikm", b"salt", b"info", n)) == n

    def test_refuses_impossible_lengths(self):
        with pytest.raises(ValueError):
            hkdf(b"i", b"s", b"n", 0)
        with pytest.raises(ValueError, match="expand beyond"):
            hkdf(b"i", b"s", b"n", 255 * 32 + 1)

    def test_salt_changes_the_output(self):
        a = hkdf(b"ikm", b"salt-a", b"info", 32)
        b = hkdf(b"ikm", b"salt-b", b"info", 32)
        assert a != b, "the beacon salt must actually influence the seed"

    def test_uses_sha3_not_sha2(self):
        sha2 = hmac.new(b"salt", b"ikm", hashlib.sha256).digest()
        assert hkdf(b"ikm", b"salt", b"", 32) != sha2

    def test_is_deterministic(self):
        assert hkdf(b"i", b"s", b"n", 32) == hkdf(b"i", b"s", b"n", 32)


# ===========================================================================
# Beacon plumbing
# ===========================================================================
class TestBeaconBackend:
    def _session(self, payload, status=200):
        class R:
            status_code = status

            @staticmethod
            def json():
                return payload

        class S:
            def __init__(self):
                self.urls = []

            def get(self, url, **kw):
                self.urls.append(url)
                return R()
        return S()

    def _pulse_payload(self, value: str | None = None):
        return {"pulse": {
            "chainIndex": 1, "pulseIndex": 999,
            "timeStamp": "2026-07-26T09:00:00.000Z",
            "outputValue": value or ("ab" * BEACON_PULSE_BYTES),
            "signatureValue": "de" * 128,
            "uri": "https://beacon.nist.gov/beacon/2.0/chain/1/pulse/999",
            "certificateId": "cc" * 32,
        }}

    def test_parses_a_pulse(self):
        backend = NistBeaconBackend(session=self._session(self._pulse_payload()))
        pulse = backend.fetch_pulse()
        assert pulse.pulse_index == 999
        assert len(pulse.value) == BEACON_PULSE_BYTES

    def test_rejects_a_wrong_length_pulse(self):
        backend = NistBeaconBackend(session=self._session(self._pulse_payload("abcd")))
        with pytest.raises(QrngUnavailable, match="bytes"):
            backend.fetch_pulse()

    def test_rejects_a_pulse_missing_its_signature(self):
        payload = self._pulse_payload()
        del payload["pulse"]["signatureValue"]
        with pytest.raises(QrngUnavailable, match="missing fields"):
            NistBeaconBackend(session=self._session(payload)).fetch_pulse()

    def test_non_json_response_is_handled(self):
        backend = NistBeaconBackend(session=self._session([1, 2, 3]))
        with pytest.raises(QrngUnavailable, match="JSON object"):
            backend.fetch_pulse()

    def test_specific_pulse_index_is_requested_for_reproducibility(self):
        session = self._session(self._pulse_payload())
        NistBeaconBackend(session=session, pulse_index=999).fetch_pulse()
        assert "/chain/1/pulse/999" in session.urls[0], (
            "a published result must be re-derivable from its pulse index"
        )

    def test_reference_lets_a_third_party_recheck(self):
        backend = NistBeaconBackend(session=self._session(self._pulse_payload()))
        backend.fetch_pulse()
        ref = backend.describe()["pulse"]
        assert ref["verify_url"].endswith("/chain/1/pulse/999")
        assert ref["output_value"] and ref["signature_value"]

    def test_signature_verification_is_an_honest_stub(self):
        """It must not silently claim to have verified anything."""
        from qknot.signing.entropy.beacon import verify_pulse_signature
        pulse = BeaconPulse(1, 1, "t", "ab" * 64, "sig", "uri")
        with pytest.raises(NotImplementedError, match="verifier can check it"):
            verify_pulse_signature(pulse, b"")

    def test_commitment_helper_is_shared_with_the_backends_module(self):
        assert commit(b"x") == commit(b"x")


class TestBackendBugsAreNotSwallowedAsUnavailability:
    """`except Exception` on the source loop hid programming errors.

    A typo inside a backend's get_bytes would have been logged as "source
    unavailable" and skipped. For SystemEntropyBackend -- the one source the
    design assumes never fails -- that means the seed silently falls to a
    network source, or NoSecretEntropy is raised naming the wrong culprit.
    """

    class _BuggyBackend:
        name = "buggy"
        is_quantum = False
        is_public = False

        def get_bytes(self, n):
            raise AttributeError("typo in the backend, not an outage")

        def describe(self):
            return {}

    class _OfflineBackend:
        name = "offline"
        is_quantum = False
        is_public = False

        def get_bytes(self, n):
            raise ConnectionError("network is down")

        def describe(self):
            return {}

    def test_a_programming_error_propagates(self):
        from qknot.signing.entropy.mixing import mix_entropy

        with pytest.raises(AttributeError, match="typo in the backend"):
            mix_entropy([self._BuggyBackend()], n_bytes=32)

    def test_a_genuine_outage_is_still_skipped(self):
        """The behaviour that must survive the narrowing: real unavailability
        is recorded and tolerated, not raised."""
        from qknot.signing.entropy.backends import SystemEntropyBackend
        from qknot.signing.entropy.mixing import mix_entropy

        result = mix_entropy(
            [SystemEntropyBackend(), self._OfflineBackend()], n_bytes=32
        )
        assert len(result.seed) == 32
        assert any("offline_unavailable" in n for n in result.attestation.notes)
