"""Tests for the QRNG backend and entropy attestation.

The property under test throughout is that the attestation cannot lie: whatever
path the entropy took, the record says so. A test suite that only checked the
happy path would miss the failure this module exists to make visible.
"""
from __future__ import annotations

import dataclasses
import json

import pytest

from qknot.signing.entropy import (
    COMMITMENT_DOMAIN,
    DEFAULT_BACKEND,
    DEFAULT_ON_FAILURE,
    AnuQrngBackend,
    EntropyAttestation,
    OnFailure,
    QrngUnavailable,
    SystemEntropyBackend,
    commit,
    get_backend,
    get_entropy,
)


class FakeQuantumBackend:
    """A quantum backend that fails a chosen number of times, then succeeds."""

    name = "anu"
    is_quantum = True

    def __init__(self, fail_times: int = 0, payload: bytes | None = None):
        self.fail_times = fail_times
        self.calls = 0
        self.payload = payload or bytes(range(32))

    def get_bytes(self, n: int) -> bytes:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise QrngUnavailable("simulated outage")
        return self.payload[:n]

    def describe(self) -> dict:
        return {"endpoint": "https://example.invalid", "authenticated": True}


class TestCommitment:
    def test_commitment_is_domain_separated(self):
        import hashlib
        raw = b"\x01" * 32
        assert commit(raw) == hashlib.sha3_256(COMMITMENT_DOMAIN + raw).hexdigest()
        assert commit(raw) != hashlib.sha3_256(raw).hexdigest(), (
            "a bare hash could be replayed as a commitment in another protocol"
        )

    def test_commitment_uses_sha3_not_sha2(self):
        import hashlib
        raw = b"\x02" * 32
        assert commit(raw) != hashlib.sha256(COMMITMENT_DOMAIN + raw).hexdigest()

    def test_commitment_binds_to_specific_entropy(self):
        assert commit(b"\x00" * 32) != commit(b"\x00" * 31 + b"\x01")

    def test_commitment_does_not_reveal_entropy(self):
        """A commitment is published; the seed is not. It must not contain it."""
        raw = b"\xab" * 32
        assert raw.hex() not in commit(raw)


class TestSystemBackend:
    def test_returns_requested_length(self):
        assert len(SystemEntropyBackend().get_bytes(48)) == 48

    def test_is_not_marked_quantum(self):
        assert SystemEntropyBackend().is_quantum is False

    def test_attestation_reports_classical_origin(self):
        result = get_entropy(32, backend="system")
        assert result.attestation.backend == "system"
        assert result.attestation.is_quantum is False
        assert result.attestation.fallback_used is False


class TestFallbackIsRecorded:
    """The central guarantee: a downgrade is never silent."""

    def test_fallback_marks_the_attestation(self):
        backend = FakeQuantumBackend(fail_times=99)
        result = get_entropy(
            32, on_failure=OnFailure.FALLBACK, interactive=False,
            _backend_obj=backend, _sleep=lambda _: None,
        )
        att = result.attestation
        assert att.fallback_used is True
        assert att.backend == "system", "the backend that actually served the bytes"
        assert att.requested_backend == "anu", "the backend that was asked for"
        assert att.is_quantum is False, (
            "a PRNG-fallback key must never claim quantum provenance"
        )

    def test_fallback_note_states_the_consequence_plainly(self):
        result = get_entropy(
            32, on_failure=OnFailure.FALLBACK, interactive=False,
            _backend_obj=FakeQuantumBackend(fail_times=99), _sleep=lambda _: None,
        )
        joined = " ".join(result.attestation.notes)
        assert "NOT of quantum origin" in joined

    def test_successful_quantum_draw_is_marked_quantum(self):
        result = get_entropy(
            32, interactive=False, _backend_obj=FakeQuantumBackend(fail_times=0),
        )
        assert result.attestation.is_quantum is True
        assert result.attestation.fallback_used is False

    def test_verifier_can_distinguish_the_two_cases(self):
        """The requirement from the memo, stated as a test."""
        quantum = get_entropy(
            32, interactive=False, _backend_obj=FakeQuantumBackend(fail_times=0)
        ).attestation
        classical = get_entropy(
            32, on_failure=OnFailure.FALLBACK, interactive=False,
            _backend_obj=FakeQuantumBackend(fail_times=99), _sleep=lambda _: None,
        ).attestation
        assert quantum.is_quantum and not classical.is_quantum
        assert quantum.to_dict() != classical.to_dict()

    def test_transient_failure_recovers_without_fallback(self):
        backend = FakeQuantumBackend(fail_times=2)
        result = get_entropy(
            32, interactive=False, max_attempts=5,
            _backend_obj=backend, _sleep=lambda _: None,
        )
        assert result.attestation.fallback_used is False
        assert backend.calls == 3
        assert any("attempt_1_failed" in n for n in result.attestation.notes), (
            "a recovered outage should still leave a trace"
        )


class TestFailurePolicies:
    def test_abort_raises(self):
        with pytest.raises(QrngUnavailable, match="policy is abort"):
            get_entropy(
                32, on_failure=OnFailure.ABORT, interactive=False,
                _backend_obj=FakeQuantumBackend(fail_times=99), _sleep=lambda _: None,
            )

    def test_wait_retries_until_success(self):
        backend = FakeQuantumBackend(fail_times=4)
        result = get_entropy(
            32, on_failure=OnFailure.WAIT, interactive=False, max_attempts=2,
            _backend_obj=backend, _sleep=lambda _: None,
        )
        assert result.attestation.fallback_used is False
        assert backend.calls == 5, "WAIT must not give up at max_attempts"

    def test_default_policy_is_fallback(self):
        assert DEFAULT_ON_FAILURE is OnFailure.FALLBACK

    def test_an_operator_who_picks_fallback_is_not_retried(self, monkeypatch):
        monkeypatch.setattr(
            "qknot.signing.entropy.backends._prompt",
            lambda attempt, error: OnFailure.FALLBACK,
        )
        delays: list[float] = []
        result = get_entropy(
            4, interactive=True, max_attempts=3,
            _backend_obj=FakeQuantumBackend(fail_times=99),
            _sleep=delays.append,
        )
        assert result.attestation.fallback_used is True
        assert delays == []

    def test_default_backend_is_anu(self):
        assert DEFAULT_BACKEND == "anu"

    def test_backoff_is_applied_between_attempts(self):
        delays = []
        get_entropy(
            32, interactive=False, max_attempts=3, backoff=2.0,
            _backend_obj=FakeQuantumBackend(fail_times=2),
            _sleep=delays.append,
        )
        assert delays == [2.0, 4.0], f"expected exponential backoff, got {delays}"


class TestAnuBackend:
    def test_uses_keyed_endpoint_when_key_present(self):
        b = AnuQrngBackend(api_key="secret")
        assert "quantumnumbers" in b.endpoint
        assert b.deprecated is False
        assert b.describe()["authenticated"] is True

    def test_falls_back_to_legacy_endpoint_without_key(self, monkeypatch):
        monkeypatch.delenv("ANU_API_KEY", raising=False)
        b = AnuQrngBackend()
        assert "jsonI.php" in b.endpoint
        assert b.deprecated is True, (
            "the unauthenticated endpoint is being retired and the attestation "
            "must say so"
        )

    def test_deprecation_surfaces_in_the_attestation(self, monkeypatch):
        monkeypatch.delenv("ANU_API_KEY", raising=False)

        class Recording(AnuQrngBackend):
            def get_bytes(self, n):
                return b"\x07" * n

        result = get_entropy(32, interactive=False, _backend_obj=Recording())
        assert result.attestation.endpoint_deprecated is True

    def test_chunks_requests_at_the_api_limit(self):
        """ANU caps a response at 1024 items, so a larger draw needs several."""
        class FakeSession:
            def __init__(self):
                self.requested = []

            def get(self, url, params, headers, timeout):
                self.requested.append(params["length"])

                class R:
                    status_code = 200

                    @staticmethod
                    def json():
                        return {"success": True, "data": [1] * params["length"]}
                return R()

        session = FakeSession()
        backend = AnuQrngBackend(api_key="k", session=session)
        raw = backend.get_bytes(2500)
        assert len(raw) == 2500
        assert session.requested == [1024, 1024, 452]

    def test_rejects_short_response(self):
        class FakeSession:
            def get(self, url, params, headers, timeout):
                class R:
                    status_code = 200

                    @staticmethod
                    def json():
                        return {"success": True, "data": [1, 2, 3]}
                return R()

        with pytest.raises(QrngUnavailable, match="items"):
            AnuQrngBackend(api_key="k", session=FakeSession()).get_bytes(32)

    def test_rejects_out_of_range_values(self):
        class FakeSession:
            def get(self, url, params, headers, timeout):
                class R:
                    status_code = 200

                    @staticmethod
                    def json():
                        return {"success": True, "data": [999] * params["length"]}
                return R()

        with pytest.raises(QrngUnavailable, match="uint8"):
            AnuQrngBackend(api_key="k", session=FakeSession()).get_bytes(8)

    def test_401_explains_the_migration(self):
        class FakeSession:
            def get(self, url, params, headers, timeout):
                class R:
                    status_code = 401
                return R()

        with pytest.raises(QrngUnavailable, match="ANU_API_KEY"):
            AnuQrngBackend(api_key="bad", session=FakeSession()).get_bytes(8)


class TestAttestationRecord:
    def test_round_trips_through_json(self):
        att = get_entropy(32, backend="system").attestation
        assert json.loads(att.to_json()) == att.to_dict()

    def test_verify_commitment_accepts_the_right_entropy(self):
        result = get_entropy(32, backend="system")
        assert result.attestation.verify_commitment(result.raw)

    def test_verify_commitment_rejects_other_entropy(self):
        result = get_entropy(32, backend="system")
        assert not result.attestation.verify_commitment(b"\x00" * 32)

    def test_attestation_is_immutable(self):
        """Frozen, because an attestation that can be edited after the fact
        attests to nothing."""
        att = get_entropy(32, backend="system").attestation
        with pytest.raises(dataclasses.FrozenInstanceError):
            att.backend = "anu"  # type: ignore[misc]

    def test_records_the_requested_length(self):
        assert get_entropy(64, backend="system").attestation.n_bytes == 64


class TestBackendRegistry:
    @pytest.mark.parametrize("name", ["anu", "system", "ibm", "usb"])
    def test_all_backends_resolvable(self, name):
        assert get_backend(name) is not None

    def test_unknown_backend_lists_the_valid_ones(self):
        with pytest.raises(ValueError, match="anu"):
            get_backend("nope")

    def test_only_quantum_backends_claim_quantum(self):
        assert get_backend("system").is_quantum is False
        for name in ("anu", "ibm", "usb"):
            assert get_backend(name).is_quantum is True


class TestIbmAndUsbAreReal:
    def test_von_neumann_drops_matching_pairs(self):
        from qknot.signing.entropy.backends import von_neumann_extract
        assert von_neumann_extract([0, 1, 1, 0, 0, 0, 1, 1]) == [1, 0]

    def test_ibm_without_a_token_names_the_token(self, monkeypatch):
        from qknot.signing.entropy.backends import IbmQuantumBackend
        monkeypatch.delenv("IBM_QUANTUM_TOKEN", raising=False)
        monkeypatch.delenv("QISKIT_IBM_TOKEN", raising=False)
        with pytest.raises(QrngUnavailable, match="IBM_QUANTUM_TOKEN"):
            IbmQuantumBackend().get_bytes(2)

    def test_ibm_extracts_bytes_from_supplied_bits(self):
        from qknot.signing.entropy.backends import IbmQuantumBackend
        backend = IbmQuantumBackend(measure=lambda n: [0, 1] * n)
        assert backend.get_bytes(2) == b"\xff\xff"
        described = backend.describe()
        assert described["extractor"] == "von-neumann"
        assert described["authenticated"] is True

    def test_a_stuck_ibm_source_does_not_return_bytes(self):
        from qknot.signing.entropy.backends import IbmQuantumBackend
        backend = IbmQuantumBackend(measure=lambda n: [1] * n)
        with pytest.raises(QrngUnavailable, match="von Neumann"):
            backend.get_bytes(1)

    def test_a_missing_ibm_extra_names_the_install(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "qiskit" or name.startswith("qiskit"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)
        from qknot.signing.entropy.backends import IbmQuantumBackend
        with pytest.raises(QrngUnavailable, match="qrng-ibm"):
            IbmQuantumBackend(token="present").get_bytes(1)

    def test_sampler_bitstrings_are_read_in_order(self):
        from qknot.signing.entropy.backends import _bits_from_sampler

        class Register:
            def get_bitstrings(self):
                return ["01", "10"]

        class Data:
            meas = Register()

        class Pub:
            data = Data()

        assert _bits_from_sampler(Pub()) == [0, 1, 1, 0]

    def test_usb_reads_the_device(self, tmp_path):
        from qknot.signing.entropy.backends import UsbQrngBackend
        device = tmp_path / "qrng"
        device.write_bytes(b"\x10\x20\x30\x40")
        assert UsbQrngBackend(str(device)).get_bytes(4) == b"\x10\x20\x30\x40"

    def test_usb_rejects_a_missing_device(self, tmp_path):
        from qknot.signing.entropy.backends import UsbQrngBackend
        with pytest.raises(QrngUnavailable, match="not found"):
            UsbQrngBackend(str(tmp_path / "missing")).get_bytes(4)

    def test_usb_rejects_constant_output(self, tmp_path):
        from qknot.signing.entropy.backends import UsbQrngBackend
        device = tmp_path / "stuck"
        device.write_bytes(b"\x00\x00\x00\x00")
        with pytest.raises(QrngUnavailable, match="health check"):
            UsbQrngBackend(str(device)).get_bytes(4)


def test_attestation_dataclass_fields_are_stable():
    """The attestation becomes a signed predicate in the Task 5 bundle, so its
    field names are part of a wire format, not an implementation detail."""
    expected = {
        "backend", "requested_backend", "fallback_used", "n_bytes", "timestamp",
        "commitment", "commitment_algorithm", "endpoint", "endpoint_deprecated",
        "authenticated", "notes",
    }
    assert set(EntropyAttestation.__dataclass_fields__) == expected
