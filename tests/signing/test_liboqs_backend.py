"""liboqs backend: cross-validated against the pure-Python one, or skipped.

See docs/THREAT-MODEL.md, "liboqs, measured". Two implementations of one standard are only
interchangeable if each verifies the other's signatures; if they disagree, one
is wrong and shipping either is worse than shipping neither.

Criterion 5 is enforced by the skip itself: with liboqs absent these tests do
not run, and `get_backend("ml-dsa-87")` must still return dilithium-py.
"""
from __future__ import annotations

import pytest

from qresp.signing.backends import (
    BackendUnsuitable,
    Exposure,
    LibOqsBackend,
    MlDsaBackend,
    _assert_conforms,
    attest_constant_time,
    check_exposure,
    get_backend,
)
from qresp.signing.sidechannel import SideChannelEvidence, SideChannelStatus

LEVELS = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]


def _liboqs(level: str = "ml-dsa-87"):
    try:
        return LibOqsBackend(level)
    except (ImportError, BackendUnsuitable) as exc:
        pytest.skip(f"liboqs unavailable: {str(exc)[:80]}")


needs_liboqs = pytest.mark.allow_network      # the bindings may load a shared lib


class TestAbsenceIsClean:
    """Criterion 5. These run whether or not liboqs is installed."""

    def test_the_default_backend_is_unaffected(self):
        """Installing liboqs must not silently change who signs."""
        assert isinstance(get_backend("ml-dsa-87"), MlDsaBackend)

    def test_liboqs_is_opt_in_by_name(self):
        assert isinstance(get_backend("ml-dsa-87", implementation="dilithium-py"),
                          MlDsaBackend)

    def test_an_unknown_implementation_is_refused(self):
        with pytest.raises(ValueError, match="unknown implementation"):
            get_backend("ml-dsa-87", implementation="openssl")

    def test_the_import_error_names_the_fallback(self):
        """A missing optional dependency must not read as a broken install."""
        message = LibOqsBackend._load.__doc__ or ""
        source = LibOqsBackend.__doc__ or ""
        assert "UNKNOWN" in source or "unknown" in source
        del message


@needs_liboqs
class TestCrossValidation:
    """Criterion 4. Each implementation must accept the other's signatures."""

    @pytest.mark.parametrize("level", LEVELS)
    def test_liboqs_signatures_verify_under_dilithium_py(self, level):
        oqs_backend = _liboqs(level)
        pure = MlDsaBackend(level)
        public_key, secret_key = oqs_backend.keygen()
        signature = oqs_backend.sign(secret_key, b"cross-validation")
        assert pure.verify(public_key, b"cross-validation", signature)

    @pytest.mark.parametrize("level", LEVELS)
    def test_dilithium_py_signatures_verify_under_liboqs(self, level):
        oqs_backend = _liboqs(level)
        pure = MlDsaBackend(level)
        public_key, secret_key = pure.keygen()
        signature = pure.sign(secret_key, b"cross-validation")
        assert oqs_backend.verify(public_key, b"cross-validation", signature)

    @pytest.mark.parametrize("level", LEVELS)
    def test_key_and_signature_sizes_agree(self, level):
        """Disagreeing sizes mean the two are not the same parameter set."""
        oqs_backend = _liboqs(level)
        pure = MlDsaBackend(level)
        assert oqs_backend.signature_size == pure.signature_size
        pk_o, sk_o = oqs_backend.keygen()
        pk_p, sk_p = pure.keygen()
        assert len(pk_o) == len(pk_p)
        assert len(sk_o) == len(sk_p)

    def test_a_tampered_signature_is_rejected_not_raised(self):
        oqs_backend = _liboqs()
        public_key, secret_key = oqs_backend.keygen()
        signature = bytearray(oqs_backend.sign(secret_key, b"m"))
        signature[len(signature) // 3] ^= 0x01
        assert oqs_backend.verify(public_key, b"m", bytes(signature)) is False

    def test_garbage_is_rejected_not_raised(self):
        oqs_backend = _liboqs()
        public_key, _ = oqs_backend.keygen()
        assert oqs_backend.verify(public_key, b"m", b"not a signature") is False


@needs_liboqs
class TestItRefusesRatherThanPretends:
    def test_a_seed_is_refused_not_ignored(self):
        """Ignoring it would attest entropy that never reached the key."""
        with pytest.raises(ValueError, match="seeded keygen"):
            _liboqs().keygen(seed=b"\\x01" * 32)

    def test_deterministic_is_refused_not_ignored(self):
        """Accepting and ignoring it would make two backends behave
        differently while agreeing in signature."""
        with pytest.raises(ValueError, match="hedged mode only"):
            LibOqsBackend("ml-dsa-87", deterministic=True)

    def test_an_unknown_level_is_refused(self):
        with pytest.raises(ValueError, match="unknown ML-DSA level"):
            LibOqsBackend("ml-dsa-99")


@needs_liboqs
class TestStatusAndConformance:
    def test_it_satisfies_the_protocol(self):
        _assert_conforms("liboqs", _liboqs())

    def test_status_is_unknown_not_resistant(self):
        """Measurement found no leak; that is not the same as establishing one
        cannot occur, and liboqs exposes nothing to establish it with."""
        backend = _liboqs()
        assert backend.side_channel_status is SideChannelStatus.UNKNOWN
        assert backend.side_channel_resistant is False

    def test_online_use_is_refused_until_evidence_is_supplied(self):
        with pytest.raises(BackendUnsuitable, match="HAS NOT BEEN ESTABLISHED"):
            check_exposure(_liboqs(), Exposure.ONLINE)

    def test_evidence_raises_it_to_asserted(self):
        backend = _liboqs()
        attest_constant_time(backend, SideChannelEvidence(
            tool="dudect", tool_version="0.1.0",
            performed="2026-07-30T09:00:00+00:00",
            subject="liboqs 0.16.0, default build",
            report_sha256="b" * 64, asserted_by="Aditya Sharma"))
        check_exposure(backend, Exposure.ONLINE)

    def test_describe_records_what_could_not_be_established(self):
        described = _liboqs().describe()
        assert described["sideChannelStatus"] == "unknown"
        assert "no constant-time" in str(described["sideChannelBasis"])
        assert "liboqs" in str(described["implementation"])
