"""Tests for qresp.parse — extracting algorithms from signature bytes."""
from __future__ import annotations

import pytest

from qresp.audit.model import SigAlgorithm, SigFormat
from qresp.audit.parse import (
    parse_gpg,
    parse_in_toto,
    parse_signature,
    parse_sigstore,
)

from .fixtures_models import (
    _make_gpg_ed25519_packet,
    _make_in_toto_envelope,
    _make_sigstore_bundle_with_cert,
    _make_sigstore_bundle_with_rsa_spki,
)


class TestSigstoreParser:
    def test_fulcio_cert_bundle_is_ecdsa_p256(self):
        result = parse_sigstore(_make_sigstore_bundle_with_cert())
        assert result.algorithm == SigAlgorithm.ECDSA_P256
        assert "fulcio" in (result.notes or "").lower()

    def test_rsa_spki_bundle_detects_rsa_2048(self):
        result = parse_sigstore(_make_sigstore_bundle_with_rsa_spki())
        # The estimator should round-trip to RSA_2048 from our 2048-bit modulus
        assert result.algorithm == SigAlgorithm.RSA_2048
        assert result.key_size_bits is not None
        assert 2000 <= result.key_size_bits <= 2080

    def test_corrupted_json_returns_unknown(self):
        result = parse_sigstore(b"this is not JSON")
        assert result.algorithm == SigAlgorithm.UNKNOWN
        assert "json" in (result.notes or "").lower()

    def test_missing_verification_material(self):
        result = parse_sigstore(b'{"mediaType":"x","other":"stuff"}')
        assert result.algorithm == SigAlgorithm.UNKNOWN
        assert "verification" in (result.notes or "").lower()


class TestGpgParser:
    def test_ed25519_packet_detected(self):
        result = parse_gpg(_make_gpg_ed25519_packet())
        assert result.algorithm == SigAlgorithm.ED25519

    def test_truncated_packet_returns_unknown(self):
        result = parse_gpg(b"\xc2\x03")
        assert result.algorithm == SigAlgorithm.UNKNOWN

    def test_random_bytes_return_unknown(self):
        result = parse_gpg(b"this is not a PGP packet at all")
        assert result.algorithm == SigAlgorithm.UNKNOWN


class TestInTotoParser:
    def test_intoto_envelope_with_fulcio_cert(self):
        result = parse_in_toto(_make_in_toto_envelope())
        assert result.algorithm == SigAlgorithm.ECDSA_P256
        assert "fulcio" in (result.notes or "").lower()

    def test_intoto_corrupted_json(self):
        result = parse_in_toto(b"definitely not json")
        assert result.algorithm == SigAlgorithm.UNKNOWN

    def test_intoto_no_signatures(self):
        result = parse_in_toto(b'{"payload":"","signatures":[]}')
        assert result.algorithm == SigAlgorithm.UNKNOWN


class TestDispatch:
    @pytest.mark.parametrize(
        "fmt,raw,expected",
        [
            (SigFormat.SIGSTORE, _make_sigstore_bundle_with_cert(), SigAlgorithm.ECDSA_P256),
            (SigFormat.IN_TOTO, _make_in_toto_envelope(), SigAlgorithm.ECDSA_P256),
            (SigFormat.GPG, _make_gpg_ed25519_packet(), SigAlgorithm.ED25519),
        ],
    )
    def test_dispatch_routes_correctly(self, fmt: SigFormat, raw: bytes, expected: SigAlgorithm):
        result = parse_signature(raw, fmt)
        assert result.algorithm == expected

    def test_custom_format_falls_back_to_sigstore_then_gpg(self):
        # JSON-shaped sigstore bundle handed in as CUSTOM should still be parsed
        sig = _make_sigstore_bundle_with_cert()
        result = parse_signature(sig, SigFormat.CUSTOM)
        assert result.algorithm == SigAlgorithm.ECDSA_P256

    def test_custom_format_gpg_fallback(self):
        sig = _make_gpg_ed25519_packet()
        result = parse_signature(sig, SigFormat.CUSTOM)
        assert result.algorithm == SigAlgorithm.ED25519
