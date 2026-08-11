"""Tests for the OpenPGP offset fix and headerless-signature classification.

Both were written after the 20k audit found real signatures in the wild that
the parser could not classify. The PGP tests in particular encode a bug that
had silently made every modern OpenPGP signature unparseable.
"""
from __future__ import annotations

import pytest

from qknot.audit.model import QLabel, SigAlgorithm, SigFormat, classify_algorithm
from qknot.audit.parse import parse_gpg, parse_raw_signature, parse_signature


def v4_signature_packet(pubkey_algo: int, hash_algo: int = 8) -> bytes:
    """A minimal, correctly framed OpenPGP v4 signature packet.

    RFC 4880 section 5.2.3: version, signature type, public-key algorithm,
    hash algorithm, then two-octet hashed subpacket length.
    """
    body = bytes([4, 0x00, pubkey_algo, hash_algo, 0x00, 0x00]) + b"\x00" * 16
    return bytes([0xC2, len(body)]) + body


def v3_signature_packet(pubkey_algo: int, hash_algo: int = 8) -> bytes:
    """RFC 4880 section 5.2.2: version, hashed length (5), sig type,
    creation time (4), key id (8), public-key algorithm, hash algorithm."""
    body = (
        bytes([3, 5, 0x00])
        + b"\x00" * 4
        + b"\x00" * 8
        + bytes([pubkey_algo, hash_algo])
        + b"\x00" * 8
    )
    return bytes([0x88, len(body)]) + body


class TestPgpPublicKeyAlgorithmOffset:
    """The regression that motivated the fix.

    The previous implementation read offset 3 of a v4 packet, which is the
    *hash* algorithm, not the public-key algorithm."""

    @pytest.mark.parametrize(
        "algo_id,expected",
        [
            (1, SigAlgorithm.RSA_OTHER),
            (17, SigAlgorithm.ECDSA_P256),
            (19, SigAlgorithm.ECDSA_P256),
            (22, SigAlgorithm.ED25519),
            (23, SigAlgorithm.ED25519),
            (28, SigAlgorithm.ED448),
        ],
    )
    def test_v4_public_key_algorithm_is_read_correctly(self, algo_id, expected):
        assert parse_gpg(v4_signature_packet(algo_id)).algorithm == expected

    @pytest.mark.parametrize("algo_id,expected", [(1, SigAlgorithm.RSA_OTHER),
                                                  (19, SigAlgorithm.ECDSA_P256),
                                                  (23, SigAlgorithm.ED25519)])
    def test_v3_public_key_algorithm_is_read_correctly(self, algo_id, expected):
        assert parse_gpg(v3_signature_packet(algo_id)).algorithm == expected

    def test_sha256_signature_is_not_reported_unparseable(self):
        """The exact symptom: hash id 8 is not a public-key id, so reading the
        wrong offset made every SHA-256 signature look unparseable."""
        result = parse_gpg(v4_signature_packet(pubkey_algo=1, hash_algo=8))
        assert result.algorithm == SigAlgorithm.RSA_OTHER

    def test_legacy_hash_does_not_masquerade_as_rsa(self):
        """Hash ids 1/2/3 collide with public-key ids 1/2/3. Reading the hash
        offset made an Ed25519 signature over SHA-1 report as RSA."""
        result = parse_gpg(v4_signature_packet(pubkey_algo=23, hash_algo=2))
        assert result.algorithm == SigAlgorithm.ED25519, (
            "hash algorithm must not be mistaken for the public-key algorithm"
        )

    def test_non_openpgp_input_is_rejected_cleanly(self):
        """Bit 7 is set on every packet tag. Random binary must not be coerced
        into a plausible-looking answer."""
        result = parse_gpg(b"\x5e\x21\x57\x00\x62\xc6\xaa\xfc" * 8)
        assert result.algorithm == SigAlgorithm.UNKNOWN
        assert "not_an_openpgp_packet" in (result.notes or "")

    def test_unknown_algorithm_id_is_reported_with_the_id(self):
        result = parse_gpg(v4_signature_packet(pubkey_algo=99))
        assert result.algorithm == SigAlgorithm.UNKNOWN
        assert "99" in (result.notes or "")


class TestRawSignatureLength:
    @pytest.mark.parametrize(
        "size,expected,label",
        [
            (64, SigAlgorithm.ECDSA_OTHER, QLabel.VULNERABLE),
            (256, SigAlgorithm.RSA_2048, QLabel.VULNERABLE),
            (384, SigAlgorithm.RSA_3072, QLabel.VULNERABLE),
            (512, SigAlgorithm.RSA_4096, QLabel.VULNERABLE),
            (2420, SigAlgorithm.ML_DSA_44, QLabel.SAFE),
            (3309, SigAlgorithm.ML_DSA_65, QLabel.SAFE),
            (4627, SigAlgorithm.ML_DSA_87, QLabel.SAFE),
            (7856, SigAlgorithm.SLH_DSA, QLabel.SAFE),
        ],
    )
    def test_known_sizes_classify(self, size, expected, label):
        result = parse_raw_signature(b"\x00" * size)
        assert result.algorithm == expected
        assert classify_algorithm(result.algorithm) == label

    def test_attribution_is_marked_as_inferred(self):
        """Length is weaker evidence than a parse and must say so, exactly as
        the Sigstore/Fulcio convention inference does."""
        result = parse_raw_signature(b"\x00" * 512)
        assert "inferred" in (result.notes or "")
        assert "no header" in (result.notes or "")

    def test_unrecognised_length_stays_unknown(self):
        result = parse_raw_signature(b"\x00" * 566)
        assert result.algorithm == SigAlgorithm.UNKNOWN
        assert "566" in (result.notes or "")

    def test_nbailab_rsa4096_case(self):
        """The real file: NbAiLab/borealis-270m-gguf signing/SHA256SUMS.sig is
        512 bytes of headerless RSA-4096 output alongside an X.509 chain."""
        result = parse_signature(b"\x9f" * 512, SigFormat.CUSTOM)
        assert result.algorithm == SigAlgorithm.RSA_4096
        assert classify_algorithm(result.algorithm) == QLabel.VULNERABLE

    def test_length_fallback_does_not_preempt_a_real_parse(self):
        """A well-formed PGP packet that happens to be 512 bytes must still be
        parsed as PGP rather than guessed from its size."""
        packet = v4_signature_packet(23)
        packet = packet + b"\x00" * (512 - len(packet))
        assert parse_signature(packet, SigFormat.CUSTOM).algorithm == SigAlgorithm.ED25519


class TestRealWorldArtefacts:
    """Byte-exact headers captured from the 20,000-repo audit.

    These are the cases the parser failed on in the wild, kept verbatim so the
    fix cannot regress against anything except reality.
    """

    THIREUS_TENSORS_MAP_SIG = (
        b"\x89\x023\x04\x00\x01\n\x00\x1d\x16!\x04\x98\x89\xd2\xff\xf6*\xb4'X"
        b"\xd7\x9f\x82b?\xa8\xbc\x18\xbd\x88\xdf\x05\x02j\x10\x9d[\x00\n\t\x10"
        b"b?\xa8\xbc\x18\xbd"
    )

    def test_thireus_gguf_signature_is_openpgp_rsa(self):
        """Thireus/*-SPECIAL_SPLIT tensors.map.sig, 566 bytes.

        Old-format OpenPGP packet (tag byte 0x89: tag 2, two-octet length),
        declaring a 563-byte body, v4, public-key algorithm 1 (RSA), hash
        algorithm 10 (SHA-512).

        This is the exact file the old scan-for-a-version-byte approach failed
        on: it located version 4 at offset 3, then read offset 6, which holds
        the SHA-512 hash id, and reported no_recognised_pgp_algo_byte.
        """
        raw = self.THIREUS_TENSORS_MAP_SIG
        assert raw[0] == 0x89
        assert int.from_bytes(raw[1:3], "big") + 3 == 566, "header + body = file size"

        result = parse_gpg(raw)
        assert result.algorithm == SigAlgorithm.RSA_OTHER
        assert classify_algorithm(result.algorithm) == QLabel.VULNERABLE

    def test_thireus_signature_via_custom_dispatch(self):
        """A bare `.sig` routes through CUSTOM, so the whole fallback chain
        must reach the same answer, not stop at the length heuristic."""
        result = parse_signature(self.THIREUS_TENSORS_MAP_SIG, SigFormat.CUSTOM)
        assert result.algorithm == SigAlgorithm.RSA_OTHER
        assert "inferred_from_raw_signature_length" not in (result.notes or ""), (
            "a real parse must take precedence over the length heuristic"
        )

    def test_old_format_two_octet_length_is_handled(self):
        """Regression on the framing itself: tag byte 0x89 means old format
        with a two-octet length, so the body starts at offset 3."""
        from qknot.audit.parse import _pgp_packet_body
        body = _pgp_packet_body(self.THIREUS_TENSORS_MAP_SIG)
        assert body is not None
        assert body[0] == 4, "version octet must be first in the body"
        assert body[2] == 1, "public-key algorithm (RSA) at body offset 2"


class TestPacketLengthBoundaries:
    """A body of exactly the minimum length used to raise IndexError.

    `len(body) < 16` guarded `body[15]`, but the note built afterwards also
    reads `body[16]`. A 16-byte body passed the guard and then indexed past the
    end. scanner.py's catch-all converted that into a `parser_crashed` record,
    so a short-but-well-formed packet was misreported as a parser bug -- and it
    broke this module's documented promise never to raise on malformed input.
    """

    @pytest.mark.parametrize("body_len", list(range(0, 20)))
    def test_v3_never_raises_at_any_length(self, body_len):
        body = bytes([3]) + bytes(body_len - 1) if body_len else b""
        parse_gpg(bytes([0x88, len(body)]) + body)

    @pytest.mark.parametrize("body_len", list(range(0, 20)))
    def test_v4_never_raises_at_any_length(self, body_len):
        body = bytes([4]) + bytes(body_len - 1) if body_len else b""
        parse_gpg(bytes([0x88, len(body)]) + body)

    def test_a_sixteen_byte_v3_body_is_reported_as_short(self):
        body = bytes([3]) + bytes(14) + bytes([19])
        result = parse_gpg(bytes([0x88, len(body)]) + body)
        assert result.notes == "pgp_v3_packet_too_short"

    def test_a_seventeen_byte_v3_body_parses(self):
        body = bytes([3]) + bytes(14) + bytes([19, 8])
        assert parse_gpg(bytes([0x88, len(body)]) + body).algorithm is SigAlgorithm.ECDSA_P256
