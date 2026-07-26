"""Hand-crafted fixtures for testing the QResP scanner.

These fixtures emulate the responses we expect from real HuggingFace models,
including all four major signature shapes plus an unsigned baseline. They let
the scanner's full pipeline be tested without network access.

Each fixture is a tuple (ModelSummary, dict[filename, bytes]) so the test
client can return matching bytes when the scanner requests them.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from qresp.audit.hf_client import ModelSummary


# ---------------------------------------------------------------------------
# Helper: build a minimal Sigstore bundle with a Fulcio-style certificate
# ---------------------------------------------------------------------------
def _make_sigstore_bundle_with_cert() -> bytes:
    """Return a JSON Sigstore bundle that looks like a keyless ECDSA-P256 sig."""
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {"rawBytes": base64.b64encode(b"FAKE-FULCIO-CERT-BYTES").decode()},
                ],
            },
            "tlogEntries": [],
        },
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": "abc123"},
            "signature": base64.b64encode(b"FAKE-SIGNATURE-BYTES").decode(),
        },
    }
    return json.dumps(bundle).encode("utf-8")


def _make_sigstore_bundle_with_rsa_spki() -> bytes:
    """A Sigstore bundle whose public key is a raw RSA-2048 SPKI."""
    # Synthetic SPKI: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { SEQUENCE { INTEGER (256 bytes), INTEGER e } } }
    # We construct just enough valid DER for the modulus-bit estimator to see 2048.
    # The estimator does not check the surrounding structure rigorously — it
    # looks for the rsaEncryption OID and then for the next INTEGER tag.
    oid_rsa = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
    null_params = b"\x05\x00"
    # Build a BIT STRING containing: 0x00 unused-bits, SEQUENCE { INTEGER modulus, INTEGER e }
    modulus = b"\x00" + b"\xab" * 256       # leading 0x00 + 256-byte (2048-bit) modulus
    modulus_tlv = b"\x02\x82\x01\x01" + modulus  # tag 0x02, long-form length 257
    exponent_tlv = b"\x02\x03\x01\x00\x01"  # INTEGER 65537
    inner_seq_body = modulus_tlv + exponent_tlv
    inner_seq = b"\x30\x82" + len(inner_seq_body).to_bytes(2, "big") + inner_seq_body
    bitstring_body = b"\x00" + inner_seq
    bitstring = b"\x03\x82" + len(bitstring_body).to_bytes(2, "big") + bitstring_body
    algid_body = oid_rsa + null_params
    algid = b"\x30" + bytes([len(algid_body)]) + algid_body
    spki_body = algid + bitstring
    spki = b"\x30\x82" + len(spki_body).to_bytes(2, "big") + spki_body

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "publicKey": {
                "rawBytes": base64.b64encode(spki).decode(),
                "keyDetails": "PKIX_RSA_PKCS1V15_2048_SHA256",
            },
        },
    }
    return json.dumps(bundle).encode("utf-8")


def _make_gpg_ed25519_packet() -> bytes:
    """A minimal binary OpenPGP signature packet declaring Ed25519 (algo 22)."""
    # Old-format header: tag=0x02 (sig), length-type 0, then version byte + body.
    # New format (RFC 9580): tag byte 0xC2, length byte, body.
    # We emit a new-format v4 signature packet:
    #   0xC2  <len>  <v=4> <sig type=0x00> <pubkey algo=22> <hash algo=8> ...
    body = bytes([
        4,        # version
        0x00,     # signature type
        22,       # public-key algorithm: Ed25519 legacy (RFC 9580 §9.1)
        8,        # hash: SHA-256
    ])
    header = bytes([0xC2, len(body)])
    return header + body


def _make_in_toto_envelope() -> bytes:
    """A minimal DSSE envelope simulating an in-toto attestation."""
    env = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(
            json.dumps({"_type": "https://in-toto.io/Statement/v1"}).encode()
        ).decode(),
        "signatures": [
            {
                "keyid": "",
                "sig": base64.b64encode(b"FAKE-SIG").decode(),
                "cert": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
            }
        ],
    }
    return json.dumps(env).encode("utf-8")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
FIXTURE_UNSIGNED = (
    ModelSummary(
        model_id="meta-llama/Llama-3-8B",
        publisher="meta-llama",
        downloads=10_000_000,
        last_modified=datetime(2025, 6, 1, tzinfo=timezone.utc),
        filenames=[
            "README.md",
            "config.json",
            "tokenizer.json",
            "model-00001-of-00004.safetensors",
            "model-00002-of-00004.safetensors",
            "model-00003-of-00004.safetensors",
            "model-00004-of-00004.safetensors",
            "model.safetensors.index.json",
        ],
    ),
    {},  # no signature bytes; the scanner should never call fetch_file
)


FIXTURE_SIGSTORE_FULCIO = (
    ModelSummary(
        model_id="example/ml-with-sigstore",
        publisher="example",
        downloads=42_000,
        last_modified=datetime(2026, 1, 10, tzinfo=timezone.utc),
        filenames=[
            "README.md",
            "config.json",
            "model.safetensors",
            "model.sig",  # OMS convention -> SIGSTORE
        ],
    ),
    {"model.sig": _make_sigstore_bundle_with_cert()},
)


FIXTURE_SIGSTORE_RSA = (
    ModelSummary(
        model_id="example/ml-with-rsa-sigstore",
        publisher="example",
        downloads=5_000,
        last_modified=datetime(2026, 2, 14, tzinfo=timezone.utc),
        filenames=[
            "README.md",
            "config.json",
            "weights.bin",
            "weights.bin.sigstore",
        ],
    ),
    {"weights.bin.sigstore": _make_sigstore_bundle_with_rsa_spki()},
)


FIXTURE_GPG_ED25519 = (
    ModelSummary(
        model_id="example/ml-with-gpg",
        publisher="example",
        downloads=1_200,
        last_modified=datetime(2025, 11, 3, tzinfo=timezone.utc),
        filenames=[
            "README.md",
            "config.json",
            "weights.pt",
            "weights.pt.asc",
        ],
    ),
    {"weights.pt.asc": _make_gpg_ed25519_packet()},
)


FIXTURE_IN_TOTO = (
    ModelSummary(
        model_id="example/ml-with-in-toto",
        publisher="example",
        downloads=900,
        last_modified=datetime(2026, 3, 22, tzinfo=timezone.utc),
        filenames=[
            "README.md",
            "config.json",
            "model.bin",
            "model.intoto.json",
        ],
    ),
    {"model.intoto.json": _make_in_toto_envelope()},
)


FIXTURE_BROKEN = (
    ModelSummary(
        model_id="example/ml-with-corrupted-sig",
        publisher="example",
        downloads=10,
        last_modified=datetime(2024, 8, 1, tzinfo=timezone.utc),
        filenames=[
            "README.md",
            "model.sig",
        ],
    ),
    {"model.sig": b"this is not valid json or a binary signature packet"},
)


ALL_FIXTURES = [
    FIXTURE_UNSIGNED,
    FIXTURE_SIGSTORE_FULCIO,
    FIXTURE_SIGSTORE_RSA,
    FIXTURE_GPG_ED25519,
    FIXTURE_IN_TOTO,
    FIXTURE_BROKEN,
]
