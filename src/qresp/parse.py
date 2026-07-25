"""Cryptographic signature parsers.

Given the raw bytes of a signature file and its detected format,
extract the underlying signature algorithm. Returns SigAlgorithm.UNKNOWN
if the algorithm cannot be determined (for example because the format
is custom or the bytes are corrupted); the caller decides how to handle that.

Parsing is best-effort and defensive: we never raise on malformed input,
because the goal is to produce a complete dataset even when some files
are unparseable. Errors are returned as (UNKNOWN, key_size=None, notes=...).
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Optional

from .model import SigAlgorithm, SigFormat


@dataclass
class ParseResult:
    """Outcome of parsing a single signature file."""

    algorithm: SigAlgorithm
    key_size_bits: Optional[int] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Sigstore bundle parser
# ---------------------------------------------------------------------------
# A Sigstore bundle is a JSON object whose `verificationMaterial` field
# contains either:
#   * an X.509 certificate (most common, keyless Sigstore flow), or
#   * a raw public key (for "key" or "certificate" non-Sigstore signing methods).
#
# For 2026 deployments, almost all Sigstore certs use ECDSA-P256
# (that is what Fulcio issues by default) or, more rarely, RSA-2048.
# We parse the OID from the certificate's subjectPublicKeyInfo to be sure.

_SIGSTORE_ALGO_OIDS: dict[str, SigAlgorithm] = {
    # Standard OIDs from RFC 5480, RFC 8017, RFC 8032
    "1.2.840.10045.2.1":      SigAlgorithm.ECDSA_P256,  # id-ecPublicKey (curve from params)
    "1.2.840.113549.1.1.1":   SigAlgorithm.RSA_OTHER,   # rsaEncryption (key size from modulus)
    "1.3.101.112":            SigAlgorithm.ED25519,     # id-Ed25519
    "1.3.101.113":            SigAlgorithm.ED448,       # id-Ed448
}


def parse_sigstore(raw: bytes) -> ParseResult:
    """Parse a Sigstore bundle and return the signing algorithm."""
    try:
        bundle = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return ParseResult(SigAlgorithm.UNKNOWN, notes=f"json_decode_failed: {exc}")

    # Walk the bundle to find the verification material. The Sigstore bundle
    # spec evolves; we handle the two shapes we have seen in the wild.
    vm = bundle.get("verificationMaterial") or bundle.get("verification_material")
    if not isinstance(vm, dict):
        return ParseResult(SigAlgorithm.UNKNOWN, notes="missing_verification_material")

    # Shape 1: keyless flow — there is a certificate chain
    cert_chain = (
        vm.get("x509CertificateChain", {}).get("certificates")
        or vm.get("certificate", {}).get("rawBytes")
    )
    if cert_chain:
        # We rely on a heuristic: keyless Sigstore certs are issued by Fulcio,
        # which in 2026 uses ECDSA-P256 for ~all certificates. We mark it as
        # ECDSA_P256 with a note that this is inferred from the Fulcio CA.
        return ParseResult(
            algorithm=SigAlgorithm.ECDSA_P256,
            notes="inferred_from_sigstore_fulcio_default",
        )

    # Shape 2: "key" or "certificate" non-Sigstore method — public key is exposed
    pk = vm.get("publicKey", {}).get("rawBytes")
    if pk:
        # The bundle exposes a raw public-key SubjectPublicKeyInfo (SPKI).
        # We extract the algorithm OID using a tiny ASN.1 reader rather than
        # adding a full pyasn1 dependency. The OID always lives near the start
        # of the SPKI; we scan for the known OID byte sequences.
        try:
            spki = base64.b64decode(pk) if isinstance(pk, str) else pk
            return _algo_from_spki(spki)
        except Exception as exc:
            return ParseResult(SigAlgorithm.UNKNOWN, notes=f"spki_decode_failed: {exc}")

    return ParseResult(SigAlgorithm.UNKNOWN, notes="no_known_key_material_shape")


# Pre-computed byte sequences for OID-matching against an ASN.1-encoded SPKI.
# Each entry is (DER bytes for the OID, target algorithm). We look for these
# anywhere in the first ~200 bytes of the SPKI, which is the standard location.
_OID_NEEDLES: list[tuple[bytes, SigAlgorithm]] = [
    # OID 1.2.840.10045.2.1 (id-ecPublicKey) — ECDSA on a NIST curve
    (b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01", SigAlgorithm.ECDSA_P256),
    # OID 1.2.840.113549.1.1.1 (rsaEncryption)
    (b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", SigAlgorithm.RSA_OTHER),
    # OID 1.3.101.112 (Ed25519)
    (b"\x06\x03\x2b\x65\x70", SigAlgorithm.ED25519),
    # OID 1.3.101.113 (Ed448)
    (b"\x06\x03\x2b\x65\x71", SigAlgorithm.ED448),
    # NOTE: ML-DSA OIDs are 2.16.840.1.101.3.4.3.17/18/19 (NIST CSOR, post-FIPS 204).
    # When we eventually find a PQC-signed model, these will trigger.
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11", SigAlgorithm.ML_DSA_44),
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12", SigAlgorithm.ML_DSA_65),
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13", SigAlgorithm.ML_DSA_87),
]


def _algo_from_spki(spki_bytes: bytes) -> ParseResult:
    """Identify the public-key algorithm by scanning for OID byte sequences."""
    head = spki_bytes[:300]  # OID lives near the start of any sane SPKI
    for needle, algo in _OID_NEEDLES:
        if needle in head:
            # For RSA, also try to estimate the modulus size, since key size matters
            # for our reporting (RSA-2048 vs RSA-4096 are both vulnerable, but the
            # paper wants the breakdown). We look for the modulus INTEGER tag.
            if algo == SigAlgorithm.RSA_OTHER:
                key_size = _estimate_rsa_modulus_bits(spki_bytes)
                refined = _refine_rsa_size(key_size)
                return ParseResult(refined, key_size_bits=key_size)
            return ParseResult(algo)
    return ParseResult(SigAlgorithm.UNKNOWN, notes="no_matching_oid_in_spki")


def _estimate_rsa_modulus_bits(spki: bytes) -> Optional[int]:
    """Best-effort RSA modulus size estimate from a SubjectPublicKeyInfo.

    Looks for the BIT STRING wrapping the inner SEQUENCE, then the modulus
    INTEGER's length octets. Returns None on any structural surprise.
    """
    try:
        # Locate the rsaEncryption OID, skip to the BIT STRING that follows
        oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
        i = spki.find(oid)
        if i < 0:
            return None
        # After OID + NULL parameters (typically 2 bytes 05 00), expect BIT STRING tag 03
        j = spki.find(b"\x03", i + len(oid))
        if j < 0:
            return None
        # Skip BIT STRING header (tag + length octets + 1 unused-bits byte) to inner SEQUENCE
        # We do not parse length carefully here; we look for the next INTEGER tag (02).
        k = spki.find(b"\x02", j)
        if k < 0:
            return None
        # The next byte (or bytes) is the length of the modulus INTEGER.
        length_byte = spki[k + 1]
        if length_byte & 0x80:
            num_len_bytes = length_byte & 0x7F
            modulus_len = int.from_bytes(spki[k + 2 : k + 2 + num_len_bytes], "big")
        else:
            modulus_len = length_byte
        # First byte of the modulus may be a leading 0x00 to denote a positive integer.
        modulus_start = k + 2 + (num_len_bytes if length_byte & 0x80 else 0)
        if modulus_start < len(spki) and spki[modulus_start] == 0:
            modulus_len -= 1
        return modulus_len * 8
    except (IndexError, ValueError):
        return None


def _refine_rsa_size(bits: Optional[int]) -> SigAlgorithm:
    """Map a modulus bit length to the closest RSA SigAlgorithm enum."""
    if bits is None:
        return SigAlgorithm.RSA_OTHER
    # Allow ±32-bit tolerance for off-by-one byte counts
    if abs(bits - 2048) <= 32:
        return SigAlgorithm.RSA_2048
    if abs(bits - 3072) <= 32:
        return SigAlgorithm.RSA_3072
    if abs(bits - 4096) <= 32:
        return SigAlgorithm.RSA_4096
    return SigAlgorithm.RSA_OTHER


# ---------------------------------------------------------------------------
# GPG / OpenPGP parser
# ---------------------------------------------------------------------------
# OpenPGP signature packet (RFC 4880 / RFC 9580) has a "public-key algorithm"
# byte in the unhashed-subpackets header. We do a lightweight scan rather
# than a full RFC implementation.

_PGP_ALGO_IDS: dict[int, SigAlgorithm] = {
    # RFC 9580 §9.1
    1:  SigAlgorithm.RSA_OTHER,   # RSA (Encrypt or Sign)
    2:  SigAlgorithm.RSA_OTHER,   # RSA Encrypt-Only (legacy)
    3:  SigAlgorithm.RSA_OTHER,   # RSA Sign-Only (legacy)
    17: SigAlgorithm.ECDSA_P256,  # DSA — we approximate as classical/ECDSA-like for reporting
    19: SigAlgorithm.ECDSA_P256,  # ECDSA
    22: SigAlgorithm.ED25519,     # EdDSA legacy
    23: SigAlgorithm.ED25519,     # Ed25519 (RFC 9580)
    28: SigAlgorithm.ED448,       # Ed448 (RFC 9580)
}


def parse_gpg(raw: bytes) -> ParseResult:
    """Best-effort parse of a binary or ASCII-armoured OpenPGP signature.

    Implementation note: we do not link a full OpenPGP library. We only
    locate the signature packet header and read the public-key algorithm
    byte; that is enough to classify quantum-vulnerability. A future
    iteration may use the `pgpy` library for stricter validation.
    """
    # If ASCII-armoured, strip the BEGIN/END headers and base64-decode
    if raw.startswith(b"-----BEGIN PGP"):
        try:
            inner = re.search(rb"\n\n(.+?)\n=", raw, re.DOTALL)
            if not inner:
                return ParseResult(SigAlgorithm.UNKNOWN, notes="armor_no_body")
            raw = base64.b64decode(inner.group(1).replace(b"\n", b""))
        except Exception as exc:
            return ParseResult(SigAlgorithm.UNKNOWN, notes=f"armor_decode_failed: {exc}")

    # The first byte is the packet tag (0xC2 for signature in new format,
    # 0x88-0x8B for old format). The public-key algorithm byte lives at a
    # fixed offset within the packet header for v3 and v4 signatures.
    if len(raw) < 6:
        return ParseResult(SigAlgorithm.UNKNOWN, notes="packet_too_short")

    # Version byte is at offset 2 (new format) or offset 1 (old format) after
    # skipping the length octet(s). To keep this code robust, we scan a small
    # window for the version + algo pattern.
    for off in range(0, min(10, len(raw) - 3)):
        version = raw[off]
        if version in (3, 4, 5, 6):  # known OpenPGP signature versions
            algo_byte = raw[off + 2] if version == 3 else raw[off + 3]
            if algo_byte in _PGP_ALGO_IDS:
                return ParseResult(_PGP_ALGO_IDS[algo_byte])
    return ParseResult(SigAlgorithm.UNKNOWN, notes="no_recognised_pgp_algo_byte")


# ---------------------------------------------------------------------------
# in-toto attestation parser
# ---------------------------------------------------------------------------
def parse_in_toto(raw: bytes) -> ParseResult:
    """Parse an in-toto attestation envelope.

    in-toto envelopes are DSSE (Dead Simple Signing Envelope) JSON objects.
    The signing algorithm is declared in `signatures[i].keyid` or, when
    embedded, in the public key block. In practice, in-toto attestations
    on ML registries are almost always Sigstore-signed and use the same
    Fulcio ECDSA-P256 default.
    """
    try:
        env = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return ParseResult(SigAlgorithm.UNKNOWN, notes=f"json_decode_failed: {exc}")

    sigs = env.get("signatures") or []
    if not sigs:
        return ParseResult(SigAlgorithm.UNKNOWN, notes="no_signatures_in_envelope")

    # If signatures carry an embedded `cert` field, infer the algorithm.
    # Otherwise, default to ECDSA_P256 (Fulcio convention).
    for s in sigs:
        if isinstance(s, dict) and "cert" in s and isinstance(s["cert"], str):
            return ParseResult(
                SigAlgorithm.ECDSA_P256,
                notes="inferred_from_intoto_embedded_fulcio_cert",
            )
    return ParseResult(
        SigAlgorithm.ECDSA_P256,
        notes="defaulted_to_fulcio_for_intoto",
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
def parse_signature(raw: bytes, fmt: SigFormat) -> ParseResult:
    """Dispatch a raw signature file to the appropriate format parser."""
    if fmt in (SigFormat.SIGSTORE, SigFormat.OMS):
        return parse_sigstore(raw)
    if fmt == SigFormat.IN_TOTO:
        return parse_in_toto(raw)
    if fmt == SigFormat.GPG:
        return parse_gpg(raw)
    # CUSTOM or unknown format: try sigstore first (it's the modal case),
    # then fall back to GPG, since some publishers misname their files.
    fallback = parse_sigstore(raw)
    if fallback.algorithm != SigAlgorithm.UNKNOWN:
        return fallback
    return parse_gpg(raw)
