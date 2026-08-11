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

from .model import SigAlgorithm, SigFormat


@dataclass
class ParseResult:
    """Outcome of parsing a single signature file."""

    algorithm: SigAlgorithm
    key_size_bits: int | None = None
    notes: str | None = None


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

    # Valid JSON is not necessarily a JSON *object*. `[]`, `null` and bare
    # scalars all decode without error and then fail on .get(). Because
    # audit_model does not wrap parse_signature, that AttributeError would
    # propagate out and abort an entire 20,000-repo scan on one malformed file.
    if not isinstance(bundle, dict):
        return ParseResult(
            SigAlgorithm.UNKNOWN,
            notes=f"bundle_is_not_a_json_object: {type(bundle).__name__}",
        )

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
                return ParseResult(
                    refined,
                    key_size_bits=key_size,
                    notes="parsed_from_spki_oid; rsa_size_from_modulus_estimate"
                    if key_size else "parsed_from_spki_oid; rsa_size_unresolved",
                )
            return ParseResult(algo, notes="parsed_from_spki_oid")
    return ParseResult(SigAlgorithm.UNKNOWN, notes="no_matching_oid_in_spki")


def _estimate_rsa_modulus_bits(spki: bytes) -> int | None:
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


def _refine_rsa_size(bits: int | None) -> SigAlgorithm:
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


def _pgp_packet_body(raw: bytes) -> bytes | None:
    """Return the body of the first OpenPGP packet, or None if not a packet.

    Handles both framings from RFC 4880 §4.2. Locating the body properly
    matters because the previous implementation scanned a fixed window for a
    plausible version byte, which both missed correctly framed packets and
    matched arbitrary binary that happened to contain a 3, 4, 5 or 6.
    """
    tag_byte = raw[0]
    if not tag_byte & 0x80:
        return None  # bit 7 is set on every packet tag; this is not OpenPGP

    if tag_byte & 0x40:  # new format: tag in low 6 bits, then a length octet
        length_octet = raw[1]
        if length_octet < 192:
            return raw[2:]
        if length_octet < 224:
            return raw[3:]
        if length_octet == 255:
            return raw[6:]
        return raw[2:]  # partial body length
    # old format: length type in the low 2 bits
    return {0: raw[2:], 1: raw[3:], 2: raw[5:], 3: raw[1:]}[tag_byte & 0x03]


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

    if len(raw) < 6:
        return ParseResult(SigAlgorithm.UNKNOWN, notes="packet_too_short")

    body = _pgp_packet_body(raw)
    if body is None:
        return ParseResult(SigAlgorithm.UNKNOWN, notes="not_an_openpgp_packet")
    if not body:
        return ParseResult(SigAlgorithm.UNKNOWN, notes="pgp_packet_empty")

    version = body[0]
    # Field offsets from RFC 4880 §5.2.2/§5.2.3 and RFC 9580 §5.2.3.
    #
    #   v3: version, hashed-material-length(=5), sig type, creation time[4],
    #       key id[8], PUBLIC-KEY ALGORITHM, hash algorithm
    #       -> public-key algorithm at offset 15
    #
    #   v4/v5/v6: version, sig type, PUBLIC-KEY ALGORITHM, hash algorithm, ...
    #       -> public-key algorithm at offset 2
    #
    # Getting this wrong is not a harmless off-by-one. An earlier version of
    # this function read offset 3 for v4, which is the *hash* algorithm, and
    # offset 2 for v3, which is the signature type. Because hash ids 1/2/3
    # (MD5/SHA1/RIPEMD160) collide with public-key ids 1/2/3 (RSA variants),
    # the bug silently reported "RSA" for legacy-hash signatures and
    # "no_recognised_pgp_algo_byte" for every modern SHA-256 one (hash id 8,
    # which is not a public-key id). Every correctly formed contemporary
    # OpenPGP signature was therefore recorded as unparseable.
    # Each version needs only enough body to reach its algorithm octet; a
    # blanket minimum would reject the short-but-valid packets that appear in
    # fixtures and in real detached signatures with few subpackets.
    #
    # The bounds below cover the HASH octet as well as the public-key one,
    # because the note built further down reads both. Guarding only the
    # public-key octet left `body[16]` (v3) and `body[3]` (v4) unguarded: a body
    # of exactly 16 bytes passed `len(body) < 16` and then raised IndexError.
    # That broke this module's documented promise never to raise on malformed
    # input -- scanner.py's catch-all turned it into a `parser_crashed` record,
    # so a short-but-well-formed packet was misreported as a parser bug.
    if version == 3:
        if len(body) < 17:
            return ParseResult(SigAlgorithm.UNKNOWN, notes="pgp_v3_packet_too_short")
        algo_byte = body[15]
    elif version in (4, 5, 6):
        if len(body) < 4:
            return ParseResult(SigAlgorithm.UNKNOWN, notes="pgp_v4_packet_too_short")
        algo_byte = body[2]
    else:
        return ParseResult(
            SigAlgorithm.UNKNOWN, notes=f"unsupported_pgp_signature_version: {version}"
        )

    if algo_byte in _PGP_ALGO_IDS:
        hash_byte = body[16] if version == 3 else body[3]
        return ParseResult(
            _PGP_ALGO_IDS[algo_byte],
            notes=f"parsed_from_openpgp_packet: v{version}, "
                  f"pubkey_algo={algo_byte}, hash_algo={hash_byte}",
        )
    return ParseResult(
        SigAlgorithm.UNKNOWN, notes=f"unknown_pgp_pubkey_algo_id: {algo_byte}"
    )


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

    # `[]`, `null` and bare scalars are valid JSON but have no .get(). Guarding
    # here keeps the promise made in the module docstring: never raise on
    # malformed input. audit_model does not wrap this call, so an exception
    # would abort the whole scan.
    if not isinstance(env, dict):
        return ParseResult(
            SigAlgorithm.UNKNOWN,
            notes=f"envelope_is_not_a_json_object: {type(env).__name__}",
        )

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
# Signature schemes emit fixed-size output, so for a bare signature carrying no
# framing the length is the only identifying signal there is.
#
# This is weaker evidence than parsing and is labelled as such in the notes.
# Two caveats a reader must not lose:
#
#   * 64 bytes is ambiguous between Ed25519 and a raw ECDSA P-256 r||s pair.
#     Both are classical, so the quantum-vulnerability label is unaffected and
#     only the specific algorithm is uncertain. ECDSA_OTHER is reported rather
#     than guessing between them.
#   * The post-quantum sizes are included so that a PQC signature in the wild
#     is recognised rather than dismissed as unparseable. Finding one would be
#     the single most important result this tool could produce, and it would be
#     absurd to miss it because the file lacked a header.
_RAW_SIGNATURE_SIZES: dict[int, SigAlgorithm] = {
    64:   SigAlgorithm.ECDSA_OTHER,  # Ed25519 or raw ECDSA P-256; classical either way
    256:  SigAlgorithm.RSA_2048,
    384:  SigAlgorithm.RSA_3072,
    512:  SigAlgorithm.RSA_4096,
    2420: SigAlgorithm.ML_DSA_44,
    3309: SigAlgorithm.ML_DSA_65,
    4627: SigAlgorithm.ML_DSA_87,
    7856: SigAlgorithm.SLH_DSA,      # SLH-DSA-128s
    16224: SigAlgorithm.SLH_DSA,     # SLH-DSA-128f
}


def parse_raw_signature(raw: bytes) -> ParseResult:
    """Classify a headerless signature by its length alone.

    Last resort for files that carry no magic number, no OID and no framing --
    the output of `openssl dgst -sign` and similar. The algorithm is genuinely
    not recoverable from such a file; length narrows it, and the note records
    that the attribution is an inference rather than a parse.

    That these signatures are not self-describing is itself worth reporting: a
    third party cannot determine what algorithm protects an artefact, which
    makes a cryptographic-agility inventory impossible without out-of-band
    information such as an accompanying certificate.
    """
    algo = _RAW_SIGNATURE_SIZES.get(len(raw))
    if algo is None:
        return ParseResult(
            SigAlgorithm.UNKNOWN,
            notes=f"headerless_signature_of_unrecognised_length: {len(raw)} bytes",
        )
    return ParseResult(
        algo,
        notes=f"inferred_from_raw_signature_length: {len(raw)} bytes, no header present",
    )


def parse_signature(raw: bytes, fmt: SigFormat) -> ParseResult:
    """Dispatch a raw signature file to the appropriate format parser."""
    if fmt in (SigFormat.SIGSTORE, SigFormat.OMS):
        return parse_sigstore(raw)
    if fmt == SigFormat.IN_TOTO:
        return parse_in_toto(raw)
    if fmt == SigFormat.GPG:
        result = parse_gpg(raw)
        if result.algorithm != SigAlgorithm.UNKNOWN:
            return result
        return parse_raw_signature(raw)
    # CUSTOM or unknown format: try sigstore first (it's the modal case), then
    # GPG since some publishers misname their files, then fall back to
    # classifying a bare signature by its length.
    fallback = parse_sigstore(raw)
    if fallback.algorithm != SigAlgorithm.UNKNOWN:
        return fallback
    gpg = parse_gpg(raw)
    if gpg.algorithm != SigAlgorithm.UNKNOWN:
        return gpg
    return parse_raw_signature(raw)
