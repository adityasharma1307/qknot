"""DSSE Pre-Authentication Encoding.

WHAT THIS FIXES
===============
An earlier version of this package signed `binding.binding_bytes` directly. The
binding commits to the suite, the digest, the digest algorithm and the context
-- and to nothing else. Everything else in the DSSE payload (the entropy
attestation, the backend descriptors, the signer's notes, the public keys) sat
*inside* the envelope, looked signed to any reader, and was covered by nothing.
An attacker could re-serialise a bundle, set `sideChannelResistant: true`,
delete the note recording a PRNG fallback, and verification still passed.

Signing the PAE over the whole payload closes that, and is what DSSE specifies
anyway. Non-separability is unaffected because the binding lives *inside* the
payload: every algorithm still signs a value that commits to the full algorithm
set, so stripping one signature still leaves the others attesting to its
absence.

WHY A PRE-AUTHENTICATION ENCODING AND NOT PLAIN CONCATENATION
=============================================================
The signed value must be unambiguous. Concatenating a payload type and a body
lets an attacker shift the boundary between them: a crafted type ending in what
looks like the start of a body produces the same byte string as a shorter type
with a longer body. Both fields are therefore length-prefixed:

    "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

where LEN is the ASCII decimal length. This is the same reasoning as the
length-prefixing in combiner.py, applied at the envelope layer.

REFERENCE
    https://github.com/secure-systems-lab/dsse -- Signing Spec, "Protocol"
"""
from __future__ import annotations

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """The exact byte string that every signature covers.

    Args:
        payload_type: the DSSE payloadType, e.g. the in-toto statement type.
        payload: the raw (un-base64'd) payload bytes.

    Returns:
        The pre-authentication encoding. Signing this rather than the payload
        means a signature over one payload type can never be replayed as a
        signature over another.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes; encode it before signing")
    type_bytes = payload_type.encode("utf-8")
    return b" ".join([
        b"DSSEv1",
        str(len(type_bytes)).encode("ascii"),
        type_bytes,
        str(len(payload)).encode("ascii"),
        bytes(payload),
    ])


def rekord_preimage(payload_type: str, payload: bytes) -> bytes:
    """SHA-256 of the PAE -- the exact bytes a hashedrekord entry commits to.

    ONE function, imported by both the artefact-bundle and the
    key-registration submission paths, because the two must agree on the
    pre-image to the byte or an inclusion proof stops validating for a reason
    nobody can see (spec section 2). It hashes the PAE of the payload, NOT the
    surrounding envelope with its signatures, so adding or reordering
    signatures cannot change what was logged.
    """
    import hashlib

    return hashlib.sha256(pae(payload_type, payload)).digest()


__all__ = ["DSSE_PAYLOAD_TYPE", "pae", "rekord_preimage"]
