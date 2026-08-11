"""Detect a post-quantum key in a certificate `cryptography` refuses to parse.

THE PROBLEM THIS EXISTS TO FIX
==============================
The entire study reports one negative: **no post-quantum signatures were found
in any ecosystem**. That claim is only worth stating if the detector could have
produced a positive. It could not.

`cryptography`'s X.509 parser rejects a certificate whose SubjectPublicKeyInfo
carries an algorithm OID it does not implement -- and it rejects it at LOAD
time, with a `ValueError`, before `public_key()` is ever reached. In
`key_algorithm_of_certificate` that error is caught and reported as
"certificate does not parse", which the scanners record as `ERROR`:
indistinguishable from a truncated file or a transport corruption.

The branch that says "this may be a post-quantum key, which would be a finding
rather than an error" sits below `public_key()` and is therefore unreachable
for a real ML-DSA certificate. `SigAlgorithm.ML_DSA_87` existed in the model and
no code path could return it.

So the first genuine post-quantum attestation to appear in any of the three
ecosystems -- the single artefact this study exists to detect -- would have been
filed as a parse error and counted in the same bucket as corrupt data. "We
found zero" and "our parser cannot represent one" would have been the same
number.

WHAT THIS DOES INSTEAD
======================
When the structured parse fails, the raw DER is searched for the NIST CSOR
algorithm OIDs of the FIPS 204 and FIPS 205 signature schemes. A hit is
reported as a **finding**, with the algorithm named, rather than as a failure.

This is a byte search, not a parse, and the module is explicit about that: it
establishes "these bytes contain the ML-DSA-87 OID", not "this is a valid
ML-DSA-87 certificate". That is the correct strength of claim for something
whose job is to stop a positive being silently discarded -- it raises a flag
for a human, it does not classify on its own authority. The alternative,
writing an X.509 parser for algorithms `cryptography` does not support, would
put far more unvalidated code under the study's central result.
"""
from __future__ import annotations

from .model import SigAlgorithm

__all__ = ["PQ_OIDS", "encode_oid", "postquantum_oid_in"]


def encode_oid(dotted: str) -> bytes:
    """DER encoding of an OID, tag and length included.

    Written out rather than hardcoded as hex so the table below can be read
    against the NIST CSOR registry by eye.
    """
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append((value & 0x7F) | 0x80)
            value >>= 7
        body.extend(reversed(chunk))
    return bytes([0x06, len(body)]) + bytes(body)


# NIST CSOR, arc 2.16.840.1.101.3.4.3 (sigAlgs). FIPS 204 and FIPS 205.
_ML_DSA = {
    "2.16.840.1.101.3.4.3.17": SigAlgorithm.ML_DSA_44,
    "2.16.840.1.101.3.4.3.18": SigAlgorithm.ML_DSA_65,
    "2.16.840.1.101.3.4.3.19": SigAlgorithm.ML_DSA_87,
}
# SLH-DSA occupies .20 through .31; every parameter set maps to one label,
# matching how SigAlgorithm already models it.
_SLH_DSA = {f"2.16.840.1.101.3.4.3.{n}": SigAlgorithm.SLH_DSA
            for n in range(20, 32)}

#: encoded OID -> algorithm. Encoded once at import.
PQ_OIDS: dict[bytes, SigAlgorithm] = {
    encode_oid(dotted): algorithm
    for dotted, algorithm in {**_ML_DSA, **_SLH_DSA}.items()
}

#: The reverse map, for error messages that name what was seen.
_NAMES: dict[bytes, str] = {
    encode_oid(dotted): dotted for dotted in {**_ML_DSA, **_SLH_DSA}
}


def postquantum_oid_in(der: bytes) -> tuple[SigAlgorithm, str] | None:
    """Return `(algorithm, dotted OID)` if the bytes contain a PQ signature OID.

    A byte search over DER, which is sound in the direction that matters: these
    OIDs are 11-byte sequences under a NIST arc, so a chance occurrence in
    unrelated data is vanishingly unlikely, and the consequence of a false
    positive is a human looking at a certificate. The consequence of the false
    NEGATIVE this replaces was the study's central claim resting on a detector
    that could not produce a positive.

    Returns None for ordinary corrupt or truncated data, so "unparseable" and
    "unparseable, and post-quantum" stay distinguishable.
    """
    for encoded, algorithm in PQ_OIDS.items():
        if encoded in der:
            return algorithm, _NAMES[encoded]
    return None
