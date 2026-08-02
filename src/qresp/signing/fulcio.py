"""Fulcio-style certificate-chain verification: steps 3-4 of the registration
verification algorithm (docs/REGISTRATION-SPEC.md).

WHAT THIS IS AND IS NOT
=======================
This validates an X.509 chain to a trusted root and extracts the OIDC identity
and issuer a Fulcio certificate binds. It is the *verification* side, which is
pure logic and fully testable offline against a locally minted CA. It does not
acquire a certificate -- that is a live OIDC + Fulcio flow, the one network seam
an operator wires to a vetted Sigstore client. The bytes it consumes are the
same either way, so the trust logic an expert reviews here is the trust logic
that runs in production.

The trust roots are a PARAMETER, never hardcoded, for the same reason
`transparency.verify_timestamp` takes its anchors as arguments: a verifier's
trust store is the verifier's decision, and a module that pins its own roots
cannot be pointed at a private Fulcio or a test CA without editing it.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

__all__ = ["ChainError", "FulcioIdentity", "verify_chain"]

# Fulcio records the OIDC issuer in a private X.509v3 extension. The v1 form
# (1.1) stored the raw issuer string; the v2 form (1.8) wraps it in DER. Both
# appear in the wild, so both are read -- pinning only one would silently drop
# identities issued under the other.
_ISSUER_OID_V1 = "1.3.6.1.4.1.57264.1.1"
_ISSUER_OID_V2 = "1.3.6.1.4.1.57264.1.8"


class ChainError(Exception):
    """A certificate chain did not validate to a trusted root."""


@dataclass(frozen=True)
class FulcioIdentity:
    """What a validated Fulcio chain attests: an OIDC subject and its issuer."""

    identity: str
    issuer: str


def _load(der: bytes) -> Any:
    from cryptography import x509

    try:
        return x509.load_der_x509_certificate(der)
    except Exception as exc:  # noqa: BLE001 -- any parse failure is a reject
        raise ChainError(f"certificate does not parse: {exc}") from exc


def _verify_signed_by(child: Any, issuer: Any) -> None:
    """Assert `child` was signed by `issuer`'s private key. Raises on failure.

    Handles the three key types a Fulcio-style chain uses -- EC, RSA, Ed25519 --
    because the root and intermediates are not always the same family as the
    leaf, and a verifier that only understood EC would reject a valid RSA root.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    key = issuer.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            raise ChainError(
                f"issuer key type {type(key).__name__} is not supported")
    except InvalidSignature as exc:
        raise ChainError(
            f"{child.subject.rfc4514_string()} is not signed by "
            f"{issuer.subject.rfc4514_string()}") from exc


def _within_validity(certificate: Any, at_time: datetime) -> None:
    # not_valid_before/after_utc are the tz-aware accessors; the naive ones are
    # deprecated and compare wrongly against a tz-aware `at_time`.
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if at_time < not_before or at_time > not_after:
        raise ChainError(
            f"certificate {certificate.subject.rfc4514_string()} is valid "
            f"{not_before.isoformat()}..{not_after.isoformat()}, outside "
            f"{at_time.isoformat()}")


def _issuer_from_certificate(certificate: Any) -> str | None:
    from cryptography import x509

    for oid_str in (_ISSUER_OID_V2, _ISSUER_OID_V1):
        try:
            ext = certificate.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(oid_str))
        except x509.ExtensionNotFound:
            continue
        raw = ext.value.value
        if oid_str == _ISSUER_OID_V2:
            # v2 wraps the issuer as a DER UTF8String (tag 0x0c). Decoded
            # inline rather than pulling in an ASN.1 library for one field;
            # falls back to the raw bytes if it is not the expected shape,
            # so a format surprise degrades to a readable string instead of
            # dropping the identity.
            return _der_utf8string(raw)
        return str(raw.decode("utf-8", "replace"))
    return None


def _der_utf8string(raw: bytes) -> str:
    """The value of a DER UTF8String, or the bytes decoded as UTF-8 if it is
    not one. Handles only the short-form length that a Fulcio issuer uses."""
    if len(raw) >= 2 and raw[0] == 0x0C:
        length = raw[1]
        if length < 0x80 and len(raw) >= 2 + length:
            return raw[2:2 + length].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


def _identity_from_certificate(certificate: Any) -> str | None:
    from cryptography import x509

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        return str(uri)
    for email in san.get_values_for_type(x509.RFC822Name):
        return str(email)
    return None


def verify_chain(
    leaf_der: bytes,
    intermediate_ders: list[bytes],
    trusted_root_ders: list[bytes],
    at_time: datetime | None = None,
) -> FulcioIdentity:
    """Validate leaf -> intermediates -> a trusted root, and return the identity.

    Steps 3 and 4 of the spec. Configuration is checked before any
    attacker-controlled bytes are parsed: an empty trust store is a
    configuration error, not a verification failure, and must not be reachable
    by a crafted leaf. This mirrors `transparency.verify_timestamp`.
    """
    if not trusted_root_ders:
        raise ChainError(
            "no trusted roots supplied; a chain cannot be validated against an "
            "empty trust store. This is a configuration error, distinct from a "
            "chain that fails to validate.")

    at_time = at_time or datetime.now(timezone.utc)

    leaf = _load(leaf_der)
    intermediates = [_load(d) for d in intermediate_ders]
    roots = [_load(d) for d in trusted_root_ders]

    # Build the path leaf -> ... and verify each link, then that the last link
    # was signed by a trusted root. Kept explicit rather than delegated to a
    # TLS-oriented verifier, because Fulcio identities live in a SAN URI and a
    # custom issuer extension, not in a DNS name a server verifier expects.
    chain = [leaf, *intermediates]
    for certificate in chain:
        _within_validity(certificate, at_time)

    for child, issuer in zip(chain, chain[1:], strict=False):
        _verify_signed_by(child, issuer)

    top = chain[-1]
    roots_by_subject = {r.subject.rfc4514_string(): r for r in roots}
    anchor = roots_by_subject.get(top.issuer.rfc4514_string())
    if anchor is None:
        raise ChainError(
            f"the chain terminates at an issuer "
            f"({top.issuer.rfc4514_string()}) that is not among the trusted "
            f"roots. The chain may be valid but it is not anchored in this "
            f"verifier's trust store.")
    _within_validity(anchor, at_time)
    _verify_signed_by(top, anchor)

    identity = _identity_from_certificate(leaf)
    issuer = _issuer_from_certificate(leaf)
    if identity is None:
        raise ChainError(
            "leaf certificate has no SAN identity; a Fulcio certificate that "
            "names no subject cannot bind a registration to anyone")
    if issuer is None:
        raise ChainError(
            "leaf certificate carries no OIDC issuer extension; the identity "
            "cannot be attributed to an issuer, so it is not trustworthy on "
            "its own")
    return FulcioIdentity(identity=identity, issuer=issuer)
