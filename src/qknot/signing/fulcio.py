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

__all__ = [
    "ChainError",
    "FulcioIdentity",
    "identity_from_leaf",
    "verify_chain",
    "verify_message",
]

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


def verify_message(certificate_der: bytes, message: bytes, signature: bytes) -> None:
    """Verify `signature` over `message` under a certificate's public key.

    Used for the classical half of a registration's proof of possession: the
    signature must be made by the key the Fulcio certificate attests, so it is
    verified under the LEAF's key directly rather than under a self-asserted
    key in the payload. Handles the key types a Fulcio leaf can hold; raises
    ChainError on any failure so the caller treats it as a rejection.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    key = _load(certificate_der).public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        else:
            raise ChainError(
                f"certificate key type {type(key).__name__} is not supported")
    except InvalidSignature as exc:
        raise ChainError(
            "signature does not verify under the certificate's key") from exc


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


_MAX_CHAIN_LENGTH = 16


def _build_path(leaf: Any, by_subject: dict[str, Any], trusted_subjects: set[str]) -> list[Any]:
    """Discover an ordered path leaf -> ... from an UNORDERED CA pool.

    A real trust store -- a TUF `trusted_root.json`, a directory of PEMs -- is an
    unordered pool, not the pre-sorted `[leaf, intermediate, ..., root]` list a
    caller would otherwise have to build. Discovery follows issuer==subject links
    through the pool until it reaches a trusted anchor or a self-signed cert, and
    is length-capped and loop-guarded so a crafted pool cannot make it spin.

    Ordering only; NO trust is decided here. Each discovered link's signature and
    the anchor's trust are checked by the caller.
    """
    path = [leaf]
    node = leaf
    seen = {node.subject.rfc4514_string()}
    for _ in range(_MAX_CHAIN_LENGTH):
        subject = node.subject.rfc4514_string()
        issuer = node.issuer.rfc4514_string()
        if subject in trusted_subjects:
            return path                     # reached a trusted anchor as a node
        if issuer == subject:
            return path                     # self-signed; anchor check decides trust
        parent = by_subject.get(issuer)
        if parent is None:
            return path                     # issuer not in pool; anchor check fails
        parent_subject = parent.subject.rfc4514_string()
        if parent_subject in seen:
            raise ChainError(
                f"certificate path loops at {parent_subject!r}; a pool that "
                f"cross-signs itself cannot terminate at a root")
        seen.add(parent_subject)
        path.append(parent)
        node = parent
    raise ChainError(
        f"certificate path exceeds the maximum length of {_MAX_CHAIN_LENGTH}; "
        f"refusing to follow an unbounded chain")


def identity_from_leaf(leaf_der: bytes) -> FulcioIdentity:
    """Parse the OIDC identity and issuer a Fulcio leaf carries -- NO chain check.

    For the `register` orchestrator, which must fill a registration's identity
    and issuer FROM the certificate Fulcio issued, never free-type them: the
    payload's claimed identity must be exactly what the cert attests, and the
    verifier cross-checks that (step 4). This is a parse only; trust in the
    certificate is established separately by `verify_chain`.
    """
    leaf = _load(leaf_der)
    identity = _identity_from_certificate(leaf)
    issuer = _issuer_from_certificate(leaf)
    if identity is None:
        raise ChainError(
            "leaf certificate has no SAN identity; it names no subject to "
            "register")
    if issuer is None:
        raise ChainError(
            "leaf certificate carries no OIDC issuer extension; its identity "
            "cannot be attributed to an issuer")
    return FulcioIdentity(identity=identity, issuer=issuer)


def verify_chain(
    leaf_der: bytes,
    intermediate_ders: list[bytes],
    trusted_root_ders: list[bytes],
    at_time: datetime | None = None,
) -> FulcioIdentity:
    """Validate a leaf to a trusted root through an UNORDERED CA pool.

    Steps 3 and 4 of the spec. `intermediate_ders` (from the bundle, untrusted)
    and `trusted_root_ders` (the verifier's trust store) are each an unordered
    pool: the caller does NOT pre-sort them into a chain. Path discovery
    (`_build_path`) does the ordering, so a real `trusted_root.json` CA pool can
    be passed as-is.

    The two pools are kept separate deliberately -- collapsing them into one
    "ca_pool" would let a bundle supply its own trust anchors. Trust is decided
    only at the anchor step, and only `trusted_root_ders` can anchor. When a
    subject appears in both pools the trusted bytes win, so a bundle cannot
    shadow a real root with a look-alike.

    Configuration is checked before any attacker-controlled bytes are parsed: an
    empty trust store is a configuration error, not a verification failure, and
    must not be reachable by a crafted leaf. This mirrors
    `transparency.verify_timestamp`.
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

    # A subject -> cert index for path discovery. Trusted roots are inserted
    # FIRST so that if an untrusted intermediate carries a trusted root's subject
    # name, the trusted bytes win and the look-alike is ignored.
    trusted_subjects = {r.subject.rfc4514_string() for r in roots}
    by_subject: dict[str, Any] = {}
    for cert in [*roots, *intermediates]:
        by_subject.setdefault(cert.subject.rfc4514_string(), cert)

    # Discover the ordered path, then verify each cert is time-valid and each
    # link is actually signed by its issuer. Kept explicit rather than delegated
    # to a TLS-oriented verifier, because Fulcio identities live in a SAN URI and
    # a custom issuer extension, not in a DNS name a server verifier expects.
    path = _build_path(leaf, by_subject, trusted_subjects)
    for certificate in path:
        _within_validity(certificate, at_time)
    for child, issuer_cert in zip(path, path[1:], strict=False):
        _verify_signed_by(child, issuer_cert)

    # Anchor: the top of the discovered path must be a trusted root, or be signed
    # by one. Both arise: the pool may include the root as a node (so the top IS
    # the root), or terminate at an intermediate whose issuer is a trusted root.
    top = path[-1]
    if top.subject.rfc4514_string() in trusted_subjects:
        _within_validity(top, at_time)      # top IS a trusted root (trusted bytes)
    else:
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
