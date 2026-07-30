"""Key registration: binding an identity to a long-term post-quantum key.

THE PROBLEM THIS SOLVES
=======================
A hybrid signature proves an artefact was signed by *some* key. It does not say
whose. Sigstore answers that question with Fulcio, which binds an OIDC identity
to a public key -- but **Fulcio will not certify an ML-DSA key**, and Rekor v2
cannot log a pure-Ed25519 one either (no externalised prehash; see
`transparency.py`). So the obvious path from identity to a post-quantum key is
closed at both ends.

The way through is an explicit vouching statement:

    OIDC -> Fulcio certificate over ECDSA P-256
         -> registration statement: "identity X vouches for ML-DSA key K"
         -> artefacts signed with hybrid(Ed25519, K)

P-256 because it is the one algorithm that satisfies both constraints at once:
Fulcio certifies it, and it has an externalised prehash (SHA-256), so Rekor v2
will accept the entry. Ed25519 fails the second, Ed25519ph the first.

WHAT THIS BUYS, AND WHAT IT COSTS -- BOTH PRECISELY
===================================================
Buys: a verifier who trusts Fulcio can learn that a named identity asserted
ownership of a specific post-quantum key, at a time that can be established
independently.

Costs: **identity assurance is only classically secure.** An adversary who can
break P-256 can forge the registration and therefore the identity binding, even
though artefact integrity remains post-quantum secure. That asymmetry is real
and must be stated wherever this mechanism is described.

The redeeming property is that the weakness is now *concentrated in one place*
rather than diffused through every artefact signature. One statement per key
carries the classical assumption, instead of every signature carrying it, which
makes the caveat easy to state and easy to replace if a PQ-capable CA appears.

THE BOUNDARY CONDITION, NOT SOFTENED
====================================
This protects only identities that registered **before** P-256's deprecation
deadline. It is not retroactive. An identity first appearing after P-256 is
broken gets no benefit: an adversary able to forge P-256 can mint a registration
for a key they control, and nothing in the statement distinguishes it from an
honest one.

Such an identity needs a non-cryptographic bootstrap -- pinning, or
trust-on-first-use -- which is a *complement* to this mechanism and not a
competing one. See docs/THREAT-MODEL.md.

ONE ABSTRACTION, TWO APPLICATIONS
=================================
`temporal.assess` is not re-implemented here. Registration timestamps go
through the identical `Bound`-typed evidence and the identical soft-warn /
hard-fail policy that artefact signatures do, because "was this signature made
while its algorithm was still trusted?" is the same question whether the
signature covers a model or a key-ownership claim. `assess_registration` is a
thin call into it, and the tests assert the two paths share a code path rather
than merely agreeing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .algorithms import REGISTRY
from .dsse import pae
from .temporal import TemporalAssessment, TimeEvidence, assess

__all__ = [
    "REGISTRATION_PAYLOAD_TYPE",
    "KeyRegistration",
    "RegistrationError",
    "SignedRegistration",
    "assess_registration",
    "sign_registration",
    "verify_registration",
]

REGISTRATION_PAYLOAD_TYPE = "application/vnd.qresp.key-registration+json"

# The algorithm the registration statement itself is signed with. Not a free
# choice: see the module docstring.
REGISTRATION_ALGORITHM = "ecdsa-p256"


class RegistrationError(Exception):
    """A registration statement is absent, malformed, or does not verify."""


@dataclass(frozen=True)
class KeyRegistration:
    """The claim: `identity` vouches for post-quantum key `public_key`.

    `created` is the signer's own clock and is **not** evidence -- an attacker
    forging a registration writes a timestamp too. It is recorded because a
    self-asserted time is still useful for diagnostics and for detecting an
    honest clock error, and it is deliberately named so that no reader mistakes
    it for something checked. Trusted time comes from `assess_registration`,
    which takes evidence obtained separately.
    """

    identity: str            # OIDC subject, e.g. an email or workload identity
    issuer: str              # OIDC issuer that authenticated it
    algorithm: str           # the algorithm of the key being vouched for
    public_key: bytes        # the key itself, raw
    created: str             # ISO-8601, self-asserted, NOT evidence

    def __post_init__(self) -> None:
        if self.algorithm not in REGISTRY:
            raise RegistrationError(
                f"unknown algorithm {self.algorithm!r}; a registration for an "
                f"algorithm the registry does not know cannot later be assessed "
                f"against a deprecation date"
            )
        if not REGISTRY[self.algorithm].resists_shor:
            raise RegistrationError(
                f"{self.algorithm} does not resist Shor's algorithm. This "
                f"mechanism exists to bind an identity to a LONG-TERM "
                f"post-quantum key; registering a classical one would create "
                f"the appearance of post-quantum identity without the substance."
            )
        if not self.public_key:
            raise RegistrationError("refusing to register an empty public key")

    def to_payload(self) -> bytes:
        """Canonical JSON. Sorted keys and no whitespace, so the bytes signed
        are a function of the values alone -- two encoders must not be able to
        produce different signatures for the same claim.
        """
        import base64

        return json.dumps(
            {
                "_type": "qresp-key-registration/v1",
                "identity": self.identity,
                "issuer": self.issuer,
                "algorithm": self.algorithm,
                "publicKey": base64.b64encode(self.public_key).decode("ascii"),
                "created": self.created,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_payload(cls, payload: bytes) -> KeyRegistration:
        import base64

        try:
            data = json.loads(payload)
        except Exception as exc:
            raise RegistrationError(f"payload is not JSON: {exc}") from exc
        if data.get("_type") != "qresp-key-registration/v1":
            raise RegistrationError(
                f"unexpected payload type {data.get('_type')!r}; refusing to "
                f"interpret a document of unknown shape as a registration"
            )
        try:
            return cls(
                identity=data["identity"],
                issuer=data["issuer"],
                algorithm=data["algorithm"],
                public_key=base64.b64decode(data["publicKey"], validate=True),
                created=data["created"],
            )
        except KeyError as exc:
            raise RegistrationError(f"registration is missing {exc}") from exc


@dataclass(frozen=True)
class SignedRegistration:
    """A registration and the P-256 signature over its PAE."""

    payload: bytes
    signature: bytes
    certificate_der: bytes           # the Fulcio-issued certificate

    @property
    def signed_bytes(self) -> bytes:
        """Exactly what the signature covers.

        DSSE Pre-Authentication Encoding, the same construction the artefact
        path uses. It binds the payload TYPE alongside the payload, so a
        registration statement cannot be reinterpreted as some other document
        that happens to share its bytes.
        """
        return pae(REGISTRATION_PAYLOAD_TYPE, self.payload)

    def to_dict(self) -> dict[str, Any]:
        import base64

        return {
            "payloadType": REGISTRATION_PAYLOAD_TYPE,
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "certificate": base64.b64encode(self.certificate_der).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedRegistration:
        import base64

        if data.get("payloadType") != REGISTRATION_PAYLOAD_TYPE:
            raise RegistrationError(
                f"unexpected payloadType {data.get('payloadType')!r}"
            )
        try:
            return cls(
                payload=base64.b64decode(data["payload"], validate=True),
                signature=base64.b64decode(data["signature"], validate=True),
                certificate_der=base64.b64decode(data["certificate"], validate=True),
            )
        except KeyError as exc:
            raise RegistrationError(f"registration envelope is missing {exc}") from exc
        except Exception as exc:
            raise RegistrationError(f"malformed registration envelope: {exc}") from exc


def sign_registration(
    registration: KeyRegistration,
    private_key: Any,
    certificate_der: bytes,
) -> SignedRegistration:
    """Sign a registration with the Fulcio-certified P-256 key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise RegistrationError(
            "registration statements are signed with ECDSA P-256. It is the "
            "only algorithm Fulcio certifies that Rekor v2 can also log; see "
            "the module docstring."
        )

    payload = registration.to_payload()
    signature = private_key.sign(
        pae(REGISTRATION_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256())
    )
    return SignedRegistration(payload=payload, signature=signature,
                              certificate_der=certificate_der)


def verify_registration(
    signed: SignedRegistration,
    *,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> KeyRegistration:
    """Check the signature and return the claim. Performs no I/O.

    This verifies that the certificate's key signed this statement. It does
    **not** validate the certificate chain to a Fulcio root -- that is the
    caller's decision, made with its own trust store, for the same reason
    `transparency.verify_timestamp` takes anchors as arguments. Nor does it
    establish *when* the statement was made; pass the result to
    `assess_registration` with independently obtained evidence.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        certificate = x509.load_der_x509_certificate(signed.certificate_der)
    except Exception as exc:
        raise RegistrationError(f"certificate does not parse: {exc}") from exc

    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise RegistrationError(
            f"registration certificate holds a {type(public_key).__name__}, "
            f"not an ECDSA key"
        )

    try:
        public_key.verify(signed.signature, signed.signed_bytes,
                          ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise RegistrationError(
            "registration signature does not verify under the certificate's key"
        ) from exc

    registration = KeyRegistration.from_payload(signed.payload)

    # The certificate says who the identity provider authenticated. The payload
    # says who the statement claims to be from. If those disagree, the statement
    # is not what it appears to be -- a signer with a valid certificate for one
    # identity must not be able to vouch in another's name.
    cert_identity = _identity_from_certificate(certificate)
    if cert_identity is not None and cert_identity != registration.identity:
        raise RegistrationError(
            f"certificate identifies {cert_identity!r} but the statement claims "
            f"to be from {registration.identity!r}"
        )

    if expected_identity is not None and registration.identity != expected_identity:
        raise RegistrationError(
            f"registration is from {registration.identity!r}, expected "
            f"{expected_identity!r}"
        )
    if expected_issuer is not None and registration.issuer != expected_issuer:
        raise RegistrationError(
            f"registration issuer is {registration.issuer!r}, expected "
            f"{expected_issuer!r}"
        )
    return registration


def _identity_from_certificate(certificate: Any) -> str | None:
    """Pull the SAN identity out of a Fulcio-style certificate, if present."""
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


def assess_registration(
    evidence: TimeEvidence | None = None,
    now: datetime | None = None,
) -> TemporalAssessment:
    """Apply the artefact-signature temporal policy to a registration.

    THE SECOND APPLICATION OF ONE ABSTRACTION
    =========================================
    This is a call into `temporal.assess`, not a parallel implementation of it.
    The question is identical in both cases -- was this signature made while its
    algorithm was still trusted? -- so the `Bound` direction rules, the
    soft-warn / hard-fail thresholds and the rescue logic are shared rather than
    duplicated. A registration forged after P-256's deadline trips exactly the
    warning a post-deadline artefact signature would.

    It takes no `KeyRegistration`, deliberately. The algorithm assessed is
    fixed -- the one the STATEMENT is signed with (`ecdsa-p256`) -- so accepting
    a registration would imply the verdict depended on its contents when it
    does not, and would invite a caller to assume the vouched-for algorithm was
    what got checked. The name carries the intent; the signature carries no
    argument it would ignore.

    That fixed algorithm is the statement's own, not the post-quantum key it
    vouches for. Registering an
    ML-DSA key does not make the act of registration post-quantum secure, and
    assessing the wrong one would report the reassuring answer instead of the
    true one.
    """
    return assess([REGISTRATION_ALGORITHM], evidence=evidence, now=now)
