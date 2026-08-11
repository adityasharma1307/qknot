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
from datetime import datetime, timezone
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

REGISTRATION_PAYLOAD_TYPE = "application/vnd.qknot.key-registration+json"

# The algorithm the registration statement itself is signed with. Not a free
# choice: see the module docstring.
REGISTRATION_ALGORITHM = "ecdsa-p256"


class RegistrationError(Exception):
    """A registration statement is absent, malformed, or does not verify."""


@dataclass(frozen=True)
class KeyRegistration:
    """TRANSITIONAL single-key registration. Prefer HybridRegistration below.

    Kept because existing callers and tests use it, but the verification chain
    (registration_chain.py) uses only the dual-key HybridRegistration path. This
    single-signature form does not carry the classical anchor and cannot express
    the temporal rescue, so it should be retired once nothing depends on it; do
    not build new callers against it.

    The claim: `identity` vouches for post-quantum key `public_key`.

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
                "_type": "qknot-key-registration/v1",
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
        if data.get("_type") != "qknot-key-registration/v1":
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


# ===========================================================================
# DUAL-KEY (hybrid) registration -- the design in docs/REGISTRATION-SPEC.md.
#
# This is the durable-PQC-identity path: one identity vouches for BOTH a
# classical key (Fulcio-attested) and a post-quantum key, over a single DSSE
# envelope carrying two signatures. It lives alongside the single-key
# KeyRegistration above rather than replacing it; the single-key path stays as
# it was, and this is the one the verification algorithm (spec section 4) and
# the CLI build target consume.
# ===========================================================================

HYBRID_REGISTRATION_PAYLOAD_TYPE = "application/vnd.qknot.hybrid-key-registration+json"


@dataclass(frozen=True)
class KeyRef:
    """One key in a registration: its algorithm and its public bytes."""

    algorithm: str
    public_key: bytes

    def __post_init__(self) -> None:
        if self.algorithm not in REGISTRY:
            raise RegistrationError(
                f"unknown algorithm {self.algorithm!r}; a key on an algorithm "
                f"the registry does not know cannot be judged against a "
                f"disallow date"
            )
        if not self.public_key:
            raise RegistrationError(f"empty public key for {self.algorithm}")

    def to_dict(self) -> dict[str, str]:
        import base64

        return {"algorithm": self.algorithm,
                "publicKey": base64.b64encode(self.public_key).decode("ascii")}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyRef:
        import base64

        try:
            return cls(algorithm=data["algorithm"],
                       public_key=base64.b64decode(data["publicKey"], validate=True))
        except KeyError as exc:
            raise RegistrationError(f"key reference missing {exc}") from exc


@dataclass(frozen=True)
class HybridRegistration:
    """Identity X vouches for a classical key AND a post-quantum key.

    `created` and `notAfter` are the signer's own clock. `created` is diagnostic
    only, never evidence -- a forger writes a timestamp too, and trusted time
    comes from the transparency log. `notAfter` is enforced (spec step 7.5) but
    against the ARTEFACT's signing time, not the verifier's clock.
    """

    identity: str
    issuer: str
    classical_key: KeyRef
    pqc_key: KeyRef
    created: str
    not_after: str | None = None
    recovery_key: KeyRef | None = None

    def __post_init__(self) -> None:
        if not REGISTRY[self.pqc_key.algorithm].resists_shor:
            raise RegistrationError(
                f"pqcKey is {self.pqc_key.algorithm}, which does not resist "
                f"Shor. This mechanism binds an identity to a LONG-TERM "
                f"post-quantum key; a classical one would be identity theatre."
            )
        if REGISTRY[self.classical_key.algorithm].resists_shor:
            raise RegistrationError(
                f"classicalKey is {self.classical_key.algorithm}, which already "
                f"resists Shor. The classical key is the deprecating anchor the "
                f"PQC key is bootstrapped from; a post-quantum one there means "
                f"the roles are confused."
            )
        for label, value in (("created", self.created),
                             ("notAfter", self.not_after)):
            if value is None:
                continue
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise RegistrationError(
                    f"{label} is not an RFC 3339 timestamp: {value!r}") from exc

    def to_payload(self) -> bytes:
        """Canonical JSON: sorted keys, no whitespace, so the signed bytes are
        a function of the values alone."""
        body: dict[str, Any] = {
            "_type": "qknot-hybrid-key-registration/v1",
            "identity": self.identity,
            "issuer": self.issuer,
            "classicalKey": self.classical_key.to_dict(),
            "pqcKey": self.pqc_key.to_dict(),
            "created": self.created,
        }
        if self.not_after is not None:
            body["notAfter"] = self.not_after
        if self.recovery_key is not None:
            body["recoveryKey"] = self.recovery_key.to_dict()
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_payload(cls, payload: bytes) -> HybridRegistration:
        try:
            data = json.loads(payload)
        except Exception as exc:
            raise RegistrationError(f"payload is not JSON: {exc}") from exc
        if data.get("_type") != "qknot-hybrid-key-registration/v1":
            raise RegistrationError(
                f"unexpected payload type {data.get('_type')!r}; refusing to "
                f"read a document of unknown shape as a hybrid registration"
            )
        try:
            recovery = data.get("recoveryKey")
            return cls(
                identity=data["identity"],
                issuer=data["issuer"],
                classical_key=KeyRef.from_dict(data["classicalKey"]),
                pqc_key=KeyRef.from_dict(data["pqcKey"]),
                created=data["created"],
                not_after=data.get("notAfter"),
                recovery_key=KeyRef.from_dict(recovery) if recovery else None,
            )
        except KeyError as exc:
            raise RegistrationError(f"registration is missing {exc}") from exc


class NotYetRegistered(RegistrationError):  # noqa: N818 -- not a malformation
    """A registration is valid but does not COVER this artefact (notAfter).

    A distinct type, not a bare RegistrationError, because the caller must tell
    "this registration does not apply to this artefact" from "this registration
    is corrupt". The bundle stays validly logged and inspectable; it is ruled
    inapplicable, not rejected as malformed.
    """


def check_not_after(registration: HybridRegistration, signing_time: datetime) -> None:
    """Spec step 7.5. Enforce notAfter against the ARTEFACT's signing time.

    Keyed to `signing_time`, never to the verifier's clock: every temporal
    decision in this design reasons about when things happened, not about when
    someone runs the verifier. A registration that expired last year still
    covers an artefact signed the year before that.
    """
    if registration.not_after is None:
        return
    limit = datetime.fromisoformat(registration.not_after.replace("Z", "+00:00"))
    if signing_time > limit:
        raise NotYetRegistered(
            f"the registration's notAfter is {registration.not_after}, but the "
            f"artefact was signed at {signing_time.isoformat()}. The "
            f"registration is validly logged and inspectable; it simply does "
            f"not cover a signature made after it lapsed."
        )


@dataclass(frozen=True)
class HybridSignedRegistration:
    """The dual-signed DSSE envelope: one payload, two signatures.

    The classical signature carries a Fulcio certificate (identity attestation);
    the PQC signature is bare, because the PQC key is the thing being registered
    and nothing vouches for it yet. Requiring BOTH is the proof of possession.
    """

    payload: bytes
    classical_signature: bytes
    classical_certificate_der: bytes      # Fulcio-issued, attests the classical key
    pqc_signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        """Exactly what BOTH signatures cover: the PAE of the payload under the
        hybrid registration payload type."""
        return pae(HYBRID_REGISTRATION_PAYLOAD_TYPE, self.payload)

    @property
    def rekord_preimage(self) -> bytes:
        """The bytes a hashedrekord entry commits to (spec section 2), via the
        one shared function so the registration and artefact paths agree."""
        from .dsse import rekord_preimage

        return rekord_preimage(HYBRID_REGISTRATION_PAYLOAD_TYPE, self.payload)

    def to_dict(self) -> dict[str, Any]:
        import base64

        return {
            "payloadType": HYBRID_REGISTRATION_PAYLOAD_TYPE,
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "classicalSignature": base64.b64encode(self.classical_signature).decode("ascii"),
            "classicalCertificate": base64.b64encode(self.classical_certificate_der).decode("ascii"),
            "pqcSignature": base64.b64encode(self.pqc_signature).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HybridSignedRegistration:
        import base64

        if data.get("payloadType") != HYBRID_REGISTRATION_PAYLOAD_TYPE:
            raise RegistrationError(
                f"unexpected payloadType {data.get('payloadType')!r}")
        try:
            return cls(
                payload=base64.b64decode(data["payload"], validate=True),
                classical_signature=base64.b64decode(data["classicalSignature"], validate=True),
                classical_certificate_der=base64.b64decode(data["classicalCertificate"], validate=True),
                pqc_signature=base64.b64decode(data["pqcSignature"], validate=True),
            )
        except KeyError as exc:
            raise RegistrationError(f"envelope missing {exc}") from exc
        except Exception as exc:
            raise RegistrationError(f"malformed envelope: {exc}") from exc


def sign_hybrid_registration(
    registration: HybridRegistration,
    classical_secret: bytes,
    pqc_secret: bytes,
    classical_certificate_der: bytes,
) -> HybridSignedRegistration:
    """Produce the dual-signed envelope. Both signatures over the same PAE."""
    from .backends import get_backend

    payload = registration.to_payload()
    signed = pae(HYBRID_REGISTRATION_PAYLOAD_TYPE, payload)
    classical = get_backend(registration.classical_key.algorithm)
    pqc = get_backend(registration.pqc_key.algorithm)
    return HybridSignedRegistration(
        payload=payload,
        classical_signature=classical.sign(classical_secret, signed),
        classical_certificate_der=classical_certificate_der,
        pqc_signature=pqc.sign(pqc_secret, signed),
    )


def verify_proof_of_possession(envelope: HybridSignedRegistration) -> HybridRegistration:
    """Both keys signed the same statement, and the classical one is the key the
    Fulcio certificate attests. Returns the parsed registration.

    Steps 2 and 5. There are THREE checks, not two, and the third was the hole
    an expert review found: the classical signature must verify under the key in
    the FULCIO LEAF, not under the self-asserted `classicalKey` in the payload.

    Without it, an attacker holding a genuine Fulcio certificate for their own
    identity (key B) could put an arbitrary key A in the payload, sign the
    statement with A, and attach the real certificate for B. Possession would
    pass on A, the chain and identity cross-check would pass on B, and the
    Fulcio attestation would never have covered the key that actually signed the
    statement. So:

      * the payload's `classicalKey` is required byte-equal to the leaf's SPKI,
        which stops the statement renaming the key Fulcio attested; and
      * the classical signature is verified under that key -- now provably the
        leaf's -- closing the gap.

    The PQC signature verifies under the payload's `pqcKey` (possession of the
    key being registered). This still does not validate the chain to a trusted
    root; that is steps 3-4 in the full verifier. It establishes that whoever
    built this holds both private keys AND that the classical key is the one the
    attached certificate is for.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    from .backends import get_backend
    from .fulcio import ChainError, verify_message

    registration = HybridRegistration.from_payload(envelope.payload)
    signed = envelope.signed_bytes

    # The classical key MUST be the one the certificate attests, byte for byte.
    try:
        leaf = x509.load_der_x509_certificate(envelope.classical_certificate_der)
    except Exception as exc:  # noqa: BLE001
        raise RegistrationError(
            f"classical certificate does not parse: {exc}") from exc
    leaf_spki = leaf.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if leaf_spki != registration.classical_key.public_key:
        raise RegistrationError(
            "the payload's classicalKey is not the key the certificate attests. "
            "The statement cannot rename the key Fulcio certified; the classical "
            "signature must be made by, and verified under, the leaf's key.")

    # Verify the classical signature UNDER THE LEAF'S KEY (not the backend, so
    # the key type follows the certificate rather than a raw-vs-SPKI encoding).
    try:
        verify_message(envelope.classical_certificate_der, signed,
                       envelope.classical_signature)
    except ChainError as exc:
        raise RegistrationError(
            f"classical signature does not verify under the certificate's key "
            f"-- the identity side of the proof of possession fails: {exc}"
        ) from exc

    pqc = get_backend(registration.pqc_key.algorithm)
    if not pqc.verify(registration.pqc_key.public_key, signed,
                     envelope.pqc_signature):
        raise RegistrationError(
            "PQC signature does not verify under the pqcKey in the payload -- "
            "the possession side of the proof of possession fails. Whoever "
            "built this does not hold the PQC private key.")

    return registration


# ---------------------------------------------------------------------------
# Revocation (spec section 5 and 5.1)
# ---------------------------------------------------------------------------
REVOCATION_PAYLOAD_TYPE = "application/vnd.qknot.key-revocation+json"


def _key_fingerprint(public_key: bytes) -> str:
    import hashlib

    return hashlib.sha3_256(b"qknot-key-fingerprint-v1" + public_key).hexdigest()[:32]


@dataclass(frozen=True)
class Revocation:
    """A statement that a registered PQC key is no longer to be trusted.

    Targets the key by fingerprint, not by value, so the revocation need not
    republish the key. Signed by the classical anchor OR a designated recovery
    key -- never by the PQC key itself, which may be the compromised one.
    """

    identity: str
    pqc_key_fingerprint: str
    reason: str
    revoked_at: str                       # RFC 3339

    def to_payload(self) -> bytes:
        return json.dumps({
            "_type": "qknot-key-revocation/v1",
            "identity": self.identity,
            "pqcKeyFingerprint": self.pqc_key_fingerprint,
            "reason": self.reason,
            "revokedAt": self.revoked_at,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_payload(cls, payload: bytes) -> Revocation:
        try:
            data = json.loads(payload)
        except Exception as exc:
            raise RegistrationError(f"revocation is not JSON: {exc}") from exc
        if data.get("_type") != "qknot-key-revocation/v1":
            raise RegistrationError(f"unexpected type {data.get('_type')!r}")
        try:
            return cls(identity=data["identity"],
                       pqc_key_fingerprint=data["pqcKeyFingerprint"],
                       reason=data["reason"], revoked_at=data["revokedAt"])
        except KeyError as exc:
            raise RegistrationError(f"revocation missing {exc}") from exc


@dataclass(frozen=True)
class SignedRevocation:
    """A revocation and one signature: by the classical anchor or the recovery
    key. Which one is determined at verification, by which key validates it."""

    payload: bytes
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return pae(REVOCATION_PAYLOAD_TYPE, self.payload)


def verify_revocation(
    signed: SignedRevocation,
    registration: HybridRegistration,
    *,
    registration_log_time: datetime,
    now: datetime | None = None,
    policies: dict[str, Any] | None = None,
) -> Revocation:
    """Is this a revocation that must be honoured against `registration`?

    Spec section 5.1. A revocation is honoured if it is signed by EITHER:

      * the registration's classicalKey, subject to the same step-7 temporal
        decision as any classical signature (binding_trust on its algorithm and
        the registration's log time); or
      * the registration's DESIGNATED recoveryKey -- and only that one -- judged
        on the RECOVERY key's own algorithm and its own date, so a recovery key
        on a still-live family works after the primary anchor is disallowed.

    Two checks the memo requires, neither optional:
      1. a recovery-key revocation is matched against the recoveryKey fixed in
         the registration, not trusted because some signature verifies;
      2. the signer's own algorithm is judged on its own date.
    """
    from .backends import get_backend
    from .temporal import BindingBasis, binding_trust

    now = now or datetime.now(timezone.utc)
    revocation = Revocation.from_payload(signed.payload)

    if revocation.identity != registration.identity:
        raise RegistrationError(
            f"revocation names {revocation.identity!r} but the registration is "
            f"for {registration.identity!r}")
    target = _key_fingerprint(registration.pqc_key.public_key)
    if revocation.pqc_key_fingerprint != target:
        raise RegistrationError(
            "revocation targets a different key than this registration's pqcKey")

    def signed_by(key: KeyRef) -> bool:
        backend = get_backend(key.algorithm)
        return bool(backend.verify(key.public_key, signed.signed_bytes,
                                   signed.signature))

    # Classical anchor: the ordinary path.
    if signed_by(registration.classical_key):
        basis = binding_trust(registration.classical_key.algorithm,
                             registration_log_time, now=now, policies=policies)
        if basis is BindingBasis.REJECTED:
            raise RegistrationError(
                f"revocation is signed by the classicalKey "
                f"({registration.classical_key.algorithm}) but that algorithm "
                f"is past its disallow date with no rescuing timestamp, so the "
                f"signature cannot be trusted now")
        return revocation

    # Recovery key: only if one was DESIGNATED, and only that one.
    if registration.recovery_key is not None and signed_by(registration.recovery_key):
        basis = binding_trust(registration.recovery_key.algorithm,
                             registration_log_time, now=now, policies=policies)
        if basis is BindingBasis.REJECTED:
            raise RegistrationError(
                f"revocation is signed by the recoveryKey "
                f"({registration.recovery_key.algorithm}) but THAT algorithm is "
                f"also past its own disallow date with no rescuing timestamp. A "
                f"recovery key on an already-broken family provides no recovery.")
        return revocation

    # Signed by neither the classical anchor nor the designated recovery key.
    if registration.recovery_key is None:
        raise RegistrationError(
            "revocation is not signed by the classicalKey, and no recoveryKey "
            "was ever designated in this registration -- there is no key "
            "authorised to revoke it after the primary anchor. A signature "
            "that merely verifies against some other key is not trusted.")
    raise RegistrationError(
        "revocation is signed by neither the classicalKey nor the designated "
        "recoveryKey of this registration")
