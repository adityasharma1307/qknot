"""The full registration verification chain: steps 1-8 of the spec, composed.

This ties together proof-of-possession (registration.py), Fulcio chain
verification (fulcio.py), transparency inclusion (rekor.py) and the temporal
decision (temporal.py) into the single verdict the spec's section 4 describes,
and reports WHICH basis it trusted -- direct or rescued-by-timestamp -- rather
than a bare accept.

THE ORDER MATTERS, AND IT IS THE SIGSTORE INSIGHT
=================================================
A Fulcio certificate is short-lived (~10 minutes). Years later it is expired,
so it cannot be validated as-of `now`. It is validated as-of the LOG's
integratedTime `T`: the entry's inclusion proof makes `T` trustworthy, and the
cert was valid then. So inclusion (step 6) runs BEFORE chain validation (step
3), and the chain is checked at `T`. This is exactly how a Sigstore verifier
treats an expired signing cert, and getting the order wrong would reject every
registration older than ten minutes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .fulcio import verify_chain
from .registration import (
    HybridRegistration,
    HybridSignedRegistration,
    RegistrationError,
    SignedRevocation,
    check_not_after,
    verify_proof_of_possession,
    verify_revocation,
)
from .rekor import LogEntry, verify_log_entry
from .temporal import BindingBasis, binding_trust

__all__ = [
    "RegistrationBundle",
    "TrustedBinding",
    "authorize_for_artifact",
    "verify_registration_chain",
]


@dataclass(frozen=True)
class RegistrationBundle:
    """Everything needed to verify a registration offline (spec section 3)."""

    envelope: HybridSignedRegistration
    intermediate_certificates: list[bytes]    # DER; the leaf is in the envelope
    log_entry: LogEntry

    def to_dict(self) -> dict[str, Any]:
        import base64

        return {
            "envelope": self.envelope.to_dict(),
            "intermediateCertificates": [
                base64.b64encode(c).decode("ascii")
                for c in self.intermediate_certificates],
            "logEntry": self.log_entry.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RegistrationBundle:
        import base64

        try:
            return cls(
                envelope=HybridSignedRegistration.from_dict(data["envelope"]),
                intermediate_certificates=[
                    base64.b64decode(c, validate=True)
                    for c in data.get("intermediateCertificates", [])],
                log_entry=LogEntry.from_dict(data["logEntry"]),
            )
        except KeyError as exc:
            raise RegistrationError(f"registration bundle missing {exc}") from exc


@dataclass(frozen=True)
class TrustedBinding:
    """The verdict of steps 1-7: an identity vouches for a PQC key, and how."""

    identity: str
    issuer: str
    pqc_algorithm: str
    pqc_public_key: bytes
    basis: BindingBasis
    valid_as_of: datetime          # the log's integratedTime T
    not_after: str | None
    registration: HybridRegistration


def verify_registration_chain(
    bundle: RegistrationBundle,
    *,
    fulcio_roots: list[bytes],
    log_public_key: bytes,
    now: datetime | None = None,
    policies: dict[str, Any] | None = None,
) -> TrustedBinding:
    """Steps 1-7. Returns the trusted binding, or raises RegistrationError.

    Does NOT apply notAfter or revocation -- those are keyed to a particular
    artefact's signing time and belong in `authorize_for_artifact`. This
    establishes that the registration itself is authentic and the PQC key is
    bound to the identity, and by what basis.
    """
    now = now or datetime.now(timezone.utc)

    # Steps 1, 2, 5: the envelope parses and BOTH keys signed it.
    registration = verify_proof_of_possession(bundle.envelope)

    # Step 6 FIRST: inclusion gives the upper bound T, which the short-lived
    # Fulcio cert must be validated against -- see the module docstring.
    preimage = bundle.envelope.rekord_preimage
    upper_bound = verify_log_entry(
        bundle.log_entry, preimage, log_public_key, at_time=now)

    # Step 3: the Fulcio chain, validated AS OF T, not now.
    try:
        fulcio_identity = verify_chain(
            bundle.envelope.classical_certificate_der,
            bundle.intermediate_certificates,
            fulcio_roots,
            at_time=upper_bound,
        )
    except Exception as exc:  # ChainError and friends -> a registration failure
        raise RegistrationError(f"certificate chain: {exc}") from exc

    # Step 4: the cert's attested identity must match the payload's claim.
    if fulcio_identity.identity != registration.identity:
        raise RegistrationError(
            f"the certificate attests identity {fulcio_identity.identity!r} but "
            f"the registration claims to be from {registration.identity!r}")
    if fulcio_identity.issuer != registration.issuer:
        raise RegistrationError(
            f"the certificate's issuer {fulcio_identity.issuer!r} does not "
            f"match the registration's {registration.issuer!r}")

    # Step 7: can the classical attestation still be trusted to vouch now?
    basis = binding_trust(
        registration.classical_key.algorithm, upper_bound, now=now,
        policies=policies)
    if basis is BindingBasis.REJECTED:
        raise RegistrationError(
            f"the classical anchor ({registration.classical_key.algorithm}) is "
            f"past its disallow date and the registration was not logged before "
            f"that date, so nothing proves the binding predates the algorithm's "
            f"deprecation. It cannot be trusted now.")

    return TrustedBinding(
        identity=registration.identity,
        issuer=registration.issuer,
        pqc_algorithm=registration.pqc_key.algorithm,
        pqc_public_key=registration.pqc_key.public_key,
        basis=basis,
        valid_as_of=upper_bound,
        not_after=registration.not_after,
        registration=registration,
    )


def authorize_for_artifact(
    binding: TrustedBinding,
    artifact_signing_time: datetime,
    *,
    revocations: list[tuple[SignedRevocation, datetime]] | None = None,
    now: datetime | None = None,
    policies: dict[str, Any] | None = None,
) -> bytes:
    """Steps 7.5 and 8: does this trusted binding COVER this artefact?

    Returns the PQC public key to verify the artefact's signature against, or
    raises. Separated from `verify_registration_chain` because both checks are
    keyed to the artefact's signing time, not to whether the registration is
    authentic.

    `revocations` are (signed revocation, its own log time) pairs -- a
    revocation is trustworthy only if it too was logged, and its log time is
    what `verify_revocation` judges the recovery key's rescue against.
    """
    now = now or datetime.now(timezone.utc)

    # Step 7.5: notAfter, against the artefact's signing time.
    check_not_after(binding.registration, artifact_signing_time)

    # Step 8: any revocation dated at or before the artefact's signing time
    # kills the binding for that artefact.
    for signed_revocation, revocation_log_time in (revocations or []):
        revocation = verify_revocation(
            signed_revocation, binding.registration,
            registration_log_time=revocation_log_time, now=now, policies=policies)
        revoked_at = datetime.fromisoformat(
            revocation.revoked_at.replace("Z", "+00:00"))
        if revoked_at <= artifact_signing_time:
            raise RegistrationError(
                f"the PQC key was revoked at {revocation.revoked_at} "
                f"({revocation.reason}), at or before the artefact's signing "
                f"time {artifact_signing_time.isoformat()}. The signature is "
                f"not trusted.")

    return binding.pqc_public_key
