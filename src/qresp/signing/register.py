"""`qresp register`: the eight-step orchestrator that produces a bundle.

Thin by design. It COMPOSES the sealed pieces -- `sign_hybrid_registration`,
`rekord_preimage`, `log_entry_from_rekor`, `verify_registration_chain` -- and
reimplements none of the checkpoint / SET / chain math. The two network
operations (get a Fulcio certificate, submit to Rekor) live behind a Protocol
seam, so the orchestration is pure, offline-testable logic: a real deployment
injects vetted Sigstore clients; tests inject fakes that mint the same trust
stack the rest of the suite uses.

The eight steps (spec section 7):

  1. hold/generate the classical P-256 key -- the deprecating anchor. It is
     ephemeral, exactly like Fulcio's own signing key: its job is to be
     certified and to sign this one registration.
  2. get a Fulcio certificate over it (FulcioClient; does OIDC internally).
  3. hold the long-term PQC key -- the caller's, and the thing being registered.
  4. build the dual-signed hybrid registration, with identity and issuer taken
     FROM the certificate, never free-typed, so the payload cannot claim an
     identity the cert does not attest.
  5. submit a hashedrekord: digest = rekord_preimage(...), signature = the
     classical DSSE signature (RekorClient).
  6. fetch the inclusion proof + checkpoint + SET (the client's response).
  7. map that response into a LogEntry with the shared mapper (both indices).
  8. assemble the RegistrationBundle and -- MANDATORY -- verify it end to end
     before returning. A registration that logs but does not verify is a
     failure, not a success; the same-process check is what keeps `register`
     honest and stops residual-3 work from silently reopening residuals 1 or 2.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .backends import get_backend
from .fulcio import identity_from_leaf
from .registration import (
    HybridRegistration,
    KeyRef,
    RegistrationError,
    sign_hybrid_registration,
)
from .registration_chain import RegistrationBundle, verify_registration_chain
from .rekor import log_entry_from_rekor

__all__ = [
    "FulcioCertificate",
    "FulcioClient",
    "RekorClient",
    "register",
]


@dataclass(frozen=True)
class FulcioCertificate:
    """What a Fulcio client returns: the leaf that attests the classical key,
    plus any intermediates needed to chain it to a trusted root."""

    leaf_der: bytes
    intermediate_ders: list[bytes] = field(default_factory=list)


class FulcioClient(Protocol):
    """The OIDC + Fulcio network seam. A real implementation runs the OIDC flow
    and certifies the classical key; it proves possession of that key to Fulcio.
    Kept behind a Protocol so the orchestrator never touches the network and can
    be exercised offline against a minted CA."""

    def certify(
        self,
        classical_public_key_spki_der: bytes,
        classical_secret_pkcs8_der: bytes,
    ) -> FulcioCertificate: ...


class RekorClient(Protocol):
    """The Rekor network seam. Submits a hashedrekord and returns the log's
    TransparencyLogEntry response (inclusion proof + checkpoint + SET) as JSON,
    exactly the shape `log_entry_from_rekor` maps."""

    def submit_hashedrekord(
        self,
        *,
        preimage: bytes,
        classical_signature: bytes,
        certificate_der: bytes,
    ) -> dict[str, Any]: ...


def register(
    *,
    pqc_algorithm: str,
    pqc_public_key: bytes,
    pqc_secret: bytes,
    fulcio: FulcioClient,
    rekor: RekorClient,
    fulcio_roots: list[bytes],
    log_public_key: bytes,
    classical_algorithm: str = "ecdsa-p256",
    created: datetime | None = None,
    not_after: str | None = None,
    recovery_key: KeyRef | None = None,
    now: datetime | None = None,
) -> RegistrationBundle:
    """Run the eight steps and return a bundle that has ALREADY been verified.

    The PQC key pair is the caller's long-term key. The classical key is
    generated here and is ephemeral. `fulcio_roots` and `log_public_key` are the
    verifier-side trust material used by the mandatory step-8 round-trip check;
    passing them here is deliberate -- `register` refuses to hand back a bundle
    it cannot itself verify.
    """
    now = now or datetime.now(timezone.utc)
    created = created or now

    # 1. The classical anchor key (ephemeral, like Fulcio's own signing key).
    classical = get_backend(classical_algorithm)
    classical_public, classical_secret = classical.keygen()

    # 2. A Fulcio certificate over it (OIDC happens inside the client).
    certificate = fulcio.certify(classical_public, classical_secret)

    # 4a. Identity and issuer come FROM the certificate, never free-typed.
    attested = identity_from_leaf(certificate.leaf_der)

    # 3 + 4. The dual-signed hybrid registration over one PAE'd payload.
    registration = HybridRegistration(
        identity=attested.identity,
        issuer=attested.issuer,
        classical_key=KeyRef(classical_algorithm, classical_public),
        pqc_key=KeyRef(pqc_algorithm, pqc_public_key),
        created=created.isoformat(),
        not_after=not_after,
        recovery_key=recovery_key,
    )
    envelope = sign_hybrid_registration(
        registration, classical_secret, pqc_secret, certificate.leaf_der)

    # 5 + 6. Submit the hashedrekord and take the log's response.
    response = rekor.submit_hashedrekord(
        preimage=envelope.rekord_preimage,
        classical_signature=envelope.classical_signature,
        certificate_der=certificate.leaf_der,
    )

    # 7. Map the response into a LogEntry (the shared mapper; both indices).
    log_entry = log_entry_from_rekor(response)

    # 8. Assemble, then verify end to end BEFORE returning. Verification runs
    #    with no special cases -- the exact call a third-party verifier makes.
    bundle = RegistrationBundle(
        envelope=envelope,
        intermediate_certificates=certificate.intermediate_ders,
        log_entry=log_entry,
    )
    try:
        verify_registration_chain(
            bundle, fulcio_roots=fulcio_roots,
            log_public_key=log_public_key, now=now)
    except RegistrationError as exc:
        raise RegistrationError(
            f"register produced a bundle that does not verify, so it is not a "
            f"successful registration: {exc}") from exc
    return bundle
