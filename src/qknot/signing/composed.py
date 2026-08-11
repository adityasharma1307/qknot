"""One verdict: this artefact was signed by a key an IDENTITY vouched for.

Verifying an artefact and verifying a registration are two different facts, and
holding both is worth nothing on its own -- "this signature is valid" plus
"alice registered some key" does not say alice signed this. The join is the
point of this module, and it is exactly one line of trust reasoning:

    the PQC key the artefact's signature was verified under MUST BE the PQC key
    the registration authorises.

Everything else here is composition of pieces that are already sealed and
tested: `sign.verify` for the artefact, `verify_registration_chain` for the
binding, `authorize_for_artifact` for notAfter and revocation. No cryptography
is reimplemented, and no verdict is softened.

THE SIGNING TIME IS TREATED WITH THE THREE-OUTCOME DISCIPLINE
=============================================================
`authorize_for_artifact` is keyed to WHEN THE ARTEFACT WAS SIGNED, not to the
verifier's clock. That time is evidence, and evidence can be absent:

  * TRUSTED    -- an upper bound from independent time evidence (a TSA
                  timestamp, a log entry). The real thing.
  * SUPPLIED   -- the caller asserted it. Useful for "would this have been
                  covered?" questions, and honestly labelled as an assertion.
  * UNESTABLISHED -- nothing trustworthy. The artefact's own `timestamp` field
                  is NOT evidence: a forger writes one too.

When the signing time is UNESTABLISHED, this module does not quietly skip
notAfter and revocation and report success. If the registration carries a
`notAfter`, or any revocation is supplied, the coverage question is REAL and
cannot be answered, so it refuses. If neither exists, the checks are vacuous --
there is nothing they could have ruled out -- and it proceeds, saying so. That
is the difference between "checked and passed" and "not checked", which this
project refuses to blur.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .registration import RegistrationError, SignedRevocation
from .registration_chain import (
    RegistrationBundle,
    authorize_for_artifact,
    verify_registration_chain,
)
from .revocation_search import RevocationSearch, not_searched, supplied
from .sign import SignedArtefact, VerifyMode, verify
from .temporal import BindingBasis

__all__ = [
    "AuthorisedArtefact",
    "SigningTimeSource",
    "verify_artefact_against_registration",
]


class SigningTimeSource(str, Enum):
    """Where the artefact's signing time came from -- and so what it is worth."""

    TRUSTED = "trusted-time-evidence"
    SUPPLIED = "supplied-by-caller"
    UNESTABLISHED = "unestablished"


@dataclass(frozen=True)
class AuthorisedArtefact:
    """The composed verdict: a valid artefact, tied to a vouched-for identity."""

    identity: str
    issuer: str
    basis: BindingBasis                 # direct, or rescued-by-timestamp
    pqc_algorithm: str
    registration_logged_at: datetime    # the log's integratedTime, T
    signing_time: datetime | None
    signing_time_source: SigningTimeSource
    coverage_checked: bool              # were notAfter/revocation actually ruled on?
    revocation_search: RevocationSearch  # what was (or was not) established
    artefact_report: dict[str, Any]     # what `verify` checked, verbatim

    @property
    def revocation_status_is_conclusive(self) -> bool:
        """Whether "not revoked" was ESTABLISHED rather than merely unobserved.

        A caller that renders this verdict must surface a False here. It is the
        difference between "the log says this key is live" and "nobody looked".
        """
        return self.revocation_search.is_conclusive


def _trusted_upper_bound(signed: SignedArtefact) -> datetime | None:
    """An UPPER bound on the artefact's signing time, if the bundle proves one.

    Only an upper bound will do: it is what says "the signature already existed
    by then". A lower bound (an entropy beacon) cannot answer whether a
    registration that lapsed still covered the signature.
    """
    from .temporal import evidence_from_attestation

    evidence = evidence_from_attestation(signed.entropy_attestation)
    return evidence.proves_not_after if evidence else None


def verify_artefact_against_registration(
    target: Path | bytes,
    artefact: SignedArtefact,
    registration: RegistrationBundle,
    *,
    fulcio_roots: list[bytes],
    log_public_key: bytes,
    mode: VerifyMode = VerifyMode.STRICT,
    context: bytes = b"",
    revocations: list[tuple[SignedRevocation, datetime]] | None = None,
    revocation_search: RevocationSearch | None = None,
    artefact_signed_at: datetime | None = None,
    now: datetime | None = None,
    policies: dict[str, Any] | None = None,
) -> AuthorisedArtefact:
    """Verify an artefact AND that an identity vouched for the key that signed it.

    Raises `VerificationFailed` if the artefact's own signature does not hold,
    and `RegistrationError` if the registration does not verify, does not cover
    the artefact, or -- the join -- authorises a different key than the one the
    artefact was signed under.
    """
    now = now or datetime.now(timezone.utc)

    # 1. The artefact's own signature. Unchanged, and it runs FIRST: there is no
    #    point asking who vouched for a key if the signature is not valid.
    report = verify(target, artefact, mode=mode, context=context)

    # 2. The registration: is this identity's vouching for a PQC key trustworthy,
    #    and on what basis (direct, or rescued by the log's timestamp)?
    binding = verify_registration_chain(
        registration, fulcio_roots=fulcio_roots, log_public_key=log_public_key,
        now=now, policies=policies)

    # 3. Revocations. Either the caller already holds them, or a search was
    #    run and carries its own outcome. Both are recorded; neither is allowed
    #    to become a bare empty list, because "found none" and "did not look"
    #    are different answers and only one of them is reassuring.
    if revocation_search is not None:
        search = revocation_search
    elif revocations:
        search = supplied(revocations)
    else:
        search = not_searched()
    known_revocations = list(search.revocations)

    # 4. When was the artefact signed? Evidence, or honestly absent.
    if artefact_signed_at is not None:
        signing_time: datetime | None = artefact_signed_at
        source = SigningTimeSource.SUPPLIED
    elif (proven := _trusted_upper_bound(artefact)) is not None:
        signing_time, source = proven, SigningTimeSource.TRUSTED
    else:
        signing_time, source = None, SigningTimeSource.UNESTABLISHED

    # 5. Coverage: notAfter and revocation, keyed to that signing time.
    if signing_time is not None:
        authorised_key = authorize_for_artifact(
            binding, signing_time, revocations=known_revocations, now=now,
            policies=policies)
        coverage_checked = True
    else:
        # Nothing trustworthy says when this was signed. Refuse to pretend the
        # coverage questions were answered when they are live questions.
        if binding.not_after is not None:
            raise RegistrationError(
                f"the registration limits itself to artefacts signed before "
                f"{binding.not_after}, but this artefact carries no trustworthy "
                f"signing time, so whether it is covered cannot be decided. "
                f"Supply one (a timestamp, or an explicit assertion) rather than "
                f"treat an unanswerable question as a pass.")
        if known_revocations:
            raise RegistrationError(
                f"{len(known_revocations)} revocation(s) exist for this key, but "
                f"this artefact carries no trustworthy signing time, so whether "
                f"it was signed before or after the revocation cannot be "
                f"decided. That is not a pass.")
        # No notAfter and no revocations: the checks are vacuous, not skipped.
        authorised_key = binding.pqc_public_key
        coverage_checked = False

    # 6. THE JOIN. The artefact must have been signed under the very key the
    #    registration authorises. Without this the two verifications above are
    #    unrelated facts and the verdict would be a non sequitur.
    signed_under = artefact.public_keys.get(binding.pqc_algorithm)
    if signed_under is None:
        raise RegistrationError(
            f"the registration vouches for a {binding.pqc_algorithm} key, but "
            f"the artefact carries no {binding.pqc_algorithm} public key, so "
            f"the registration cannot be about this signature. Keys present: "
            f"{sorted(artefact.public_keys)}")
    if signed_under != authorised_key:
        raise RegistrationError(
            f"the artefact was signed under a {binding.pqc_algorithm} key that "
            f"this registration does not authorise. {binding.identity} vouched "
            f"for a different key, so this signature is NOT attributable to "
            f"them -- both the signature and the registration are individually "
            f"valid, which is exactly the confusion this check exists to stop.")

    return AuthorisedArtefact(
        identity=binding.identity,
        issuer=binding.issuer,
        basis=binding.basis,
        pqc_algorithm=binding.pqc_algorithm,
        registration_logged_at=binding.valid_as_of,
        signing_time=signing_time,
        signing_time_source=source,
        coverage_checked=coverage_checked,
        revocation_search=search,
        artefact_report=report,
    )
