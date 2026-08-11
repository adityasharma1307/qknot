"""Finding revocations in the log -- and being honest when we did not.

`authorize_for_artifact` takes revocations as an argument, which is the correct
offline API: a verifier that already holds the revocations can decide. But a
verifier that holds NONE has two very different situations in front of it, and
conflating them is the softest hole in this entire design:

    "I searched the log and there are no revocations for this key"
    "I did not search / the search failed"

Treating the second as the first hands a free pass to anyone who can make the
search fail -- block the network, rate-limit the verifier, take the log offline
-- which is a far cheaper attack than breaking any of the cryptography this
project is otherwise careful about. So a search here always returns an OUTCOME,
never a bare list, and the outcome of "I could not look" is not "nothing found".

This is the same absent-versus-unchecked rule the artefact scans apply to
`error` rows and the composed verdict applies to signing time, recursed one
level further.

WHAT A SEARCH ACTUALLY PROVES
=============================
Even a successful search proves something narrower than it appears, and this
module does not pretend otherwise:

  * it is a search of ONE log, as of NOW. A revocation logged a second later, or
    to a different log, is not in the answer.
  * it authenticates every candidate it returns through the SAME
    `verify_log_entry` path a registration goes through -- inclusion proof,
    signed checkpoint, SET -- so a revocation is only honoured if the log really
    carries it. An unauthenticated "revocation" found by search is worthless;
    anyone can serve JSON.
  * it does NOT establish that the log is complete or has not been forked.
    Detecting a split view needs a witness/monitor network, which this does not
    implement, and the docstring on the result type says so.

A STRUCTURAL LIMIT OF hashedrekord, STATED PLAINLY
==================================================
Rekor's `hashedrekord` stores a DIGEST, not the document. So the log can prove
that a given revocation statement was logged, and when -- but it cannot hand you
the statement you have never seen. Searching the log by identity yields entries
whose contents are opaque digests.

A revocation therefore needs a DISTRIBUTION channel as well as a log: somewhere
the statements themselves are published (a well-known URL, a repository, an
internal feed). The log's job is to authenticate and timestamp what that channel
serves, which is exactly the job it should have -- the channel need not be
trusted, because a statement it serves is only honoured once the log proves it.

This module takes candidate statements alongside the entries (`qknotRevocation`)
for that reason. When entries exist but their statements cannot be obtained, the
outcome is FAILED, NOT "none found": unexamined candidates are the one thing
that must never be reported as an all-clear.

Whether the revocation is one this registration must HONOUR -- signed by the
classical anchor or the designated recovery key, judged on that key's own
disallow date -- is `verify_revocation`'s decision, not this module's. Here we
only find candidates and prove the log carries them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol

from .registration import (
    REVOCATION_PAYLOAD_TYPE,
    RegistrationError,
    Revocation,
    SignedRevocation,
)

__all__ = [
    "RevocationSearch",
    "RevocationSearchOutcome",
    "RevocationSearchClient",
    "find_revocations",
    "not_searched",
    "supplied",
]


class RevocationSearchOutcome(str, Enum):
    """What actually happened -- never collapsed into "no revocations"."""

    FOUND = "found"                      # searched, and revocations were found
    NONE_FOUND = "none-found"            # searched, and there were none
    NOT_SEARCHED = "not-searched"        # nobody asked for a search
    FAILED = "failed"                    # searched, and the search broke
    SUPPLIED = "supplied"                # caller provided them; no search run


@dataclass(frozen=True)
class RevocationSearch:
    """The result of looking (or not looking) for revocations.

    `revocations` are (statement, log time) pairs, each already proven to be in
    the log; the log time is the authenticated `integratedTime`, which is what
    `verify_revocation` judges a recovery key's rescue against.

    NOT a proof that the log is complete or unforked: a verifier that needs that
    guarantee needs witnesses, which this does not implement.
    """

    outcome: RevocationSearchOutcome
    revocations: list[tuple[SignedRevocation, datetime]] = field(
        default_factory=list)
    detail: str = ""
    candidates_examined: int = 0

    @property
    def is_conclusive(self) -> bool:
        """True only when the absence of revocations was actually established.

        A caller deciding whether to trust a signature must branch on this, not
        on `not self.revocations`.
        """
        return self.outcome in (RevocationSearchOutcome.FOUND,
                                RevocationSearchOutcome.NONE_FOUND,
                                RevocationSearchOutcome.SUPPLIED)


def not_searched(reason: str = "no revocation search was requested") -> RevocationSearch:
    return RevocationSearch(RevocationSearchOutcome.NOT_SEARCHED, detail=reason)


def supplied(
    revocations: list[tuple[SignedRevocation, datetime]],
) -> RevocationSearch:
    """Revocations the caller already holds. Their provenance is the caller's
    problem; this records that no search was performed."""
    return RevocationSearch(
        RevocationSearchOutcome.SUPPLIED, revocations=list(revocations),
        detail="revocations supplied by the caller; the log was not searched")


class RevocationSearchClient(Protocol):
    """The network seam: find candidate log entries for an identity.

    Returns raw transparency-log entries in the shape `log_entry_from_rekor`
    maps. Implementations are dumb transports and make no trust decisions --
    every entry they return is authenticated here before it counts.
    """

    def search_by_identity(self, identity: str) -> list[dict[str, Any]]: ...


def find_revocations(
    identity: str,
    pqc_key_fingerprint: str,
    *,
    client: RevocationSearchClient,
    log_public_key: bytes,
    now: datetime | None = None,
    known_non_revocation_digests: set[str] | None = None,
) -> RevocationSearch:
    """Search the log for revocations of `(identity, pqc_key_fingerprint)`.

    Every candidate is authenticated through `verify_log_entry` -- the same
    inclusion proof, signed checkpoint and SET a registration goes through -- so
    the result contains only revocations the log demonstrably carries. Entries
    that are not qknot revocations, or that name a different identity or key,
    are ignored rather than treated as failures: a log search legitimately
    returns unrelated entries.

    `known_non_revocation_digests` are digests the caller already knows are NOT
    revocations (typically the registration pre-image of the binding being
    verified). Without that filter, every identity that has registered produces
    unexaminable hashedrekord entries (the registration itself) and the search
    would always return FAILED for lack of a statement feed -- which is honest
    about opacity but useless for the common case of "I registered, I never
    revoked." Known digests are skipped, not counted as unexaminable.

    A transport failure returns outcome FAILED. It does NOT raise, because the
    caller must be able to render "I could not check" as a verdict rather than a
    crash -- but it also must not be able to mistake it for "nothing found".
    """
    from .dsse import rekord_preimage
    from .rekor import (
        InclusionError,
        hashedrekord_digest,
        log_entry_from_rekor,
        verify_log_entry,
    )

    known = {d.lower() for d in (known_non_revocation_digests or set())}

    try:
        raw_entries = client.search_by_identity(identity)
    except Exception as exc:  # noqa: BLE001 -- any transport failure is FAILED
        return RevocationSearch(
            RevocationSearchOutcome.FAILED,
            detail=f"the revocation search could not be completed: {exc}. "
                   f"This is NOT evidence that no revocation exists.")

    found: list[tuple[SignedRevocation, datetime]] = []
    examined = 0
    unexaminable = 0
    skipped_known = 0
    for raw in raw_entries:
        examined += 1
        try:
            entry = log_entry_from_rekor(raw)
        except InclusionError:
            continue                     # not an entry shape we can read

        # Known non-revocations (e.g. this binding's registration pre-image):
        # skip before demanding a statement. The log indexes by identity, so
        # the registration entry always shows up and is not a revocation.
        try:
            entry_digest = hashedrekord_digest(entry.entry_body).hex()
        except InclusionError:
            entry_digest = ""
        if entry_digest and entry_digest.lower() in known:
            skipped_known += 1
            continue

        # The revocation statement travels alongside the entry: the log stores a
        # digest, not the document (see the module docstring). Without the
        # statement this candidate cannot be examined -- which is NOT the same as
        # examining it and finding it harmless, so it is counted separately.
        statement = raw.get("qknotRevocation")
        if not isinstance(statement, dict):
            unexaminable += 1
            continue
        try:
            payload = _b64(statement["payload"])
            signature = _b64(statement["signature"])
        except (KeyError, ValueError, TypeError):
            unexaminable += 1
            continue

        # Is it a revocation for THIS key? Parse before trusting anything.
        try:
            revocation = Revocation.from_payload(payload)
        except RegistrationError:
            continue
        if (revocation.identity != identity
                or revocation.pqc_key_fingerprint != pqc_key_fingerprint):
            continue                     # a real revocation, but not of this key

        # It CLAIMS to be about this key. Now make the LOG prove it carries it:
        # the entry's digest must be this statement's pre-image.
        #
        # From here on, failure is INCONCLUSIVE rather than harmless. A
        # candidate naming this key that does not authenticate is either noise,
        # or a real revocation whose proof has been corrupted by someone who
        # wants it ignored. Silently skipping it would let an attacker suppress
        # a revocation by damaging its proof -- the same unearned all-clear this
        # module exists to prevent, arrived at from the other direction.
        expected = rekord_preimage(REVOCATION_PAYLOAD_TYPE, payload)
        try:
            if hashedrekord_digest(entry.entry_body) != expected:
                unexaminable += 1        # the entry is not about this statement
                continue
            logged_at = verify_log_entry(entry, expected, log_public_key,
                                         at_time=now)
        except InclusionError:
            unexaminable += 1
            continue
        found.append((SignedRevocation(payload=payload, signature=signature),
                      logged_at))

    if found:
        return RevocationSearch(
            RevocationSearchOutcome.FOUND, revocations=found,
            candidates_examined=examined,
            detail=f"{len(found)} authenticated revocation(s) for this key")
    if unexaminable:
        # Entries exist that we could not read. Reporting "none found" here
        # would be the exact conflation this module exists to prevent.
        return RevocationSearch(
            RevocationSearchOutcome.FAILED, candidates_examined=examined,
            detail=f"{unexaminable} of {examined} log entr(ies) for {identity} "
                   f"could not be examined or did not authenticate"
                   f"{f' ({skipped_known} known non-revocation(s) skipped)' if skipped_known else ''}. "
                   f"The log stores digests, so an entry whose statement is "
                   f"unavailable is opaque; pass --revocation-statements with a "
                   f"published feed to examine candidates. Whether this key is "
                   f"revoked is UNKNOWN, not 'no'.")
    detail = (
        f"searched {examined} log entr(ies) for {identity}; none was an "
        f"authenticated revocation of this key"
    )
    if skipped_known:
        detail += (
            f" ({skipped_known} known non-revocation entr(ies) skipped, "
            f"e.g. the registration itself)"
        )
    detail += (
        ". This is a search of one log as of now, not a proof that none will "
        "ever exist."
    )
    return RevocationSearch(
        RevocationSearchOutcome.NONE_FOUND, candidates_examined=examined,
        detail=detail)


def _b64(value: str) -> bytes:
    import base64

    return base64.b64decode(value + "=" * (-len(value) % 4))
