"""Upper-bound time evidence: RFC 3161 timestamps over a signature.

WHY A TIMESTAMP AUTHORITY AND NOT REKOR
=======================================
`temporal.py` can rescue a signature whose algorithm was later disallowed, but
only given an UPPER bound -- evidence the signature *already existed* at time T.
Nothing in a bundle provides that on its own, so until now the rescue branch was
unreachable from any real artefact.

The obvious source is a transparency log. It is not usable here, and the reason
is worth stating because it is a finding rather than an inconvenience:

  * Rekor v2 supports only the `hashedrekord` entry type, whose digest is taken
    over an externalised prehash (rekor-v2-spec 6.1.4).
  * ML-DSA has no externalised prehash in Sigstore's algorithm registry, so a
    post-quantum signature cannot be logged at all.
  * Fulcio will not certify an ML-DSA key either.

The deployed transparency ecosystem has no post-quantum path. That is precisely
the gap this project documents, so building on it was never an option.

An RFC 3161 Time-Stamp Authority has none of those constraints: **it hashes
opaque bytes**. It never parses the signature, never learns the algorithm, and
never needs to recognise the key. `sigstore-python` relies on the same property
-- `_verify_signed_timestamp(tsr, bundle.signature)` passes raw signature bytes
-- so this is not a workaround invented here, it is the mechanism the ecosystem
already uses for exactly this purpose, and the one part of it that happens to be
algorithm-agnostic.

WHAT A TIMESTAMP DOES AND DOES NOT PROVE
========================================
It proves these bytes existed at time T. It says nothing about who made them,
whether the signer was authorised, or whether the artefact is what it claims to
be. It is time evidence and only time evidence, which is why it produces a
`TimeEvidence` with `Bound.UPPER` and nothing else.

It also gives no *discoverability*: a timestamp is evidence you hold and must
present, whereas a log entry is evidence a third party can go and find. For key
registration that difference matters and Rekor earns its complexity; for
rescuing an artefact signature it does not, because the verifier already has
the bundle in hand.

OFFLINE BY CONSTRUCTION
=======================
Obtaining a timestamp needs the network exactly once, at signing time.
Verification never does: `verify_timestamp` takes trust anchors as an argument
and performs no I/O. A verifier that must reach a server to decide whether a
signature is valid has made availability a precondition of integrity, which is
the wrong trade for an air-gapped release pipeline -- and would make this
project's own offline verification claim false.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "DEFAULT_TSA_URLS",
    "VERIFIED_TIME_THRESHOLD",
    "TimestampError",
    "TimestampToken",
    "TimestampUnavailableError",
    "establish_time",
    "request_timestamp",
    "verify_timestamp",
]


# Two operators, deliberately. See `establish_time`.
DEFAULT_TSA_URLS: tuple[str, ...] = (
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
)

# How many INDEPENDENT verified times an artefact must carry.
#
# sigstore-python sets its equivalent to 1 (verify/verifier.py:68). Two is
# stricter, and the reason is that a timestamp is a trust delegation: one TSA
# that is compromised, coerced, or simply wrong about its own clock can move a
# signature across an algorithm-deprecation boundary, which is the single
# decision this evidence exists to make. Two operators in different
# jurisdictions must both be wrong in the same direction for that to happen.
#
# It is a policy number, not a law: `establish_time(threshold=1)` is a supported
# and sometimes correct choice. It is not the default.
VERIFIED_TIME_THRESHOLD = 2

_MAX_TIMESTAMPS = 32          # refuse absurd bundles rather than loop over them


class TimestampError(Exception):
    """A timestamp was present but did not verify."""


class TimestampUnavailableError(Exception):
    """A timestamp could not be obtained. Distinct from `TimestampError`.

    "I could not reach a TSA" and "this timestamp is forged" must never be
    reported the same way, and must never be caught by the same handler. The
    first is an availability problem at signing time; the second is an attack.
    """


def _require_client() -> Any:
    """Import the RFC 3161 implementation, or explain what to install.

    Lazily, so `qresp sign` keeps working without it -- the same package
    boundary discipline that keeps the audit dependencies out of the signing
    path. Timestamping is opt-in; signing without it is a supported
    configuration that simply cannot rescue a deprecated algorithm later.
    """
    try:
        import rfc3161_client
    except ImportError as exc:                    # pragma: no cover
        raise TimestampUnavailableError(
            "RFC 3161 support needs `rfc3161-client`. Install with:\n"
            "    pip install 'qresp[transparency]'\n"
            "Signing works without it; timestamping and algorithm-deprecation "
            "rescue do not."
        ) from exc
    return rfc3161_client


@dataclass(frozen=True)
class TimestampToken:
    """An RFC 3161 response, kept as the bytes the TSA actually signed.

    The DER is retained verbatim rather than decomposed into fields. A parsed
    copy is not evidence -- only the signed bytes are -- and re-encoding ASN.1
    is a reliable way to invalidate a signature you meant to preserve.
    """

    der: bytes
    url: str | None = None

    # ---- serialisation ---------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "rfc3161",
            "url": self.url,
            "response": base64.b64encode(self.der).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimestampToken:
        if data.get("kind") != "rfc3161":
            raise TimestampError(
                f"unsupported time-evidence kind {data.get('kind')!r}; this "
                f"verifier understands 'rfc3161'"
            )
        raw = data.get("response")
        if not isinstance(raw, str):
            raise TimestampError("time evidence has no 'response' field")
        try:
            der = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise TimestampError(f"'response' is not valid base64: {exc}") from exc
        return cls(der=der, url=data.get("url"))

    # ---- inspection ------------------------------------------------------
    @property
    def gen_time(self) -> datetime:
        """The time the TSA asserts, WITHOUT verifying its signature.

        Deliberately separate from `verify_timestamp`. Reading a field out of
        unverified ASN.1 is parsing, not proof, and code that conflates the two
        is how an attacker-supplied timestamp gets believed. Nothing in the
        trust path may call this; it exists for diagnostics and for error
        messages that want to say what was claimed.
        """
        client = _require_client()
        response = client.decode_timestamp_response(self.der)
        stamped: datetime = response.tst_info.gen_time
        return stamped if stamped.tzinfo else stamped.replace(tzinfo=timezone.utc)


def request_timestamp(
    message: bytes,
    url: str,
    *,
    session: Any = None,
    timeout: float = 10.0,
) -> TimestampToken:
    """Ask a TSA to timestamp `message`. The only function here that uses I/O.

    `message` should be the signature bytes, not the artefact digest. Timestamping
    the digest would prove the *artefact* existed, which nobody doubts; what has
    to be pinned in time is the signature over it.
    """
    client = _require_client()

    request = (
        client.TimestampRequestBuilder()
        .data(message)
        .nonce(nonce=True)          # replay protection on this exchange
        .cert_request(True)         # ask the TSA to include its certificate
        .build()
    )

    if session is None:
        import requests

        session = requests.Session()

    try:
        reply = session.post(
            url,
            data=request.as_bytes(),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=timeout,
        )
        reply.raise_for_status()
    except Exception as exc:
        raise TimestampUnavailableError(f"{url}: {exc}") from exc

    try:
        response = client.decode_timestamp_response(reply.content)
    except Exception as exc:
        raise TimestampError(f"{url} returned an undecodable response: {exc}") from exc

    if response.status != client.PKIStatus.GRANTED:
        raise TimestampUnavailableError(
            f"{url} refused: status={response.status} {response.status_string}"
        )

    return TimestampToken(der=reply.content, url=url)


def verify_timestamp(
    token: TimestampToken,
    message: bytes,
    *,
    tsa_certificate: Any,
    roots: list[Any],
    intermediates: list[Any] | None = None,
) -> datetime:
    """Verify a timestamp offline and return the time it establishes.

    Performs no I/O. Trust anchors are arguments, so a verifier decides for
    itself whom it trusts rather than inheriting whatever the bundle asserts --
    a bundle that carried its own root certificate would be self-certifying, and
    an attacker who can add a timestamp can add a root to go with it.

    `message` MUST be the bytes the caller independently expects to have been
    timestamped. This is the whole security property: a valid timestamp over
    *different* bytes is not evidence about this signature, and passing bytes
    taken from the same untrusted bundle would verify a token against itself.
    """
    client = _require_client()

    # Check our own configuration BEFORE parsing attacker-controlled bytes.
    # Ordering matters twice over: an empty trust store is a deployment error
    # that should be reported as one rather than as a malformed token, and
    # there is no reason to hand untrusted ASN.1 to a parser when the result
    # could not be trusted regardless of what it says.
    if not roots:
        raise TimestampError(
            "no root certificates supplied; a timestamp cannot be verified "
            "against an empty trust store, and treating that as success would "
            "make every forged token valid"
        )

    try:
        response = client.decode_timestamp_response(token.der)
    except Exception as exc:
        raise TimestampError(f"undecodable timestamp response: {exc}") from exc

    builder = client.VerifierBuilder().tsa_certificate(tsa_certificate)
    for root in roots:
        builder = builder.add_root_certificate(root)
    for intermediate in intermediates or []:
        builder = builder.add_intermediate_certificate(intermediate)

    try:
        builder.build().verify_message(response, message)
    except Exception as exc:
        raise TimestampError(f"timestamp does not verify: {exc}") from exc

    stamped: datetime = response.tst_info.gen_time
    return stamped if stamped.tzinfo else stamped.replace(tzinfo=timezone.utc)


def establish_time(
    tokens: list[TimestampToken],
    message: bytes,
    *,
    anchors: dict[str, Any],
    threshold: int = VERIFIED_TIME_THRESHOLD,
) -> datetime:
    """Verify every token and return the EARLIEST time that survives.

    Two policies, both borrowed from deployed practice and both deliberate.

    **Earliest, not latest.** cosign does the same -- `pkg/cosign/verify.go`:
    *"Always return the earliest integrated entry. That always suffices for
    verification of signature time."* For an upper bound, earliest is the
    strongest defensible claim: asserting a signature existed by January is
    harder to satisfy than by March, so taking the earliest never overstates
    what the evidence supports. Taking the latest would let an attacker who
    obtained one late timestamp push a signature past a deprecation boundary
    simply by adding it.

    **Threshold, not one.** See `VERIFIED_TIME_THRESHOLD`.

    Raises rather than returning a sentinel, because "could not establish a
    time" and "established the epoch" must not be confusable by a caller.
    """
    if len(tokens) > _MAX_TIMESTAMPS:
        raise TimestampError(
            f"{len(tokens)} timestamps supplied (limit {_MAX_TIMESTAMPS}); "
            f"refusing to verify an unbounded list"
        )

    seen: set[bytes] = set()
    verified: list[datetime] = []
    failures: list[str] = []

    for token in tokens:
        # Duplicates must not count towards the threshold. Otherwise the same
        # token pasted twice satisfies "two independent sources", which is the
        # cheapest possible forgery of independence.
        if token.der in seen:
            failures.append(f"{token.url or 'unknown'}: duplicate token ignored")
            continue
        seen.add(token.der)

        anchor = anchors.get(token.url or "")
        if anchor is None:
            failures.append(
                f"{token.url or 'unknown'}: no trust anchor configured for this "
                f"authority, so its timestamp cannot be checked"
            )
            continue

        try:
            verified.append(verify_timestamp(
                token, message,
                tsa_certificate=anchor["tsa_certificate"],
                roots=anchor["roots"],
                intermediates=anchor.get("intermediates"),
            ))
        except TimestampError as exc:
            failures.append(f"{token.url or 'unknown'}: {exc}")

    if len(verified) < threshold:
        detail = "; ".join(failures) if failures else "none supplied"
        raise TimestampError(
            f"{len(verified)} verified timestamp(s), need {threshold}. "
            f"Cannot establish an upper bound on signing time. Detail: {detail}"
        )

    return min(verified)
