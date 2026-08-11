"""When a signature stops meaning anything.

TWO QUESTIONS, OFTEN CONFLATED
==============================
A signature made with a now-weak algorithm raises two separate questions, and
answering only the first is the common mistake:

  1. **Was the signer negligent?** Did they sign with an algorithm that was
     already deprecated at the time? That is a process failure, and it is what
     most "algorithm deprecation" checks test.

  2. **Is the signature still evidence?** Once an algorithm is genuinely
     broken, an attacker can forge a signature *and claim it was made years
     ago*. Every old signature under that algorithm becomes indistinguishable
     from a fresh forgery. The signature does not decay because it is old; it
     decays because the attacker's new forgeries are now equally plausible.

The second is the one that matters for long-lived artefacts, and it has an
unintuitive consequence: **an old signature is only worth more than a new
forgery if there is independent evidence of when it was made.**

EVIDENCE OF TIME HAS A DIRECTION, AND THE DIRECTION IS THE WHOLE POINT
======================================================================
This is the distinction an earlier version of this module got wrong, and it is
worth stating precisely because the error is natural and invisible: it treats
"trusted timestamp" as one thing when it is two.

  **Lower bound** -- "this signature was made no EARLIER than T."
      A NIST beacon pulse gives this. The pulse value did not exist before it
      was published, so anything derived from it came afterwards.

  **Upper bound** -- "this signature already existed at T."
      A transparency-log inclusion proof gives this. The log is append-only and
      witnessed, so an entry could not have been inserted later.

The two answer different questions and are not interchangeable:

    to RESCUE an old signature      need: signature <= break date   UPPER bound
    to CONVICT a negligent signer   need: signature >  deadline     LOWER bound

A beacon pulse cannot rescue a signature. Knowing a signature was made no
earlier than 2026 says nothing about whether it was made before 2030. The
beacon establishes the opposite bound from the one a rescue requires.

This matters in practice and not only in principle, because the entropy
attestation this package produces carries a beacon pulse and therefore yields
only a lower bound. **A bundle signed by this package cannot, on its own
evidence, have a classical signature rescued after the deadline.** Getting an
upper bound requires logging the signature to a transparency log, which is a
publishing step this package does not perform. `evidence_from_attestation`
reflects that honestly rather than overclaiming, and the assessment says so in
as many words instead of failing silently.

THE DATES BELOW ARE POLICY, NOT OBSERVATION
===========================================
No public algorithm in the registry has been *observed* broken. The dates are
standards-body positions on when each becomes unacceptable, and they move. They
live in `algorithms.py` with their sources, alongside the Shor-resistance and
backend-availability facts, so the three cannot drift apart.

The default posture is therefore SOFT WARNING. Failing verification because a
standards body picked a date would break every legitimately-signed artefact on
a calendar boundary. STRICT mode makes it a hard failure, for callers who have
decided that is the trade they want.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .algorithms import REGISTRY as ALGORITHM_POLICIES
from .algorithms import AlgorithmSpec as AlgorithmPolicy
from .algorithms import TrustStatus


class Bound(str, Enum):
    """Which direction a piece of time evidence constrains.

    Naming these is the fix for the bug this module used to have. With a single
    `trusted` flag there was no way to express that a beacon and a transparency
    log prove opposite things, so both were used for both purposes and one of
    those uses was unsound.
    """

    LOWER = "lower"   # the signature was made no EARLIER than this time
    UPPER = "upper"   # the signature already EXISTED at this time


@dataclass(frozen=True)
class TimeEvidence:
    """Independent evidence of when a signature was made.

    Two fields carry the weight. `trusted` says whether the claim is worth
    anything at all -- a timestamp the signer wrote themselves is not evidence,
    because an attacker forging a signature writes one too. `bound` says which
    question it can answer; see the module docstring.
    """

    kind: str                     # "transparency-log" | "beacon" | "self-asserted"
    timestamp: str
    trusted: bool
    bound: Bound
    reference: dict[str, Any] | None = None

    @classmethod
    def from_beacon(cls, not_before: str,
                    reference: dict[str, Any] | None = None) -> TimeEvidence:
        """A beacon pulse fixes a LOWER bound: the signature cannot predate it.

        Sufficient to show a signer used an algorithm after its deadline. NOT
        sufficient to show a signature predates a break -- see the module
        docstring for why that asymmetry is not a technicality.
        """
        return cls(kind="beacon", timestamp=not_before, trusted=True,
                   bound=Bound.LOWER, reference=reference)

    @classmethod
    def from_transparency_log(
        cls, entry_time: str, reference: dict[str, Any] | None = None
    ) -> TimeEvidence:
        """An append-only log entry fixes an UPPER bound: it existed by then.

        This is the only evidence in this module that can rescue a signature
        whose algorithm has since passed its deadline.
        """
        return cls(kind="transparency-log", timestamp=entry_time, trusted=True,
                   bound=Bound.UPPER, reference=reference)

    @classmethod
    def from_timestamp_authority(
        cls, gen_time: str, reference: dict[str, Any] | None = None
    ) -> TimeEvidence:
        """A verified RFC 3161 timestamp fixes an UPPER bound.

        Same direction as a transparency-log entry and for the same reason: the
        TSA signed over bytes that must therefore have existed when it did so.
        It is a *different* kind because the two are not interchangeable in
        every respect -- a log entry is publicly discoverable, a timestamp is
        evidence the holder must present -- and a reader of an attestation is
        entitled to know which one they have.

        Only construct this AFTER `transparency.verify_timestamp` has returned.
        The constructor cannot check the signature, so calling it on an
        unverified token would mint trusted evidence out of attacker-supplied
        bytes.
        """
        return cls(kind="timestamp-authority", timestamp=gen_time, trusted=True,
                   bound=Bound.UPPER, reference=reference)

    @classmethod
    def self_asserted(cls, timestamp: str) -> TimeEvidence:
        """What the signer claims. Recorded, never relied on."""
        return cls(kind="self-asserted", timestamp=timestamp, trusted=False,
                   bound=Bound.UPPER)

    @property
    def as_datetime(self) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @property
    def proves_not_after(self) -> datetime | None:
        """The time by which the signature demonstrably existed, if established."""
        if self.trusted and self.bound is Bound.UPPER:
            return self.as_datetime
        return None

    @property
    def proves_not_before(self) -> datetime | None:
        """The time before which the signature cannot have been made, if established."""
        if self.trusted and self.bound is Bound.LOWER:
            return self.as_datetime
        return None


@dataclass(frozen=True)
class TemporalFinding:
    """One concern about an algorithm's standing at a point in time."""

    algorithm: str
    severity: str                 # "info" | "warning" | "critical"
    message: str
    policy_source: str = ""


@dataclass(frozen=True)
class TemporalAssessment:
    findings: list[TemporalFinding] = field(default_factory=list)
    evidence: TimeEvidence | None = None

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        return any(f.severity in ("warning", "critical") for f in self.findings)

    def messages(self) -> list[str]:
        return [f"[{f.severity}] {f.algorithm}: {f.message}" for f in self.findings]


def assess(
    algorithms: list[str],
    evidence: TimeEvidence | None = None,
    now: datetime | None = None,
    policies: dict[str, AlgorithmPolicy] | None = None,
) -> TemporalAssessment:
    """Judge a set of algorithms against the policy registry.

    Args:
        algorithms: what the bundle's binding declares.
        evidence: independent evidence of signing time, if any. Its `bound`
            decides what it can establish; a lower bound cannot rescue.
        now: override the clock, for tests and for asking "how will this look
            in 2031?"
    """
    policies = policies if policies is not None else ALGORITHM_POLICIES
    now = now or datetime.now(timezone.utc)
    findings: list[TemporalFinding] = []

    existed_by = evidence.proves_not_after if evidence else None
    made_after = evidence.proves_not_before if evidence else None

    # Bound once rather than reached for inside each branch. The branches below
    # are only entered when `evidence` is non-None, but that is an invariant a
    # reader (and a type checker) has to reconstruct from two levels away, and
    # it would be quietly broken by anyone adding a branch.
    evidence_kind = evidence.kind if evidence else "no"
    evidence_stamp = evidence.timestamp if evidence else "an unknown time"

    quantum_safe = [
        a for a in algorithms
        if policies.get(a) and policies[a].status is TrustStatus.CURRENT
    ]

    for algorithm in algorithms:
        policy = policies.get(algorithm)
        if policy is None:
            findings.append(TemporalFinding(
                algorithm=algorithm, severity="warning",
                message="not in the policy registry; its standing cannot be assessed",
            ))
            continue

        if policy.status is TrustStatus.BROKEN:
            findings.append(TemporalFinding(
                algorithm=algorithm, severity="critical",
                message=f"considered BROKEN. {policy.note}",
                policy_source=policy.source,
            ))
            continue

        deadline = policy.disallowed_after_date
        if deadline is None:
            continue

        if now > deadline:
            # The deadline has passed as of the moment of verification. The
            # question is no longer "should they have used this" but "is this
            # still distinguishable from a forgery made today".
            if quantum_safe:
                findings.append(TemporalFinding(
                    algorithm=algorithm, severity="info",
                    message=(
                        f"past its {policy.disallowed_after} deadline, but this "
                        f"bundle is also signed with {sorted(quantum_safe)}, which "
                        f"remains current. The hybrid is doing its job."
                    ),
                    policy_source=policy.source,
                ))
            elif existed_by is not None and existed_by <= deadline:
                # The only branch that rescues, and it needs an UPPER bound.
                findings.append(TemporalFinding(
                    algorithm=algorithm, severity="warning",
                    message=(
                        f"past its {policy.disallowed_after} deadline, but "
                        f"{evidence_kind} evidence establishes that the signature "
                        f"already existed at {evidence_stamp}, before that "
                        f"date. The signature stands; do not issue new ones with "
                        f"this algorithm."
                    ),
                    policy_source=policy.source,
                ))
            elif made_after is not None and made_after > deadline:
                # A lower bound later than the deadline convicts: the signature
                # cannot predate the lower bound, so it was made too late.
                findings.append(TemporalFinding(
                    algorithm=algorithm, severity="critical",
                    message=(
                        f"{evidence_kind} evidence places the signature no earlier "
                        f"than {evidence_stamp}, after this algorithm's "
                        f"{policy.disallowed_after} deadline. The signer used a "
                        f"disallowed algorithm, and it is now past its deadline, "
                        f"so the signature is not evidence either."
                    ),
                    policy_source=policy.source,
                ))
            elif made_after is not None:
                # A lower bound EARLIER than the deadline. Tempting to read as
                # exculpatory; it is not. "No earlier than 2026" is consistent
                # with having been made this morning.
                findings.append(TemporalFinding(
                    algorithm=algorithm, severity="critical",
                    message=(
                        f"past its {policy.disallowed_after} deadline. The available "
                        f"{evidence_kind} evidence fixes only a lower bound "
                        f"({evidence_stamp}), which cannot establish that the "
                        f"signature predates the deadline: a forgery created today "
                        f"is also 'no earlier than' that pulse, so it remains "
                        f"indistinguishable from a genuine old signature. A "
                        f"transparency-log inclusion proof would settle this."
                    ),
                    policy_source=policy.source,
                ))
            elif existed_by is not None:
                # Upper bound, but after the deadline: it proves the signature
                # existed by then, not that it predates the deadline.
                findings.append(TemporalFinding(
                    algorithm=algorithm, severity="critical",
                    message=(
                        f"past its {policy.disallowed_after} deadline. The "
                        f"{evidence_kind} evidence places the signature at "
                        f"{evidence_stamp}, which is after that deadline, so it "
                        f"does not establish the signature predates it. A forgery "
                        f"would be indistinguishable from a genuine old signature."
                    ),
                    policy_source=policy.source,
                ))
            else:
                findings.append(TemporalFinding(
                    algorithm=algorithm, severity="critical",
                    message=(
                        f"past its {policy.disallowed_after} deadline and there is "
                        f"no trusted evidence of when this signature was made. A "
                        f"forgery created today would be indistinguishable from a "
                        f"genuine old signature."
                    ),
                    policy_source=policy.source,
                ))

        elif made_after is not None and made_after > deadline:
            # Deadline not yet reached, but the signature provably postdates it:
            # a clock problem or a fabricated timestamp.
            findings.append(TemporalFinding(
                algorithm=algorithm, severity="warning",
                message=(
                    f"the signature was made no earlier than {evidence_stamp}, "
                    f"after this algorithm's {policy.disallowed_after} deadline. "
                    f"The signer used a disallowed algorithm."
                ),
                policy_source=policy.source,
            ))
        elif policy.status is TrustStatus.DEPRECATED:
            findings.append(TemporalFinding(
                algorithm=algorithm, severity="info",
                message=(
                    f"deprecated; unacceptable for new signatures after "
                    f"{policy.disallowed_after}. {policy.note}"
                ),
                policy_source=policy.source,
            ))

    # --- what the evidence itself is worth --------------------------------
    if evidence is not None and not evidence.trusted:
        findings.append(TemporalFinding(
            algorithm="-", severity="warning",
            message=(
                "the only timestamp available is self-asserted, so it is not "
                "evidence: anyone forging a signature writes a timestamp too. A "
                "transparency-log entry or beacon pulse would fix this."
            ),
        ))
    elif evidence is None:
        findings.append(TemporalFinding(
            algorithm="-", severity="info",
            message=(
                "no independent evidence of signing time. This does not matter "
                "while every algorithm is current, and matters a great deal once "
                "one is not."
            ),
        ))
    elif evidence.bound is Bound.LOWER:
        findings.append(TemporalFinding(
            algorithm="-", severity="info",
            message=(
                f"{evidence_kind} evidence fixes a lower bound only: the signature "
                f"was made no earlier than {evidence_stamp}. That can show a "
                f"signer used an algorithm past its deadline, but it cannot show a "
                f"signature predates one. Only an upper bound -- a transparency-log "
                f"inclusion proof -- can do that."
            ),
        ))

    return TemporalAssessment(findings=findings, evidence=evidence)


class BindingBasis(str, Enum):
    """Whether a CLASSICAL attestation can be trusted to vouch for a binding.

    The three outcomes of spec section 4 step 7, made a value so the verifier
    can report WHICH one held rather than just accept/reject -- a verdict that
    hides its basis is the thing this whole design exists to avoid.
    """

    DIRECT = "direct"                       # the algorithm is still allowed
    RESCUED = "rescued-by-timestamp"        # disallowed now, but logged before D
    REJECTED = "rejected"                   # nothing proves it predates D


def binding_trust(
    algorithm: str,
    upper_bound: datetime | None,
    now: datetime | None = None,
    policies: dict[str, Any] | None = None,
) -> BindingBasis:
    """Can a signature by `algorithm` be trusted to vouch for a binding now?

    This is spec step 7, and it is called TWICE and identically: once for the
    primary classical anchor, and once -- with the recovery key's own algorithm
    and its own date -- for a recovery-key revocation (spec 5.1). Structurally
    one decision, so it is one function.

      DIRECT   now < D                         the algorithm is still allowed
      RESCUED  now >= D, upper_bound < D        a log timestamp proves the act
                                                happened while it was allowed
      REJECTED now >= D, upper_bound absent      nothing proves it predates D;
               or upper_bound >= D               it may be a forgery made after
                                                 the algorithm broke

    `upper_bound` is the log's integratedTime T -- an UPPER bound ("existed
    by"), the only bound direction that can rescue. A lower bound cannot, which
    is why this takes a datetime already known to be an upper bound rather than
    a TimeEvidence whose direction it would have to trust.
    """
    policies = policies if policies is not None else ALGORITHM_POLICIES
    now = now or datetime.now(timezone.utc)

    spec = policies.get(algorithm)
    if spec is None:
        raise ValueError(
            f"no policy for {algorithm!r}; a binding on an algorithm with no "
            f"disallow date cannot be judged, so it is not silently trusted"
        )
    disallow = spec.disallowed_after_date
    if disallow is None or now <= disallow:
        # No deadline, or not yet past it: the attestation stands on its own.
        return BindingBasis.DIRECT
    if upper_bound is not None and upper_bound <= disallow:
        return BindingBasis.RESCUED
    return BindingBasis.REJECTED


def evidence_from_attestation(attestation: Any) -> TimeEvidence | None:
    """Extract time evidence from an entropy attestation, if it carries any.

    A beacon contribution records `not_before`, which is a genuine lower bound:
    the seed could not have been derived before that pulse existed.

    It is *only* a lower bound, and this function does not dress it up as more.
    A bundle whose sole time evidence is its entropy attestation therefore
    cannot have a post-deadline classical signature rescued -- correctly, since
    nothing in the bundle establishes that the signature predates anything. To
    obtain an upper bound, publish the signature to a transparency log and pass
    the resulting inclusion proof to `verify(time_evidence=...)`.
    """
    if attestation is None:
        return None

    def get(key: str) -> Any:
        return (attestation.get(key) if isinstance(attestation, dict)
                else getattr(attestation, key, None))

    # Upper-bound evidence, if the caller recorded any, outranks the beacon:
    # it is the stronger direction. `time_evidence` carries a `kind`
    # discriminator so a reader can tell a timestamp from a log entry; the older
    # `transparency_log` field is still recognised so bundles written before it
    # existed keep verifying.
    #
    # NOTE: nothing here verifies anything. This function reads what a bundle
    # CLAIMS. The trusted flag it sets means "this kind of evidence is capable
    # of being trusted", not "this instance was checked" -- verification happens
    # in `transparency.verify_timestamp`, against anchors the verifier supplies,
    # and `verify(time_evidence=...)` is how a checked result gets in. A bundle
    # that reaches `assess` unverified must not be able to rescue itself.
    evidence = get("time_evidence") or get("timeEvidence")
    if isinstance(evidence, dict):
        kind = evidence.get("kind")
        stamped = evidence.get("gen_time") or evidence.get("integrated_time")
        if kind == "rfc3161" and stamped:
            return TimeEvidence.from_timestamp_authority(
                str(stamped), reference=evidence)
        if kind in ("transparency-log", "rekor") and stamped:
            return TimeEvidence.from_transparency_log(
                str(stamped), reference=evidence)

    log_entry = get("transparency_log") or get("transparencyLog")
    if isinstance(log_entry, dict) and log_entry.get("integrated_time"):
        return TimeEvidence.from_transparency_log(
            str(log_entry["integrated_time"]), reference=log_entry
        )

    not_before = get("not_before")
    if not not_before:
        return None

    reference = None
    for contribution in get("contributions") or []:
        role = (contribution.get("role") if isinstance(contribution, dict)
                else getattr(contribution, "role", None))
        if role == "public":
            reference = (contribution.get("reference") if isinstance(contribution, dict)
                         else getattr(contribution, "reference", None))
            break

    return TimeEvidence.from_beacon(not_before, reference)


__all__ = [
    "ALGORITHM_POLICIES",
    "BindingBasis",
    "binding_trust",
    "AlgorithmPolicy",
    "Bound",
    "TemporalAssessment",
    "TemporalFinding",
    "TimeEvidence",
    "TrustStatus",
    "assess",
    "evidence_from_attestation",
]
