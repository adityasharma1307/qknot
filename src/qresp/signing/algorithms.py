"""One registry for every algorithm this package knows about.

WHY THIS FILE EXISTS
====================
The question "does this algorithm resist Shor?" was previously answered in
three places that had no reason to agree, and did not:

    combiner.KNOWN_ALGORITHMS    listed slh-dsa-128f and ecdsa-p384
    backends._BACKENDS           implemented neither
    temporal.ALGORITHM_POLICIES  had a policy for slh-dsa-128s but not -128f

So a suite naming `slh-dsa-128f` was accepted by the combiner, rejected by the
backend factory with a bare "unknown algorithm", and reported by the temporal
layer as "standing cannot be assessed" -- three different answers to one
question, none of them wrong on its own terms.

Drift between parallel tables is not a bug you fix once. It is a bug you keep
fixing, unless the tables stop being parallel. Everything below is the single
source; the other modules derive their views from it and cannot disagree.

THE THREE PROPERTIES, WHICH ARE GENUINELY INDEPENDENT
=====================================================
    resists_shor   cryptographic fact about the algorithm
    backend        whether *this package* can compute it
    status/date    a standards-body position, which moves

Conflating the second with the first is how "we don't implement it" quietly
becomes "it isn't safe". They are kept as separate fields so that an algorithm
we cannot compute still gets an honest assessment of its standing.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class TrustStatus(str, Enum):
    """How much an algorithm can still be relied on."""

    CURRENT = "current"            # recommended
    DEPRECATED = "deprecated"      # discouraged; existing signatures still stand
    DISALLOWED = "disallowed"      # must not be used for new signatures
    BROKEN = "broken"              # forgery is practical; old signatures suspect


@dataclass(frozen=True)
class AlgorithmSpec:
    """Everything the package knows about one algorithm.

    `disallowed_after` is a *date*, and the policy it encodes reads "unacceptable
    for new signatures after 2030-12-31" -- meaning the whole of that day is
    still acceptable. `disallowed_after_date` therefore returns the last instant
    of the named day, not its midnight. Comparing against midnight would have
    declared a signature made at noon on the deadline to be past it.
    """

    algorithm: str
    resists_shor: bool
    status: TrustStatus
    disallowed_after: str | None
    source: str
    note: str = ""
    backend: str | None = None      # key into backends._BACKENDS, or None

    @property
    def has_backend(self) -> bool:
        return self.backend is not None

    @property
    def disallowed_after_date(self) -> datetime | None:
        """The last instant that is still inside the deadline."""
        if not self.disallowed_after:
            return None
        day = datetime.fromisoformat(self.disallowed_after).replace(tzinfo=timezone.utc)
        return day + timedelta(days=1) - timedelta(microseconds=1)


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------
# Editable data with cited provenance, not buried constants. No algorithm here
# has been *observed* broken; the dates are transition deadlines and they move.
REGISTRY: dict[str, AlgorithmSpec] = {
    "ed25519": AlgorithmSpec(
        algorithm="ed25519",
        resists_shor=False,
        status=TrustStatus.DEPRECATED,
        disallowed_after="2030-12-31",
        source="NIST SP 800-131A Rev.2 transition timeline for classical "
               "public-key algorithms",
        note="Shor-vulnerable. Sound against classical adversaries today; the "
             "date reflects the transition deadline, not a known break.",
        backend="ed25519",
    ),
    "ecdsa-p256": AlgorithmSpec(
        algorithm="ecdsa-p256",
        resists_shor=False,
        status=TrustStatus.DEPRECATED,
        disallowed_after="2030-12-31",
        source="NIST SP 800-131A Rev.2",
        note="Shor-vulnerable. Note that published quantum resource estimates "
             "for ECDLP-256 target secp256k1 rather than P-256; the distinction "
             "matters and should not be blurred when citing them.",
    ),
    "ecdsa-p384": AlgorithmSpec(
        algorithm="ecdsa-p384",
        resists_shor=False,
        status=TrustStatus.DEPRECATED,
        disallowed_after="2030-12-31",
        source="NIST SP 800-131A Rev.2",
        note="Shor-vulnerable; a larger curve delays classical attack, not quantum.",
    ),
    "rsa-2048": AlgorithmSpec(
        algorithm="rsa-2048",
        resists_shor=False,
        status=TrustStatus.DEPRECATED,
        disallowed_after="2030-12-31",
        source="NIST SP 800-131A Rev.2",
        note="Shor-vulnerable.",
    ),
    "rsa-4096": AlgorithmSpec(
        algorithm="rsa-4096",
        resists_shor=False,
        status=TrustStatus.DEPRECATED,
        disallowed_after="2030-12-31",
        source="NIST SP 800-131A Rev.2",
        note="Shor-vulnerable; key size does not help against Shor.",
    ),
    "ml-dsa-44": AlgorithmSpec(
        algorithm="ml-dsa-44",
        resists_shor=True,
        status=TrustStatus.CURRENT,
        disallowed_after=None,
        source="FIPS 204",
        note="Module-LWE. No efficient quantum algorithm known.",
        backend="ml-dsa-44",
    ),
    "ml-dsa-65": AlgorithmSpec(
        algorithm="ml-dsa-65",
        resists_shor=True,
        status=TrustStatus.CURRENT,
        disallowed_after=None,
        source="FIPS 204",
        backend="ml-dsa-65",
    ),
    "ml-dsa-87": AlgorithmSpec(
        algorithm="ml-dsa-87",
        resists_shor=True,
        status=TrustStatus.CURRENT,
        disallowed_after=None,
        source="FIPS 204; NSA CNSA 2.0 names ML-DSA-87 for national security systems",
        backend="ml-dsa-87",
    ),
    "slh-dsa-128s": AlgorithmSpec(
        algorithm="slh-dsa-128s",
        resists_shor=True,
        status=TrustStatus.CURRENT,
        disallowed_after=None,
        source="FIPS 205",
        note="Hash-based; security rests only on the hash, so it survives even "
             "if lattice assumptions fall. No backend here: included so its "
             "standing can be assessed in a bundle this package did not produce.",
    ),
    "slh-dsa-128f": AlgorithmSpec(
        algorithm="slh-dsa-128f",
        resists_shor=True,
        status=TrustStatus.CURRENT,
        disallowed_after=None,
        source="FIPS 205",
        note="The fast SLH-DSA parameter set: larger signatures, faster signing. "
             "No backend here.",
    ),
}


def spec(algorithm: str) -> AlgorithmSpec | None:
    return REGISTRY.get(algorithm.strip().lower())


def resists_shor(algorithm: str) -> bool:
    """Whether an algorithm survives a quantum adversary.

    Unknown algorithms return False. That is the safe direction: an unrecognised
    name must never be counted as quantum protection.
    """
    found = spec(algorithm)
    return bool(found and found.resists_shor)


def is_known(algorithm: str) -> bool:
    return spec(algorithm) is not None


def implemented() -> list[str]:
    return sorted(name for name, s in REGISTRY.items() if s.has_backend)


__all__ = [
    "REGISTRY",
    "AlgorithmSpec",
    "TrustStatus",
    "implemented",
    "is_known",
    "resists_shor",
    "spec",
]
