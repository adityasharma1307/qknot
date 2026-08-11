"""Side-channel status as evidence, not as a boolean.

THE SAME MISTAKE THE FULCIO BUG WAS, ONE LEVEL UP
=================================================
The Fulcio bug inferred a signature algorithm from issuer convention instead of
parsing it out of the certificate. The fix was to read the fact from the
artefact rather than deduce it from context.

`side_channel_resistant: bool` is that mistake again, at the level of backend
trust rather than certificate trust. Two states cannot express what is actually
known, because there are three situations:

* dilithium-py is **measured** to leak -- signing varies ~10-85 ms with the key,
  and key identification reaches 79.5% at 1,600 traces even against 0-50 ms of
  injected noise.
* liboqs **cannot be checked at runtime at all**. Probed directly: the entire
  per-mechanism surface it exposes is `name`, `version`, `claimed_nist_level`,
  `is_ind_cca` and the key/signature lengths. There is no constant-time flag, no
  build-configuration flag, no CPU-extension flag. liboqs verifies constant-time
  behaviour in its own CI under valgrind; none of that reaches the API.
* an operator may have verified their specific build with a real tool, in which
  case something IS known -- but it is known to them, not to us.

A boolean collapses the middle case into one of the outer two, and both
collapses are wrong. `False` says "this leaks", which is unproven. `True` says
"this is safe", which is unverified.

WHY AN ALLOWLIST WAS REJECTED
=============================
The obvious fallback -- trust `(liboqs version, platform)` pairs known to be
built correctly -- fails for the same reason the Fulcio convention did. A
version string does not carry build flags. The same liboqs version compiles
with different `OQS_OPT_TARGET` settings, with distribution patches, or with
optimisations that reintroduce data-dependent branches. Asserting a build
property from metadata that does not contain it is inference from convention,
which is precisely the discipline this project exists to replace with
measurement.

WHAT `ASSERTED` REQUIRES
========================
A free-text field would make `ASSERTED` a slightly more honest place to put an
unverified claim, which would defeat the point of having three states. So the
evidence is structured and validated: a named analysis tool, when it was run,
what it examined, and a digest or locator for the report itself. A downstream
verifier can then evaluate the claim -- or reject it -- rather than take it.

The claim is recorded as the DEPLOYER'S, attributed to them by name. This
module never upgrades a status on its own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

__all__ = [
    "RECOGNISED_TOOLS",
    "SideChannelEvidence",
    "SideChannelStatus",
]


class SideChannelStatus(str, Enum):
    """What is known about a backend's timing behaviour, and how it is known."""

    KNOWN_LEAKY = "known-leaky"
    """Measured to leak. Not a suspicion: a number, in docs/THREAT-MODEL.md."""

    UNKNOWN = "unknown"
    """Not established. No runtime mechanism exists to establish it."""

    ASSERTED = "asserted"
    """A deployer verified their build and named the evidence. Their claim."""

    @property
    def permits_online(self) -> bool:
        """Only a substantiated claim admits an online exposure.

        UNKNOWN is treated exactly as KNOWN_LEAKY is, so introducing the third
        state changes no gate: it changes what the bundle says about why.
        """
        return self is SideChannelStatus.ASSERTED


# Tools that actually establish constant-time behaviour, as opposed to
# asserting it. dudect is statistical (timing distributions under two input
# classes); ctgrind and valgrind-memcheck track secret-dependent branches
# dynamically; Binsec/Rel proves it symbolically over the binary. A name
# outside this set is not rejected outright -- the field records what was
# actually used -- but it must be spelled out rather than left blank.
RECOGNISED_TOOLS = frozenset({
    "dudect", "ctgrind", "valgrind", "binsec-rel", "ctverif", "flowtracker",
    "microwalk", "data", "haybale-pitchfork",
})

_DIGEST = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class SideChannelEvidence:
    """A deployer's substantiation for an ASSERTED status.

    Every field is required. An assertion missing any of them is not weaker
    evidence, it is unevaluable -- a reader cannot tell what was examined, when,
    with what, or whether the artefact under test is the one now running.
    """

    tool: str
    """The analysis tool. See RECOGNISED_TOOLS."""

    tool_version: str
    """Which version. Constant-time analyses change between releases."""

    performed: str
    """RFC 3339 timestamp. A result predating the build proves nothing."""

    subject: str
    """What was analysed -- library version and build flags, spelled out."""

    report_sha256: str
    """SHA-256 of the report, so the claim is bound to a specific artefact."""

    asserted_by: str
    """Who is making the claim. It is theirs, not this library's."""

    report_uri: str | None = None
    """Where the report can be fetched, when it is published."""

    def __post_init__(self) -> None:
        for field in ("tool", "tool_version", "performed", "subject",
                      "report_sha256", "asserted_by"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"SideChannelEvidence.{field} is required and must be "
                    f"non-empty. An assertion missing it cannot be evaluated "
                    f"by anyone downstream, which is the only reason ASSERTED "
                    f"exists as a state."
                )

        if not _DIGEST.match(self.report_sha256.lower()):
            raise ValueError(
                f"report_sha256 must be 64 lowercase hex characters; got "
                f"{self.report_sha256!r}. Without a digest the claim is not "
                f"bound to any particular report."
            )

        try:
            when = datetime.fromisoformat(self.performed.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(
                f"performed must be an RFC 3339 timestamp; got "
                f"{self.performed!r}"
            ) from exc
        if when.tzinfo is None:
            raise ValueError(
                "performed must carry a timezone offset; a naive timestamp is "
                "ambiguous by up to a day and this field exists to order the "
                "analysis against the build it describes."
            )
        if when > datetime.now(timezone.utc):
            raise ValueError(
                f"performed is in the future ({self.performed}); an analysis "
                f"that has not happened yet cannot substantiate anything."
            )

        if self.tool.strip().lower() not in RECOGNISED_TOOLS:
            # Recorded, not refused: an unfamiliar tool may be legitimate, and
            # silently dropping the name would leave a reader unable to judge.
            object.__setattr__(self, "tool", self.tool.strip())

    @property
    def tool_is_recognised(self) -> bool:
        return self.tool.strip().lower() in RECOGNISED_TOOLS

    def to_dict(self) -> dict[str, object]:
        """As recorded in a bundle: the deployer's claim, attributed."""
        return {
            "tool": self.tool,
            "toolVersion": self.tool_version,
            "toolRecognised": self.tool_is_recognised,
            "performed": self.performed,
            "subject": self.subject,
            "reportSha256": self.report_sha256.lower(),
            "reportUri": self.report_uri,
            "assertedBy": self.asserted_by,
        }
