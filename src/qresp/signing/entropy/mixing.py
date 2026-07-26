"""Combine entropy sources instead of choosing between them.

THE PROBLEM WITH CHOOSING
=========================
An earlier design asked "quantum or classical?" and fell back to `os.urandom`
when the QRNG was unreachable. That framing creates a downgrade to agonise
over, an `--on-qrng-failure` policy to configure, and a permanent question of
whether any given key is "really" quantum.

It is also unnecessary. Combining entropy sources with a KDF yields a result at
least as strong as the strongest input, so there is no reason to pick one. This
is what the Linux kernel RNG does, and it dissolves the problem: a run with a
reachable beacon and a run without differ in *what evidence they carry*, not in
whether the key is sound.

SECRET AND PUBLIC INPUTS ARE NOT INTERCHANGEABLE
================================================
Sources divide into two kinds, and conflating them is catastrophic:

  * **Secret** -- `os.urandom`, ANU, a hardware QRNG. Nobody else sees these
    bytes. They provide unpredictability.
  * **Public** -- the NIST beacon. Everyone sees these bytes. They provide
    verifiability and a timestamp, and *no* unpredictability whatsoever.

Deriving a key from public inputs alone hands that key to anyone who reads the
beacon. `mix_entropy` therefore refuses to produce a seed unless at least one
secret contribution is present. That is a hard error, not a warning, because
the failure is silent and total: the resulting key would look perfectly random
and be entirely predictable.

Public randomness enters as the HKDF **salt**; secret randomness as the input
keying material. RFC 5869 is explicit that the salt need not be secret.

WHAT THE ATTESTATION RECORDS
============================
Every contributing source, its role, whether it was quantum, and a commitment
to what it contributed. For the beacon it also records the pulse index and
signature, so a reader can fetch that exact pulse from NIST and confirm the
salt. That is the difference between a claim and evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .backends import COMMITMENT_DOMAIN, EntropyBackend, QrngUnavailable, commit

log = logging.getLogger(__name__)

KDF_NAME = "HKDF-SHA3-256"
KDF_INFO_PREFIX = b"qresp-signing-seed-v1"


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) over SHA3-256
# ---------------------------------------------------------------------------
def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA3-256.

    Implemented here rather than pulled from `cryptography` to keep the signing
    package dependency-light; it is meant to be droppable into any project.
    Roughly twenty lines, and tested against the structure of the RFC.

    SHA-3 rather than SHA-2 throughout this package: Grover's algorithm halves
    a hash's effective preimage security, and SHA-3's larger internal state
    leaves more margin under that reduction.
    """
    if length <= 0:
        raise ValueError("length must be positive")
    hash_len = hashlib.sha3_256().digest_size
    if length > 255 * hash_len:
        raise ValueError(f"HKDF cannot expand beyond {255 * hash_len} bytes")

    # Extract: compress the input keying material into a pseudorandom key.
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()

    # Expand: stretch the PRK to the requested length.
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha3_256).digest()
        okm += block
        counter += 1
    return okm[:length]


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SourceContribution:
    """What one entropy source contributed, and how a verifier can check it."""

    backend: str
    role: str                       # "secret" or "public"
    is_quantum: bool
    n_bytes: int
    commitment: str                 # tagged hash of this source's bytes
    public_value: str | None = None  # only for public sources; safe to publish
    reference: dict[str, Any] | None = None  # beacon pulse id, signature, etc.
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MixedEntropyAttestation:
    """Evidence of how a seed was derived, and from what.

    Records every contributing source rather than a single "backend", because
    the whole design is that sources combine. `quantum_contributors` reports
    which of them were physically random; `verifiable_contributors` reports
    which a third party can independently re-check, which is a different and
    arguably more useful property.
    """

    kdf: str
    n_bytes: int
    timestamp: str
    commitment: str                 # commitment to the derived seed
    contributions: list[SourceContribution]
    not_before: str | None = None   # earliest possible creation time, from a beacon
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def verify_commitment(self, seed: bytes) -> bool:
        return commit(seed) == self.commitment

    @property
    def quantum_contributors(self) -> list[str]:
        return [c.backend for c in self.contributions if c.is_quantum]

    @property
    def verifiable_contributors(self) -> list[str]:
        """Sources a third party can independently confirm.

        A secret source can never be on this list -- that is what makes it
        secret. Only public randomness with a published, signed reference is
        externally checkable.
        """
        return [c.backend for c in self.contributions
                if c.role == "public" and c.reference is not None]

    @property
    def has_secret_contribution(self) -> bool:
        return any(c.role == "secret" for c in self.contributions)

    @property
    def is_quantum_seeded(self) -> bool:
        """True if any quantum source contributed *secret* material.

        Deliberately excludes public quantum sources. A beacon is quantum and
        contributes nothing to unpredictability, so counting it here would let
        a key claim quantum seeding while every unpredictable bit came from the
        system CSPRNG.
        """
        return any(c.is_quantum and c.role == "secret" for c in self.contributions)


@dataclass(frozen=True)
class MixedEntropyResult:
    seed: bytes
    attestation: MixedEntropyAttestation


# ---------------------------------------------------------------------------
# Mixing
# ---------------------------------------------------------------------------
class NoSecretEntropy(ValueError):  # noqa: N818
    """Refused to derive a seed from public randomness alone.

    Not a warning. A seed built only from beacon pulses is computable by anyone
    who reads the beacon, so the resulting key would be indistinguishable from
    random to inspection and entirely predictable to an attacker.
    """


def mix_entropy(
    sources: list[EntropyBackend],
    n_bytes: int = 32,
    context: bytes = b"",
    require_quantum: bool = False,
) -> MixedEntropyResult:
    """Derive `n_bytes` of seed material from every source that responds.

    Args:
        sources: backends to try. Failures are recorded and skipped, not fatal,
            provided at least one secret source succeeds.
        context: domain separation, e.g. b"ml-dsa-44-keygen". Different
            contexts yield different seeds from identical inputs, so one
            compromised seed does not compromise another purpose.
        require_quantum: fail unless a quantum source contributed secret
            material. For callers whose threat model genuinely demands it.

    Raises:
        NoSecretEntropy: if no secret source produced bytes.
        QrngUnavailable: if `require_quantum` and no quantum secret source did.
    """
    if not sources:
        raise NoSecretEntropy("no entropy sources supplied")

    started = datetime.now(timezone.utc)
    contributions: list[SourceContribution] = []
    secret_material: list[bytes] = []
    salt_material: list[bytes] = []
    not_before: str | None = None
    notes: list[str] = []

    for source in sources:
        is_public = getattr(source, "is_public", False)
        want = 64 if is_public else n_bytes
        try:
            raw = source.get_bytes(want)
        except (QrngUnavailable, NotImplementedError, OSError) as exc:
            # Deliberately NOT `except Exception`. Anything outside these is a
            # bug in the backend, not an unavailable source, and swallowing it
            # here would be silent and consequential: a typo in
            # SystemEntropyBackend -- the one source assumed never to fail --
            # would be logged as "unavailable" and skipped, leaving the seed to
            # a network source or raising a NoSecretEntropy that points at the
            # wrong culprit. Network failures reach us as OSError subclasses
            # (requests' ConnectionError and Timeout both inherit from it) or
            # already wrapped as QrngUnavailable.
            log.warning("Entropy source %s unavailable: %s", source.name, exc)
            notes.append(f"{source.name}_unavailable: {exc}")
            continue

        described = source.describe() or {}
        if is_public:
            salt_material.append(raw)
            reference = described.get("pulse")
            if described.get("not_before"):
                not_before = described["not_before"]
            contributions.append(SourceContribution(
                backend=source.name, role="public",
                is_quantum=bool(getattr(source, "is_quantum", False)),
                n_bytes=len(raw), commitment=commit(raw),
                public_value=raw.hex(), reference=reference,
                notes=["public randomness: contributes verifiability and a "
                       "timestamp, not unpredictability"],
            ))
        else:
            secret_material.append(raw)
            contributions.append(SourceContribution(
                backend=source.name, role="secret",
                is_quantum=bool(getattr(source, "is_quantum", False)),
                n_bytes=len(raw), commitment=commit(raw),
                public_value=None,
                reference={k: v for k, v in described.items() if k != "pulse"} or None,
            ))

    if not secret_material:
        raise NoSecretEntropy(
            "every secret entropy source failed; only public randomness was "
            "obtained. A seed derived from public values alone is computable "
            "by anyone who reads them. Refusing to produce a key."
        )

    if require_quantum and not any(
        c.is_quantum and c.role == "secret" for c in contributions
    ):
        raise QrngUnavailable(
            "require_quantum was set, but no quantum source contributed secret "
            "material. A public quantum beacon does not satisfy this: it adds "
            "no unpredictability."
        )

    # Secret bytes are the input keying material; public bytes are the salt.
    # RFC 5869 is explicit that the salt need not be secret, which is exactly
    # why the beacon belongs here and nowhere else.
    ikm = b"".join(secret_material)
    salt = b"".join(salt_material) or b"\x00" * hashlib.sha3_256().digest_size
    info = KDF_INFO_PREFIX + b"|" + context

    seed = hkdf(ikm=ikm, salt=salt, info=info, length=n_bytes)

    return MixedEntropyResult(
        seed=seed,
        attestation=MixedEntropyAttestation(
            kdf=KDF_NAME,
            n_bytes=n_bytes,
            timestamp=started.isoformat(),
            commitment=commit(seed),
            contributions=contributions,
            not_before=not_before,
            notes=notes,
        ),
    )


def default_sources(anu_api_key: str | None = None,
                    use_beacon: bool = True) -> list[EntropyBackend]:
    """The recommended combination: system CSPRNG, ANU, and the NIST beacon.

    Ordered secret-first so that a seed is always obtainable even when both
    network sources are down. The system CSPRNG never fails, so `mix_entropy`
    over this list raises only if `os.urandom` itself is broken.
    """
    from .backends import AnuQrngBackend, SystemEntropyBackend

    sources: list[EntropyBackend] = [SystemEntropyBackend(), AnuQrngBackend(api_key=anu_api_key)]
    if use_beacon:
        from .beacon import NistBeaconBackend

        sources.append(NistBeaconBackend())
    return sources


__all__ = [
    "COMMITMENT_DOMAIN",
    "KDF_NAME",
    "MixedEntropyAttestation",
    "MixedEntropyResult",
    "NoSecretEntropy",
    "SourceContribution",
    "default_sources",
    "hkdf",
    "mix_entropy",
]
