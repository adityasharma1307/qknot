"""Signature backends, with each one honest about what it does not protect.

WHY A BACKEND ABSTRACTION
=========================
The contribution of this project is the non-separable hybrid combiner and the
OMS extension, neither of which depends on *who* computes an ML-DSA signature.
Treating the primitive as swappable keeps the interesting part independent of
an implementation choice that will change as the ecosystem matures.

THE SIDE-CHANNEL PROBLEM, STATED PLAINLY
========================================
`dilithium-py` says: "Under no circumstances should this be used for
cryptographic applications... not designed to be secure against any form of
side-channel attack." That warning is about **timing**, not correctness. The
library reproduces NIST's ACVP FIPS 204 vectors byte for byte -- key generation,
signing (deterministic and hedged) and verification, 180 vectors -- checked on
every test run by `tests/signing/test_fips204_acvp.py`.

ML-DSA signing uses rejection sampling: it loops until a candidate signature
falls within bounds, and the iteration count depends on secret data. Measured
on this implementation, signing the same key varies from ~10 ms to ~85 ms, and
two different keys have distinguishable medians.

Writing our own would not help. Python cannot express constant-time code:
arbitrary-precision integers vary in cost with value, the garbage collector
fires unpredictably, and bytecode dispatch is not under our control. A fresh
implementation would inherit exactly this exposure and add unvalidated NTT,
rejection bounds and encodings on top.

Nor does injecting random delay help. Averaging suppresses zero-mean noise as
1/sqrt(N) while the secret-dependent signal stays fixed, so the attacker simply
collects more traces. Measured: with 0-50 ms of uniform noise against a 1.6 ms
signal, key identification still reaches 79.5% at 1600 traces and climbs. A
noise wrapper raises the price and lets the module claim a protection it does
not provide, which is worse than claiming nothing.

WHAT ACTUALLY WORKS: SCOPE THE EXPOSURE
=======================================
A timing attack needs an adversary who can trigger signing operations and
measure each one. Release signing is offline: you sign once, on your own
machine, and publish. That adversary does not exist. An attacker with the
ability to time your signing loop already has code execution on the signing
host, at which point they take the key directly.

Where it genuinely breaks is a **signing service** -- an endpoint that signs on
request, where the attacker supplies messages and times responses at will.

So `sign()` requires an explicit `exposure`, and refuses to use a
non-constant-time backend in an online one. That is a hard error rather than a
warning, because the failure is silent: nothing about a leaked key looks wrong
until it is used against you. See docs/THREAT-MODEL.md.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .algorithms import REGISTRY, implemented, is_known

log = logging.getLogger(__name__)


class Exposure(str, Enum):
    """Who can observe the signing operation.

    OFFLINE   A human signs a release on a machine an attacker cannot reach.
              Signing happens rarely, at times the attacker does not choose,
              and the timings are not observable. This is the OMS workflow and
              the one this project targets.

    ONLINE    Signing is exposed as a service. An attacker submits messages and
              measures response times, as often as they like. Only a
              constant-time backend is acceptable here.
    """

    OFFLINE = "offline"
    ONLINE = "online"


class BackendUnsuitable(Exception):  # noqa: N818
    """The chosen backend must not be used in the declared exposure."""


class SignatureBackend(Protocol):
    """One signature algorithm.

    `side_channel_resistant` is not decoration. It gates whether `sign` may run
    at all in an online exposure, so a backend that lies here defeats the
    protection for everyone downstream.
    """

    algorithm: str
    quantum_resistant: bool
    side_channel_resistant: bool
    signature_size: int

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]: ...
    def sign(self, secret_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
    def describe(self) -> dict[str, object]: ...


@dataclass(frozen=True)
class BackendInfo:
    """What a bundle records about the implementation that produced it."""

    algorithm: str
    implementation: str
    quantum_resistant: bool
    side_channel_resistant: bool
    suitable_exposures: list[str]
    caveats: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "implementation": self.implementation,
            "quantumResistant": self.quantum_resistant,
            "sideChannelResistant": self.side_channel_resistant,
            "suitableExposures": self.suitable_exposures,
            "caveats": self.caveats,
        }


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------
class Ed25519Backend:
    """Ed25519 via `cryptography`, which wraps constant-time OpenSSL.

    Present for backward compatibility: it is what existing verifiers can
    check. It is also Shor-vulnerable, which is the entire reason the hybrid
    exists.
    """

    algorithm = "ed25519"
    quantum_resistant = False
    side_channel_resistant = True
    signature_size = 64

    def __init__(self) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "Ed25519 requires the `cryptography` package: pip install cryptography"
            ) from exc

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if seed is not None:
            if len(seed) < 32:
                raise ValueError("Ed25519 needs at least 32 bytes of seed")
            private = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])
        else:
            private = ed25519.Ed25519PrivateKey.generate()

        raw = serialization.Encoding.Raw
        return (
            private.public_key().public_bytes(
                encoding=raw, format=serialization.PublicFormat.Raw),
            private.private_bytes(
                encoding=raw, format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()),
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        return ed25519.Ed25519PrivateKey.from_private_bytes(secret_key).sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def describe(self) -> dict[str, object]:
        return BackendInfo(
            algorithm=self.algorithm,
            implementation="cryptography (OpenSSL)",
            quantum_resistant=False,
            side_channel_resistant=True,
            suitable_exposures=["offline", "online"],
            caveats=["Shor-vulnerable: present for backward compatibility only"],
        ).to_dict()


# ---------------------------------------------------------------------------
# ML-DSA
# ---------------------------------------------------------------------------
ML_DSA_SIGNATURE_SIZES = {"ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627}


class MlDsaBackend:
    """ML-DSA (FIPS 204) via `dilithium-py`.

    Functionally correct and validated against the FIPS 204 known-answer tests.
    **Not** constant-time, and cannot be: it is pure Python.

    Suitable for offline release signing, where nobody can observe the timing.
    Refused for online signing. For a signing service, implement
    `SignatureBackend` over `liboqs-python`, whose C core is constant-time.
    """

    quantum_resistant = True
    side_channel_resistant = False

    def __init__(self, level: str = "ml-dsa-87", deterministic: bool = False):
        """
        Args:
            deterministic: FIPS 204 defines both a *hedged* and a *deterministic*
                signing mode. Hedged is the default here and in the standard: it
                mixes 32 fresh random bytes into each signature, which is the
                recommended defence against fault-injection attacks and against
                a signature leaking key material when the same message is signed
                twice.

                The cost is that **signing is not reproducible**: the same key
                and the same message produce different signature bytes each
                time, so two bundles over one artefact are not byte-identical.
                Set this to True when byte-reproducibility is the point -- test
                vectors, a demo notebook a reader re-runs, benchmark artefacts --
                and understand that it trades away the fault-attack margin.

                Key generation is deterministic from the seed in either mode.
        """
        level = level.lower()
        if level not in ML_DSA_SIGNATURE_SIZES:
            raise ValueError(
                f"unknown level {level!r}; choose from {sorted(ML_DSA_SIGNATURE_SIZES)}"
            )
        self.algorithm = level
        self.deterministic = deterministic
        self.signature_size = ML_DSA_SIGNATURE_SIZES[level]
        self._impl = self._load(level)

    @staticmethod
    def _load(level: str) -> Any:
        try:
            from dilithium_py import ml_dsa
        except ImportError as exc:
            raise ImportError(
                "ML-DSA requires dilithium-py: pip install dilithium-py\n"
                "Note its own warning: it is an educational implementation and "
                "is not side-channel resistant. See docs/THREAT-MODEL.md."
            ) from exc
        return {"ml-dsa-44": ml_dsa.ML_DSA_44,
                "ml-dsa-65": ml_dsa.ML_DSA_65,
                "ml-dsa-87": ml_dsa.ML_DSA_87}[level]

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        """Generate a key pair, optionally from a supplied seed.

        The seed path exists so that the attested entropy from
        `qresp.signing.entropy` actually reaches the key. Without it the
        entropy attestation would describe bytes that were never used, which
        is worse than having no attestation.
        """
        if seed is None:
            pair: tuple[bytes, bytes] = self._impl.keygen()
            return pair
        if len(seed) < 32:
            raise ValueError("ML-DSA keygen needs at least 32 bytes of seed")
        derived: tuple[bytes, bytes] = self._impl.key_derive(seed[:32])
        return derived

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        signature: bytes = self._impl.sign(
            secret_key, message, deterministic=self.deterministic)
        return signature

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return bool(self._impl.verify(public_key, message, signature))
        except Exception:
            return False

    def describe(self) -> dict[str, object]:
        return BackendInfo(
            algorithm=self.algorithm,
            implementation="dilithium-py (pure Python, educational)",
            quantum_resistant=True,
            side_channel_resistant=False,
            suitable_exposures=["offline"],
            caveats=[
                "NOT constant-time: ML-DSA rejection sampling makes signing "
                "duration depend on secret data",
                "safe for offline release signing, where timings are not "
                "observable; NOT for an online signing service",
                "functional correctness validated against NIST ACVP FIPS 204 "
                "vectors; that establishes correctness, not side-channel resistance",
                "for online use, implement this interface over liboqs-python",
            ],
        ).to_dict()


class LibOqsBackend:
    """ML-DSA via liboqs. NOT IMPLEMENTED -- documented contract.

    The production path. liboqs' ML-DSA is written in C with constant-time
    discipline, so it is the backend an online signing service needs.

    An implementation MUST:
      * set `side_channel_resistant = True` only after confirming the liboqs
        build was compiled with its constant-time options and not with
        optimisations that reintroduce data-dependent branches;
      * record the liboqs version and build flags in `describe()`, since the
        resistance claim is a property of the build, not of the API;
      * pass the same FIPS 204 KATs as the pure-Python backend, so that
        swapping backends cannot silently change signature semantics.

    Note the class attribute below is False, not True. The dangerous default is
    the permissive one: whoever fills in `__init__` inherits whatever is written
    here, and a forgotten line would ship an unproven constant-time claim into
    an ONLINE exposure -- exactly the failure `check_exposure` exists to stop.
    Claiming resistance must be a deliberate edit, made after the verification
    above, not something acquired by default.
    """

    algorithm = "ml-dsa-87"
    quantum_resistant = True
    side_channel_resistant = False
    signature_size = 4627

    def __init__(self, level: str = "ml-dsa-87") -> None:
        raise NotImplementedError(
            "LibOqsBackend is a documented contract, not an implementation. "
            "See the class docstring for what an implementation must establish."
        )


# ---------------------------------------------------------------------------
# Exposure gating
# ---------------------------------------------------------------------------
def check_exposure(backend: SignatureBackend, exposure: Exposure) -> None:
    """Refuse a backend that is unsafe for the declared exposure.

    Raises rather than warns. A warning would be printed once, scrolled past,
    and the service would ship: the consequence of ignoring it is a leaked
    signing key, and nothing about that failure is visible until it is used.
    """
    if exposure is Exposure.ONLINE and not backend.side_channel_resistant:
        raise BackendUnsuitable(
            f"{backend.algorithm} via this backend is not constant-time and "
            f"must not sign in an ONLINE exposure, where an attacker can "
            f"submit messages and time the responses.\n\n"
            f"  Offline release signing: pass exposure=Exposure.OFFLINE.\n"
            f"  Signing service: use a constant-time backend (liboqs).\n\n"
            f"Adding random delay does not fix this. Averaging removes "
            f"zero-mean noise while the secret-dependent signal remains; see "
            f"docs/THREAT-MODEL.md for the measurement."
        )


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking where they differ.

    Used for verification results. A naive `==` returns as soon as it finds a
    mismatched byte, so an attacker measuring comparison time learns how many
    leading bytes of a forged signature were correct, and can build a valid
    one byte at a time.

    `hmac.compare_digest` is the standard primitive for this and is
    implemented in C.
    """
    return hmac.compare_digest(a, b)


def key_fingerprint(public_key: bytes) -> str:
    """A short, stable identifier for a public key.

    SHA3-256 truncated to 16 bytes. Used in bundles so a verifier can tell
    which key was meant without the bundle carrying the whole key.
    """
    return hashlib.sha3_256(b"qresp-key-fingerprint-v1" + public_key).hexdigest()[:32]


_BACKENDS: dict[str, Any] = {
    "ed25519": lambda **kw: Ed25519Backend(),
    "ml-dsa-44": lambda **kw: MlDsaBackend("ml-dsa-44", **kw),
    "ml-dsa-65": lambda **kw: MlDsaBackend("ml-dsa-65", **kw),
    "ml-dsa-87": lambda **kw: MlDsaBackend("ml-dsa-87", **kw),
}

DEFAULT_SUITE = ["ed25519", "ml-dsa-87"]


def get_backend(algorithm: str, deterministic: bool = False) -> SignatureBackend:
    """Instantiate the backend for an algorithm.

    `deterministic` is accepted by every backend and meaningful only for ML-DSA;
    Ed25519 is deterministic by construction (RFC 8032). See MlDsaBackend for
    what the flag trades away.

    Distinguishes "we have never heard of this" from "this is a real algorithm
    we cannot compute". Collapsing the two into one `unknown algorithm` message
    was actively misleading: SLH-DSA is a FIPS 205 standard, and reporting it as
    unknown invited the reading that it was somehow suspect rather than simply
    unimplemented here.
    """
    algorithm = algorithm.lower()
    if algorithm in _BACKENDS:
        made: SignatureBackend = _BACKENDS[algorithm](deterministic=deterministic)
        return made

    if is_known(algorithm):
        raise ValueError(
            f"{algorithm!r} is a recognised algorithm but this package has no "
            f"backend for it, so it cannot sign or verify. Implemented: "
            f"{implemented()}. Implement the SignatureBackend protocol to add one."
        )
    raise ValueError(
        f"unknown algorithm {algorithm!r}; available: {sorted(_BACKENDS)}"
    )


def _assert_registry_agrees() -> None:
    """Fail loudly at import if a backend and the registry disagree.

    Cheap (four constructions of nothing), runs once, and catches the exact
    class of drift that motivated algorithms.py: a backend claiming quantum
    resistance the registry does not grant it, or a backend for an algorithm
    the registry has never heard of. A mismatch here would make the two answers
    diverge silently at the point where it matters most.
    """
    for name in _BACKENDS:
        spec = REGISTRY.get(name)
        if spec is None:
            raise RuntimeError(
                f"backend {name!r} has no entry in the algorithm registry"
            )
        if spec.backend != name:
            raise RuntimeError(
                f"registry entry for {name!r} names backend {spec.backend!r}"
            )
    for name, spec in REGISTRY.items():
        if spec.has_backend and name not in _BACKENDS:
            raise RuntimeError(
                f"registry claims a backend for {name!r} but none is registered"
            )


_assert_registry_agrees()
