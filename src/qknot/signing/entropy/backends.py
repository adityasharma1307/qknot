"""Quantum random number generation with attested provenance.

Phase II, Task 4. Supplies entropy for ML-DSA key generation and records where
that entropy actually came from.

WHY THE ATTESTATION IS THE POINT
================================
A key seeded from a quantum source and a key seeded from `os.urandom` are
indistinguishable by inspection. Both are 32 uniform-looking bytes. If the
pipeline silently falls back when the QRNG is unreachable -- which it will,
because it is a free public web service -- then every downstream claim about
quantum entropy becomes unfalsifiable, and a reader has to take the signer's
word for it.

So every call records an `EntropyAttestation`: which backend actually served
the bytes, when, how many, and a commitment to the material. That record is
what lets a verifier distinguish a QRNG-seeded key from a PRNG-fallback key
instead of assuming a provenance that was never established. It becomes a
signed predicate in the Task 5 bundle.

Falling back is not a security failure. ML-DSA's FIPS 204 guarantee rests on
the hardness of Module-LWE, not on the physical origin of the seed, and
`os.urandom` is a CSPRNG seeded from the operating system's entropy pool. The
fallback is a defensible engineering choice; concealing it would not be.

BACKENDS
========
    anu       ANU Quantum Numbers, over HTTPS. Default. See the note below.
    system    os.urandom. Always available, always honest about being classical.
    ibm       IBM Quantum. Documented contract only, not implemented.
    usb       Local USB hardware QRNG. Documented contract only, not implemented.

A NOTE ON THE ANU ENDPOINT
==========================
The project memo specifies ANU as a "public HTTPS API, no auth". That was true
of the original `qrng.anu.edu.au/API/jsonI.php` service, but ANU has since
migrated to `api.quantumnumbers.anu.edu.au`, which requires a free API key, and
describes the unauthenticated endpoint as being phased out. Both are supported
here: the keyed endpoint is used when `ANU_API_KEY` is set, and the legacy one
otherwise, with the deprecation surfaced in the attestation rather than hidden.

This matters beyond configuration. Task 7 requires a Colab notebook that is
"fully reproducible without hardware QRNG access (ANU backend only)". If the
default backend needs a key that the reader does not have, the notebook is not
reproducible by an arbitrary reader. Flagged for a decision rather than
resolved here.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

log = logging.getLogger(__name__)

# ANU caps a request at 1024 items, so larger draws are chunked.
ANU_MAX_ITEMS_PER_REQUEST = 1024
ANU_LEGACY_URL = "https://qrng.anu.edu.au/API/jsonI.php"
ANU_KEYED_URL = "https://api.quantumnumbers.anu.edu.au"

# Domain separation for the entropy commitment. Hashing the raw seed bare would
# still be preimage-resistant, but a tagged hash cannot be replayed as a
# commitment in any other protocol that happens to hash the same bytes.
COMMITMENT_DOMAIN = b"qknot-entropy-attestation-v1"
COMMITMENT_ALGORITHM = "sha3-256"


class QrngUnavailable(RuntimeError):  # noqa: N818
    """The requested quantum backend could not supply entropy.

    Named for the condition rather than with an ``Error`` suffix because it is
    raised, caught and reasoned about as a state of the world -- the QRNG is
    unavailable -- and reads that way at every call site.
    """


class OnFailure(str, Enum):
    """What to do when the quantum backend is unreachable and no human is present.

    WAIT      retry with backoff until the backend recovers. For pipelines where
              quantum provenance is a hard requirement and latency is not.
    FALLBACK  use os.urandom and record the substitution in the attestation.
              The default: the resulting key is cryptographically sound, and the
              attestation prevents the downgrade from going unnoticed.
    ABORT     raise. For anyone whose threat model genuinely requires a quantum
              seed, where a classical key is worse than no key.
    """

    WAIT = "wait"
    FALLBACK = "fallback"
    ABORT = "abort"


DEFAULT_ON_FAILURE = OnFailure.FALLBACK


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class EntropyAttestation:
    """Evidence of where a key's entropy came from.

    Deliberately records the backend that *actually served the bytes*, not the
    one that was requested. `requested_backend` and `backend` differing is
    precisely the fallback case a verifier needs to see.

    The commitment is a tagged SHA3-256 over the raw entropy. SHA-3 rather than
    SHA-2 for the same reason the Task 5 digest uses it: Grover's algorithm
    halves the effective preimage security of a hash, and SHA-3's larger
    internal state leaves more margin. The commitment binds the attestation to
    specific entropy without publishing it, so a signer who later discloses the
    seed can be checked, and one who does not still cannot swap the record onto
    different key material.
    """

    backend: str
    requested_backend: str
    fallback_used: bool
    n_bytes: int
    timestamp: str
    commitment: str
    commitment_algorithm: str = COMMITMENT_ALGORITHM
    endpoint: str | None = None
    endpoint_deprecated: bool = False
    authenticated: bool | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def verify_commitment(self, raw: bytes) -> bool:
        """Check that this attestation commits to `raw`."""
        return commit(raw) == self.commitment

    @property
    def is_quantum(self) -> bool:
        """True only if a quantum backend actually served the entropy.

        A verifier should branch on this rather than on `requested_backend`,
        which records an intention, not an outcome.
        """
        return not self.fallback_used and self.backend in _QUANTUM_BACKENDS


def commit(raw: bytes) -> str:
    """Tagged SHA3-256 commitment to entropy material."""
    return hashlib.sha3_256(COMMITMENT_DOMAIN + raw).hexdigest()


@dataclass(frozen=True)
class EntropyResult:
    """Entropy plus its provenance. The two travel together by construction."""

    raw: bytes
    attestation: EntropyAttestation


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------
class EntropyBackend(Protocol):
    name: str
    is_quantum: bool

    def get_bytes(self, n: int) -> bytes:
        """Return exactly n bytes, or raise QrngUnavailable."""
        ...

    def describe(self) -> dict[str, Any]:
        """Backend-specific fields for the attestation."""
        ...


# ---------------------------------------------------------------------------
# System CSPRNG
# ---------------------------------------------------------------------------
class SystemEntropyBackend:
    """os.urandom. The fallback, and the only backend that never fails.

    Not a lesser source in any cryptographic sense: it is the operating
    system's CSPRNG, which is what essentially all deployed key generation
    uses. It is simply not quantum, and says so.
    """

    name = "system"
    is_quantum = False

    def get_bytes(self, n: int) -> bytes:
        return os.urandom(n)

    def describe(self) -> dict[str, Any]:
        return {"endpoint": None, "authenticated": None}


# ---------------------------------------------------------------------------
# ANU Quantum Numbers
# ---------------------------------------------------------------------------
class AnuQrngBackend:
    """Entropy from ANU's vacuum-fluctuation quantum random number generator.

    Two endpoints, because ANU migrated services:

      * `api.quantumnumbers.anu.edu.au` -- current, requires a free API key
        supplied via `api_key` or the ANU_API_KEY environment variable.
      * `qrng.anu.edu.au/API/jsonI.php` -- original, unauthenticated, described
        by ANU as being phased out. Used only when no key is available, and
        flagged as deprecated in the attestation so that a run which silently
        depended on a dying endpoint is visible after the fact.
    """

    name = "anu"
    is_quantum = True

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 30.0,
        session: Any = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("ANU_API_KEY")
        self.timeout = timeout
        self._session = session
        self.endpoint = ANU_KEYED_URL if self.api_key else ANU_LEGACY_URL
        self.deprecated = not self.api_key

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def get_bytes(self, n: int) -> bytes:
        if n <= 0:
            raise ValueError("n must be positive")
        session = self._get_session()
        out = bytearray()

        # ANU caps a single response at 1024 items regardless of endpoint, so a
        # 32-byte seed is one request but a large draw is several.
        while len(out) < n:
            want = min(ANU_MAX_ITEMS_PER_REQUEST, n - len(out))
            out.extend(self._request_block(session, want))

        if len(out) != n:
            raise QrngUnavailable(f"expected {n} bytes, assembled {len(out)}")
        return bytes(out)

    def _request_block(self, session: Any, count: int) -> bytes:
        params = {"length": count, "type": "uint8"}
        headers = {"User-Agent": "qknot/0.2 (BITS Pilani CS F376 research)"}
        if self.api_key:
            headers["x-api-key"] = self.api_key

        try:
            response = session.get(
                self.endpoint, params=params, headers=headers, timeout=self.timeout
            )
        except Exception as exc:
            raise QrngUnavailable(f"ANU request failed: {exc}") from exc

        if response.status_code == 401:
            raise QrngUnavailable(
                "ANU rejected the API key (401). The unauthenticated endpoint is "
                "being retired; register for a free key at "
                "https://quantumnumbers.anu.edu.au and set ANU_API_KEY."
            )
        if response.status_code != 200:
            raise QrngUnavailable(f"ANU returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except Exception as exc:
            raise QrngUnavailable(f"ANU response was not JSON: {exc}") from exc

        if not payload.get("success", False):
            raise QrngUnavailable(f"ANU reported failure: {payload!r}")

        data = payload.get("data")
        if not isinstance(data, list) or len(data) != count:
            raise QrngUnavailable(
                f"ANU returned {len(data) if isinstance(data, list) else '?'} "
                f"items, expected {count}"
            )
        if not all(isinstance(v, int) and 0 <= v <= 255 for v in data):
            raise QrngUnavailable("ANU returned values outside the uint8 range")
        return bytes(data)

    def describe(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "endpoint_deprecated": self.deprecated,
            "authenticated": bool(self.api_key),
        }


# ---------------------------------------------------------------------------
# Documented contracts, not implementations
# ---------------------------------------------------------------------------
class IbmQuantumBackend:
    """Entropy from measurement on IBM Quantum hardware. NOT IMPLEMENTED.

    Contract, so that a future implementation and any verifier agree on what
    the attestation means:

      * A circuit of `ceil(8n / qubits)` shots prepares each qubit in |+> via a
        Hadamard and measures in the computational basis, yielding one raw bit
        per qubit per shot from state collapse.
      * Raw measurements MUST be de-biased before use. Real devices have
        asymmetric readout error, so P(0) != P(1) and the raw stream is not
        uniform. Von Neumann extraction over disjoint pairs is the minimum;
        Toeplitz extraction with a documented min-entropy estimate is better.
        Skipping this step is the most likely way for an implementation to
        produce a seed that looks quantum and is measurably biased.
      * `describe()` MUST report backend name, calibration timestamp and the
        extractor used, since the entropy quality claim is meaningless without
        them.
      * Queue latency is unbounded in practice, so callers should expect this
        backend to be the one that triggers the wait-or-fallback decision.

    Requires `qiskit` and IBM Quantum credentials.
    """

    name = "ibm"
    is_quantum = True

    def __init__(self, backend_name: str = "least_busy", token: str | None = None):
        self.backend_name = backend_name
        self.token = token or os.environ.get("IBM_QUANTUM_TOKEN")

    def get_bytes(self, n: int) -> bytes:
        raise NotImplementedError(
            "IBM Quantum backend is a documented contract, not an implementation. "
            "See the class docstring for the required de-biasing step."
        )

    def describe(self) -> dict[str, Any]:
        return {"endpoint": f"ibm-quantum:{self.backend_name}", "authenticated": bool(self.token)}


class UsbQrngBackend:
    """Entropy from a local USB hardware QRNG. NOT IMPLEMENTED.

    Contract:

      * Reads from a character device (`/dev/qrandom0`, a vendor SDK, or a
        serial endpoint) exposed by devices such as the ID Quantique Quantis.
      * The device's own health tests MUST be polled and their result recorded;
        a hardware RNG that has silently failed still returns bytes, and those
        bytes may be constant. This is the failure mode the attestation exists
        to catch, so an implementation that ignores health status is worse than
        no hardware backend at all.
      * `describe()` MUST report device model, serial number and firmware
        version, so an attestation can be tied to a specific physical device.
      * Unlike the network backends this one cannot be reached by an auditor,
        which makes its attestation the least externally checkable of the four
        and the most dependent on the signer's honesty.
    """

    name = "usb"
    is_quantum = True

    def __init__(self, device_path: str = "/dev/qrandom0"):
        self.device_path = device_path

    def get_bytes(self, n: int) -> bytes:
        raise NotImplementedError(
            "USB QRNG backend is a documented contract, not an implementation. "
            "See the class docstring for the required health-test polling."
        )

    def describe(self) -> dict[str, Any]:
        return {"endpoint": f"usb:{self.device_path}", "authenticated": None}


_BACKENDS: dict[str, type] = {
    "anu": AnuQrngBackend,
    "system": SystemEntropyBackend,
    "ibm": IbmQuantumBackend,
    "usb": UsbQrngBackend,
}
_QUANTUM_BACKENDS = frozenset({"anu", "ibm", "usb"})

DEFAULT_BACKEND = "anu"


def get_backend(name: str, **kwargs: Any) -> EntropyBackend:
    if name not in _BACKENDS:
        raise ValueError(f"unknown backend {name!r}; choose from {sorted(_BACKENDS)}")
    made: EntropyBackend = _BACKENDS[name](**kwargs)
    return made


# ---------------------------------------------------------------------------
# Acquisition
# ---------------------------------------------------------------------------
def _is_interactive() -> bool:
    """True when a human can answer a prompt.

    CI is checked explicitly because a build agent may still allocate a tty,
    and a pipeline that blocks on a prompt nobody will ever see is worse than
    one that takes the documented default.
    """
    if os.environ.get("CI", "").lower() in ("1", "true", "yes"):
        return False
    return sys.stdin.isatty() and sys.stderr.isatty()


def _prompt(attempt: int, error: Exception) -> OnFailure:
    """Ask the operator what to do. Interactive contexts only."""
    print(f"\nQuantum entropy source unavailable (attempt {attempt}): {error}",
          file=sys.stderr)
    print("  [w] wait and retry", file=sys.stderr)
    print("  [f] fall back to os.urandom, recorded in the attestation", file=sys.stderr)
    print("  [a] abort", file=sys.stderr)
    while True:
        try:
            choice = input("Choice [w/f/a]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborting.", file=sys.stderr)
            return OnFailure.ABORT
        if choice in ("w", "wait"):
            return OnFailure.WAIT
        if choice in ("f", "fallback"):
            return OnFailure.FALLBACK
        if choice in ("a", "abort"):
            return OnFailure.ABORT


def get_entropy(
    n_bytes: int = 32,
    backend: str = DEFAULT_BACKEND,
    on_failure: OnFailure = DEFAULT_ON_FAILURE,
    interactive: bool | None = None,
    max_attempts: int = 3,
    backoff: float = 2.0,
    _backend_obj: EntropyBackend | None = None,
    _sleep: Any = time.sleep,
) -> EntropyResult:
    """Acquire `n_bytes` of entropy from ONE source and attest to its origin.

    SUPERSEDED BY `mixing.mix_entropy`. Kept because it is a coherent API and
    the CLI still exposes it behind `--backend`, but new code should mix:

      * Choosing one source creates a downgrade to reason about and an
        `on_failure` policy to configure. Combining sources with a KDF yields a
        result at least as strong as the strongest input, so the question does
        not arise.
      * The `EntropyAttestation` produced here has no `not_before` and no
        per-source `contributions`, so `temporal.evidence_from_attestation`
        cannot read it. A key seeded through this path carries no time evidence
        a verifier can use. That fails closed, but it is a silent loss of a
        property the mixing path provides.
      * There is no secret/public distinction here. It happens to be safe --
        `get_backend` cannot return the NIST beacon, so public randomness can
        never reach a key through this function -- but the safety is a property
        of the registry rather than an enforced invariant. `mix_entropy` raises
        `NoSecretEntropy` instead of relying on that.

    Args:
        n_bytes: how much entropy to draw. 32 seeds any ML-DSA parameter set.
        backend: one of anu, system, ibm, usb.
        on_failure: behaviour when a quantum backend fails and no human is
            present. Ignored in interactive sessions, where the operator is
            asked instead.
        interactive: override the tty/CI detection. Mainly for tests.
        max_attempts: attempts before honouring `on_failure`.

    Returns:
        EntropyResult carrying the bytes and the attestation.

    Raises:
        QrngUnavailable: if the backend fails and the effective policy is ABORT.
    """
    source = _backend_obj or get_backend(backend)
    ask_human = _is_interactive() if interactive is None else interactive
    notes: list[str] = []
    started = datetime.now(timezone.utc)

    if not source.is_quantum:
        raw = source.get_bytes(n_bytes)
        return EntropyResult(
            raw=raw,
            attestation=_attest(source, backend, raw, started, False, notes),
        )

    attempt = 0
    policy = on_failure
    while True:
        attempt += 1
        try:
            raw = source.get_bytes(n_bytes)
        except Exception as exc:
            log.warning("Quantum backend %s failed on attempt %d: %s",
                        source.name, attempt, exc)
            notes.append(f"attempt_{attempt}_failed: {exc}")

            if ask_human:
                policy = _prompt(attempt, exc)

            if policy is OnFailure.ABORT:
                raise QrngUnavailable(
                    f"{source.name} unavailable after {attempt} attempt(s) and "
                    f"policy is abort: {exc}"
                ) from exc

            if policy is OnFailure.WAIT or attempt < max_attempts:
                delay = backoff ** attempt
                log.info("Retrying %s in %.1fs", source.name, delay)
                _sleep(delay)
                continue

            # FALLBACK
            notes.append(
                "fell back to os.urandom: the key is cryptographically sound, "
                "but its entropy is NOT of quantum origin"
            )
            fallback = SystemEntropyBackend()
            raw = fallback.get_bytes(n_bytes)
            return EntropyResult(
                raw=raw,
                attestation=_attest(fallback, backend, raw, started, True, notes),
            )
        else:
            return EntropyResult(
                raw=raw,
                attestation=_attest(source, backend, raw, started, False, notes),
            )


def _attest(
    source: EntropyBackend,
    requested: str,
    raw: bytes,
    started: datetime,
    fallback_used: bool,
    notes: list[str],
) -> EntropyAttestation:
    described = source.describe()
    return EntropyAttestation(
        backend=source.name,
        requested_backend=requested,
        fallback_used=fallback_used,
        n_bytes=len(raw),
        timestamp=started.isoformat(),
        commitment=commit(raw),
        endpoint=described.get("endpoint"),
        endpoint_deprecated=described.get("endpoint_deprecated", False),
        authenticated=described.get("authenticated"),
        notes=notes,
    )
