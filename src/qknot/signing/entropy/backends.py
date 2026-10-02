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
    ibm       IBM Quantum. Needs IBM_QUANTUM_TOKEN and the qrng-ibm extra.
    usb       A local QRNG device path. Needs the device, or QKNOT_USB_QRNG.

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
from pathlib import Path
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


def von_neumann_extract(bits: list[int]) -> list[int]:
    """Drop pairs that match. 01 -> 1, 10 -> 0. Removes a constant bias."""
    out: list[int] = []
    for i in range(0, len(bits) - 1, 2):
        left, right = bits[i], bits[i + 1]
        if left != right:
            out.append(right)
    return out


def _pack_bits(bits: list[int]) -> bytes:
    out = bytearray()
    for start in range(0, len(bits), 8):
        byte = 0
        for bit in bits[start:start + 8]:
            byte = (byte << 1) | (bit & 1)
        out.append(byte)
    return bytes(out)


class IbmQuantumBackend:
    """Entropy from |+> measurements on IBM Quantum hardware.

    Each qubit gets a Hadamard and is measured. Raw bits are von Neumann
    extracted before they are returned, because readout is biased.
    Needs `pip install qknot[qrng-ibm]` and `IBM_QUANTUM_TOKEN`.
    """

    name = "ibm"
    is_quantum = True

    def __init__(self, backend_name: str = "least_busy", token: str | None = None,
                 measure: Any = None) -> None:
        self.backend_name = backend_name
        self.token = token or os.environ.get("IBM_QUANTUM_TOKEN") or os.environ.get("QISKIT_IBM_TOKEN")
        self._measure = measure
        self._resolved_backend: str | None = None
        self._calibration: str | None = None

    def get_bytes(self, n: int) -> bytes:
        if n <= 0:
            raise ValueError("n must be positive")
        needed = n * 8
        extracted: list[int] = []
        raw_count = 0
        for _ in range(6):
            batch = self._raw_bits(max(needed * 4, 64))
            raw_count += len(batch)
            extracted.extend(von_neumann_extract(batch))
            if len(extracted) >= needed:
                return _pack_bits(extracted[:needed])
        raise QrngUnavailable(
            f"von Neumann extractor produced {len(extracted)} unbiased bits "
            f"from {raw_count} raw bits; need {needed}"
        )

    def _raw_bits(self, n_bits: int) -> list[int]:
        if self._measure is not None:
            bits = [int(bit) & 1 for bit in self._measure(n_bits)]
            self._resolved_backend = self._resolved_backend or "injected"
            return bits
        if not self.token:
            raise QrngUnavailable(
                "IBM Quantum needs IBM_QUANTUM_TOKEN (or QISKIT_IBM_TOKEN). "
                "Also install the extra: pip install 'qknot[qrng-ibm]'."
            )
        return self._sample_ibm(n_bits)

    def _sample_ibm(self, n_bits: int) -> list[int]:
        try:
            from qiskit import QuantumCircuit
            from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
            from qiskit_ibm_runtime import QiskitRuntimeService
            from qiskit_ibm_runtime import SamplerV2 as Sampler
        except ImportError as exc:
            raise QrngUnavailable(
                "IBM Quantum needs the optional extra: pip install 'qknot[qrng-ibm]'."
            ) from exc
        service = QiskitRuntimeService(channel="ibm_quantum_platform", token=self.token)
        if self.backend_name == "least_busy":
            backend = service.least_busy(operational=True, simulator=False)
        else:
            backend = service.backend(self.backend_name)
        self._resolved_backend = getattr(backend, "name", self.backend_name)
        properties = getattr(backend, "properties", None)
        if callable(properties):
            try:
                report = properties()
                updated = getattr(report, "last_update_date", None)
                self._calibration = None if updated is None else str(updated)
            except Exception:
                self._calibration = None
        width = max(1, min(int(getattr(backend, "num_qubits", 1) or 1), 8, n_bits))
        shots = max(1, (n_bits + width - 1) // width)
        circuit = QuantumCircuit(width)
        circuit.h(range(width))
        circuit.measure_all()
        isa = generate_preset_pass_manager(optimization_level=1, backend=backend).run(circuit)
        job = Sampler(mode=backend).run([isa], shots=shots)
        return _bits_from_sampler(job.result()[0])[: n_bits]

    def describe(self) -> dict[str, Any]:
        return {
            "endpoint": f"ibm-quantum:{self._resolved_backend or self.backend_name}",
            "authenticated": bool(self.token or self._measure is not None),
            "extractor": "von-neumann",
            "calibration": self._calibration,
        }


def _bits_from_sampler(pub_result: Any) -> list[int]:
    data = getattr(pub_result, "data", None)
    register = getattr(data, "meas", None)
    if register is None and data is not None:
        for value in vars(data).values():
            if hasattr(value, "get_bitstrings") or hasattr(value, "get_counts"):
                register = value
                break
    if register is None:
        raise QrngUnavailable("IBM Sampler result had no measurement register")
    if hasattr(register, "get_bitstrings"):
        bits: list[int] = []
        for bitstring in register.get_bitstrings():
            bits.extend(int(char) for char in bitstring if char in "01")
        return bits
    counts = register.get_counts()
    bits = []
    for bitstring, count in counts.items():
        shot = [int(char) for char in bitstring if char in "01"]
        for _ in range(int(count)):
            bits.extend(shot)
    return bits


class UsbQrngBackend:
    """Read bytes from a local QRNG device.

    The path defaults to `/dev/qrandom0`, or `QKNOT_USB_QRNG` when that is set.
    A full read of identical bytes is a failed health check, not entropy.
    """

    name = "usb"
    is_quantum = True

    def __init__(self, device_path: str | None = None) -> None:
        self.device_path = device_path or os.environ.get("QKNOT_USB_QRNG") or "/dev/qrandom0"

    def get_bytes(self, n: int) -> bytes:
        if n <= 0:
            raise ValueError("n must be positive")
        path = Path(self.device_path)
        if not path.exists():
            raise QrngUnavailable(
                f"USB QRNG not found at {path}. Pass --usb-device or set QKNOT_USB_QRNG."
            )
        try:
            with path.open("rb") as handle:
                data = handle.read(n)
        except OSError as exc:
            raise QrngUnavailable(f"USB QRNG read failed: {exc}") from exc
        if len(data) != n:
            raise QrngUnavailable(
                f"USB QRNG at {path} returned {len(data)} bytes, expected {n}"
            )
        if len(set(data)) < 2:
            raise QrngUnavailable(
                f"USB QRNG health check failed: {path} returned constant bytes"
            )
        return data

    def describe(self) -> dict[str, Any]:
        return {
            "endpoint": f"usb:{self.device_path}",
            "authenticated": None,
            "health": "full-read and not constant",
        }


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
    backend_kwargs: dict[str, Any] | None = None,
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
    source = _backend_obj or get_backend(backend, **(backend_kwargs or {}))
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

            # A person who picks fallback means now. The unattended fallback
            # policy still retries until max_attempts, then falls back.
            if policy is OnFailure.FALLBACK and (ask_human or attempt >= max_attempts):
                pass
            elif policy is OnFailure.WAIT or attempt < max_attempts:
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
