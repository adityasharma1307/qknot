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
from .sidechannel import SideChannelEvidence, SideChannelStatus

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
    """Derived from `side_channel_status`. Kept because every call site reads
    it, but it is a projection of the three-state value, not the source of
    truth: only ASSERTED maps to True."""
    side_channel_status: SideChannelStatus
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
    # Ed25519 in `cryptography` is OpenSSL's, which is constant-time by
    # construction and continuously analysed. Not a claim about ML-DSA.
    side_channel_status = SideChannelStatus.ASSERTED
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
# ECDSA P-256
# ---------------------------------------------------------------------------
class EcdsaP256Backend:
    """ECDSA over NIST P-256 via `cryptography` (OpenSSL, constant-time).

    The classical anchor a Fulcio certificate attests. Public keys are SPKI DER
    and signatures are DER-encoded, so a key or signature taken straight from an
    X.509 certificate verifies without re-encoding -- which is the whole point
    of the classical half being the one PKI already understands. Shor-vulnerable,
    which is exactly why it is paired with a post-quantum key.
    """

    algorithm = "ecdsa-p256"
    quantum_resistant = False
    side_channel_resistant = True
    side_channel_status = SideChannelStatus.ASSERTED
    signature_size = 72          # max DER-encoded P-256 signature

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: F401

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        if seed is not None:
            private = ec.derive_private_key(
                int.from_bytes(seed[:32], "big") % ec.SECP256R1().key_size
                or 1, ec.SECP256R1())
        else:
            private = ec.generate_private_key(ec.SECP256R1())
        pub = private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        priv = private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        return pub, priv

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = serialization.load_der_private_key(secret_key, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError(
                f"ecdsa-p256 secret key decoded to a {type(key).__name__}, "
                f"not an EC key")
        return key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        try:
            key = serialization.load_der_public_key(public_key)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                return False
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    def describe(self) -> dict[str, object]:
        return BackendInfo(
            algorithm=self.algorithm,
            implementation="cryptography (OpenSSL)",
            quantum_resistant=False, side_channel_resistant=True,
            suitable_exposures=["offline", "online"],
            caveats=["Shor-vulnerable: the classical anchor, paired with a PQC key"],
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
    # MEASURED, not suspected: ~10-85 ms variance with the key, and 79.5%
    # key identification at 1,600 traces. See docs/THREAT-MODEL.md.
    side_channel_status = SideChannelStatus.KNOWN_LEAKY

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
        `qknot.signing.entropy` actually reaches the key. Without it the
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
    """ML-DSA via liboqs, through the `oqs` bindings.

    The production path: liboqs' ML-DSA is C with constant-time discipline, and
    it is roughly 330x faster than the pure-Python backend -- 0.046 ms against
    15.2 ms for ML-DSA-44 -- which is what makes an online signing service
    practical at all.

    STATUS IS `UNKNOWN`, DELIBERATELY, AND MEASUREMENT DOES NOT CHANGE IT
    ====================================================================
    liboqs exposes no constant-time or build-configuration flag at runtime. Its
    entire per-mechanism surface is `name`, `version`, `claimed_nist_level`,
    `is_ind_cca` and the key and signature lengths -- probed, not assumed. So a
    build's discipline cannot be established from inside this process.

    A black-box timing measurement of this backend found no separation at 5,000
    samples per key and 3,200 traces, while the same harness separates
    dilithium-py from 10 traces (docs/THREAT-MODEL.md, "liboqs, measured").
    That bounds a leak; it does not prove the absence of one, and it is not a
    constant-time analysis. The
    status therefore stays `UNKNOWN` and `check_exposure` keeps refusing online
    use until a deployer supplies `SideChannelEvidence` from dudect, ctgrind or
    Binsec/Rel against their specific build.

    Our own favourable measurement is exactly the evidence it would be tempting
    to promote to a guarantee, which is the reason the three states exist.
    """

    quantum_resistant = True
    side_channel_resistant = False
    # UNKNOWN, and this is the honest default rather than a placeholder:
    # liboqs exposes NO constant-time or build-configuration flag at
    # runtime, so a build's discipline cannot be checked from here.
    side_channel_status = SideChannelStatus.UNKNOWN

    #: qknot's lowercase names to liboqs' mechanism names.
    _MECHANISMS = {"ml-dsa-44": "ML-DSA-44",
                   "ml-dsa-65": "ML-DSA-65",
                   "ml-dsa-87": "ML-DSA-87"}

    def __init__(self, level: str = "ml-dsa-87", deterministic: bool = False):
        level = level.lower()
        if level not in self._MECHANISMS:
            raise ValueError(
                f"unknown ML-DSA level {level!r}; expected one of "
                f"{sorted(self._MECHANISMS)}"
            )
        if deterministic:
            # liboqs signs in FIPS 204 hedged mode and exposes no switch. The
            # pure-Python backend accepts `deterministic` and honours it, so
            # accepting it here and ignoring it would make two backends differ
            # in behaviour while agreeing in signature -- the precise drift
            # _assert_conforms exists to catch, arriving through a parameter
            # value rather than a parameter name.
            raise ValueError(
                "liboqs signs in hedged mode only and exposes no deterministic "
                "switch. Use the dilithium-py backend when byte-reproducible "
                "signatures are the point, or drop deterministic=True."
            )

        self.algorithm = level
        self.deterministic = False
        self.signature_size = ML_DSA_SIGNATURE_SIZES[level]
        self.mechanism = self._MECHANISMS[level]
        self._oqs = self._load()

        enabled = self._oqs.get_enabled_sig_mechanisms()
        if self.mechanism not in enabled:
            raise BackendUnsuitable(
                f"this liboqs build does not enable {self.mechanism}. Enabled "
                f"ML-DSA mechanisms: "
                f"{[m for m in enabled if 'ML-DSA' in m] or 'none'}. A build "
                f"compiled without it cannot sign, and falling back silently "
                f"would change the algorithm out from under the caller."
            )

    #: Cached across instances: see _load for why this is not an optimisation.
    _module: Any = None
    _load_error: str | None = None

    @classmethod
    def _load(cls) -> Any:
        """Import `oqs` once, and survive the two ways it misbehaves.

        `import oqs` CALLS sys.exit() when its build fails. SystemExit derives
        from BaseException, not Exception, so an ordinary `except Exception`
        does not catch it and the import terminates the host process -- a
        signing service would die at startup because an OPTIONAL dependency
        could not compile. Caught explicitly here.

        It also downloads and compiles liboqs from source on first import,
        which takes minutes. So the outcome is cached, including the failure:
        without that, every construction re-runs the build, and a test suite
        that touches this class a dozen times hangs rather than skipping.

        Worth stating in the paper: the post-quantum library one would adopt to
        strengthen supply-chain integrity fetches and builds its own C core at
        import time, with no signature verification over what it downloaded,
        and exits the process if that fails.
        """
        if cls._module is not None:
            return cls._module
        if cls._load_error is not None:
            raise ImportError(cls._load_error)

        try:
            import oqs
        except KeyboardInterrupt:
            raise
        except BaseException as exc:      # noqa: BLE001 -- SystemExit included
            cls._load_error = (
                f"liboqs is unavailable: {type(exc).__name__}: {exc}\n\n"
                f"Install with `pip install liboqs-python`, which compiles "
                f"liboqs from source and needs cmake, a C toolchain and "
                f"OpenSSL headers. Note that it downloads and builds that "
                f"source WITHOUT verifying a signature over it, and calls "
                f"sys.exit() if the build fails.\n\n"
                f"qknot does not need liboqs: get_backend() returns the "
                f"pure-Python backend by default, which is suitable for "
                f"offline release signing."
            )
            raise ImportError(cls._load_error) from None

        cls._module = oqs
        return oqs

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        """Generate a key pair. A seed is REFUSED rather than ignored.

        The pure-Python backend derives a key deterministically from a seed so
        that attested entropy actually reaches the key. liboqs' API generates
        internally and offers no seeded path, so honouring the parameter is
        impossible -- and ignoring it would produce a key unrelated to the
        entropy the bundle attests to, which is worse than having no
        attestation at all. It is the same failure as recording a signature
        algorithm nobody parsed.
        """
        if seed is not None:
            raise ValueError(
                "liboqs generates keys internally and exposes no seeded "
                "keygen, so the attested entropy cannot reach the key. Use "
                "the dilithium-py backend when the entropy attestation must "
                "bind to the key material; silently ignoring the seed would "
                "make the attestation describe bytes that were never used."
            )
        signer = self._oqs.Signature(self.mechanism)
        public_key: bytes = signer.generate_keypair()
        secret_key: bytes = signer.export_secret_key()
        return public_key, secret_key

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with self._oqs.Signature(self.mechanism, secret_key) as signer:
            signature: bytes = signer.sign(message)
        return signature

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            with self._oqs.Signature(self.mechanism) as verifier:
                return bool(verifier.verify(message, signature, public_key))
        except Exception:
            # A malformed signature is a failed verification, not a crash.
            return False

    def describe(self) -> dict[str, object]:
        """What produced a signature, including what could NOT be established."""
        with self._oqs.Signature(self.mechanism) as signer:
            details = dict(signer.details)
        return {
            "algorithm": self.algorithm,
            "implementation": f"liboqs {self._oqs.oqs_version()} "
                              f"via liboqs-python {self._oqs.oqs_python_version()}",
            "mechanism": self.mechanism,
            "mechanismVersion": details.get("version"),
            "claimedNistLevel": details.get("claimed_nist_level"),
            "quantumResistant": self.quantum_resistant,
            "sideChannelStatus": self.side_channel_status.value,
            "sideChannelBasis": (
                "liboqs exposes no constant-time or build-configuration flag at "
                "runtime, so this build's discipline cannot be established from "
                "within the process. See docs/THREAT-MODEL.md, "
                "'liboqs, measured'."
            ),
            "deterministic": False,
            "signatureSize": self.signature_size,
        }


# ---------------------------------------------------------------------------
# Exposure gating
# ---------------------------------------------------------------------------
def check_exposure(backend: SignatureBackend, exposure: Exposure) -> None:
    """Refuse a backend that is unsafe for the declared exposure.

    Raises rather than warns. A warning would be printed once, scrolled past,
    and the service would ship: the consequence of ignoring it is a leaked
    signing key, and nothing about that failure is visible until it is used.
    """
    status = getattr(backend, "side_channel_status", None)
    if status is None:                      # a backend predating the tri-state
        status = (SideChannelStatus.ASSERTED if backend.side_channel_resistant
                  else SideChannelStatus.KNOWN_LEAKY)

    if exposure is Exposure.ONLINE and not status.permits_online:
        # UNKNOWN and KNOWN_LEAKY gate identically -- introducing the third
        # state changed no decision, only the reason given for it. What it
        # stops is the bundle asserting a fact nobody established.
        if status is SideChannelStatus.UNKNOWN:
            why = (f"whether {backend.algorithm} via this backend is "
                   f"constant-time HAS NOT BEEN ESTABLISHED, and no runtime "
                   f"mechanism exists to establish it: liboqs exposes no "
                   f"constant-time or build-configuration flag. Unknown is "
                   f"refused exactly as measured leakage is, because an "
                   f"unverified claim is not a weaker guarantee -- it is none")
        else:
            why = (f"{backend.algorithm} via this backend is MEASURED to leak "
                   f"timing and must not sign in an ONLINE exposure, where an "
                   f"attacker can submit messages and time the responses")
        raise BackendUnsuitable(
            f"{why}.\n\n"
            f"  Offline release signing: pass exposure=Exposure.OFFLINE.\n"
            f"  Signing service: use a constant-time backend (liboqs) whose "
            f"build\n    you have verified, and attach SideChannelEvidence to "
            f"raise it to\n    ASSERTED. Note that installing liboqs does not "
            f"by itself establish\n    anything: it exposes no constant-time "
            f"flag at runtime.\n\n"
            f"Adding random delay does not fix this. Averaging removes "
            f"zero-mean noise while the secret-dependent signal remains; see "
            f"docs/THREAT-MODEL.md for the measurement."
        )


def attest_constant_time(backend: Any, evidence: SideChannelEvidence) -> Any:
    """Record a deployer's verification of THIS build, raising it to ASSERTED.

    The only route out of UNKNOWN, and deliberately a manual one. Nothing here
    inspects the build -- there is nothing to inspect, since liboqs exposes no
    constant-time or build-configuration flag at runtime. What this does is
    attach a structured, attributed claim so a downstream verifier can evaluate
    it, which is the whole reason ASSERTED is distinguishable from True.

    Refuses to raise a backend that is MEASURED to leak. dilithium-py's timing
    variance is a property of the implementation, not of anyone's build, so no
    evidence about a build can overturn it -- and permitting that would make
    the state machine a formality.
    """
    status = getattr(backend, "side_channel_status", None)
    if status is SideChannelStatus.KNOWN_LEAKY:
        raise BackendUnsuitable(
            f"{backend.algorithm} via {type(backend).__name__} is MEASURED to "
            f"leak timing; evidence about a build cannot overturn a property "
            f"of the implementation. See docs/THREAT-MODEL.md."
        )
    if not isinstance(evidence, SideChannelEvidence):
        raise TypeError(
            "attest_constant_time requires SideChannelEvidence, not a free "
            "string: an assertion nobody downstream can evaluate is exactly "
            "what the three states exist to prevent."
        )
    backend.side_channel_status = SideChannelStatus.ASSERTED
    backend.side_channel_resistant = True
    backend.side_channel_evidence = evidence
    logging.getLogger(__name__).warning(
        "backend %s raised to ASSERTED on %s's evidence (%s %s, report %s)",
        backend.algorithm, evidence.asserted_by, evidence.tool,
        evidence.tool_version, evidence.report_sha256[:16])
    return backend


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
    return hashlib.sha3_256(b"qknot-key-fingerprint-v1" + public_key).hexdigest()[:32]


_BACKENDS: dict[str, Any] = {
    "ecdsa-p256": lambda **kw: EcdsaP256Backend(),
    "ed25519": lambda **kw: Ed25519Backend(),
    "ml-dsa-44": lambda **kw: MlDsaBackend("ml-dsa-44", **kw),
    "ml-dsa-65": lambda **kw: MlDsaBackend("ml-dsa-65", **kw),
    "ml-dsa-87": lambda **kw: MlDsaBackend("ml-dsa-87", **kw),
}

DEFAULT_SUITE = ["ed25519", "ml-dsa-87"]


def get_backend(algorithm: str, deterministic: bool = False,
                implementation: str | None = None) -> SignatureBackend:
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

    if implementation is not None:
        # Opt-in only. Installing liboqs must not silently change which
        # implementation signs: a caller who never asked for it would get a
        # different backend, a different side-channel status and no seeded
        # keygen, none of which is visible at the call site.
        if implementation == "liboqs":
            return LibOqsBackend(algorithm, deterministic=deterministic)
        if implementation in ("dilithium-py", "pure-python"):
            return MlDsaBackend(algorithm, deterministic=deterministic)
        raise ValueError(
            f"unknown implementation {implementation!r}; "
            f"expected 'liboqs' or 'dilithium-py'"
        )

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


def _assert_conforms(name: str, backend: Any) -> None:
    """Check a backend really satisfies SignatureBackend, at registration time.

    `Protocol` without `@runtime_checkable` is a static-analysis construct: it
    binds nothing at runtime, and `get_backend` returned whatever the registry
    held. Even `@runtime_checkable` would only check that method NAMES exist --
    `isinstance` against a Protocol deliberately ignores signatures -- so a
    backend whose `sign` grew a required argument would still pass and fail
    later, at the call site, in whatever context first used it.

    That is the expensive kind of failure: a second implementation of an
    interface is exactly where drift appears, and this project is about to add
    one. So the shape is checked explicitly and eagerly, and a mismatch is an
    import-time error naming the offending member.
    """
    import inspect

    cls = type(backend)
    # Attributes are read from the INSTANCE: MlDsaBackend sets `algorithm` in
    # __init__ because it varies by level, so checking the class would report a
    # conforming backend as broken.
    for attribute, expected in (("algorithm", str), ("quantum_resistant", bool),
                                ("side_channel_resistant", bool),
                                ("signature_size", int)):
        if not hasattr(backend, attribute):
            raise RuntimeError(
                f"backend {name!r} ({cls.__name__}) is missing the required "
                f"attribute {attribute!r} of SignatureBackend"
            )
        value = getattr(backend, attribute)
        if not isinstance(value, expected):
            raise RuntimeError(
                f"backend {name!r} declares {attribute}={value!r}; "
                f"SignatureBackend requires {expected.__name__}"
            )

    status = getattr(backend, "side_channel_status", None)
    if status is not None and backend.side_channel_resistant != status.permits_online:
        raise RuntimeError(
            f"backend {name!r} declares side_channel_resistant="
            f"{backend.side_channel_resistant} but side_channel_status="
            f"{status.value}, which permits_online="
            f"{status.permits_online}. The bool is a projection of the "
            f"three-state value; if they disagree, whichever a caller happens "
            f"to read decides whether a leaky backend signs online."
        )

    for method, params in (("keygen", ["seed"]),
                           ("sign", ["secret_key", "message"]),
                           ("verify", ["public_key", "message", "signature"]),
                           ("describe", [])):
        function = getattr(cls, method, None)
        if function is None or not callable(function):
            raise RuntimeError(
                f"backend {name!r} ({cls.__name__}) does not implement "
                f"{method}(), required by SignatureBackend"
            )
        actual = [p for p in inspect.signature(function).parameters
                  if p not in ("self", "cls")]
        # Positional names must match in order. A backend free to rename
        # `message` to `data` would break every keyword call site, and the
        # protocol is the thing that is supposed to make callers portable.
        if actual[:len(params)] != params:
            raise RuntimeError(
                f"backend {name!r} ({cls.__name__}).{method} takes {actual!r}; "
                f"SignatureBackend requires {params!r} first. Signature drift "
                f"between backends is what this check exists to catch."
            )


def _assert_registry_agrees() -> None:
    """Fail loudly at import if a backend and the registry disagree.

    Cheap (four constructions of nothing), runs once, and catches the exact
    class of drift that motivated algorithms.py: a backend claiming quantum
    resistance the registry does not grant it, or a backend for an algorithm
    the registry has never heard of. A mismatch here would make the two answers
    diverge silently at the point where it matters most.
    """
    for name, factory in _BACKENDS.items():
        # The registry holds factories, not classes, so conformance is checked
        # against a real instance -- which is the thing get_backend hands out,
        # and therefore the thing that has to satisfy the protocol.
        _assert_conforms(name, factory(deterministic=False))
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
