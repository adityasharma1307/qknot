"""Hybrid signing and verification.

Ties together the four pieces built separately:

    digest.py    what is being signed
    combiner.py  the algorithm binding that prevents stripping
    backends.py  the primitives, each honest about its side-channel posture
    entropy/     where the key's randomness came from, and the evidence

WHAT GETS SIGNED
================
The DSSE pre-authentication encoding of the whole in-toto statement -- not the
artefact digest, and not the binding alone.

The binding sits *inside* that statement, so it is still true that every
algorithm signs a value committing to the full algorithm set, which is what
makes the hybrid non-separable (see combiner.py for the attack that prevents).
Signing the enclosing statement rather than the binding by itself additionally
brings the entropy attestation, the backend descriptors and the signer's notes
under signature. Those used to travel inside the envelope while being covered by
nothing, which meant they looked signed and were freely editable -- see dsse.py.

VERIFICATION MODES
==================
    CLASSICAL  Ed25519 only. What a legacy verifier can do today.
    PQC        the post-quantum signature only.
    STRICT     every algorithm the binding names must be present and valid.

STRICT is not merely "check more signatures". It is the only mode that
consults the binding, so it is the only mode that detects stripping. A caller
who verifies in CLASSICAL mode against a hybrid bundle gets exactly the
protection Ed25519 offers and no more, which is the correct semantics but must
be understood.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .backends import (
    DEFAULT_SUITE,
    Exposure,
    SignatureBackend,
    check_exposure,
    get_backend,
    key_fingerprint,
)
from .combiner import BindingMismatch, HybridBinding, build_binding, verify_binding
from .digest import DEFAULT_ALGORITHM, Manifest, digest_artefact
from .dsse import DSSE_PAYLOAD_TYPE, pae
from .temporal import TimeEvidence, assess, evidence_from_attestation

log = logging.getLogger(__name__)


class VerifyMode(str, Enum):
    CLASSICAL = "classical"
    PQC = "pqc"
    STRICT = "strict"


class VerificationFailed(Exception):  # noqa: N818
    """A signature, or the binding covering the signatures, did not check out."""


@dataclass(frozen=True)
class KeyPair:
    algorithm: str
    public_key: bytes
    secret_key: bytes
    fingerprint: str
    entropy_attestation: Any | None = None

    def public_info(self) -> dict[str, Any]:
        """Everything about the key that is safe to publish."""
        return {
            "algorithm": self.algorithm,
            "publicKey": self.public_key.hex(),
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class HybridKeySet:
    """One key per algorithm in the suite, derived from one attested seed."""

    keys: dict[str, KeyPair]
    suite: list[str]
    entropy_attestation: Any | None = None

    def public_keys(self) -> dict[str, dict[str, Any]]:
        return {alg: key.public_info() for alg, key in self.keys.items()}


@dataclass(frozen=True)
class SignedArtefact:
    """A signature over an artefact, with everything a verifier needs.

    `payload` is the exact bytes the signatures cover, carried verbatim rather
    than rebuilt on demand. Regenerating it would mean every consumer had to
    reproduce our JSON serialisation byte for byte -- key order, separators,
    unicode escaping -- and any divergence would surface as an invalid
    signature with no indication that formatting was the cause.
    """

    binding: HybridBinding
    signatures: dict[str, bytes]
    public_keys: dict[str, bytes]
    digest: str
    digest_algorithm: str
    timestamp: str
    payload: bytes = b""
    subject_name: str = "artefact"
    manifest: Manifest | None = None
    entropy_attestation: Any | None = None
    backend_info: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def signed_bytes(self) -> bytes:
        """The DSSE pre-authentication encoding every signature covers."""
        if not self.payload:
            raise ValueError(
                "this SignedArtefact carries no payload, so there is nothing to "
                "verify against. It predates DSSE PAE signing and must be re-signed."
            )
        return pae(DSSE_PAYLOAD_TYPE, self.payload)

    @property
    def algorithms(self) -> list[str]:
        return sorted(self.signatures)

    @property
    def total_signature_bytes(self) -> int:
        return sum(len(s) for s in self.signatures.values())


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------
def keygen(
    suite: list[str] | None = None,
    seed: bytes | None = None,
    entropy_sources: list[Any] | None = None,
    entropy_attestation: Any | None = None,
) -> HybridKeySet:
    """Generate one key per algorithm in the suite.

    All keys derive from a single attested seed, domain-separated per algorithm
    so that compromising one key does not compromise the others. Deriving them
    independently would need one attestation each and make the provenance story
    harder to state, for no security gain.

    Args:
        suite: algorithms to generate for. Defaults to ed25519 + ML-DSA-87.
        seed: explicit seed. Mutually exclusive with `entropy_sources`.
        entropy_sources: entropy backends to mix. When given, the resulting
            attestation travels with the key set, so a bundle can record where
            the key's randomness actually came from.
    """
    suite = suite or list(DEFAULT_SUITE)

    if seed is None:
        from .entropy.mixing import default_sources, mix_entropy

        sources = entropy_sources if entropy_sources is not None else default_sources()
        result = mix_entropy(sources, n_bytes=32, context=b"qknot-keygen")
        seed = result.seed
        entropy_attestation = result.attestation
    elif len(seed) < 32:
        raise ValueError("seed must be at least 32 bytes")
    # Explicit seed: key material is the caller's. Attestation is optional --
    # pass `entropy_attestation=attest_explicit_seed(seed, ...)` (as the CLI
    # does) for a beacon ceremony witness without mixing the beacon into the
    # seed. Leaving it None keeps offline unit tests network-free.

    from .entropy.mixing import hkdf

    keys: dict[str, KeyPair] = {}
    for algorithm in suite:
        backend = get_backend(algorithm)
        # Domain-separate per algorithm: one leaked key must not expose another.
        per_key_seed = hkdf(
            ikm=seed, salt=b"qknot-keygen-v1",
            info=algorithm.encode(), length=32,
        )
        public_key, secret_key = backend.keygen(per_key_seed)
        keys[algorithm] = KeyPair(
            algorithm=algorithm,
            public_key=public_key,
            secret_key=secret_key,
            fingerprint=key_fingerprint(public_key),
            entropy_attestation=entropy_attestation,
        )

    return HybridKeySet(keys=keys, suite=suite, entropy_attestation=entropy_attestation)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
def sign(
    target: Path | bytes,
    keys: HybridKeySet,
    exposure: Exposure = Exposure.OFFLINE,
    context: bytes = b"",
    digest_algorithm: str = DEFAULT_ALGORITHM,
    subject_name: str = "artefact",
    deterministic: bool = False,
) -> SignedArtefact:
    """Sign an artefact with every algorithm in the key set.

    Every algorithm signs the DSSE pre-authentication encoding of the *whole*
    statement, not the binding alone. The binding still sits inside that
    statement, so non-separability is unchanged; what changes is that the
    entropy attestation, backend descriptors and notes are now covered too. See
    dsse.py for what that fixes.

    Args:
        target: a file, a directory, or raw bytes. Directories are digested via
            a canonical manifest, so a thousand-shard model reduces to one
            value.
        exposure: OFFLINE for release signing, ONLINE for a signing service.
            A non-constant-time backend raises in ONLINE. This argument has no
            default that hides the decision -- see docs/THREAT-MODEL.md.
        context: domain separation, e.g. b"model-release".
        subject_name: the name recorded in the statement's subject. Fixed at
            signing time because it is inside the signed payload.
        deterministic: make signing byte-reproducible. OFF by default, matching
            FIPS 204's hedged mode: ML-DSA normally mixes 32 fresh random bytes
            into every signature as a defence against fault-injection attacks,
            which means two signings of the same artefact with the same key
            produce *different* bytes. Turn this on when reproducibility is the
            requirement -- test vectors, a notebook someone re-runs, benchmark
            artefacts -- and note it gives up that margin. Keys are derived
            deterministically from the seed either way.

    Raises:
        BackendUnsuitable: a backend is not safe for the declared exposure.
    """
    backends: dict[str, SignatureBackend] = {}
    for algorithm in keys.suite:
        backend = get_backend(algorithm, deterministic=deterministic)
        # Checked before any signing happens, so an unsuitable configuration
        # cannot produce a partial result.
        check_exposure(backend, exposure)
        backends[algorithm] = backend

    if isinstance(target, (bytes, bytearray)):
        from .digest import digest_bytes

        digest, manifest = digest_bytes(bytes(target), digest_algorithm), None
    else:
        digest, manifest = digest_artefact(Path(target), digest_algorithm)

    binding = build_binding(
        algorithms=list(keys.suite), digest=digest,
        digest_algorithm=digest_algorithm, context=context,
    )

    public_keys: dict[str, bytes] = {}
    backend_info: dict[str, dict[str, Any]] = {}
    for algorithm, backend in backends.items():
        public_keys[algorithm] = keys.keys[algorithm].public_key
        backend_info[algorithm] = backend.describe()

    notes = []
    if not binding.survives_shor:
        notes.append(
            "no member of this suite resists Shor's algorithm; the signature "
            "protects against tampering today but not against a quantum "
            "adversary"
        )
    if any(not b.side_channel_resistant for b in backends.values()):
        notes.append(
            f"signed with a non-constant-time backend under exposure="
            f"{exposure.value}; safe for offline release signing only"
        )
    if deterministic:
        notes.append(
            "signed in FIPS 204 deterministic mode for byte-reproducibility; "
            "this forgoes the hedged mode's fault-injection margin"
        )

    # The statement must exist before anything is signed, because the signatures
    # cover it. It does not depend on the signatures, so this is not circular:
    # a provisional artefact with no signatures carries everything the statement
    # needs, and the real one is built from it once the signing is done.
    from .bundle import build_statement

    provisional = SignedArtefact(
        binding=binding,
        signatures={},
        public_keys=public_keys,
        digest=digest,
        digest_algorithm=digest_algorithm,
        timestamp=datetime.now(timezone.utc).isoformat(),
        subject_name=subject_name,
        manifest=manifest,
        entropy_attestation=keys.entropy_attestation,
        backend_info=backend_info,
        notes=notes,
    )
    statement = build_statement(provisional, subject_name)
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    signed_bytes = pae(DSSE_PAYLOAD_TYPE, payload)

    # Every algorithm signs the SAME bytes, and those bytes contain the binding
    # that names the whole suite. That is what makes the signatures inseparable:
    # each one attests to the presence of the others.
    signatures = {
        algorithm: backend.sign(keys.keys[algorithm].secret_key, signed_bytes)
        for algorithm, backend in backends.items()
    }

    return replace(provisional, signatures=signatures, payload=payload)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def verify(
    target: Path | bytes,
    signed: SignedArtefact,
    mode: VerifyMode = VerifyMode.STRICT,
    context: bytes = b"",
    time_evidence: TimeEvidence | None = None,
    now: Any | None = None,
) -> dict[str, Any]:
    """Verify an artefact against a signature.

    Returns a report rather than a bare boolean, because "did it verify" is
    less useful than "what exactly was checked". A caller who verifies in
    CLASSICAL mode should be able to see that no post-quantum signature was
    consulted.

    Raises:
        VerificationFailed: the digest changed, a signature is invalid, or --
            in STRICT mode -- the binding does not match what the bundle
            carries.
    """
    if isinstance(target, (bytes, bytearray)):
        from .digest import digest_bytes

        digest = digest_bytes(bytes(target), signed.digest_algorithm)
    else:
        digest, _ = digest_artefact(Path(target), signed.digest_algorithm)

    if digest != signed.digest:
        raise VerificationFailed(
            f"artefact digest does not match the signature.\n"
            f"  signed:  {signed.digest}\n"
            f"  present: {digest}\n"
            f"The artefact has been modified since it was signed."
        )

    # The exact bytes the signatures cover. Resolved once, before any signature
    # is checked, so that a bundle with no payload fails with a clear message
    # rather than as a mysterious invalid signature.
    signed_bytes = signed.signed_bytes
    _check_payload_agrees_with_binding(signed)

    # STRICT is the only mode that consults the binding, and therefore the only
    # mode that can detect a stripped signature.
    if mode is VerifyMode.STRICT:
        try:
            verify_binding(
                signed.binding,
                present_algorithms=list(signed.signatures),
                digest=digest,
                context=context,
            )
        except BindingMismatch as exc:
            raise VerificationFailed(f"algorithm binding failed: {exc}") from exc

    if mode is VerifyMode.CLASSICAL:
        wanted = [a for a in signed.signatures if not get_backend(a).quantum_resistant]
    elif mode is VerifyMode.PQC:
        wanted = [a for a in signed.signatures if get_backend(a).quantum_resistant]
    else:
        wanted = list(signed.binding.algorithms)

    if not wanted:
        raise VerificationFailed(
            f"no signature in this bundle satisfies mode={mode.value}. "
            f"Present: {sorted(signed.signatures)}"
        )

    checked: list[str] = []
    for algorithm in wanted:
        signature = signed.signatures.get(algorithm)
        if signature is None:
            raise VerificationFailed(
                f"the binding names {algorithm} but the bundle carries no such "
                f"signature. A signature has been stripped."
            )
        backend = get_backend(algorithm)
        if not backend.verify(signed.public_keys[algorithm], signed_bytes, signature):
            raise VerificationFailed(
                f"{algorithm} signature is invalid. The signature covers the "
                f"entire statement, so this fires for any edit to the payload -- "
                f"including to the entropy attestation, backend descriptors or "
                f"notes, not only to the binding."
            )
        checked.append(algorithm)

    # --- temporal trust boundary ------------------------------------------
    # Soft-warn by default: failing verification because a standards body chose
    # a date would break every legitimately-signed artefact on a calendar
    # boundary. STRICT makes it a hard failure for callers who want that.
    evidence = time_evidence or evidence_from_attestation(signed.entropy_attestation)
    temporal = assess(signed.binding.algorithms, evidence=evidence, now=now)

    if mode is VerifyMode.STRICT and temporal.has_critical:
        raise VerificationFailed(
            "temporal trust boundary crossed (hard failure in STRICT mode):\n  "
            + "\n  ".join(temporal.messages())
            + "\n\nVerify in CLASSICAL or PQC mode to see this as a warning instead."
        )

    unchecked = sorted(set(signed.signatures) - set(checked))
    warnings = _verification_warnings(mode, checked, unchecked)
    warnings.extend(m for m in temporal.messages() if not m.startswith("[info]"))

    return {
        "verified": True,
        "mode": mode.value,
        "algorithms_checked": sorted(checked),
        "algorithms_present_but_unchecked": unchecked,
        "quantum_resistant": any(get_backend(a).quantum_resistant for a in checked),
        "binding_enforced": mode is VerifyMode.STRICT,
        "digest": digest,
        "temporal": {
            "findings": temporal.messages(),
            "evidence": evidence.kind if evidence else None,
            "evidence_trusted": evidence.trusted if evidence else False,
            "evidence_bound": evidence.bound.value if evidence else None,
            "critical": temporal.has_critical,
        },
        "signed_claims": _signed_claims(signed),
        "warnings": warnings,
    }


def _check_payload_agrees_with_binding(signed: SignedArtefact) -> None:
    """The payload is authoritative; confirm the parsed view did not drift.

    `parse_bundle` reads the binding out of the payload, so under normal use
    these agree by construction. This guards the case where a `SignedArtefact`
    is assembled by hand or by future code that sets the two independently: a
    verifier that checked signatures against the payload while reporting a
    binding taken from elsewhere would produce a true "verified" beside a suite
    nobody signed.
    """
    try:
        statement = json.loads(signed.payload)
        carried = statement["subject"][0]["algorithmBinding"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise VerificationFailed(
            f"the signed payload is not a statement carrying an algorithmBinding: {exc}"
        ) from exc

    if carried.get("binding") != signed.binding.binding:
        raise VerificationFailed(
            "the binding in the signed payload does not match the one being "
            "verified against. The signatures cover the payload, so the payload "
            "is authoritative."
        )
    if list(carried.get("algorithms") or []) != list(signed.binding.algorithms):
        raise VerificationFailed(
            f"the signed payload declares algorithms {carried.get('algorithms')} "
            f"but verification is proceeding against {signed.binding.algorithms}."
        )


def _signed_claims(signed: SignedArtefact) -> dict[str, Any]:
    """Signer-asserted metadata that IS covered by the signatures.

    Two different properties, and collapsing them would overclaim:

      * **Tamper-evident.** Since signatures cover the DSSE PAE of the whole
        statement, editing any field here invalidates every signature. An
        attacker cannot flip `sideChannelResistant` or delete a PRNG-fallback
        note in transit.

      * **Still self-asserted.** The *signer* chose these values. A signer who
        wants to claim a quantum entropy source they never used can do so and
        sign it. No cryptography fixes that; it is the same trust one places in
        any signed statement about a process the verifier did not witness.

    The beacon reference is the exception worth noting: it carries a pulse index
    and value a third party can re-fetch from NIST, so that one contribution is
    externally checkable rather than merely attested.
    """
    return {
        "_note": (
            "covered by the signatures (tamper-evident), but asserted by the "
            "signer and not independently witnessed. Beacon contributions carry "
            "a pulse reference that can be re-fetched from NIST."
        ),
        "entropy": _entropy_summary(signed.entropy_attestation),
        "backends": signed.backend_info,
        "signer_notes": signed.notes,
    }


def _entropy_summary(attestation: Any) -> dict[str, Any] | None:
    """Surface what the key's entropy attestation claims, if anything.

    A verifier should be able to see that a key fell back to the system CSPRNG
    without digging through the bundle. Claims only; see `_unverified_claims`.
    """
    if attestation is None:
        return None
    get = (attestation.get if isinstance(attestation, dict)
           else lambda k, d=None: getattr(attestation, k, d))
    contributions = get("contributions", []) or []

    def field_of(c: Any, name: str) -> Any:
        return c.get(name) if isinstance(c, dict) else getattr(c, name, None)

    quantum_secret = [
        field_of(c, "backend") for c in contributions
        if field_of(c, "is_quantum") and field_of(c, "role") == "secret"
    ]
    verifiable = [
        field_of(c, "backend") for c in contributions
        if field_of(c, "role") == "public" and field_of(c, "reference")
    ]
    return {
        "quantum_seeded": bool(quantum_secret),
        "quantum_secret_sources": quantum_secret,
        "externally_verifiable_sources": verifiable,
        "not_before": get("not_before", None),
    }


def _verification_warnings(
    mode: VerifyMode, checked: list[str], unchecked: list[str]
) -> list[str]:
    warnings: list[str] = []
    if mode is not VerifyMode.STRICT:
        warnings.append(
            f"mode={mode.value} does not enforce the algorithm binding, so a "
            f"stripped signature would not be detected. Use STRICT to check."
        )
    if unchecked:
        warnings.append(
            f"signatures present but not checked in this mode: {unchecked}"
        )
    if not any(get_backend(a).quantum_resistant for a in checked):
        warnings.append(
            "only classical signatures were verified; this artefact is not "
            "protected against a quantum adversary by this check"
        )
    return warnings
