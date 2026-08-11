"""Non-separable hybrid signature combination.

THE ATTACK THIS EXISTS TO STOP
==============================
A hybrid signature carries both a classical signature (Ed25519, for verifiers
that exist today) and a post-quantum one (ML-DSA, for the horizon the artefact
must survive). The obvious construction is to compute both over the artefact
digest and put them side by side in the bundle.

That construction is broken, and not by cryptanalysis. An attacker **deletes**
the ML-DSA signature and presents a bundle carrying only Ed25519. The remaining
signature is perfectly valid over the same digest. A legacy verifier accepts it
without complaint, and so does a hybrid verifier that merely checks "every
signature present is valid". The post-quantum protection is removed by
dropping a JSON field: no forgery, no key compromise, no computation.

Once a cryptographically relevant quantum computer exists, that attacker forges
the surviving Ed25519 signature at will. The ML-DSA signature was the only
thing standing in the way, and it was discarded for free.

THE FIX: BIND THE ALGORITHM SET INTO WHAT IS SIGNED
===================================================
Both algorithms sign a value that commits to the *set of algorithms in use*.
This module computes that commitment; `sign.py` places it inside the in-toto
statement and signs the DSSE encoding of the whole statement, so the property
below holds over the enclosing envelope rather than over a bare hash:

    binding = SHA3-256(
        domain || len-prefixed(suite) || len-prefixed(digest_alg)
               || len-prefixed(digest) || len-prefixed(context)
    )

where `suite` is the sorted, canonicalised algorithm list, e.g.
`"ed25519+ml-dsa-44"`.

Now stripping the ML-DSA signature leaves an Ed25519 signature over a binding
that names two algorithms. A verifier recomputes the binding from the declared
suite: if the bundle claims `ed25519+ml-dsa-44` it must carry both, and if an
attacker edits the suite down to `ed25519` the binding changes and the
surviving signature no longer validates. Either way the tamper is detected.

This is **strong non-separability** in the sense of Bindel, Herath, McKague and
Stebila, "Transitioning to a quantum-resistant public key infrastructure"
(PQCrypto 2017): a component signature cannot be extracted and presented as a
standalone signature over the same message.

WHY LENGTH PREFIXES
===================
Concatenating variable-length fields is how combiners get broken. Without
prefixes, suite `"ed25519"` with digest `"+ml-dsa-44abcd"` serialises
identically to suite `"ed25519+ml-dsa-44"` with digest `"abcd"`, and an
attacker who controls either field can forge a collision without touching a
hash function. Every field below is length-prefixed for that reason.

SCOPE
=====
Artefact-agnostic. This module knows about digests and algorithm names, not
about models, files, or registries.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .algorithms import REGISTRY

BINDING_DOMAIN = b"qknot-hybrid-binding-v1"
BINDING_ALGORITHM = "sha3-256"
SUITE_SEPARATOR = "+"

# Algorithms this combiner will bind, and whether each resists Shor.
#
# Derived from the single registry in algorithms.py rather than restated here.
# This table and the backend table and the policy table used to be maintained
# by hand and had already drifted apart; see that module's docstring.
KNOWN_ALGORITHMS: dict[str, bool] = {
    name: spec.resists_shor for name, spec in REGISTRY.items()
}


class SuiteError(ValueError):
    """The algorithm suite is malformed or cannot be bound."""


class BindingMismatch(Exception):  # noqa: N818
    """The recomputed binding does not match the one presented.

    In practice this means one of: a signature was stripped, the declared
    suite was edited, the digest was swapped, or the bundle was assembled for
    a different context. All are tampering; the verifier cannot tell which.
    """


def canonical_suite(algorithms: list[str]) -> str:
    """Normalise an algorithm list into a stable suite identifier.

    Sorted and lowercased, so that `["ML-DSA-44", "ed25519"]` and
    `["ed25519", "ml-dsa-44"]` produce the same binding. Without
    canonicalisation an attacker could reorder the list to change the binding
    while leaving the semantics identical, and a verifier reconstructing the
    suite in a different order would reject a legitimate bundle.
    """
    if not algorithms:
        raise SuiteError("an algorithm suite cannot be empty")

    normalised = [a.strip().lower() for a in algorithms]
    if any(not a for a in normalised):
        raise SuiteError("algorithm names cannot be empty")
    if any(SUITE_SEPARATOR in a for a in normalised):
        raise SuiteError(
            f"algorithm names cannot contain {SUITE_SEPARATOR!r}; it separates "
            f"suite members and would make the suite ambiguous"
        )
    if len(set(normalised)) != len(normalised):
        raise SuiteError(f"duplicate algorithms in suite: {algorithms}")

    unknown = [a for a in normalised if a not in KNOWN_ALGORITHMS]
    if unknown:
        raise SuiteError(
            f"unknown algorithm(s) {unknown}. Refusing to bind an algorithm "
            f"whose quantum resistance this tool cannot assess."
        )
    return SUITE_SEPARATOR.join(sorted(normalised))


def _field(data: bytes) -> bytes:
    """Length-prefix one field. See the module docstring on why."""
    return len(data).to_bytes(8, "big") + data


def compute_binding(
    suite: str,
    digest: str,
    digest_algorithm: str,
    context: bytes = b"",
) -> bytes:
    """The value both algorithms actually sign.

    Args:
        suite: canonical suite string from `canonical_suite`.
        digest: hex artefact digest.
        digest_algorithm: which hash produced it. Included so that the same
            digest value computed under a different algorithm cannot be
            substituted -- a 64-hex-char SHA3-256 digest and a 64-hex-char
            SHA-256 digest are otherwise interchangeable to a verifier.
        context: optional domain separation, e.g. b"model-release".
    """
    if not suite:
        raise SuiteError("suite must not be empty")
    try:
        digest_raw = bytes.fromhex(digest)
    except ValueError as exc:
        raise SuiteError(f"digest must be hex: {exc}") from None
    if not digest_raw:
        raise SuiteError("digest must not be empty")

    h = hashlib.sha3_256()
    h.update(BINDING_DOMAIN)
    h.update(_field(suite.encode()))
    h.update(_field(digest_algorithm.encode()))
    h.update(_field(digest_raw))
    h.update(_field(context))
    return h.digest()


@dataclass(frozen=True)
class HybridBinding:
    """The commitment both signatures cover, plus what a verifier needs."""

    suite: str
    algorithms: list[str]
    digest: str
    digest_algorithm: str
    binding: str                  # hex
    binding_algorithm: str = BINDING_ALGORITHM
    context: str = ""

    @property
    def binding_bytes(self) -> bytes:
        return bytes.fromhex(self.binding)

    @property
    def is_hybrid(self) -> bool:
        return len(self.algorithms) > 1

    @property
    def quantum_resistant_members(self) -> list[str]:
        return [a for a in self.algorithms if KNOWN_ALGORITHMS.get(a, False)]

    @property
    def classical_members(self) -> list[str]:
        return [a for a in self.algorithms if not KNOWN_ALGORITHMS.get(a, True)]

    @property
    def survives_shor(self) -> bool:
        """True if at least one member resists a quantum adversary.

        A hybrid's whole purpose. Note this says *at least one*: a hybrid is
        as strong as its strongest member precisely because non-separability
        stops an attacker discarding that member.
        """
        return bool(self.quantum_resistant_members)

    def to_dict(self) -> dict[str, object]:
        return {
            "algorithms": self.algorithms,
            "suite": self.suite,
            "binding": self.binding,
            "bindingAlgorithm": self.binding_algorithm,
            "digestAlgorithm": self.digest_algorithm,
            "context": self.context,
        }


def build_binding(
    algorithms: list[str],
    digest: str,
    digest_algorithm: str = "sha3-256",
    context: bytes = b"",
) -> HybridBinding:
    """Construct the binding that every member algorithm will sign."""
    suite = canonical_suite(algorithms)
    binding = compute_binding(suite, digest, digest_algorithm, context)
    return HybridBinding(
        suite=suite,
        algorithms=suite.split(SUITE_SEPARATOR),
        digest=digest,
        digest_algorithm=digest_algorithm,
        binding=binding.hex(),
        context=context.decode("utf-8", errors="replace"),
    )


def verify_binding(
    binding: HybridBinding,
    present_algorithms: list[str],
    digest: str,
    context: bytes = b"",
) -> None:
    """Check a presented binding against what the bundle actually carries.

    This is where stripping is caught. Three things must agree:

      1. The binding recomputes from the declared suite and digest. If either
         was edited, it will not.
      2. Every algorithm the suite names is actually present. If a signature
         was removed, it is not.
      3. No unexpected algorithm appears. An added signature over the same
         binding is not covered by the suite and must not be silently accepted.

    Raises:
        BindingMismatch: on any of the above. The caller cannot distinguish
            which, and should not try: all are tampering.
    """
    expected = compute_binding(
        binding.suite, digest, binding.digest_algorithm, context
    )
    if expected.hex() != binding.binding:
        raise BindingMismatch(
            "binding does not recompute from the declared suite and digest. "
            "The suite, the digest, the context or the binding itself has been "
            "altered."
        )

    declared = set(binding.algorithms)
    present = {a.strip().lower() for a in present_algorithms}

    missing = declared - present
    if missing:
        raise BindingMismatch(
            f"the suite declares {sorted(declared)} but the bundle carries only "
            f"{sorted(present)}. Missing: {sorted(missing)}. A signature has "
            f"been stripped."
        )

    extra = present - declared
    if extra:
        raise BindingMismatch(
            f"the bundle carries {sorted(extra)}, which the binding does not "
            f"cover. An unbound signature must not be treated as protection."
        )
