"""Core data model for the QKnot audit.

Defines the per-model record schema, the quantum-vulnerability enum,
and the classification rules from Table 4.1 of the project report.

The schema is deliberately minimal: it captures only what is needed
to classify quantum vulnerability and reproduce the audit.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class QLabel(str, Enum):
    """The quantum-vulnerability label assigned to a model.

    Categories follow the classification rules in the project report.
    They are mutually exclusive: a single model gets exactly one label.
    """

    SAFE = "safe"             # Uses a known post-quantum scheme (ML-DSA, SLH-DSA, ...)
    VULNERABLE = "vulnerable" # Uses RSA, ECDSA, Ed25519, or any other Shor-broken scheme
    UNSIGNED = "unsigned"     # No detectable signature file at all
    MIXED = "mixed"           # Multiple signatures with disagreeing labels
    ERROR = "error"           # Scan failed (network, parse, etc.); preserves row count


class SigAlgorithm(str, Enum):
    """Concrete signature algorithm detected in a signature file."""

    # Classical (quantum-vulnerable)
    RSA_2048 = "rsa_2048"
    RSA_3072 = "rsa_3072"
    RSA_4096 = "rsa_4096"
    RSA_OTHER = "rsa_other"        # any other RSA key size
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"
    ECDSA_OTHER = "ecdsa_other"
    ED25519 = "ed25519"
    ED448 = "ed448"

    # Post-quantum (safe)
    ML_DSA_44 = "ml_dsa_44"
    ML_DSA_65 = "ml_dsa_65"
    ML_DSA_87 = "ml_dsa_87"
    SLH_DSA = "slh_dsa"            # any SLH-DSA parameter set

    # Catch-alls
    UNKNOWN = "unknown"            # signature present but algorithm couldn't be parsed
    NONE = "none"                  # no signature file at all


class SigFormat(str, Enum):
    """Container format that wraps the actual signature."""

    GPG = "gpg"
    SIGSTORE = "sigstore"          # Sigstore bundle (.sig, model.sig, .sigstore)
    IN_TOTO = "in_toto"            # in-toto attestation
    OMS = "oms"                    # OpenSSF Open Model Signing v1 (sigstore-bundle-based)
    CUSTOM = "custom"              # other / unrecognised container
    NONE = "none"


# ---------------------------------------------------------------------------
# Per-model record
# ---------------------------------------------------------------------------
class ModelRecord(BaseModel):
    """One row in the audit dataset.

    Serialises directly to JSON Lines (one record per line).
    """

    # Identity
    model_id: str = Field(..., description="HuggingFace repo identifier, e.g. 'meta-llama/Llama-3-8B'")
    publisher: str = Field(..., description="Organisation or individual that published the model")

    # Activity / popularity
    downloads: int = Field(..., ge=0, description="All-time download count at scan time")
    last_modified: datetime | None = Field(None, description="Last-modified timestamp")
    file_count: int = Field(..., ge=0, description="Total number of files in the repo")

    # Cryptographic findings
    has_signature: bool = Field(..., description="True if at least one signature file was found")
    candidate_files: list[str] = Field(default_factory=list, description="Filenames identified as signature candidates")
    sig_algorithm: SigAlgorithm = Field(..., description="Detected signature algorithm")
    sig_format: SigFormat = Field(..., description="Detected signature container format")
    key_size_bits: int | None = Field(None, description="Key size in bits where applicable")

    # Classification
    q_label: QLabel = Field(..., description="Final quantum-vulnerability classification")

    # Provenance / debugging
    audit_ts: datetime = Field(..., description="UTC timestamp when this record was produced")
    notes: str | None = Field(None, description="Free-text notes from the parser, e.g. error details")


# ---------------------------------------------------------------------------
# Classification rules — Table 4.1 of the report
# ---------------------------------------------------------------------------
_VULNERABLE_ALGOS: frozenset[SigAlgorithm] = frozenset({
    SigAlgorithm.RSA_2048,
    SigAlgorithm.RSA_3072,
    SigAlgorithm.RSA_4096,
    SigAlgorithm.RSA_OTHER,
    SigAlgorithm.ECDSA_P256,
    SigAlgorithm.ECDSA_P384,
    SigAlgorithm.ECDSA_OTHER,
    SigAlgorithm.ED25519,
    SigAlgorithm.ED448,
})

_SAFE_ALGOS: frozenset[SigAlgorithm] = frozenset({
    SigAlgorithm.ML_DSA_44,
    SigAlgorithm.ML_DSA_65,
    SigAlgorithm.ML_DSA_87,
    SigAlgorithm.SLH_DSA,
})


def classify_algorithm(algo: SigAlgorithm) -> QLabel:
    """Map a single detected algorithm to a quantum-vulnerability label.

    These rules are deliberately conservative: any classical algorithm
    covered by a polynomial-time quantum attack is labelled `vulnerable`,
    regardless of key size. We do not, for example, distinguish RSA-2048
    from RSA-4096; both are broken in polynomial time by Shor's algorithm.
    """
    if algo == SigAlgorithm.NONE:
        return QLabel.UNSIGNED
    if algo == SigAlgorithm.UNKNOWN:
        # We saw something that looked like a signature but couldn't parse it.
        # Treating it as `error` keeps it visible in the dataset for manual review,
        # rather than misreporting it as either safe or vulnerable.
        return QLabel.ERROR
    if algo in _SAFE_ALGOS:
        return QLabel.SAFE
    if algo in _VULNERABLE_ALGOS:
        return QLabel.VULNERABLE
    # Defensive default: anything unhandled is flagged for review
    return QLabel.ERROR


def reconcile_labels(labels: list[QLabel]) -> QLabel:
    """Reconcile multiple per-signature labels into a single per-repo label.

    Rules, in order:

      * empty list                     -> unsigned
      * any VULNERABLE present         -> vulnerable, unless a SAFE also
                                          appears, in which case mixed
      * SAFE and VULNERABLE together   -> mixed
      * any ERROR alongside SAFE only  -> error
      * UNSIGNED plus one other        -> the other
      * otherwise                      -> mixed

    WHY VULNERABLE OUTRANKS ERROR
    -----------------------------
    An earlier version returned ERROR whenever any signature failed to parse,
    described as "be conservative". That is conservative in the wrong
    direction for a security audit. If one signature parsed cleanly as ECDSA
    P-256 and a second file could not be read, we *know* the repo carries a
    signature that Shor's algorithm breaks. Reporting `error` discards a
    confirmed finding because of an unrelated unknown, and it understates the
    vulnerable count -- the very statistic this project exists to measure.

    Conservatism for a vulnerability survey means never claiming something is
    safe when it might not be, not suppressing what has been established. A
    known-vulnerable signature is therefore reported as vulnerable regardless
    of what else in the repo failed to parse.

    ERROR still wins over SAFE alone, because a repo whose only readable
    signature is post-quantum but which also carries something unreadable has
    not been shown to be safe.
    """
    if not labels:
        return QLabel.UNSIGNED

    unique = set(labels)
    if len(unique) == 1:
        return labels[0]

    # A confirmed vulnerable signature is a fact about the repo and survives
    # any amount of surrounding uncertainty.
    if QLabel.VULNERABLE in unique:
        if QLabel.SAFE in unique:
            return QLabel.MIXED
        return QLabel.VULNERABLE

    if QLabel.ERROR in unique:
        return QLabel.ERROR
    if QLabel.UNSIGNED in unique and len(unique) == 2:
        unique.discard(QLabel.UNSIGNED)
        return next(iter(unique))
    return QLabel.MIXED
