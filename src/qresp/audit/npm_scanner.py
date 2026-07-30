"""Classify one npm package's attestation state.

Emits the same `SigAlgorithm`/`QLabel` vocabulary as the HuggingFace and PyPI
audits, so `stats.py` treats all three ecosystems identically. Three outcomes,
never two: unattested, attested, and could-not-check.

WHAT MAKES npm DIFFERENT FROM PyPI HERE
=======================================
A version can carry two attestations. Only the SLSA provenance one embeds a
certificate whose algorithm can be read; npm's own publish attestation
references a key by ID.

The record therefore reports both: `sig_algorithm` describes the provenance
attestation, and `predicate_types` lists everything present. A package with
*only* npm's publish attestation is genuinely attested but not
algorithm-classifiable from the bundle alone, and is recorded as exactly that
rather than as unsigned or as classical.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .model import QLabel, SigAlgorithm, classify_algorithm
from .npm_client import (
    NpmClientProtocol,
    NpmError,
    predicate_types,
    provenance_certificate,
)
from .pypi_client import PyPiError, key_algorithm_of_certificate

__all__ = ["audit_package", "unavailable_package"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base(name: str) -> dict[str, Any]:
    return {
        "project": name,
        "ecosystem": "npm",
        "total_versions": 0,
        "has_signature": False,
        "attested_version_count": 0,
        "sig_algorithm": SigAlgorithm.NONE.value,
        "key_size_bits": None,
        "q_label": classify_algorithm(SigAlgorithm.NONE).value,
        "publisher": None,
        "predicate_types": [],
        "audit_ts": _now(),
        "notes": None,
    }


def audit_package(client: NpmClientProtocol, name: str,
                  fetch_algorithm: bool = True) -> dict[str, Any]:
    """One record for `name`. Never raises for a remote failure."""
    try:
        versions = client.package_versions(name)
    except NpmError as exc:
        return unavailable_package(name, exc)

    record = _base(name)
    record["total_versions"] = versions.total_versions

    if not versions.has_attestation:
        return record

    record.update({
        "has_signature": True,
        "attested_version_count": len(versions.attested_versions),
        "sig_algorithm": SigAlgorithm.UNKNOWN.value,
        "q_label": classify_algorithm(SigAlgorithm.UNKNOWN).value,
    })

    if not fetch_algorithm:
        record["notes"] = ("attestation present; algorithm not fetched "
                           "(fetch_algorithm=False)")
        return record

    # Most recent attested version: the algorithm in use now, not in 2023.
    try:
        attestations = client.fetch_attestations(name, versions.attested_versions[-1])
    except NpmError as exc:
        record["notes"] = f"attestations unreadable: {exc}"
        return record

    record["predicate_types"] = predicate_types(attestations)

    certificate = provenance_certificate(attestations)
    if certificate is None:
        # Genuinely attested, genuinely not classifiable from the bundle. npm's
        # publish attestation names its key by ID rather than embedding a
        # certificate, so there is nothing here to read an algorithm off.
        record["notes"] = (
            "attested, but no SLSA provenance certificate present "
            f"(predicates: {', '.join(record['predicate_types']) or 'none'}); "
            "algorithm not determinable from the bundle"
        )
        return record

    try:
        algorithm, key_size = key_algorithm_of_certificate(certificate)
    except PyPiError as exc:
        record["notes"] = f"UNRECOGNISED KEY TYPE -- classify by hand: {exc}"
        return record

    record["sig_algorithm"] = algorithm.value
    record["key_size_bits"] = key_size
    record["q_label"] = classify_algorithm(algorithm).value
    record["publisher"] = _publisher_from_certificate(certificate)
    return record


def _publisher_from_certificate(certificate_b64: str) -> str | None:
    """The signing workflow, from the certificate's SAN.

    npm's provenance certificates carry the GitHub Actions workflow URI, which
    is the npm analogue of PyPI's `publisher` block -- and lets the same
    "adoption follows the pipeline, not the vendor" question be asked of both.
    """
    import base64

    from cryptography import x509

    try:
        certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_b64))
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except Exception:
        return None
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        return str(uri)
    return None


def unavailable_package(name: str, cause: BaseException | str) -> dict[str, Any]:
    """Could not be checked. ERROR, never UNSIGNED."""
    record = _base(name)
    record.update({
        "sig_algorithm": SigAlgorithm.UNKNOWN.value,
        "q_label": QLabel.ERROR.value,
        "notes": f"unavailable: {cause}",
    })
    return record
