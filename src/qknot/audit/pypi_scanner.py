"""Classify one PyPI project's attestation state.

Produces records in the same vocabulary as the HuggingFace audit
(`QLabel`, `SigAlgorithm`), so `stats.py` computes Wilson intervals, Newcombe
differences and Fisher exact tests over both ecosystems with no per-ecosystem
branching. Identical statistics is not a convenience here -- a cross-ecosystem
comparison where each leg is analysed differently is not a comparison.

THE DISTINCTION THIS MODULE EXISTS TO PRESERVE
==============================================
Three outcomes, never two:

  * **unattested** -- checked, and no release has ever carried provenance
  * **attested** -- checked, and the signing algorithm was read off the
    certificate
  * **unavailable** -- could NOT be checked (QLabel.ERROR, never UNSIGNED)

The HuggingFace study reports three gated repositories as unclassified rather
than unsigned, because folding "could not check" into "checked and found
nothing" reports a conclusion that was never reached. The same rule applies
here, and `unavailable_project` exists so a network failure cannot quietly
become evidence of absence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .model import QLabel, SigAlgorithm, classify_algorithm
from .pypi_client import (
    PostQuantumCertificate,
    PyPiClientProtocol,
    PyPiError,
    key_algorithm_of_certificate,
)

__all__ = ["audit_project", "unavailable_project"]

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit_project(client: PyPiClientProtocol, name: str,
                  fetch_algorithm: bool = True) -> dict[str, Any]:
    """Return one record for `name`. Never raises for a remote failure.

    `fetch_algorithm` costs one extra request per ATTESTED project, and only
    for those -- the attested minority is small, so the cost is bounded by the
    finding rather than by the sample size. Turning it off yields presence
    without the algorithm, which is a weaker record and is labelled as such.
    """
    try:
        files = client.project_files(name)
    except PyPiError as exc:
        return unavailable_project(name, exc)

    if not files.has_attestation:
        return {
            "project": name,
            "ecosystem": "pypi",
            "total_files": files.total_files,
            "has_signature": False,
            "attested_file_count": 0,
            "sig_algorithm": SigAlgorithm.NONE.value,
            "key_size_bits": None,
            "q_label": classify_algorithm(SigAlgorithm.NONE).value,
            "publisher": None,
            "audit_ts": _now(),
            "notes": None,
        }

    record: dict[str, Any] = {
        "project": name,
        "ecosystem": "pypi",
        "total_files": files.total_files,
        "has_signature": True,
        "attested_file_count": len(files.provenance_urls),
        "sig_algorithm": SigAlgorithm.UNKNOWN.value,
        "key_size_bits": None,
        "q_label": classify_algorithm(SigAlgorithm.UNKNOWN).value,
        "publisher": None,
        "audit_ts": _now(),
        "notes": None,
    }

    if not fetch_algorithm:
        record["notes"] = ("attestation present; algorithm not fetched "
                           "(fetch_algorithm=False)")
        return record

    try:
        provenance = client.fetch_provenance(files.provenance_urls[0])
    except PyPiError as exc:
        # Attestation exists but its contents could not be read. That is NOT
        # the same as an unclassifiable attestation, and it is not unsigned.
        record["notes"] = f"provenance unreadable: {exc}"
        return record

    bundles = provenance.get("attestation_bundles") or []
    if not bundles:
        record["notes"] = "provenance document carries no attestation bundles"
        return record

    bundle = bundles[0]
    publisher = bundle.get("publisher") or {}
    if isinstance(publisher, dict):
        kind = publisher.get("kind")
        repository = publisher.get("repository")
        record["publisher"] = f"{kind}:{repository}" if kind and repository else kind

    attestations = bundle.get("attestations") or []
    if not attestations:
        record["notes"] = "attestation bundle is empty"
        return record

    certificate = (attestations[0].get("verification_material") or {}).get("certificate")
    if not certificate:
        record["notes"] = "attestation carries no certificate; algorithm unknown"
        return record

    try:
        algorithm, key_size = key_algorithm_of_certificate(certificate)
    except PostQuantumCertificate as exc:
        # The result this study exists to detect. Recorded as a CLASSIFICATION,
        # not as an error: cryptography rejects a post-quantum certificate at
        # PARSE time, so before this branch existed the first such attestation
        # in any ecosystem would have been filed alongside corrupt data, and
        # the headline "we found zero" would have been describing the detector
        # rather than the ecosystem.
        record["sig_algorithm"] = exc.algorithm.value
        record["q_label"] = classify_algorithm(exc.algorithm).value
        record["notes"] = f"POST-QUANTUM FINDING (oid {exc.oid}): {exc}"
        return record
    except PyPiError as exc:
        # An unrecognised key type might be a post-quantum one, which would be
        # the single most interesting result this scan could produce. Record it
        # loudly as unclassified rather than defaulting it to classical.
        record["notes"] = f"UNRECOGNISED KEY TYPE -- classify by hand: {exc}"
        return record

    record["sig_algorithm"] = algorithm.value
    record["key_size_bits"] = key_size
    record["q_label"] = classify_algorithm(algorithm).value
    return record


def unavailable_project(name: str, cause: BaseException | str) -> dict[str, Any]:
    """A project that could not be checked. Distinct from one with no signature.

    `q_label` is ERROR, never UNSIGNED. A rate limit, a deleted project
    or a transport error is an absence of evidence, and reporting it as
    evidence of absence would inflate the unsigned count with the study's own
    failures.
    """
    return {
        "project": name,
        "ecosystem": "pypi",
        "total_files": 0,
        "has_signature": False,
        "attested_file_count": 0,
        "sig_algorithm": SigAlgorithm.UNKNOWN.value,
        "key_size_bits": None,
        "q_label": QLabel.ERROR.value,
        "publisher": None,
        "audit_ts": _now(),
        "notes": f"unavailable: {cause}",
    }
