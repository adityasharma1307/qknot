"""PyPI access for the multi-ecosystem attestation audit.

WHAT MADE THIS CHEAPER THAN PLANNED
===================================
The task memo assumed attestation presence would be checked per package via
PyPI's Integrity API. It does not have to be. The **Simple API in JSON form**
(PEP 691, `Accept: application/vnd.pypi.simple.v1+json`) returns every file a
project has ever published, each with a `provenance` field that is a URL when
that file carries a PEP 740 attestation and null when it does not.

So "has this project ever attested any release?" is **one request per project**,
not one per release per file. For a 20,000-project sample that is 20,000
requests rather than millions, and the Integrity API is needed only when the
attestation's *contents* matter -- which they do, but only for the small
attested minority.

CLASSIFYING THE ALGORITHM, RATHER THAN ASSUMING IT
==================================================
A provenance document embeds the Fulcio certificate that signed the
attestation, so the signing algorithm can be read off the certificate's public
key. That matters: the HuggingFace study's headline is that **zero** signed
repositories used a post-quantum algorithm, and repeating that claim for PyPI
on the grounds that "PyPI uses Sigstore and Sigstore is classical" would be an
inference, not a measurement. Reading the key type from each certificate makes
it the latter, and leaves room for the answer to be surprising.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote

__all__ = [
    "PYPI_SIMPLE_JSON",
    "PyPiClient",
    "PyPiClientProtocol",
    "PyPiError",
    "ProjectFiles",
    "key_algorithm_of_certificate",
]

PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"

_BASE = "https://pypi.org"


class PyPiError(Exception):
    """A PyPI request failed in a way the caller must not treat as 'absent'."""


@dataclass(frozen=True)
class ProjectFiles:
    """Every file a project has published, and which of them are attested."""

    name: str
    total_files: int
    provenance_urls: list[str] = field(default_factory=list)

    @property
    def has_attestation(self) -> bool:
        """True if ANY file of ANY release carries provenance.

        Per-project, any release ever attested -- the unit of analysis fixed in
        docs/DATASETS.md before collection began. A project that attested
        through 2025 and has not released since counts as having adopted
        attestation, because it did.
        """
        return bool(self.provenance_urls)


class PyPiClientProtocol(Protocol):
    """The surface the scanner needs, so tests can substitute a fake."""

    def list_projects(self) -> list[str]: ...
    def project_files(self, name: str) -> ProjectFiles: ...
    def fetch_provenance(self, url: str) -> dict[str, Any]: ...


class PyPiClient:
    """Live PyPI client. One request per project for presence."""

    def __init__(self, session: Any = None, timeout: float = 30.0,
                 user_agent: str = "qresp-audit (+https://github.com/qresp)") -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self._session = session

    def _get(self, url: str, accept: str = "application/json") -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        try:
            response = self._session.get(
                url,
                headers={"Accept": accept, "User-Agent": self.user_agent},
                timeout=self.timeout,
            )
        except Exception as exc:
            raise PyPiError(f"{url}: {exc}") from exc

        if response.status_code == 404:
            raise PyPiError(f"{url}: 404 not found")
        if response.status_code != 200:
            raise PyPiError(f"{url}: HTTP {response.status_code}")
        try:
            return response.json()
        except Exception as exc:
            raise PyPiError(f"{url}: response is not JSON: {exc}") from exc

    def list_projects(self) -> list[str]:
        """The full PyPI namespace -- the sampling frame for the long tail."""
        data = self._get(f"{_BASE}/simple/", accept=PYPI_SIMPLE_JSON)
        return [entry["name"] for entry in data.get("projects", [])]

    def project_files(self, name: str) -> ProjectFiles:
        data = self._get(f"{_BASE}/simple/{quote(name)}/", accept=PYPI_SIMPLE_JSON)
        files = data.get("files", [])
        return ProjectFiles(
            name=name,
            total_files=len(files),
            provenance_urls=[f["provenance"] for f in files if f.get("provenance")],
        )

    def fetch_provenance(self, url: str) -> dict[str, Any]:
        result = self._get(url)
        if not isinstance(result, dict):
            raise PyPiError(f"{url}: provenance is not an object")
        return result


def key_algorithm_of_certificate(certificate_b64: str) -> tuple[Any, int | None]:
    """Read the signing algorithm off a Fulcio certificate.

    Returns `(SigAlgorithm, key_size_bits)` -- the SAME enum the HuggingFace
    audit uses, not a parallel vocabulary. Records from the two ecosystems then
    flow through one `classify_algorithm`, so a cross-ecosystem comparison is
    not quietly comparing two different classification schemes.

    Raises on anything unrecognised rather than guessing. An unknown key type
    must surface as "could not classify" rather than silently becoming
    classical -- if a post-quantum attestation ever appears, misfiling it would
    erase the one finding this study exists to detect.
    """
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from .model import SigAlgorithm

    try:
        certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_b64))
    except Exception as exc:
        raise PyPiError(f"certificate does not parse: {exc}") from exc

    public_key = certificate.public_key()

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        by_curve = {"secp256r1": SigAlgorithm.ECDSA_P256,
                    "secp384r1": SigAlgorithm.ECDSA_P384}
        return (by_curve.get(public_key.curve.name, SigAlgorithm.ECDSA_OTHER),
                public_key.key_size)

    if isinstance(public_key, rsa.RSAPublicKey):
        by_size = {2048: SigAlgorithm.RSA_2048,
                   3072: SigAlgorithm.RSA_3072,
                   4096: SigAlgorithm.RSA_4096}
        return (by_size.get(public_key.key_size, SigAlgorithm.RSA_OTHER),
                public_key.key_size)

    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return SigAlgorithm.ED25519, 256

    raise PyPiError(
        f"unrecognised public key type {type(public_key).__name__}. This may be "
        f"a post-quantum key, which would be a finding rather than an error -- "
        f"classify it deliberately rather than defaulting it to classical."
    )


def load_head_ranking(path: str) -> list[str]:
    """Read a published top-downloads ranking from disk.

    Deliberately a local file rather than a fetch. The ranking is a *dated
    artefact*: committed beside the scan, it lets a reader reconstruct the exact
    head stratum. Re-querying a live source later would return different
    numbers and make the stratum unreproducible -- the reason BigQuery was
    dropped in the first place (docs/DATASETS.md).
    """
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    rows = data.get("rows") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise PyPiError(f"{path}: expected a list of ranked projects")

    names = []
    for row in rows:
        name = row.get("project") if isinstance(row, dict) else row
        if not isinstance(name, str):
            raise PyPiError(f"{path}: row has no project name: {row!r}")
        names.append(name)
    return names
