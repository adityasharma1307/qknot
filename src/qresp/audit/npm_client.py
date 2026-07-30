"""npm registry access for the multi-ecosystem attestation audit.

PROBED AGAINST THE LIVE REGISTRY, 2026-07-30
============================================
npm turned out to mirror PyPI closely, which was not obvious in advance:

* **Presence is one request per package.** The abbreviated packument
  (`Accept: application/vnd.npm.install-v1+json`) returns every version with a
  `dist.attestations` field present or absent. No per-version fetching.
* **Scoped packages work** with `%2f` encoding.
* **The algorithm is readable from a certificate**, exactly as on PyPI.

TWO ATTESTATIONS PER VERSION, AND THEY ARE NOT THE SAME THING
=============================================================
`/-/npm/v1/attestations/{pkg}@{version}` returns two:

| predicateType | verification material |
|---|---|
| `github.com/npm/attestation/.../publish/v0.1` | `publicKey` -- npm's own registry key, **by reference** |
| `slsa.dev/provenance/v1` | `certificate` -- a **Fulcio** certificate |

Only the SLSA one embeds a certificate, so only it can have its algorithm read
off directly. The npm publish attestation names a key by ID, and resolving that
ID needs npm's published key set.

This module classifies the **provenance** attestation and records the presence
of the publish one separately. Folding them together would double-count a
single publishing event as two signatures; ignoring the publish attestation
entirely would undercount what npm actually signs. Neither is acceptable
silently, so both are reported.

WHY RANKING NEEDS TWO STAGES
============================
npm publishes no downloads ranking. The bulk downloads endpoint takes 128
packages per request, so ranking a ~3.5M frame is ~27,000 requests -- about 23
minutes at the rate this project sustains elsewhere, which is affordable.

**The obstacle is not volume. It is that the bulk endpoint rejects scoped
packages.** Scoped names must be queried one at a time, and `@babel/*`,
`@types/*` and similar are a large share of the most-depended-on packages, so
excluding them would bias the head stratum towards unscoped names rather than
towards popular ones.

Hence: a candidate pool first (which may come from any popularity-ish source,
since it only has to avoid *losing* packages), then real download counts over
that pool -- bulk for unscoped, individually for scoped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote

__all__ = [
    "BULK_LIMIT",
    "NPM_ABBREVIATED",
    "NpmClient",
    "NpmClientProtocol",
    "NpmError",
    "PackageVersions",
    "is_scoped",
]

NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"
_REGISTRY = "https://registry.npmjs.org"
_API = "https://api.npmjs.org"

# npm's bulk downloads endpoint accepts at most 128 names, and rejects scoped
# packages outright. Both limits shape the ranking design; see the module
# docstring.
BULK_LIMIT = 128

PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"


class NpmError(Exception):
    """An npm request failed in a way the caller must not read as 'absent'."""


def is_scoped(name: str) -> bool:
    """`@scope/name`. These cannot go through the bulk downloads endpoint."""
    return name.startswith("@")


@dataclass(frozen=True)
class PackageVersions:
    """Every version of a package, and which of them carry attestations."""

    name: str
    total_versions: int
    attested_versions: list[str] = field(default_factory=list)

    @property
    def has_attestation(self) -> bool:
        """True if ANY version has ever been attested.

        Per-project, any release ever attested -- the unit of analysis fixed in
        docs/DATASETS.md before collection began, and the same rule applied to
        PyPI so the two rates mean the same thing.
        """
        return bool(self.attested_versions)


class NpmClientProtocol(Protocol):
    def package_versions(self, name: str) -> PackageVersions: ...
    def fetch_attestations(self, name: str, version: str) -> dict[str, Any]: ...
    def bulk_downloads(self, names: list[str]) -> dict[str, int | None]: ...


class NpmClient:
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
                url, headers={"Accept": accept, "User-Agent": self.user_agent},
                timeout=self.timeout)
        except Exception as exc:
            raise NpmError(f"{url}: {exc}") from exc

        if response.status_code == 404:
            raise NpmError(f"{url}: 404 not found")
        if response.status_code != 200:
            raise NpmError(f"{url}: HTTP {response.status_code}")
        try:
            return response.json()
        except Exception as exc:
            raise NpmError(f"{url}: response is not JSON: {exc}") from exc

    def package_versions(self, name: str) -> PackageVersions:
        data = self._get(f"{_REGISTRY}/{quote(name, safe='')}", NPM_ABBREVIATED)
        versions = data.get("versions") or {}
        attested = [v for v, meta in versions.items()
                    if (meta.get("dist") or {}).get("attestations")]
        return PackageVersions(name=name, total_versions=len(versions),
                               attested_versions=attested)

    def fetch_attestations(self, name: str, version: str) -> dict[str, Any]:
        url = f"{_REGISTRY}/-/npm/v1/attestations/{quote(name, safe='')}@{version}"
        result = self._get(url)
        if not isinstance(result, dict):
            raise NpmError(f"{url}: attestations response is not an object")
        return result

    def bulk_downloads(self, names: list[str]) -> dict[str, int | None]:
        """Last-month downloads for up to `BULK_LIMIT` UNSCOPED packages.

        Returns None for any name the API declined to answer for, rather than
        0. A missing count and a genuine zero are different facts, and
        conflating them would silently sort unknown packages to the bottom of
        the ranking as though they were measured and found unpopular.
        """
        if not names:
            return {}
        if len(names) > BULK_LIMIT:
            raise NpmError(
                f"{len(names)} names exceeds npm's bulk limit of {BULK_LIMIT}"
            )
        scoped = [n for n in names if is_scoped(n)]
        if scoped:
            raise NpmError(
                f"bulk downloads rejects scoped packages; {len(scoped)} passed "
                f"(e.g. {scoped[0]}). Query these individually."
            )

        data = self._get(f"{_API}/downloads/point/last-month/{','.join(names)}")
        # For a single name the API returns a flat object rather than a mapping.
        if len(names) == 1 and "downloads" in data:
            return {names[0]: data.get("downloads")}
        out: dict[str, int | None] = {}
        for name in names:
            entry = data.get(name)
            out[name] = entry.get("downloads") if isinstance(entry, dict) else None
        return out

    def single_downloads(self, name: str) -> int | None:
        """Last-month downloads for one package. The only route for scoped names.

        RAISES on failure rather than returning None. An earlier version
        swallowed `NpmError` here and returned None, which silently converted
        every rate-limited request into "no count" -- indistinguishable from a
        package the API genuinely has no data for. That erased exactly the
        absent-versus-unchecked distinction the scanners exist to preserve, and
        it hid a 429 storm that cost 19,299 of 19,527 scoped measurements
        before anyone noticed. The caller decides whether to retry; the client
        does not get to decide the failure never happened.
        """
        data = self._get(f"{_API}/downloads/point/last-month/{quote(name, safe='@/')}")
        return data.get("downloads") if isinstance(data, dict) else None


def provenance_certificate(attestations: dict[str, Any]) -> str | None:
    """Pull the Fulcio certificate out of the SLSA provenance attestation.

    Returns None when there is no provenance attestation carrying a
    certificate -- which is a real state, not an error: a package may have only
    npm's publish attestation, whose key is referenced by ID rather than
    embedded.
    """
    for attestation in attestations.get("attestations") or []:
        if attestation.get("predicateType") != PROVENANCE_PREDICATE:
            continue
        material = (attestation.get("bundle") or {}).get("verificationMaterial") or {}
        certificate = material.get("certificate") or {}
        raw = certificate.get("rawBytes")
        if raw:
            return str(raw)
        chain = (material.get("x509CertificateChain") or {}).get("certificates") or []
        if chain and chain[0].get("rawBytes"):
            return str(chain[0]["rawBytes"])
    return None


def predicate_types(attestations: dict[str, Any]) -> list[str]:
    """Every predicate type present, so the publish attestation stays visible."""
    return [a.get("predicateType", "") for a in attestations.get("attestations") or []]
