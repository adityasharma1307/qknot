"""Live Sigstore adapters: the two network seams `register` depends on.

These implement the `FulcioClient` and `RekorClient` Protocols against the public
Sigstore REST APIs. They are the ONLY code in the signing package that touches
the network, and they are deliberately dumb: they translate request/response
SHAPES and make no trust decisions. Every trust decision stays in the verifier,
which `register` runs over the result before returning a bundle.

They live in `src/` rather than in a script so the CLI and the capture harness
share one implementation -- a second copy is where the two would drift, and the
drift would only show up against live infrastructure.

TWO PRODUCTION QUIRKS ARE HANDLED HERE, both found by an actual live capture:

  * Rekor's REST v1 API returns `rootHash` and the inclusion-proof `hashes` as
    HEX strings, while the Sigstore BUNDLE format -- what `log_entry_from_rekor`
    and the whole verifier speak -- uses base64. The conversion belongs here, in
    the REST-to-canonical translation, not in the verifier.
  * Fulcio's proof of possession for the interactive email flows is a signature
    over the EMAIL claim (also the SAN identity the cert will carry), not over
    the raw `sub`.

Requires `requests`; imported lazily so the signing package stays importable
without it.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from .register import FulcioCertificate

__all__ = [
    "SigstoreClientError",
    "FULCIO_URL",
    "OAUTH_ISSUER_URL",
    "REKOR_URL",
    "FulcioRestClient",
    "RekorRestClient",
    "RekorRevocationSearchClient",
    "acquire_identity_token",
    "rekor_public_key_der",
]

FULCIO_URL = "https://fulcio.sigstore.dev"
REKOR_URL = "https://rekor.sigstore.dev"
OAUTH_ISSUER_URL = "https://oauth2.sigstore.dev/auth"


class SigstoreClientError(Exception):
    """A live Sigstore call failed, with the server's own explanation."""


def _post(url: str, json_body: dict[str, Any]) -> Any:
    """POST and surface the server's error body -- Fulcio and Rekor both return
    a JSON explanation that a bare raise_for_status() would hide."""
    import requests

    resp = requests.post(url, json=json_body, timeout=30)
    if not resp.ok:
        raise SigstoreClientError(
            f"{url} returned HTTP {resp.status_code}:\n{resp.text}")
    return resp.json()


# ---------------------------------------------------------------------------
# OIDC
# ---------------------------------------------------------------------------

def acquire_identity_token(
    *, force_oob: bool = False, supplied: str | None = None,
) -> str:
    """An OIDC identity token, via the vetted `sigstore` client or supplied.

    `force_oob` runs the out-of-band flow (print a URL, paste a code), which is
    what a machine without a usable browser -- WSL, a container -- needs.
    """
    if supplied:
        return supplied
    try:
        from sigstore import oidc
    except Exception as exc:  # noqa: BLE001
        raise SigstoreClientError(
            f"could not import sigstore ({exc}); `pip install sigstore` or pass "
            f"an identity token explicitly") from exc

    # sigstore 4.x dropped Issuer.production() and no longer exports the default
    # URL; construct from the known endpoint, keeping the old path for <4.
    issuer = (oidc.Issuer.production() if hasattr(oidc.Issuer, "production")
              else oidc.Issuer(OAUTH_ISSUER_URL))
    try:
        token = issuer.identity_token(force_oob=force_oob)
    except TypeError:                       # older signature without force_oob
        token = issuer.identity_token()
    return str(token)


def identity_token_claims(token: str) -> dict[str, Any]:
    """The JWT payload claims, unverified -- Fulcio verifies the token itself.

    Used only to learn which value the proof of possession must cover and to
    show the operator whose identity is being registered.
    """
    payload_b64 = token.split(".")[1]
    data: dict[str, Any] = json.loads(base64.urlsafe_b64decode(
        payload_b64 + "=" * (-len(payload_b64) % 4)))
    return data


def _pop_subject(claims: dict[str, Any]) -> str:
    """The value Fulcio's proof of possession must be signed over.

    For the interactive email-based issuers (sigstore's dex, Google) that is the
    EMAIL claim -- also the SAN identity the certificate will carry. Some machine
    issuers use the raw `sub`, so fall back to it.
    """
    return str(claims.get("email") or claims.get("sub"))


# ---------------------------------------------------------------------------
# Fulcio
# ---------------------------------------------------------------------------

class FulcioRestClient:
    """Certifies a classical key against a live Fulcio (`FulcioClient`)."""

    def __init__(self, token: str, base_url: str = FULCIO_URL):
        self.token = token
        self.claims = identity_token_claims(token)
        self.subject = _pop_subject(self.claims)
        self.base_url = base_url

    def certify(self, classical_public_key_spki_der: bytes,
                classical_secret_pkcs8_der: bytes) -> FulcioCertificate:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        priv = serialization.load_der_private_key(
            classical_secret_pkcs8_der, password=None)
        if not isinstance(priv, ec.EllipticCurvePrivateKey):
            raise SigstoreClientError(
                f"Fulcio certification here supports EC keys; got "
                f"{type(priv).__name__}")
        # Proof of possession: sign the OIDC subject with the key being certified.
        pop = priv.sign(self.subject.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        pub_pem = serialization.load_der_public_key(
            classical_public_key_spki_der).public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

        data = _post(f"{self.base_url}/api/v2/signingCert", {
            "credentials": {"oidcIdentityToken": self.token},
            "publicKeyRequest": {
                "publicKey": {"algorithm": "ECDSA", "content": pub_pem},
                "proofOfPossession": base64.b64encode(pop).decode("ascii"),
            },
        })
        chain = (data.get("signedCertificateEmbeddedSct")
                 or data.get("signedCertificateDetachedSct") or {})
        pems = chain.get("chain", {}).get("certificates", [])
        if not pems:
            raise SigstoreClientError(
                f"Fulcio returned no certificate chain: {data}")
        ders = [x509.load_pem_x509_certificate(p.encode()).public_bytes(
            serialization.Encoding.DER) for p in pems]
        return FulcioCertificate(leaf_der=ders[0], intermediate_ders=ders[1:])


# ---------------------------------------------------------------------------
# Rekor
# ---------------------------------------------------------------------------

def _hex_to_b64(value: str) -> str:
    return base64.b64encode(bytes.fromhex(value)).decode("ascii")


class RekorRestClient:
    """Submits a hashedrekord to a live Rekor (`RekorClient`).

    The response is reshaped into the canonical bundle form the shared
    `log_entry_from_rekor` mapper reads -- including the HEX-to-base64
    normalisation described in the module docstring.
    """

    def __init__(self, base_url: str = REKOR_URL):
        self.base_url = base_url
        # Kept for diagnostics: the raw response as Rekor sent it, and the
        # canonical-shaped dict handed to the mapper. A capture harness can dump
        # both and diagnose a verification failure without re-authenticating.
        self.last_raw_entry: dict[str, Any] | None = None
        self.last_mapped: dict[str, Any] | None = None

    def submit_hashedrekord(self, *, preimage: bytes, classical_signature: bytes,
                            certificate_der: bytes) -> dict[str, Any]:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        cert_pem = x509.load_der_x509_certificate(certificate_der).public_bytes(
            Encoding.PEM)
        proposed = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": preimage.hex()}},
                "signature": {
                    "content": base64.b64encode(classical_signature).decode("ascii"),
                    "publicKey": {
                        "content": base64.b64encode(cert_pem).decode("ascii")},
                },
            },
        }
        # {uuid: {body, logIndex, logID, integratedTime, verification}}
        (_uuid, entry), = _post(
            f"{self.base_url}/api/v1/log/entries", proposed).items()
        self.last_raw_entry = entry
        verification = entry["verification"]
        proof = verification["inclusionProof"]
        mapped = {
            "canonicalizedBody": entry["body"],             # already base64
            "logIndex": entry["logIndex"],                  # GLOBAL: SET signs it
            "logId": {"keyId": _hex_to_b64(entry["logID"])},
            "integratedTime": entry["integratedTime"],
            "inclusionPromise": {
                "signedEntryTimestamp": verification["signedEntryTimestamp"]},
            "inclusionProof": {
                "logIndex": proof["logIndex"],              # shard-local: Merkle
                "rootHash": _hex_to_b64(proof["rootHash"]),
                "treeSize": proof["treeSize"],
                "hashes": [_hex_to_b64(h) for h in proof["hashes"]],
                "checkpoint": proof["checkpoint"],
            },
        }
        self.last_mapped = mapped
        return mapped


class RekorRevocationSearchClient:
    """Searches a live Rekor for entries naming an identity.

    Implements `RevocationSearchClient`. Rekor's index can be queried by email,
    which returns entry UUIDs; each is then fetched and reshaped into the
    canonical form the shared mapper reads.

    IT CANNOT RETURN THE REVOCATION STATEMENTS THEMSELVES. A `hashedrekord`
    stores a digest, so the log proves that a statement was logged and when, but
    cannot produce a statement the verifier has never seen. `statement_source`
    supplies them -- a published feed, a directory, an internal service --
    keyed by the digest the log holds. Without it, entries come back opaque and
    `find_revocations` reports the honest UNKNOWN rather than an all-clear.
    """

    def __init__(self, base_url: str = REKOR_URL,
                 statement_source: dict[str, dict[str, str]] | None = None):
        self.base_url = base_url
        # digest hex -> {"payload": b64, "signature": b64}
        self.statement_source = statement_source or {}

    def search_by_identity(self, identity: str) -> list[dict[str, Any]]:
        import requests

        found = _post(f"{self.base_url}/api/v1/index/retrieve",
                      {"email": identity})
        uuids = found if isinstance(found, list) else []
        entries: list[dict[str, Any]] = []
        for uuid in uuids:
            resp = requests.get(
                f"{self.base_url}/api/v1/log/entries/{uuid}", timeout=30)
            if not resp.ok:
                # One unreachable entry must not look like "no revocation":
                # raising makes the whole search FAILED, which is the honest
                # outcome when part of the answer is missing.
                raise SigstoreClientError(
                    f"log entry {uuid} could not be fetched (HTTP "
                    f"{resp.status_code}); the revocation search is incomplete")
            (_uuid, entry), = resp.json().items()
            mapped = _map_entry(entry)
            digest = _entry_digest_hex(mapped)
            if digest and digest in self.statement_source:
                mapped["qrespRevocation"] = self.statement_source[digest]
            entries.append(mapped)
        return entries


def _map_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """A Rekor REST log entry in the canonical bundle shape (hex -> base64)."""
    verification = entry["verification"]
    proof = verification["inclusionProof"]
    return {
        "canonicalizedBody": entry["body"],
        "logIndex": entry["logIndex"],
        "logId": {"keyId": _hex_to_b64(entry["logID"])},
        "integratedTime": entry["integratedTime"],
        "inclusionPromise": {
            "signedEntryTimestamp": verification["signedEntryTimestamp"]},
        "inclusionProof": {
            "logIndex": proof["logIndex"],
            "rootHash": _hex_to_b64(proof["rootHash"]),
            "treeSize": proof["treeSize"],
            "hashes": [_hex_to_b64(h) for h in proof["hashes"]],
            "checkpoint": proof["checkpoint"],
        },
    }


def _entry_digest_hex(mapped: dict[str, Any]) -> str | None:
    """The digest a hashedrekord entry commits to, for statement lookup."""
    from .rekor import InclusionError, hashedrekord_digest

    try:
        body = base64.b64decode(mapped["canonicalizedBody"])
        return hashedrekord_digest(body).hex()
    except (InclusionError, KeyError, ValueError):
        return None


def rekor_public_key_der(base_url: str = REKOR_URL) -> bytes:
    """The log's public key, as DER SubjectPublicKeyInfo.

    Fetched for convenience. A verifier's trust store is the VERIFIER's decision:
    for third-party verification this should come from a pinned trust root (TUF),
    not from the log being verified. Fetching it is appropriate when producing a
    bundle, and the CLI says so.
    """
    import requests
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    resp = requests.get(f"{base_url}/api/v1/log/publicKey", timeout=30)
    if not resp.ok:
        raise SigstoreClientError(
            f"could not fetch the Rekor public key: HTTP {resp.status_code}")
    return load_pem_public_key(resp.content).public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
