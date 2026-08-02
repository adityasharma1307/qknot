"""Capture ONE real registration bundle -- the residual-3 fixture.

Runs the `qresp register` orchestrator against LIVE Fulcio + Rekor, so the emitted
bundle is production bytes that `tests/signing/test_registration_fixture.py` then
locks. Mirrors how `scripts/verify/check_sigstore_fixture.py` captured the
artefact fixture.

RUN THIS ON A MACHINE WITH NETWORK + A BROWSER (it cannot run in the qresp CI
sandbox). On WSL without a browser, pass `--oauth-force-oob` or run under
PowerShell, exactly as with `sigstore sign`.

    python scripts/register/capture_registration.py \
        --save tests/signing/fixtures/registration

THE TWO NETWORK SEAMS below (FulcioRestClient, RekorRestClient) are the ONE part
of this project that could not be exercised offline. They talk to the public
Sigstore REST APIs. If a call shape has drifted, the script fails LOUDLY -- and
crucially, `register()` VERIFIES the bundle end to end before this script ever
writes it, so a bad capture is never saved. A traceback here names the step to
fix; report it and the adapter is a small change, the orchestrator is not.

OIDC token acquisition uses the vetted `sigstore` client if installed; otherwise
pass a token with `--identity-token` (e.g. from `sigstore get-identity-token`).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

# The qresp package must be importable (run from the repo root, or install -e).
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from qresp.signing.backends import get_backend  # noqa: E402
from qresp.signing.register import FulcioCertificate, register  # noqa: E402

_FULCIO = "https://fulcio.sigstore.dev"
_REKOR = "https://rekor.sigstore.dev"
_OAUTH_ISSUER = "https://oauth2.sigstore.dev/auth"   # sigstore's production OIDC


def _post(url: str, json_body: dict[str, Any]) -> Any:
    """POST and surface the server's error body on failure -- Fulcio and Rekor
    both return a JSON explanation that raise_for_status() otherwise hides."""
    import requests

    resp = requests.post(url, json=json_body, timeout=30)
    if not resp.ok:
        raise SystemExit(
            f"{url} returned HTTP {resp.status_code}:\n{resp.text}\n"
            f"--- request body sent ---\n{json.dumps(json_body, indent=2)[:1200]}")
    return resp.json()


# --------------------------------------------------------------------------
# OIDC: prefer the vetted sigstore client; fall back to a supplied token.
# --------------------------------------------------------------------------
def acquire_identity_token(force_oob: bool, supplied: str | None) -> str:
    if supplied:
        return supplied
    try:
        import sigstore
        from sigstore import oidc
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(
            f"could not import sigstore ({exc}); either `pip install sigstore` "
            f"or pass --identity-token") from exc

    print(f"sigstore-python {getattr(sigstore, '__version__', '?')}")

    # The production OIDC issuer. sigstore 4.x dropped Issuer.production() and no
    # longer exports the default URL, so construct it from the known endpoint;
    # keep the classmethod path for older versions.
    if hasattr(oidc.Issuer, "production"):
        issuer = oidc.Issuer.production()
    else:
        issuer = oidc.Issuer(_OAUTH_ISSUER)

    # The interactive browser / out-of-band flow; force_oob is not accepted by
    # every version, so fall back to the no-arg form.
    try:
        token = issuer.identity_token(force_oob=force_oob)
    except TypeError:
        token = issuer.identity_token()
    return str(token)


def _jwt_subject(token: str) -> str:
    """The value Fulcio's proof of possession must be signed over.

    Fulcio derives the challenge subject per issuer. For the interactive
    email-based flows (sigstore's dex, Google) that is the EMAIL claim, which is
    also the SAN identity the cert will carry; only some machine issuers use the
    raw `sub`. So prefer email, falling back to sub.
    """
    payload_b64 = token.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(
        payload_b64 + "=" * (-len(payload_b64) % 4)))
    subject = payload.get("email") or payload.get("sub")
    print(f"OIDC identity: {subject}  (issuer {payload.get('iss')})")
    return str(subject)


# --------------------------------------------------------------------------
# Fulcio: certify OUR classical key (we must control it to sign the payload).
# --------------------------------------------------------------------------
class FulcioRestClient:
    def __init__(self, token: str, base_url: str = _FULCIO):
        self.token = token
        self.subject = _jwt_subject(token)
        self.base_url = base_url

    def certify(self, classical_public_key_spki_der: bytes,
                classical_secret_pkcs8_der: bytes) -> FulcioCertificate:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        priv = serialization.load_der_private_key(
            classical_secret_pkcs8_der, password=None)
        # Proof of possession: sign the OIDC subject with the key being certified.
        pop = priv.sign(self.subject.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        pub_pem = serialization.load_der_public_key(
            classical_public_key_spki_der).public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

        body = {
            "credentials": {"oidcIdentityToken": self.token},
            "publicKeyRequest": {
                "publicKey": {"algorithm": "ECDSA", "content": pub_pem},
                "proofOfPossession": base64.b64encode(pop).decode("ascii"),
            },
        }
        data = _post(f"{self.base_url}/api/v2/signingCert", body)
        chain = (data.get("signedCertificateEmbeddedSct")
                 or data.get("signedCertificateDetachedSct") or {})
        pems = chain.get("chain", {}).get("certificates", [])
        if not pems:
            raise SystemExit(f"Fulcio returned no certificate chain: {data}")
        from cryptography import x509
        ders = [x509.load_pem_x509_certificate(p.encode()).public_bytes(
            serialization.Encoding.DER) for p in pems]
        return FulcioCertificate(leaf_der=ders[0], intermediate_ders=ders[1:])


# --------------------------------------------------------------------------
# Rekor: submit the hashedrekord and reshape the response for the mapper.
# --------------------------------------------------------------------------
class RekorRestClient:
    def __init__(self, base_url: str = _REKOR):
        self.base_url = base_url
        self.last_raw_entry: dict[str, Any] | None = None    # for diagnostics
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
                    "publicKey": {"content": base64.b64encode(cert_pem).decode("ascii")},
                },
            },
        }
        # Response is {uuid: {body, logIndex, logID, integratedTime, verification}}
        (_uuid, entry), = _post(
            f"{self.base_url}/api/v1/log/entries", proposed).items()
        self.last_raw_entry = entry
        verification = entry["verification"]
        proof = verification["inclusionProof"]
        key_id_hex = entry["logID"]

        # NORMALISATION: Rekor's REST v1 API returns rootHash and the proof
        # hashes as HEX strings, whereas the Sigstore bundle format (what the
        # shared mapper and the whole verifier expect) uses base64. Convert here,
        # in the client, so the canonical shape the mapper reads is base64 --
        # exactly the artefact-fixture shape. Getting this wrong silently
        # base64-decodes hex and reconstructs the wrong Merkle root.
        def _hex_to_b64(h: str) -> str:
            return base64.b64encode(bytes.fromhex(h)).decode("ascii")

        mapped = {
            "canonicalizedBody": entry["body"],              # already base64
            "logIndex": entry["logIndex"],
            "logId": {"keyId": base64.b64encode(
                bytes.fromhex(key_id_hex)).decode("ascii")},
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
        self.last_mapped = mapped
        return mapped


def _rekor_public_key_der(base_url: str = _REKOR) -> bytes:
    import requests
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )
    resp = requests.get(f"{base_url}/api/v1/log/publicKey", timeout=30)
    resp.raise_for_status()
    return load_pem_public_key(resp.content).public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save", type=Path, required=True,
                        help="Directory to write bundle.json + trust material.")
    parser.add_argument("--pqc-algorithm", default="ml-dsa-87")
    parser.add_argument("--identity-token", default=None,
                        help="Skip the browser flow; supply an OIDC token.")
    parser.add_argument("--oauth-force-oob", action="store_true",
                        help="Out-of-band OIDC (WSL / no local browser).")
    parser.add_argument("--fulcio-roots", type=Path, default=None,
                        help="Optional: a trusted_root.json or PEM to save as the "
                             "verifier's Fulcio pool. If omitted, the returned "
                             "chain's certificates are saved.")
    args = parser.parse_args()

    token = acquire_identity_token(args.oauth_force_oob, args.identity_token)
    fulcio = FulcioRestClient(token)
    rekor = RekorRestClient()

    # The long-term PQC key -- the thing being registered. Held by the caller.
    pqc = get_backend(args.pqc_algorithm)
    pqc_pub, pqc_sk = pqc.keygen()

    # Trust material for register()'s mandatory round-trip verification.
    log_key_der = _rekor_public_key_der()
    # We do not yet know the Fulcio root pool until the chain returns; register
    # needs roots for its internal verify, so certify once up front to learn them.
    print("Certifying the classical key with Fulcio ...")
    probe_backend = get_backend("ecdsa-p256")
    probe_pub, probe_sk = probe_backend.keygen()
    probe_cert = fulcio.certify(probe_pub, probe_sk)
    roots = _load_fulcio_roots(args.fulcio_roots, probe_cert)

    print("Running qresp register against live Fulcio + Rekor ...")
    from qresp.signing.registration import RegistrationError
    try:
        bundle = register(
            pqc_algorithm=args.pqc_algorithm, pqc_public_key=pqc_pub,
            pqc_secret=pqc_sk, fulcio=fulcio, rekor=rekor,
            fulcio_roots=roots, log_public_key=log_key_der)
    except RegistrationError as exc:
        _diagnose_and_dump(args.save, rekor, log_key_der, exc)
        return 1

    args.save.mkdir(parents=True, exist_ok=True)
    (args.save / "bundle.json").write_text(
        json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
    (args.save / "rekor_key.der").write_bytes(log_key_der)
    for i, der in enumerate(roots):
        (args.save / f"fulcio_root_{i}.der").write_bytes(der)
    print(f"\n[OK] verified registration bundle written to {args.save}")
    print("     run: python -m pytest tests/signing/test_registration_fixture.py -v")
    return 0


def _diagnose_and_dump(save: Path, rekor: RekorRestClient, log_key_der: bytes,
                       exc: Exception) -> None:
    """When the round-trip verify fails, dump the raw Rekor response and print
    the exact numbers so the mismatch can be diagnosed offline -- no re-auth."""
    print(f"\n[FAIL] register did not verify: {exc}")
    if rekor.last_raw_entry is None:
        print("       (no Rekor response captured)")
        return
    save.mkdir(parents=True, exist_ok=True)
    (save / "DEBUG_rekor_raw.json").write_text(
        json.dumps(rekor.last_raw_entry, indent=2), encoding="utf-8")
    print(f"       raw Rekor response saved to {save / 'DEBUG_rekor_raw.json'}")

    # Focused comparison using our own verifier pieces.
    from qresp.signing.rekor import (
        InclusionError,
        leaf_hash,
        log_entry_from_rekor,
        verify_checkpoint,
        verify_inclusion_root,
    )

    mapped = rekor.last_mapped or {}
    proof = mapped.get("inclusionProof", {})
    print("\n--- diagnostic ---")
    print(f"  global logIndex        : {mapped.get('logIndex')}")
    print(f"  proof logIndex (shard) : {proof.get('logIndex')}")
    print(f"  proof treeSize         : {proof.get('treeSize')}")
    print(f"  proof #hashes          : {len(proof.get('hashes', []))}")
    print(f"  proof rootHash         : {proof.get('rootHash')}")
    try:
        cp_size, cp_root = verify_checkpoint(
            proof["checkpoint"], log_key_der)
        import base64
        print(f"  checkpoint treeSize    : {cp_size}")
        print(f"  checkpoint root (b64)  : {base64.b64encode(cp_root).decode()}")
        print(f"  checkpoint == proof.rootHash? "
              f"{base64.b64encode(cp_root).decode() == proof.get('rootHash')}")
        print(f"  checkpoint treeSize == proof.treeSize? "
              f"{cp_size == proof.get('treeSize')}")
        entry = log_entry_from_rekor(mapped)
        import base64 as _b
        recomputed = verify_inclusion_root(
            entry.proof_index, cp_size, leaf_hash(entry.entry_body),
            entry.inclusion_proof)
        print(f"  reconstructed (cp size): {_b.b64encode(recomputed).decode()}")
        recomputed_ps = verify_inclusion_root(
            entry.proof_index, proof["treeSize"], leaf_hash(entry.entry_body),
            entry.inclusion_proof)
        print(f"  reconstructed (proof sz): {_b.b64encode(recomputed_ps).decode()}")
    except (InclusionError, KeyError, ValueError) as diag_exc:
        print(f"  (diagnostic could not run fully: {diag_exc})")
    print("\n  ^ paste this block; it says whether the checkpoint is ahead of "
          "the proof, or the body/leaf hashing differs.")


def _load_fulcio_roots(supplied: Path | None,
                       probe_cert: FulcioCertificate) -> list[bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    if supplied is None:
        # Save the whole returned chain as the trust pool (leaf excluded);
        # verify_chain does path discovery over it.
        return list(probe_cert.intermediate_ders) or [probe_cert.leaf_der]
    raw = supplied.read_bytes()
    try:
        return [c.public_bytes(Encoding.DER)
                for c in x509.load_pem_x509_certificates(raw)]
    except (ValueError, TypeError):
        # a trusted_root.json: pull certificate authorities' certs
        data = json.loads(raw)
        out: list[bytes] = []
        for ca in data.get("certificateAuthorities", []):
            for cert in ca.get("certChain", {}).get("certificates", []):
                out.append(base64.b64decode(cert["rawBytes"]))
        return out


if __name__ == "__main__":
    raise SystemExit(main())
