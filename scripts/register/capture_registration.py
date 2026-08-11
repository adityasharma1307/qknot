"""Capture ONE real registration bundle -- the residual-3 fixture.

Runs the `qknot register` orchestrator against LIVE Fulcio + Rekor, so the
emitted bundle is production bytes that `tests/signing/test_registration_fixture.py`
locks. Mirrors how `scripts/verify/check_sigstore_fixture.py` captured the
artefact fixture.

RUN THIS ON A MACHINE WITH NETWORK + OIDC (it cannot run in the CI sandbox). On
WSL or anywhere without a usable browser, pass `--oauth-force-oob`.

    python scripts/register/capture_registration.py \
        --save tests/signing/fixtures/registration

The network adapters live in `qknot.signing.sigstore_clients`, NOT here: the CLI
(`qknot register`) and this harness share one implementation, because a second
copy is where the two would drift and the drift would only show against live
infrastructure. This script is now just "run register, save the pieces, and if
verification fails dump enough to diagnose it offline".

`register()` verifies the bundle end to end before this script writes anything,
so a bad capture is never saved.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

# The qknot package must be importable (run from the repo root, or install -e).
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from qknot.signing.backends import get_backend  # noqa: E402
from qknot.signing.register import FulcioCertificate, register  # noqa: E402
from qknot.signing.registration import RegistrationError  # noqa: E402
from qknot.signing.sigstore_clients import (  # noqa: E402
    FulcioRestClient,
    RekorRestClient,
    acquire_identity_token,
    rekor_public_key_der,
)


def _diagnose_and_dump(save: Path, rekor: RekorRestClient, log_key_der: bytes,
                       exc: Exception) -> None:
    """On a verification failure, dump the raw Rekor response and print the
    numbers that pin the cause -- so it can be diagnosed without re-authing."""
    print(f"\n[FAIL] register did not verify: {exc}")
    if rekor.last_raw_entry is None:
        print("       (no Rekor response captured)")
        return
    save.mkdir(parents=True, exist_ok=True)
    (save / "DEBUG_rekor_raw.json").write_text(
        json.dumps(rekor.last_raw_entry, indent=2), encoding="utf-8")
    print(f"       raw Rekor response saved to {save / 'DEBUG_rekor_raw.json'}")

    from qknot.signing.rekor import (
        InclusionError,
        leaf_hash,
        log_entry_from_rekor,
        verify_checkpoint,
        verify_inclusion_root,
    )

    entry_json = rekor.last_raw_entry
    proof = entry_json.get("verification", {}).get("inclusionProof", {})
    print("\n--- diagnostic ---")
    print(f"  global logIndex        : {entry_json.get('logIndex')}")
    print(f"  proof logIndex (shard) : {proof.get('logIndex')}")
    print(f"  proof treeSize         : {proof.get('treeSize')}")
    print(f"  proof #hashes          : {len(proof.get('hashes', []))}")
    try:
        cp_size, cp_root = verify_checkpoint(proof["checkpoint"], log_key_der)
        print(f"  checkpoint treeSize    : {cp_size}  "
              f"(== proof treeSize? {cp_size == proof.get('treeSize')})")
        print(f"  checkpoint root        : {base64.b64encode(cp_root).decode()}")
        entry = log_entry_from_rekor(rekor.last_mapped or {})
        recomputed = verify_inclusion_root(
            entry.proof_index, cp_size, leaf_hash(entry.entry_body),
            entry.inclusion_proof)
        print(f"  reconstructed root     : "
              f"{base64.b64encode(recomputed).decode()}  "
              f"(match? {recomputed == cp_root})")
    except (InclusionError, KeyError, ValueError, AttributeError) as diag_exc:
        print(f"  (diagnostic could not run fully: {diag_exc})")
    print("\n  ^ paste this block: it says whether the checkpoint is ahead of "
          "the proof, or the body/leaf hashing differs.")


def _load_fulcio_roots(supplied: Path | None,
                       probe_cert: FulcioCertificate) -> list[bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    if supplied is None:
        # The chain Fulcio returned. Self-consistent, not independent trust --
        # fine for a fixture, and the CLI says the same thing out loud.
        return list(probe_cert.intermediate_ders) or [probe_cert.leaf_der]
    raw = supplied.read_bytes()
    try:
        return [c.public_bytes(Encoding.DER)
                for c in x509.load_pem_x509_certificates(raw)]
    except (ValueError, TypeError):
        data = json.loads(raw)                      # a TUF trusted_root.json
        return [base64.b64decode(cert["rawBytes"])
                for ca in data.get("certificateAuthorities", [])
                for cert in ca.get("certChain", {}).get("certificates", [])]


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
                        help="A trusted_root.json or PEM to use as the "
                             "verifier's Fulcio pool. Default: the chain Fulcio "
                             "returns.")
    args = parser.parse_args()

    token = acquire_identity_token(
        force_oob=args.oauth_force_oob, supplied=args.identity_token)
    fulcio = FulcioRestClient(token)
    rekor = RekorRestClient()
    print(f"OIDC identity: {fulcio.subject}  "
          f"(issuer {fulcio.claims.get('iss')})")

    # The long-term PQC key -- the thing being registered.
    pqc_pub, pqc_sk = get_backend(args.pqc_algorithm).keygen()
    log_key_der = rekor_public_key_der()

    # register() needs roots for its own verification, so learn the CA pool from
    # a throwaway certification first.
    print("Certifying the classical key with Fulcio ...")
    probe_pub, probe_sk = get_backend("ecdsa-p256").keygen()
    roots = _load_fulcio_roots(args.fulcio_roots, fulcio.certify(probe_pub, probe_sk))

    print("Running qknot register against live Fulcio + Rekor ...")
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


if __name__ == "__main__":
    raise SystemExit(main())
