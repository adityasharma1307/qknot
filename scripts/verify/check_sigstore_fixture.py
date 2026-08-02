"""Run QResP's chain + inclusion verifiers against a REAL Sigstore bundle.

WHAT THIS IS FOR
================
Every registration test mints its own trust stack, so it proves the logic
against self-consistent bytes. This proves it against PRODUCTION bytes: a real
Fulcio leaf (with its EKU / SCT / issuer-extension quirks) and a real Rekor
inclusion proof + checkpoint. It is expected to SURFACE GAPS -- that is the
point. Whatever it reports goes back to the expert.

HOW TO PRODUCE THE INPUT (you, once, interactively)
===================================================
    pip install sigstore
    echo "qresp fixture" > /tmp/fixture.txt
    sigstore sign --bundle /tmp/fixture.sigstore /tmp/fixture.txt
        # opens a browser for OIDC; produces a .sigstore bundle containing a
        # real Fulcio cert chain and a real Rekor entry.

Then extract the trust root (Fulcio root cert + Rekor public key). The simplest
route is the sigstore Python trust root; if that API has drifted, pass the files
explicitly with --fulcio-root and --rekor-key.

    python scripts/verify/check_sigstore_fixture.py --bundle /tmp/fixture.sigstore

WHAT IT CHECKS
==============
1. fulcio.verify_chain(leaf, intermediates, [fulcio_root]) at the cert's own
   validity window -> the real identity and issuer, or the exact rejection.
2. rekor.verify_inclusion_root(logIndex, treeSize, leaf_hash(canonicalBody),
   hashes) == the checkpoint root -> the RFC 6962 math against a real entry.

It does NOT check the full registration chain: a Sigstore artefact bundle is not
a qresp registration, so the digest-to-preimage binding does not apply. What it
de-risks is the two modules that must consume production bytes.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


def _b64(value: str) -> bytes:
    # Sigstore protobuf-JSON uses standard base64, sometimes without padding.
    pad = "=" * (-len(value) % 4)
    return base64.b64decode(value + pad)


def _leaf_and_chain(material: dict) -> tuple[bytes, list[bytes]]:
    """Return (leaf DER, [intermediate DER]) from either bundle cert shape."""
    if "certificate" in material:                       # bundle v0.3+
        leaf = _b64(material["certificate"]["rawBytes"])
        return leaf, []
    chain = material["x509CertificateChain"]["certificates"]
    ders = [_b64(c["rawBytes"]) for c in chain]
    return ders[0], ders[1:]


def _tlog_entry(material: dict) -> dict:
    entries = material.get("tlogEntries") or []
    if not entries:
        raise SystemExit("bundle has no tlogEntries; nothing to check inclusion on")
    return entries[0]


def _trust_root(args: argparse.Namespace) -> tuple[list[bytes], bytes | None]:
    """Fulcio roots and the Rekor public key, from files or the sigstore TUF root."""
    if args.fulcio_root:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        raw = Path(args.fulcio_root).read_bytes()
        try:
            certs = x509.load_pem_x509_certificates(raw)
            roots = [c.public_bytes(Encoding.DER) for c in certs]
        except ValueError:
            roots = [raw]
        key = Path(args.rekor_key).read_bytes() if args.rekor_key else None
        return roots, key

    # Fall back to the sigstore library's trusted root. The accessor names have
    # changed across versions, so try a few and report clearly if none work.
    try:
        from sigstore.trust import TrustedRoot
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(
            f"could not import sigstore.trust ({exc}); pass --fulcio-root and "
            f"--rekor-key explicitly instead") from None

    tr = None
    for factory in ("production", "staging"):
        try:
            tr = getattr(TrustedRoot, factory)()
            break
        except Exception:  # noqa: BLE001
            continue
    if tr is None:
        raise SystemExit(
            "could not build a sigstore TrustedRoot; pass --fulcio-root/--rekor-key")

    from cryptography.hazmat.primitives.serialization import Encoding

    roots = []
    for accessor in ("get_fulcio_certs", "fulcio_certificate_authorities"):
        try:
            certs = getattr(tr, accessor)()
            roots = [c.public_bytes(Encoding.DER) if hasattr(c, "public_bytes")
                     else c for c in certs]
            break
        except Exception:  # noqa: BLE001
            continue
    return roots, None      # Rekor key extraction is version-specific; --rekor-key preferred


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=Path, required=True,
                        help="A .sigstore bundle from `sigstore sign`.")
    parser.add_argument("--fulcio-root", type=Path, default=None,
                        help="Fulcio root cert (PEM/DER). Default: sigstore TUF.")
    parser.add_argument("--rekor-key", type=Path, default=None,
                        help="Rekor public key (DER). Needed to check the "
                             "checkpoint signature; the RFC 6962 root check runs "
                             "without it.")
    parser.add_argument("--save", type=Path, default=None,
                        help="Directory to write the extracted fixture pieces to.")
    args = parser.parse_args(argv)

    from qresp.signing.fulcio import ChainError, verify_chain
    from qresp.signing.rekor import (
        InclusionError,
        leaf_hash,
        verify_inclusion_root,
    )

    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    material = bundle["verificationMaterial"]
    leaf, intermediates = _leaf_and_chain(material)
    entry = _tlog_entry(material)
    roots, rekor_key = _trust_root(args)

    print("=" * 70)
    print("1. FULCIO CHAIN  (production leaf, EKU/SCT/issuer-extension real)")
    print("=" * 70)
    from cryptography import x509

    cert = x509.load_der_x509_certificate(leaf)
    at = cert.not_valid_before_utc.replace(tzinfo=timezone.utc)
    print(f"  leaf subject : {cert.subject.rfc4514_string()}")
    print(f"  valid from   : {cert.not_valid_before_utc.isoformat()}")
    print(f"  roots loaded : {len(roots)}, intermediates in bundle: {len(intermediates)}")
    try:
        identity = verify_chain(leaf, intermediates, roots, at_time=at)
        print(f"  [OK] identity = {identity.identity!r}  issuer = {identity.issuer!r}")
    except ChainError as exc:
        print(f"  [GAP] verify_chain rejected a real leaf: {exc}")
        print("        ^ this is exactly the kind of production quirk to report.")

    print("\n" + "=" * 70)
    print("2. REKOR INCLUSION  (RFC 6962 math against a real entry)")
    print("=" * 70)
    proof = entry.get("inclusionProof") or {}
    if not proof:
        print("  [GAP] no inclusionProof in the entry; only an inclusionPromise? "
              "Report the bundle's tlog shape.")
    else:
        try:
            body = _b64(entry["canonicalizedBody"])
            log_index = int(proof["logIndex"])
            tree_size = int(proof["treeSize"])
            hashes = [_b64(h) for h in proof.get("hashes", [])]
            root_hash = _b64(proof["rootHash"])
            computed = verify_inclusion_root(
                log_index, tree_size, leaf_hash(body), hashes)
            match = computed == root_hash
            print(f"  logIndex={log_index} treeSize={tree_size} "
                  f"proof_hashes={len(hashes)}")
            if match:
                print("  [OK] RFC 6962 reconstruction matches the checkpoint root.")
            else:
                print("  [GAP] reconstructed root != checkpoint root.")
                print(f"        computed   {computed.hex()}")
                print(f"        checkpoint {root_hash.hex()}")
                print("        ^ leaf-hash canonicalisation differs from ours; report it.")
        except (InclusionError, KeyError, ValueError) as exc:
            print(f"  [GAP] inclusion check could not run: {exc}")

    if args.save:
        args.save.mkdir(parents=True, exist_ok=True)
        (args.save / "leaf.der").write_bytes(leaf)
        for i, der in enumerate(intermediates):
            (args.save / f"intermediate_{i}.der").write_bytes(der)
        for i, der in enumerate(roots):
            (args.save / f"fulcio_root_{i}.der").write_bytes(der)
        (args.save / "tlog_entry.json").write_text(
            json.dumps(entry, indent=2), encoding="utf-8")
        print(f"\n  saved fixture pieces to {args.save}")

    print("\nWhatever [GAP] lines appear above are the findings for the expert.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
