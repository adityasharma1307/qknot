"""Derive a raw keypair from a seed, so the SAME key can be used by both
`qknot sign --seed` and `qknot register --pqc-public-key/--pqc-secret-key`.

The gap this closes: `sign` derives reproducible keys from a seed but only
ever writes the PUBLIC half to disk (`--keys-out`); `register` accepts an
existing keypair as raw files but has no `--seed` of its own. Neither command
alone can produce a signature and a registration that refer to the same key.
This script does the one thing in between: given a seed, write out the raw
public/secret key files in exactly the shape `register` reads them, deriving
them with the identical HKDF domain separation `keygen()` uses internally
(salt `qknot-keygen-v1`, info=algorithm name) -- so the ML-DSA-87 key this
produces IS the one `qknot sign --seed <same hex> --suite ed25519+ml-dsa-87`
signs with, byte for byte, whether or not ed25519 is in the suite passed
here (each algorithm's key is derived independently of what else is in the
suite).

    python -c "import secrets; print(secrets.token_hex(32))"   # 1. a seed
    python scripts/release/derive_keypair.py --seed <hex> --out release/keys

    qknot sign artefact --seed <hex> --out bundle.json           # 2. sign
    qknot register --pqc-public-key release/keys/ml-dsa-87.pub \\  # 3. register
        --pqc-secret-key release/keys/ml-dsa-87.key --out ./registration \\
        --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub

THE SEED IS THE KEY. Treat it exactly like a private key: generate it on a
machine you trust (not an ephemeral sandbox), never commit it, never print it
to a log you don't control, and store it somewhere that survives -- losing it
means losing the ability to re-derive this identity's signing key.
"""
from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from qknot.signing.sign import keygen  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", required=True,
                        help="Hex seed, 32+ bytes (64+ hex characters). Treat as a secret.")
    parser.add_argument("--algorithm", default="ml-dsa-87",
                        help="Which algorithm's key to derive and write "
                             "(default: ml-dsa-87, matching `register`'s default).")
    parser.add_argument("--out", type=Path, required=True,
                        help="Directory to write <algorithm>.pub and <algorithm>.key into.")
    args = parser.parse_args()

    try:
        seed_bytes = bytes.fromhex(args.seed)
    except ValueError:
        raise SystemExit("--seed must be hex") from None
    if len(seed_bytes) < 32:
        raise SystemExit(f"--seed must be at least 32 bytes (64 hex chars); "
                         f"got {len(seed_bytes)}")

    keys = keygen(suite=[args.algorithm], seed=seed_bytes)
    key = keys.keys[args.algorithm]

    args.out.mkdir(parents=True, exist_ok=True)
    pub_path = args.out / f"{args.algorithm}.pub"
    sk_path = args.out / f"{args.algorithm}.key"
    pub_path.write_bytes(key.public_key)
    sk_path.write_bytes(key.secret_key)
    with contextlib.suppress(OSError):  # e.g. a Windows mount; restrict access yourself
        sk_path.chmod(0o600)

    print(f"algorithm   : {args.algorithm}")
    print(f"fingerprint : {key.fingerprint}")
    print(f"public key  -> {pub_path}")
    print(f"secret key  -> {sk_path}  (TREAT AS A PRIVATE KEY -- move it "
          f"somewhere safe, do not commit it)")
    print()
    print("Use the SAME --seed with `qknot sign` to sign with this exact key,")
    print(f"and point `qknot register` at {pub_path} / {sk_path} to register it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
