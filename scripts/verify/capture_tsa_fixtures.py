"""Re-capture the RFC 3161 fixtures in tests/signing/tsa_fixtures/.

The fixtures are real timestamp tokens from public authorities. They are signed
data, so they keep proving what they proved on the day they were issued -- but
they prove it about ONE message, and only that message. When the message
constant changes (as it did when the project was renamed), the old tokens stop
matching and must be re-issued. There is no way around that: a TSA signs the
bytes it was given, and no amount of editing renames what it signed.

    python scripts/verify/capture_tsa_fixtures.py

Needs network, and `pip install -e ".[transparency]"`. Writes one `.b64` per
authority plus `manifest.json`, which records the message and each token's
gen_time so the test asserts against what was actually captured rather than a
hand-copied constant that has to be kept in sync.

The SwissSign root fingerprint is NOT written by this script. The test pins it
deliberately: verifying against a root pulled out of the response being verified
would be circular. This script only reports whether the observed root still
matches the pin, so a rotation is surfaced as a decision rather than absorbed
silently.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

FIXTURES = REPO_ROOT / "tests" / "signing" / "tsa_fixtures"

# Must match MESSAGE in tests/signing/test_transparency_real.py.
MESSAGE = b"qknot-fixture-v1"

AUTHORITIES = {
    "swisssign": "http://tsa.swisssign.net",
    "sslcom": "http://ts.ssl.com",
}

# SwissSign Signature Services Root 2020 - 2, DER SHA-256. See the module
# docstring: reported against, never written from, the response.
SWISSSIGN_ROOT_SHA256 = (
    "b87f292a4d9feace2d669159eb26f56d85ec77c19e01098cd754e8abb310cde5"
)


def _root_fingerprint(der: bytes) -> str | None:
    import rfc3161_client
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    response = rfc3161_client.decode_timestamp_response(der)
    for raw in response.signed_data.certificates:
        cert = x509.load_der_x509_certificate(raw)
        if cert.subject == cert.issuer:
            return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=FIXTURES)
    args = parser.parse_args()

    from qknot.signing.transparency import request_timestamp

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    manifest: dict[str, object] = {
        "message": MESSAGE.decode(),
        "captured": datetime.now(timezone.utc).isoformat(),
        "tokens": {},
    }

    for name, url in AUTHORITIES.items():
        print(f"requesting {url} ...")
        token = request_timestamp(MESSAGE, url)
        filename = f"{name}_{stamp}.b64"
        (args.out / filename).write_text(
            base64.b64encode(token.der).decode() + "\n", encoding="utf-8")

        entry = {"file": filename, "url": url,
                 "gen_time": token.gen_time.isoformat()}
        manifest["tokens"][name] = entry  # type: ignore[index]
        print(f"  -> {filename}  gen_time={token.gen_time.isoformat()}")

        if name == "swisssign":
            observed = _root_fingerprint(token.der)
            if observed != SWISSSIGN_ROOT_SHA256:
                print(f"  !! SwissSign root fingerprint is {observed}, "
                      f"pinned {SWISSSIGN_ROOT_SHA256}.\n"
                      f"     Establish WHY before updating the pin in "
                      f"tests/signing/test_transparency_real.py -- a rotation "
                      f"and a substituted chain look identical from here.")

    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out / 'manifest.json'}")
    print("Delete the superseded *.b64 files, then run:")
    print("  python -m pytest tests/signing/test_transparency_real.py -q")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
