"""Find which public Time-Stamp Authorities produce responses we can verify.

WHY THIS EXISTS
===============
`DEFAULT_TSA_URLS` cannot be chosen from documentation. A TSA is only usable
here if its response survives a *strict DER* parse, and not all of them do.

DigiCert's `timestamp.digicert.com` is the concrete case. It answers correctly
and returns a well-formed timestamp by most measures, but its CMS
`SignedData::certificates` SET is not sorted in DER order. RFC 5652 defines
that field as a `SET OF`, and DER requires the elements of a SET OF to be
sorted by their encoding; `rfc3161-client` enforces the rule and rejects the
response with:

    ASN.1 parse error: InvalidSetOrdering
    location: RawTimeStampResp::time_stamp_token
              -> TimeStampToken::content
              -> SignedData::certificates[1]

This is an interoperability fact, not a bug in this project, and the response
is NOT to relax the parser. Accepting non-canonical DER in a verification path
is how signature-malleability bugs are introduced: if two distinct byte strings
can both be accepted as "the same" structure, an attacker gains a degree of
freedom in something that is supposed to be exactly comparable. The parser is
right to be strict. The correct fix is to pick authorities that emit canonical
DER, which is what this script is for.

    python scripts/verify/probe_tsa.py

It makes one real network request per authority and reports, for each, whether
the response arrives, parses, and carries a sane time. Nothing is written; the
output is meant to be read and used to set `DEFAULT_TSA_URLS`.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

# Public, free, no-registration TSAs. Ordered roughly by how widely used they
# are, not by expected success -- the point is to find out.
CANDIDATES = [
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.apple.com/ts01",
    "http://rfc3161.ai.moda",
    "http://freetsa.org/tsr",
    "http://tsa.swisssign.net",
    "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
    "http://ts.ssl.com",
]

PROBE = b"qknot-tsa-probe"


def probe(url: str, timeout: float = 15.0) -> tuple[str, str]:
    """Return (verdict, detail) for one authority. Never raises."""
    from qknot.signing.transparency import (
        TimestampError,
        TimestampUnavailableError,
        request_timestamp,
    )

    try:
        token = request_timestamp(PROBE, url, timeout=timeout)
    except TimestampUnavailableError as exc:
        return "UNREACHABLE", str(exc)[:140]
    except TimestampError as exc:
        detail = str(exc)
        if "InvalidSetOrdering" in detail:
            return "NON-CANONICAL DER", "certificates SET is not DER-sorted"
        return "UNPARSEABLE", detail[:140]
    except Exception as exc:                       # noqa: BLE001 - probe script
        return "ERROR", f"{type(exc).__name__}: {exc}"[:140]

    try:
        stamped = token.gen_time
    except Exception as exc:                       # noqa: BLE001
        return "NO TIME", f"parsed, but gen_time failed: {exc}"[:140]

    skew = abs(stamped - datetime.now(timezone.utc))
    if skew > timedelta(hours=1):
        return "CLOCK SKEW", f"{stamped.isoformat()} is {skew} from local time"

    return "OK", f"{stamped.isoformat()}  ({len(token.der)} bytes)"


def main() -> int:
    print(f"Probing {len(CANDIDATES)} timestamp authorities.\n")
    usable: list[str] = []

    for url in CANDIDATES:
        verdict, detail = probe(url)
        print(f"  {verdict:18} {url}")
        print(f"  {'':18} {detail}\n")
        if verdict == "OK":
            usable.append(url)

    print("=" * 78)
    if len(usable) >= 2:
        print(f"{len(usable)} usable. Set DEFAULT_TSA_URLS to two run by "
              f"DIFFERENT organisations:\n")
        for url in usable:
            print(f'    "{url}",')
        print("\nIndependence is the point of the threshold -- two endpoints "
              "operated by\none company are one source of trust wearing two "
              "hats.")
    elif len(usable) == 1:
        print(f"Only one usable authority ({usable[0]}).")
        print("VERIFIED_TIME_THRESHOLD is 2, so signing will not be able to "
              "establish\nan upper bound. Either find a second authority, or "
              "lower the threshold\ndeliberately and record why.")
    else:
        print("No usable authority found. Do NOT relax the DER parser to make "
              "one work:\naccepting non-canonical encodings in a verification "
              "path trades a real\nsecurity property for convenience.")
    return 0 if len(usable) >= 2 else 1


if __name__ == "__main__":
    raise SystemExit(main())
