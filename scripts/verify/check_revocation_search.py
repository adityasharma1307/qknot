"""Validate the revocation-search adapter against LIVE Rekor.

The offline tests prove the search logic; this proves the REST adapter -- the
index query, the entry fetch, and the mapping into the canonical shape -- against
production bytes. Same role the artefact and registration captures played for the
other two adapters.

    python scripts/verify/check_revocation_search.py \
        --registration tests/signing/fixtures/registration/bundle.json \
        --log-key      tests/signing/fixtures/registration/rekor_key.der

It needs NO artefact and NO OIDC: it reads the identity and the registered key
out of a registration bundle you already have, then asks the log what it knows
about that identity.

WHAT COUNTS AS SUCCESS HERE IS NOT "no revocations"
===================================================
The interesting outcomes are all informative:

  none-found  the index returned nothing for this identity, or nothing that was
              a revocation of this key. Conclusive.
  failed      entries exist but could not be examined -- the expected result
              against real Rekor, because a hashedrekord stores a DIGEST and the
              statements live in a distribution channel this script has not been
              given. That is the structural limit in docs/REGISTRATION-SPEC.md
              section 9.1, demonstrated on production data rather than asserted.
  found       an authenticated revocation of this key exists.

A traceback, or an outcome the adapter cannot explain, is the failure mode worth
reporting -- it means the live API shape differs from what the client assumes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from qknot.signing.registration import (  # noqa: E402
    HybridRegistration,
    _key_fingerprint,
)
from qknot.signing.registration_chain import RegistrationBundle  # noqa: E402
from qknot.signing.rekor import (  # noqa: E402
    InclusionError,
    hashedrekord_digest,
    log_entry_from_rekor,
    verify_log_entry,
)
from qknot.signing.revocation_search import (  # noqa: E402
    RevocationSearchOutcome,
    find_revocations,
)
from qknot.signing.sigstore_clients import (  # noqa: E402
    REKOR_URL,
    RekorRevocationSearchClient,
)


class CountingClient(RekorRevocationSearchClient):
    """The real client, with the raw index answer kept for diagnostics."""

    def __init__(self, base_url: str, limit: int | None):
        super().__init__(base_url)
        self.limit = limit
        self.uuids: list[str] = []
        self.fetched: list[dict] = []

    def search_by_identity(self, identity: str):
        import requests

        resp = requests.post(f"{self.base_url}/api/v1/index/retrieve",
                             json={"email": identity}, timeout=30)
        if not resp.ok:
            raise RuntimeError(
                f"index query returned HTTP {resp.status_code}: {resp.text[:400]}")
        self.uuids = resp.json() if isinstance(resp.json(), list) else []
        print(f"  index      : {len(self.uuids)} entr(ies) for this identity")
        if self.limit and len(self.uuids) > self.limit:
            print(f"  index      : examining the first {self.limit} "
                  f"(--limit); the rest are not looked at, which is itself an "
                  f"inconclusive answer for a real verifier")
            self.uuids = self.uuids[:self.limit]

        entries = []
        for index, uuid in enumerate(self.uuids, start=1):
            entry_resp = requests.get(
                f"{self.base_url}/api/v1/log/entries/{uuid}", timeout=30)
            if not entry_resp.ok:
                raise RuntimeError(
                    f"entry {uuid} could not be fetched (HTTP "
                    f"{entry_resp.status_code}); the search is incomplete")
            (_uuid, entry), = entry_resp.json().items()
            from qknot.signing.sigstore_clients import _map_entry

            mapped = _map_entry(entry)
            entries.append(mapped)
            self.fetched.append(mapped)
            if index % 5 == 0 or index == len(self.uuids):
                print(f"  fetched    : {index}/{len(self.uuids)}")
        return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registration", type=Path, required=True,
                        help="A registration bundle JSON.")
    parser.add_argument("--log-key", type=Path, required=True,
                        help="The transparency log's public key (DER).")
    parser.add_argument("--rekor-url", default=REKOR_URL)
    parser.add_argument("--limit", type=int, default=25,
                        help="Examine at most N index hits. 0 for all.")
    args = parser.parse_args()

    bundle = RegistrationBundle.from_dict(
        json.loads(args.registration.read_text(encoding="utf-8")))
    payload = HybridRegistration.from_payload(bundle.envelope.payload)
    fingerprint = _key_fingerprint(payload.pqc_key.public_key)

    print("=" * 70)
    print("REVOCATION SEARCH against live Rekor")
    print("=" * 70)
    print(f"  identity   : {payload.identity}")
    print(f"  key        : {payload.pqc_key.algorithm}")
    print(f"  fingerprint: {fingerprint}")
    print(f"  log        : {args.rekor_url}")

    log_key_der = args.log_key.read_bytes()
    client = CountingClient(args.rekor_url, args.limit or None)
    result = find_revocations(
        payload.identity, fingerprint, client=client,
        log_public_key=log_key_der)

    # `find_revocations` deliberately lumps every unexaminable candidate into one
    # inconclusive outcome -- that is the right verdict. But for VALIDATING the
    # adapter the two reasons must be told apart:
    #
    #   opaque        the entry authenticates; we simply have no statement for
    #                 it (the structural hashedrekord limit -- expected);
    #   unauthentic   the entry does NOT authenticate under the log key, which
    #                 would mean the fetch/map/verify path is broken.
    #
    # Only the first is a clean result.
    print("\n" + "-" * 70)
    print("  per-entry breakdown (validation only; not part of the verdict)")
    opaque = unauthentic = 0
    for index, raw in enumerate(client.fetched, start=1):
        try:
            entry = log_entry_from_rekor(raw)
            own_digest = hashedrekord_digest(entry.entry_body)
            logged_at = verify_log_entry(entry, own_digest, log_key_der)
            opaque += 1
            print(f"   {index}. authenticates OK, logged {logged_at.isoformat()} "
                  f"-- statement not available, so contents opaque")
        except InclusionError as exc:
            unauthentic += 1
            print(f"   {index}. DOES NOT AUTHENTICATE: {exc}")
    print(f"  authenticated: {opaque}   unauthenticated: {unauthentic}")

    print("\n" + "-" * 70)
    print(f"  OUTCOME    : {result.outcome.value}")
    print(f"  conclusive : {result.is_conclusive}")
    print(f"  examined   : {result.candidates_examined}")
    print(f"  detail     : {result.detail}")
    for statement, logged_at in result.revocations:
        data = json.loads(statement.payload)
        print(f"    revocation: {data.get('reason')!r} "
              f"revokedAt={data.get('revokedAt')} logged={logged_at.isoformat()}")

    print("\n" + "-" * 70)
    if result.outcome is RevocationSearchOutcome.FAILED:
        if unauthentic:
            print(f"  [GAP] {unauthentic} entr(ies) did not authenticate. That "
                  f"is NOT the\n        structural limit -- it means the "
                  f"fetch/map/verify path disagrees\n        with the live API. "
                  f"Report the per-entry lines above.")
        else:
            print("  [OK] every entry the log returned AUTHENTICATED (inclusion "
                  "proof,\n       signed checkpoint, SET) -- so the adapter's "
                  "fetch, mapping and\n       verification all work on "
                  "production bytes. The outcome is still\n       inconclusive, "
                  "and correctly so: a hashedrekord stores a digest, so\n"
                  "       the statements must come from a distribution channel "
                  "(spec 9.1).\n       The limit is structural, not a defect, "
                  "and is now shown on real data.")
    elif result.outcome is RevocationSearchOutcome.NONE_FOUND:
        print("  [OK] the adapter reached the log, examined every candidate, and "
              "found\n       no revocation of this key. A conclusive answer.")
    elif result.outcome is RevocationSearchOutcome.FOUND:
        print("  [OK] an authenticated revocation of this key exists in the log.")
    print("       Report this whole block; a traceback above would mean the live "
          "API\n       shape differs from what the client assumes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
