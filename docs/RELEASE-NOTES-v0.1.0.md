# v0.1.0 — first public release

Quantum-Resilient Provenance: hybrid post-quantum signing and identity
registration that a today's-verifier still accepts, motivated by a
cross-registry audit of how much of the software supply chain would survive
a quantum adversary right now (not much).

## Headline finding

A stratified audit of HuggingFace, npm and PyPI (10,000 most-downloaded +
10,000 uniform-random each, 60,000 artefacts total) found **0 post-quantum
signatures anywhere** — a one-sided upper bound of 0.038% per stratum at 95%
confidence. Every signature found is Shor-breakable (ECDSA P-256, RSA), and
the zero holds even on PyPI and npm, where signing is routine. See the
README and `docs/RESULTS.md` for the full statistics.

## What's in this release

**Sign / verify.** A non-separable hybrid signature (Ed25519 + ML-DSA-87 by
default) that a bare-field-deletion attack cannot silently downgrade, in an
OMS v1.0-compatible Sigstore bundle. 180/180 NIST ACVP FIPS 204 vectors pass
offline on every test run. **This release signs itself** — see
`release/qresp-0.1.0.bundle.json` and `release/README.md`.

**Identity registration.** `qresp register` binds a post-quantum key to your
existing OIDC identity through a classical Fulcio certificate, before that
certificate's algorithm is deprecated — logged to Rekor so the binding is
provably time-anchored and survives the classical algorithm's disallowance.
`qresp verify --registration` gives the composed verdict: not just "the
signature is valid" but "and it's attributable to this identity, on this
basis." `qresp trust-material` fetches a real Fulcio/Rekor trust store from
Sigstore's production TUF root, so this doesn't require hand-assembling one.

**Revocation search.** `--check-revocations` searches Rekor live and
authenticates every candidate; the verdict distinguishes "searched, found
nothing" from "search failed / nobody looked" from "found" — it never
collapses an inconclusive search into a clean bill of health. See
`docs/REGISTRATION-SPEC.md` §9.1 for the structural limit this exposes
(Rekor stores a digest, not a statement) and how it's handled.

**Audit.** `qresp scan` / `scan-ids` / `audit-npm` / `audit-pypi` /
`summarise` — HuggingFace, npm and PyPI, each with a head/tail stratified
design, resumable, and honest about unreachable rows (`error`, never folded
into `unsigned`). The evidence base for why the above exists.

## Validated on live infrastructure, not only simulated

- A real Fulcio certificate + Rekor entry, captured and run through the full
  registration verification chain including the temporal rescue
  (`tests/signing/test_registration_fixture.py`).
- The revocation-search adapter validated against live Rekor: 5/5 log entries
  fetched and authenticated on production data, 0 unauthenticated
  (`scripts/verify/check_revocation_search.py`).

## Tests

1261 passing offline, 57 skipped by default (need network or a captured
fixture — see `CONTRIBUTING.md`). What is and is not protected is stated
plainly, in both directions, in `docs/THREAT-MODEL.md`.

## Known limitations, stated plainly

- Registration's binding is only as strong as the OIDC identity that anchored
  it; the temporal rescue only helps registrations logged *before* the
  classical algorithm's disallow date.
- Revocation search cannot read `hashedrekord` entries whose statement wasn't
  separately obtained — a structural property of the log, not a bug. See
  `docs/REGISTRATION-SPEC.md` §9.1 and `docs/THREAT-MODEL.md`.
- `data/npm_frame_2026-07-30.txt` is 85 MB, over GitHub's recommended (not
  hard) file-size threshold; a future release may move it to Git LFS or a
  release asset.
- This is a research/reference implementation (Alpha). See `SECURITY.md` for
  how to report an issue, and `DISCLAIMER.md` for warranty/liability limits
  covering the author, supervisor, and institution.

## New since the design-project submission

`qresp trust-material`, the identity-registration product surface
(`register` / `verify --registration` / `--check-revocations`), npm/PyPI
audit commands, `SECURITY.md`, `CONTRIBUTING.md`, a self-signed release
process (`scripts/release/`), and this release itself.
