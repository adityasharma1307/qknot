# v0.1.1 — renamed to QKnot

The project was called QResP through v0.1.0. That name collides with an
existing, published, actively-hosted tool — *Qresp, a tool for curating,
discovering and exploring reproducible scientific papers* (Govoni et al.,
*Scientific Data*, 2019; qresp.org) — in a different field, but a collision
all the same. QKnot is the name from here on: the knot is the point, since a
knot cannot be untied one strand at a time, which is exactly what the hybrid
binding guarantees about the two signatures.

Nothing about the design changed. This is a rename, one real fix, and a
re-signed release.

## Breaking changes

**Everything user-facing is renamed.** The package is `qknot`, the command is
`qknot`, the module is `qknot`. Reinstall rather than upgrade:

```bash
pip uninstall qresp && pip install qknot
```

**The wire format's identifiers changed**, so v0.1.0 artefacts do not verify
under v0.1.1:

| was | now |
| --- | --- |
| `application/vnd.qresp.key-registration+json` | `application/vnd.qknot.key-registration+json` |
| `application/vnd.qresp.hybrid-key-registration+json` | `application/vnd.qknot.hybrid-key-registration+json` |
| `application/vnd.qresp.key-revocation+json` | `application/vnd.qknot.key-revocation+json` |
| `qresp-keygen-v1` (HKDF salt) | `qknot-keygen-v1` |
| `qresp-key-fingerprint-v1` | `qknot-key-fingerprint-v1` |

Two consequences worth stating plainly rather than discovering later:

- **The same seed derives a different key than it did under v0.1.0**, because
  the HKDF salt is part of the derivation. A v0.1.0 seed is not portable.
- **Key fingerprints changed**, so a v0.1.0 registration does not name the
  same key under v0.1.1.

Both are acceptable at v0.1.x with no external users, and both are the
honest consequence of domain separation actually being domain separation. If
either had been left alone for compatibility, the identifiers would no longer
match the project they name.

One string is deliberately *not* renamed: the TSA fixture message
`qresp-fixture-v1` in `tests/signing/test_transparency_real.py`. Those tokens
were signed by public timestamp authorities over those exact bytes. Renaming
the constant would not rename what was signed — it would just stop matching
it.

## Fixed

**The revocation search is now bounded** (`RekorRevocationSearchClient`,
`max_entries`, default 512). Rekor's index is attacker-influenced: anyone can
log entries naming any email, so an identity's entry count is not something
the verifier controls, and walking it one fetch at a time without a bound made
`verify --check-revocations` an unbounded network operation an adversary could
stretch at will. Exceeding the bound now *raises* rather than truncating —
a truncated walk that found nothing is indistinguishable from a complete walk
that found nothing, and this module's entire purpose is to never report an
unearned all-clear. It surfaces as FAILED ("could not establish"), which is
the honest verdict.

## This release signs itself, and says who signed it

`release/qknot-0.1.1.tar.gz` carries a hybrid Ed25519 + ML-DSA-87 signature
whose post-quantum key is registered to a real OIDC identity and logged to
Rekor. `release/README.md` documents both verification paths — signature
alone, and signature + identity + live revocation check — including an
explanation of the two lines in the attributed output that report honest
uncertainty rather than failure.

## Unchanged from v0.1.0

The audit findings, the threat model, the registration design, and the
measured benchmarks all stand as published. See
`docs/RELEASE-NOTES-v0.1.0.md` in the v0.1.0 tag for the original release
notes, and `docs/RESULTS.md` for the audit itself: 60,000 artefacts across
HuggingFace, npm and PyPI, **0 post-quantum signatures**, a one-sided upper
bound of 0.038% per stratum at 95% confidence.
