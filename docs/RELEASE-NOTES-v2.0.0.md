# v2.0.0

The wire format is unchanged from v0.1.1. The same media types and HKDF salts
still apply, and a v0.1.1 bundle still verifies. This release changes how you
install QKnot and what several commands require.

## Breaking changes

`pip install qknot` no longer installs the Hugging Face client, Pydantic, or
Tenacity. Audit commands need `pip install "qknot[audit]"`. A faster ML-DSA
backend needs `qknot[pqc-fast]`. IBM Quantum entropy needs `qknot[qrng-ibm]`.

`qknot sign --deterministic` is refused unless you also pass
`--i-am-producing-test-vectors`. Hedged signing stays the default.

`qknot register` requires `--recovery-key` or `--generate-recovery-key`.
Ed25519 shares the classical disallow date, so it is not an independent
recovery family. Bundles that were logged without a recovery key still verify.

Bare `qknot verify` checks integrity only. It says so. Pin keys you already
trust with `--expect-fingerprint`.

`qknot entropy` mixes the system CSPRNG with the NIST beacon. ANU is only used
with `--backend anu`.

When liboqs is installed, `get_backend("ml-dsa-87")` uses it. Its side-channel
status stays `UNKNOWN` until you attest that build. Key generation still uses
dilithium-py, because liboqs has no seeded keygen.

## Added

- NIST beacon pulse signatures are checked. A bad signature or the wrong
  certificate returns false.
- `qknot timestamp` attaches an RFC 3161 upper bound to a bundle.
  `--require-upper-bound` fails closed when that bound was not verified.
- `FileKeyStore` writes owner-only secret files and refuses a world-readable
  key on load. Secrets are written only with `--secret-keys-out`.
- `qknot monitor-registrations` lists Rekor entries for an identity. An
  unfinished walk is `NOT ESTABLISHED`, not an all-clear.
- IBM Quantum and a local USB QRNG path are real entropy sources. A missing
  token or a stuck device fails instead of pretending.
- An OMS manifest that names a file you did not fetch is `manifest-incomplete`,
  not covered and not unsigned.
- CI runs Python 3.10 through 3.13 with the network on.

## Unchanged

Media types:

- `application/vnd.qknot.key-registration+json`
- `application/vnd.qknot.hybrid-key-registration+json`
- `application/vnd.qknot.key-revocation+json`

Salts: `qknot-keygen-v1`, `qknot-key-fingerprint-v1`.

The v0.1.1 source tarball and its hybrid signature under `release/` are still
the signed artefact for that version. This tag does not replace them.
