# Signed release artifacts

`qresp-0.1.0.tar.gz` is the v0.1.0 source release, built by
`scripts/release/build_sdist.py` (`pyproject.toml`, `README.md`, `LICENSE`,
and `src/` — nothing else). `qresp-0.1.0.bundle.json` is its hybrid
signature, produced by `qresp sign` itself, with a key registered to a real
identity in `registration/bundle.json`.

## Verify the signature

```bash
pip install -e ".[dev]"     # or just `pip install qresp` once published
qresp verify release/qresp-0.1.0.tar.gz \
    --bundle release/qresp-0.1.0.bundle.json \
    --context qresp-release
```

Expect:

```
VERIFIED
  algorithms checked: ['ed25519', 'ml-dsa-87']
  quantum resistant : True
  binding enforced  : True
```

`binding enforced: True` is the property the hybrid design exists for —
neither signature can be stripped without the verifier noticing, unlike a
naive "two signatures side by side" scheme where deleting one JSON field
silently downgrades to classical-only.

## Verify who signed it

This release's signing key is registered against a real identity, logged to
a public transparency log (Rekor). A trust store first, then the attributed
verification:

```bash
qresp trust-material --out ./trust
qresp verify release/qresp-0.1.0.tar.gz \
    --bundle release/qresp-0.1.0.bundle.json --context qresp-release \
    --registration release/registration/bundle.json \
    --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub \
    --check-revocations
```

Expect:

```
VERIFIED AND ATTRIBUTED
  signed by         : aditya.137.sharma@gmail.com (via https://github.com/login/oauth)
  key               : ml-dsa-87, vouched for by that identity
  basis             : direct
  registered by     : 2026-08-02T17:49:19+00:00 (the log's integratedTime)
  mode              : strict
  algorithms checked: ['ed25519', 'ml-dsa-87']
  quantum resistant : True
```

Two lines in the real output are worth explaining rather than mistaking for
failures:

- `covers this sig: not checked` — this release was signed with `--seed`
  (needed to make the key registerable; see below), which currently skips
  the NIST-beacon time evidence `qresp sign` can otherwise attach. Without
  that evidence the tool has no trustworthy signing time to check the
  registration's upper bound against, so it says so rather than guessing.
- `revocations: NOT ESTABLISHED` — `qresp`'s revocation search only trusts a
  log entry it can authenticate as an actual revocation statement, and no
  published revocation-statement feed exists yet for any identity. Until one
  does, `--check-revocations` will honestly report "cannot establish" rather
  than an unearned "clean" for any release, not just this one.

Neither is a defect in this artifact; both are the tool declining to claim
more certainty than it has.

## What this proves

**The signature:** the exact bytes in `qresp-0.1.0.tar.gz` are what was
signed, non-separably bound to both a classical (Ed25519) and a
post-quantum (ML-DSA-87) signature. Tampering with the tarball — even by one
byte — fails verification (`VERIFICATION FAILED: artefact digest does not
match`).

**The identity:** the ML-DSA-87 key that produced this signature is the same
key registered in `registration/bundle.json` against
`aditya.137.sharma@gmail.com` via GitHub OIDC, logged to Rekor at
`2026-08-02T17:49:19+00:00`. `docs/REGISTRATION-SPEC.md` and the main
README's "Identity & attribution" section describe that mechanism in full.

## Completing the cycle: signature + transparency log + identity

`sign` and `register` are independent commands, and by default each
generates its own throwaway key — so a plain `qresp sign` and a plain
`qresp register` never refer to the same key unless you make them.
`scripts/release/derive_keypair.py` closes that gap: given a seed, it writes
the exact same raw keypair `sign --seed <hex>` derives internally, in the
file shape `register --pqc-public-key/--pqc-secret-key` reads. This is the
recipe v0.1.0 itself went through, and the one to repeat for any future
release:

```bash
# 1. A secret seed -- this IS the key material, generate and store it like
#    one (a password manager, not a shell history file). Run this on a
#    machine you trust, not a CI runner or a throwaway sandbox.
python -c "import secrets; print(secrets.token_hex(32))"

# 2. Derive the raw keypair once
python scripts/release/derive_keypair.py --seed <hex> --out release/keys

# 3. Sign the release with that exact key
qresp sign release/qresp-0.1.0.tar.gz --seed <hex> \
    --out release/qresp-0.1.0.bundle.json \
    --keys-out release/qresp-0.1.0.keys.json \
    --name qresp-0.1.0 --context qresp-release

# 4. A real trust store, once
qresp trust-material --out ./trust

# 5. Register that SAME key against a real OIDC identity -- logs to Rekor,
#    which is what gives an UPPER bound (a beacon alone only gives a lower
#    bound -- see `qresp verify`'s own "time evidence" line)
qresp register --out release/registration --pqc-algorithm ml-dsa-87 \
    --pqc-public-key release/keys/ml-dsa-87.pub \
    --pqc-secret-key release/keys/ml-dsa-87.key \
    --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub

# 6. The composed verdict: a valid signature, attributable to an identity,
#    with revocation checked live
qresp verify release/qresp-0.1.0.tar.gz \
    --bundle release/qresp-0.1.0.bundle.json --context qresp-release \
    --registration release/registration/bundle.json \
    --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub \
    --check-revocations
```

After step 2, `release/keys/ml-dsa-87.key` and the seed itself are long-term
key material. **Never commit either one.** `.gitignore` refuses
`release/keys/` and any `*.key` file so `git add -A` cannot do it by
accident, but that is a safety net, not a storage plan — move the key
somewhere safe (a password manager, an HSM, anywhere that is not this
working copy) immediately after step 2, and keep the seed nowhere this
repository can see it.

Only `qresp-0.1.0.tar.gz`, `qresp-0.1.0.bundle.json`, `qresp-0.1.0.keys.json`
(public keys), and `registration/bundle.json` (plus the Fulcio/Rekor
material `register` bundled alongside it) are committed here. The raw
secret key, the seed, and `./trust/` (re-fetched by `qresp trust-material`,
not a source artifact) are not.

## Reproducing the build (not the signature)

```bash
python scripts/release/build_sdist.py --version 0.1.0
```

The tarball is not byte-reproducible run to run (tar/gzip embed mtimes), so
a fresh build will not match the committed signature — that is expected and
is exactly why the signed artifact itself, not just the recipe, is committed
here. To re-sign a freshly built tarball, use the `sign` step above with
your own seed; it will not match `qresp-0.1.0.bundle.json` unless it is
built from and signed over the exact committed tarball.
