# Signed release artifacts

`qresp-0.1.0.tar.gz` is the v0.1.0 source release, built by
`scripts/release/build_sdist.py` (`pyproject.toml`, `README.md`, `LICENSE`,
and `src/` — nothing else). `qresp-0.1.0.bundle.json` is its hybrid
signature, produced by `qresp sign` itself. `qresp-0.1.0.keys.json` is the
matching public keys.

Verify it with the tool this repository ships:

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

## What this does and does not prove

**Proves:** the exact bytes in `qresp-0.1.0.tar.gz` are what was signed, and
the signature has both a classical (Ed25519) and a post-quantum (ML-DSA-87)
component, non-separably. Tampering with the tarball — even by one byte —
fails verification (`VERIFICATION FAILED: artefact digest does not match`).

**Does not (yet) prove:** *who* signed it. This signature was produced with a
freshly generated, ephemeral keypair — deliberately not written to disk
(`qresp sign` never persists a secret key unless you pass `--seed`), so there
is no long-term key here to misuse or leak. It authenticates the artifact,
not the identity behind it.

Binding a release key to a real identity is a separate mechanism —
`qresp register` — that needs a live OIDC login and therefore has to be run
by a maintainer directly, not from an automated build. See the "Identity &
attribution" section of the main README and `docs/REGISTRATION-SPEC.md` for
that path. Future releases may carry both: this artifact signature, plus a
registration binding the signing key to `adityasharma1307`'s identity.

## Reproducing

```bash
python scripts/release/build_sdist.py --version 0.1.0
qresp sign release/qresp-0.1.0.tar.gz \
    --out release/qresp-0.1.0.bundle.json \
    --keys-out release/qresp-0.1.0.keys.json \
    --name qresp-0.1.0 --context qresp-release
```

The tarball is not byte-reproducible run to run (tar/gzip embed mtimes), so
a fresh build will not match the committed signature — that is expected and
is exactly why the signed artifact itself, not just the recipe, is committed
here.
