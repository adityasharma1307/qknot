# QResP — Quantum-Resilient Provenance

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
[![CI](https://github.com/adityasharma1307/qresp/actions/workflows/tests.yml/badge.svg)](https://github.com/adityasharma1307/qresp/actions/workflows/tests.yml)
![Tests](https://img.shields.io/badge/Tests-1261%20passing-brightgreen.svg)
![FIPS 204](https://img.shields.io/badge/FIPS%20204%20ACVP-180%2F180-brightgreen.svg)
![Self-signed release](https://img.shields.io/badge/v0.1.0-self--signed%20hybrid%20PQC-blueviolet.svg)
![PQ-safe found](https://img.shields.io/badge/PQ--safe%20signatures%20found%20in%20audit-0-red.svg)

> Phase I and II of *Quantum-Resilient Provenance for Machine Learning Supply Chains*
> Supervisor: Dr. Tamizharasan Periyasamy.

## Status

`qresp` is a **hybrid post-quantum signing and identity-registration tool**:
it signs artefacts with a non-separable Ed25519 + ML-DSA-87 signature that
existing OpenSSF Model Signing verifiers still accept, and it binds a
post-quantum key to your existing OIDC identity through classical PKI so a
signature made today stays attributable after classical algorithms are
broken. A cross-registry audit (HuggingFace, npm, PyPI — see below) is what
motivated building it: **zero post-quantum signatures found anywhere**,
across three ecosystems and 60,000 sampled artefacts.

Both halves are tested against production infrastructure, not only
simulated: the Sigstore/Fulcio/Rekor chain, an end-to-end key registration,
and the live revocation search have each been run against real Sigstore and
locked with a passing test. 1261 tests pass offline (57 more need network or
a captured fixture — see `CONTRIBUTING.md`). What is and is not protected is
stated plainly, in both directions, in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

**This repository signs its own releases.** v0.1.0's source tarball ships
with a real hybrid signature over its own bytes — see
["This release signs itself"](#this-release-signs-itself) below.

Phase I as originally submitted (report, figures, and the 2026-05-21 dataset)
is archived unmodified at
[adityasharma1307/qresp-pilot](https://github.com/adityasharma1307/qresp-pilot);
this repository is where development continues, and has grown past a single
semester's scope. The accompanying end-semester report is available in
[`docs/report.pdf`](docs/report.pdf).

### Disclaimer (please read)

This is a **student research / Alpha reference** project (CS F376, BITS Pilani
Dubai Campus), not a commercial security product and not professional advice.
The software and materials are provided **AS IS**, without warranty. To the
maximum extent permitted by law, **neither the author (Aditya Sharma), the
supervisor (Dr. Tamizharasan Periyasamy), nor BITS Pilani Dubai Campus** is
liable for damages arising from use of or reliance on this work, including
audit findings and third-party systems measured or discussed here.

Full text: [`DISCLAIMER.md`](DISCLAIMER.md). License: [`LICENSE`](LICENSE) (MIT).

---

## Signing: the quantum-resilient pipeline

**A non-separable hybrid signature** that an existing OpenSSF Model Signing
verifier still accepts.

```bash
qresp sign ./my-model --out model.bundle.json --keys-out keys.json \
    --name my-model --context model-release
qresp verify ./my-model --bundle model.bundle.json --context model-release
```

The design problem is that the obvious hybrid — one classical signature and one
post-quantum signature side by side — is broken by **deleting a JSON field**. A
verifier that checks "every signature present is valid" accepts the remainder,
and the post-quantum protection is gone at no cost to the attacker. So both
algorithms sign a value committing to the *set* of algorithms in use; removing
one leaves the other attesting to its absence.

| | |
|---|---|
| **Default suite** | Ed25519 + ML-DSA-87 (CNSA 2.0; -44/-65 selectable) |
| **Digest** | SHA3-256, with SHA-256 alongside for OMS conformance |
| **Format** | OMS v1.0-compatible Sigstore bundle, validated against the published schemas |
| **Entropy** | Sources mixed, never chosen between; quantum origin attested, never assumed; falls back cleanly when unreachable (demonstrated on this repo's own release, below) |
| **Signed** | DSSE PAE over the whole statement — attestation and metadata included |
| **Conformance** | 180 NIST ACVP FIPS 204 vectors, byte-exact, run offline on every test invocation |

`qresp.signing` imports nothing from `qresp.audit` and knows nothing about
HuggingFace or machine learning. It signs bytes. That boundary is enforced by
a test, and works for anything that needs signing — firmware, datasets,
documents, container images, source releases (including its own — see below).

## Identity & attribution: registering a PQC key off classical PKI, durably

Fulcio will certify a P-256 key against your OIDC identity. It will not certify
an ML-DSA key. So QResP uses the classical certificate **while it is still
valid** to vouch for the post-quantum key, and logs that vouching in
transparency — the log timestamp then proves the binding predates the classical
algorithm's deprecation, so it survives it.

**The full path, end to end:**

```bash
# 0. Get a real trust store, once (or whenever it goes stale)
qresp trust-material --out ./trust

# 1. Register a PQC key against your OIDC identity (opens a browser for
#    the login unless --identity-token or --oauth-force-oob is given)
qresp register --out ./my-registration \
    --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub

# 2. Sign an artefact -- registration is independent of signing
qresp sign ./my-model --out model.bundle.json --context model-release

# 3. Verify BOTH the signature and who it belongs to
qresp verify ./my-model --bundle model.bundle.json --context model-release \
    --registration ./my-registration/bundle.json \
    --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub \
    --check-revocations
```

`register` will not hand back a bundle it cannot itself verify, and
`verify` / `verify-registration` name *how* the key was trusted — `direct`, or
`rescued-by-timestamp` — rather than a bare yes.

**Always pass `--fulcio-roots` and `--log-key`.** Without them, `register`
falls back to trusting whatever certificate chain Fulcio itself handed back in
the moment — that proves internal consistency, not third-party trust — and
`verify --registration` / `verify-registration` refuse to run at all, on
purpose: attribution needs a trust store, and the CLI will not invent one.
`qresp trust-material` pulls a real one from Sigstore's production TUF root
(the same mechanism `sigstore-python` itself uses); see its `--help` for what
it does, and `--staging` if you're testing against Sigstore's staging
instance. Test-only material also exists
(`tests/signing/fixtures/registration/`) but is exactly that — fine for trying
the CLI, not for trusting a real registration.

**OIDC needs a browser** by default (`register`'s step 1 opens one for the
identity login). On a machine with no usable browser — SSH session, container,
CI — pass `--oauth-force-oob` for a URL to open elsewhere and a code to paste
back, or `--identity-token` if you already have a token.

**Revocation search is honest about what it did not check.**
`--check-revocations` searches Rekor live and authenticates every candidate it
finds through the same inclusion-proof/checkpoint/SET path as everything else
— but a Rekor `hashedrekord` entry stores a digest, not a statement, so an
entry whose content cannot be retrieved comes back as `NOT ESTABLISHED`, never
a silent "no revocations". See
[`docs/REGISTRATION-SPEC.md`, section 9.1](docs/REGISTRATION-SPEC.md#91-revocation-search-and-the-limit-it-exposed-2026-08-02)
for the full reasoning and what this feature does and does not prove.

This path is verified against **live Sigstore**, not simulated: a real Fulcio
certificate and a real Rekor entry are captured and run through the full
verification chain, including the temporal rescue at an instant past the
classical disallow date
([`tests/signing/test_registration_fixture.py`](tests/signing/test_registration_fixture.py),
captured by [`scripts/register/capture_registration.py`](scripts/register/capture_registration.py);
the test skips cleanly if you have not captured a fixture), and the revocation
search adapter has separately been run and validated against live Rekor
(`scripts/verify/check_revocation_search.py`) — 5/5 log entries fetched and
authenticated on production data. Design, two rounds of expert review, and the
honest residuals: [`docs/REGISTRATION-SPEC.md`](docs/REGISTRATION-SPEC.md).

## This release signs itself

[`release/qresp-0.1.0.tar.gz`](release/qresp-0.1.0.tar.gz) is the v0.1.0
source release, and [`release/qresp-0.1.0.bundle.json`](release/qresp-0.1.0.bundle.json)
is its own hybrid signature — produced by `qresp sign` against its own
bytes, not a demo artefact:

```bash
qresp verify release/qresp-0.1.0.tar.gz \
    --bundle release/qresp-0.1.0.bundle.json --context qresp-release
```

```
VERIFIED
  algorithms checked: ['ed25519', 'ml-dsa-87']
  quantum resistant : True
  binding enforced  : True
```

This authenticates the artifact — tamper with one byte and verification
fails with a digest mismatch. `sign` and `register` generate independent
throwaway keys by default, so a signature and a registration don't refer to
the same key unless you make them: `scripts/release/derive_keypair.py`
bridges that gap (one seed, fed to both `sign --seed` and `register
--pqc-public-key/--pqc-secret-key`), so a release can carry a signature, a
Rekor transparency-log entry, *and* an identity binding, all for the same
key. See [`release/README.md`](release/README.md) for what each piece does
and does not prove, and the full walkthrough.

### Benchmarks

[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — signing latency, signature sizes,
scaling with artefact size, and the entropy-source analysis.

Two numbers worth knowing, both measured:

**Hashing dominates.** The signature cost is flat at ~19 ms regardless of
artefact size, while the digest grows linearly. At 338 MB/s a 7 GB model takes
21 s to hash against 19 ms to sign — the post-quantum signature is **0.09% of
the total**, and that share *falls* as models grow.

**The Ed25519 half is nearly free.** The hybrid costs 21.2 ms more than Ed25519
alone, but only **0.28 ms more than ML-DSA alone**. Once you are paying for a
post-quantum signature, backward compatibility with every verifier that exists
today costs almost nothing — which is the practical argument for a hybrid over a
straight migration.

### Run it end to end

[`notebooks/qresp_demo.ipynb`](notebooks/qresp_demo.ipynb) signs
`openai/privacy-filter` — one of the signed repositories found in the audit
below, currently carrying an ECDSA P-256 Sigstore signature — then attacks
the result seven ways: artefact tampering, unsigned additions to an excluded
directory, signature stripping (with and without rewriting the declared
suite), metadata forgery, verification from 2031, and artefact substitution.

Runs in Colab with no API keys and no hardware; falls back cleanly and says so
when the network is unavailable. Regenerate with
`python scripts/demo/build_notebook.py --run`.

---

## Why this matters: the audit

Signing and registration are the response to a gap this project measured
directly, across three registries, none of them cherry-picked toward the
result:

| ecosystem | registry size | combined signed | head (top 10k) | tail (random 10k) |
|---|---|---|---|---|
| **HuggingFace** | 2,928,107 | 0.101% [0.039, 0.163] | 0.39% | 0.10% |
| **npm** | 4,290,079 | 3.681% [3.315, 4.046] | 25.40% | 3.63% |
| **PyPI** | 860,900 | 8.907% [8.363, 9.451] | 23.15% | 8.74% |

Same two-stratum design on all three: a **census** of the 10,000
most-downloaded packages/repositories, and a **uniform random draw** of
10,000 from the remainder, so the result describes the ecosystem rather than
its popular corner. **Zero post-quantum signatures in any stratum, of any
ecosystem, out of 60,000 sampled artefacts.** Every signature found is
Shor-breakable — ECDSA P-256 or RSA — and each per-stratum 95% Wilson upper
bound on post-quantum adoption is 0.038%, so the null is not a small-sample
artefact.

npm and PyPI matter to the finding precisely because they remove the obvious
objection to the HuggingFace number: signing there is rare (0.1%–0.4%), which
invites the reply that the post-quantum absence says little if almost nothing
is signed at all. On PyPI and npm, signing is routine — 26–87× more common —
and post-quantum adoption is still exactly zero. **Even where signing is
normal, post-quantum signing does not exist.**

Full per-ecosystem numbers, methodology, caveats (unreadable/deleted
repositories are labelled `error`, never folded into `unsigned`), benchmarks,
entropy analysis and correctness evidence are in one place:
[`docs/RESULTS.md`](docs/RESULTS.md). Dataset provenance for every file in
`data/`: [`docs/DATASETS.md`](docs/DATASETS.md).

The tool itself never downloads model/package weights — it checks only for
signature sidecar files, so a 1,000-repository scan completes in seconds and
the full 20,000-repository HuggingFace audit in a few hours, network-bound
throughout. It tags each artefact `safe` (ML-DSA/SLH-DSA), `vulnerable`
(RSA/ECDSA/Ed25519), `unsigned`, `mixed`, or `error` (could not be assessed —
never counted as unsigned).

---

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/adityasharma1307/qresp
cd qresp
pip install -e .
```

For `qresp register` and `qresp trust-material` (OIDC login, the TUF client):

```bash
pip install -e ".[register]"
```

`sign`, `verify` (without `--registration`), and the audit commands need none
of this — `qresp.signing`'s core does not depend on `sigstore` at all. For
analysis notebooks: `pip install -e ".[analysis]"`. For development (tests,
linter): `pip install -e ".[dev]"` — see `CONTRIBUTING.md`.

> **Windows note:** if `qresp` is not found after install, the Python
> Scripts directory may not be on your PATH. Either add it:
> ```
> python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
> ```
> and put the printed path on your PATH, or skip PATH entirely and always
> invoke the module form, which works regardless:
> ```
> python -m qresp sign ./my-model --out model.bundle.json
> ```

### What needs a network, and what doesn't

| Works fully offline | Needs network (and sometimes a browser) |
|---|---|
| `qresp sign` / `qresp verify` (no `--registration`) | `qresp register` (OIDC login, Fulcio, Rekor) |
| `qresp verify --registration` / `verify-registration`, given a bundle and a trust store you already have | `qresp trust-material` (fetches Sigstore's TUF root) |
| `qresp entropy` (falls back to CSPRNG if unreachable) | `--check-revocations` (searches Rekor live) |
| Almost the whole test suite (1261 of 1318 tests) | `qresp scan` / `audit-npm` / `audit-pypi` (query the registries) |

So a fresh clone with no network at all can still sign, verify signatures,
verify a registration you already hold the trust material for, and run
nearly the entire test suite.

---

## Usage

### Sign and verify an artefact

```bash
qresp sign ./my-model --out model.bundle.json --keys-out keys.json
qresp verify ./my-model --bundle model.bundle.json
```

Add `--deterministic` for byte-reproducible signatures. It is off by default:
FIPS 204 hedged signing mixes fresh randomness into every signature as a
defence against fault injection, and that margin is worth more than
reproducibility outside of test vectors and demos. Resume is on by default
for directories — if interrupted, rerun the same command and it picks up
where it left off.

### Register an identity and verify attribution

See ["Identity & attribution"](#identity--attribution-registering-a-pqc-key-off-classical-pki-durably)
above for the full walkthrough (`trust-material` → `register` → `sign` →
`verify --registration --check-revocations`).

### Audit HuggingFace, npm, or PyPI

Same two-stratum design across all three — a `head` of the most-downloaded
packages and a `tail` sampled at random from the rest:

```bash
# HuggingFace
qresp scan --n 10000 --out data/head_$(date +%Y-%m-%d).jsonl --token $HF_TOKEN
python scripts/audit/sample_longtail.py --k 10000 --seed 20260725
qresp scan-ids --ids data/longtail_sample_$(date +%Y-%m-%d).txt \
    --out data/longtail_$(date +%Y-%m-%d).jsonl --token $HF_TOKEN

# PyPI
qresp audit-pypi --out data/pypi_$(date +%Y-%m-%d).jsonl

# npm -- publishes no ranking, so both inputs are produced locally first
python scripts/audit/fetch_npm_frame.py --out data/npm_frame.txt
python scripts/audit/rank_npm.py        --out data/npm_ranking.json
qresp audit-npm --ranking data/npm_ranking.json --frame data/npm_frame.txt \
    --out data/npm_$(date +%Y-%m-%d).jsonl
```

All three write a manifest beside the output recording the seed, the frame
size and a digest of the frame, so the sample is re-derivable rather than
merely described. All three resume if interrupted, and rows labelled `error`
are retried on re-run rather than counted — a repository/package that could
not be reached was not checked, and folding those into "unsigned" would
inflate the headline rate. A HuggingFace token is optional under 1,000
repositories and effectively required beyond that (free, read-only:
https://huggingface.co/settings/tokens).

Reproduce the published statistics:

```bash
python -m qresp.audit.stats \
  --head data/head_10k_2026-07-25.jsonl \
  --tail data/longtail_10k_2026-07-25.jsonl \
  --manifest data/longtail_manifest_2026-07-25.json
```

Full output format, detection coverage (Sigstore/in-toto/GPG/generic `.sig`),
and worked statistical output are in
[`docs/DATASETS.md`](docs/DATASETS.md) and [`docs/RESULTS.md`](docs/RESULTS.md).

---

## Project structure

Two halves, deliberately separable.

```
qresp/
├── src/qresp/
│   ├── signing/        PHASE II -- signing anything, reusable
│   │   └── entropy/        attested entropy acquisition
│   ├── audit/          PHASE I -- surveying three registries
│   └── cli.py
├── scripts/
│   ├── release/         builds and signs this repository's own releases
│   ├── register/         live-registration capture
│   ├── verify/           red team and live-infrastructure validation
│   └── audit/            sampling, trimming, relabelling, the 20k runner
├── tests/
│   ├── signing/         Phase II, including the package-boundary test
│   ├── audit/           Phase I
│   └── adversarial/     attempts to make the audit lie
├── release/             this project's own signed release artifacts
├── data/                date-stamped datasets and sampling manifests
├── docs/                RESULTS.md, DATASETS.md, REGISTRATION-SPEC.md, THREAT-MODEL.md, report, figures
├── security/            responsible-disclosure material
├── SECURITY.md          how to report a vulnerability in this code
└── CONTRIBUTING.md      how the codebase is organised, and what a PR needs
```

**`qresp.signing` does not import `qresp.audit`, and never will.** The
signing/identity pipeline is meant to be usable by anyone who needs
post-quantum-ready signatures with honest provenance — for firmware,
datasets, documents, container images, anything; the audit answers a
research question about specific registries and is the evidence for why the
signing half exists. `tests/signing/test_package_boundary.py` fails the
build if that separation is broken, and also if `qresp.signing` acquires a
dependency on `huggingface_hub`, `transformers` or `datasets`.

---

## Citing this work

**Living repository** (signing, identity registration, multi-registry results):

```bibtex
@misc{sharma2026qresp,
  author       = {Sharma, Aditya},
  title        = {{QResP}: Quantum-Resilient Provenance for
                  Machine Learning Supply Chains},
  year         = {2026},
  howpublished = {CS F376 Design Project, BITS Pilani Dubai Campus},
  url          = {https://github.com/adityasharma1307/qresp},
  note         = {Supervisor: Dr.\ Tamizharasan Periyasamy},
}
```

**Phase I archive** (frozen report, figures, and the 2026-05-21 pilot dataset;
not modified further):

```bibtex
@misc{sharma2026qresp-pilot,
  author       = {Sharma, Aditya},
  title        = {{QResP} Phase I archive},
  year         = {2026},
  howpublished = {CS F376 Design Project, BITS Pilani Dubai Campus},
  url          = {https://github.com/adityasharma1307/qresp-pilot},
}
```

---

## Licence

This project is released under the [MIT License](LICENSE).
