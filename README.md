# QResP — Quantum-Resilient Provenance Audit

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Models audited](https://img.shields.io/badge/Repositories%20audited-20%2C000-green.svg)
![PQ-safe](https://img.shields.io/badge/PQ--safe%20repositories-0-red.svg)
![Tests](https://img.shields.io/badge/Tests-1261%20passing-brightgreen.svg)
![FIPS 204](https://img.shields.io/badge/FIPS%20204%20ACVP-180%2F180-brightgreen.svg)

> Phase I and II of *Quantum-Resilient Provenance for Machine Learning Supply Chains*
> CS F376 Design Project, BITS Pilani Dubai Campus, 2025–26.
> Supervisor: Dr. Tamizharasan Periyasamy.

## Status

Phase I (the audit) and Phase II (hybrid signing and PQC identity
registration) are both implemented and tested against production
infrastructure where it matters, not only simulated: the Sigstore /
Fulcio / Rekor chain, an end-to-end key registration, and the live revocation
search have each been run against real Sigstore and locked with a passing
test. 1261 tests pass offline; 57 more are skipped by default because they
need network access or a captured fixture (see
[`docs/RUNBOOK.md`](docs/RUNBOOK.md)). What is and is not protected is stated
plainly, in both directions, in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

Phase I as originally submitted (report, figures, and the 2026-05-21 dataset)
is archived unmodified at
[adityasharma1307/qresp](https://github.com/adityasharma1307/qresp); this
repository is where development continues, and has grown past a single
semester's scope.

`qresp` does three things. It **audits** the cryptographic provenance of
public packages — currently HuggingFace, npm and PyPI — classifying each by
quantum vulnerability; it **signs** artefacts with a non-separable hybrid
signature that remains compatible with existing OpenSSF Model Signing
verifiers; and it **registers** a post-quantum key against your existing
(classical) OIDC identity, so a signature made today stays attributable after
classical algorithms are broken.

The audit establishes that the gap is real and near-total. Signing and
registration are the response to it, and are deliberately independent of both
HuggingFace and machine learning: they operate on bytes and identities, and
work for anything that needs signing — firmware, datasets, documents,
container images.

The accompanying end-semester report is available in [`docs/report.pdf`](docs/report.pdf).

---

## Key findings

### The 20,000-repository stratified audit (2026-07-25)

The registry is too skewed to sample uniformly and too large to enumerate, so
the audit uses two strata: a **census** of the 10,000 most-downloaded
repositories, and a **uniform random draw** of 10,000 from the 2,928,107
remaining, seed `20260725`.

| | head (census) | long tail (sample) | ratio | Fisher exact |
|---|---|---|---|---|
| signed | 39 / 10,000 = 0.390% | 10 / 10,000 = 0.100% | 3.9x | p = 3.8e-05 |
| vulnerable | 36 / 10,000 = 0.360% | 10 / 10,000 = 0.100% | 3.6x | p = 1.5e-04 |
| **post-quantum** | **0** | **0** | — | p = 1 |

Weighted to the whole registry: **0.101%** signed [95% CI 0.039%–0.163%], and
**0%** post-quantum with a one-sided upper bound of **0.038%**.

**Not one repository in 20,000 carries a post-quantum signature.** Every
signature found is Shor-breakable: ECDSA P-256 via Sigstore in the head, RSA in
the tail. Popular repositories are ~4x more likely to be signed than obscure
ones, and the difference is significant — but signing anything at all remains a
rounding error, and signing with anything quantum-resistant does not happen.

Reproduce with:

```bash
python -m qresp.audit.stats \
  --head data/head_10k_2026-07-25.jsonl \
  --tail data/longtail_10k_2026-07-25.jsonl \
  --manifest data/longtail_manifest_2026-07-25.json
```

Caveats are carried in the data rather than in prose: 58 tail repositories
vanished between the frame being built and the scan, and 3 gated CohereLabs
repositories could not be read. Both are labelled `error`, never `unsigned` —
absence of evidence is not evidence of absence, and counting them as unsigned
would inflate the very statistic being reported.

HuggingFace is the flagship dataset (it's what the figures and report cover),
but the same zero holds on PyPI and npm too, where signing is far more
common — see [`docs/RESULTS.md`](docs/RESULTS.md) for the full cross-ecosystem
numbers, benchmarks, entropy analysis and correctness evidence in one place.

### The n = 1,000 pilot (2026-05-21 and 2026-07-06)

Two top-1,000 snapshots seven weeks apart both gave 998 unsigned / 2 vulnerable
/ 0 safe. *Which* models were signed changed completely between them, while the
aggregate held — evidence that the near-total absence of signing is a property
of the registry rather than of one snapshot. Superseded in scale by the audit
above; retained because the turnover is itself a finding. See
[`docs/DATASETS.md`](docs/DATASETS.md) for provenance of every dataset.

---

## Signing: the quantum-resilient pipeline

The audit establishes the gap. The `qresp.signing` package is the response: a
**non-separable hybrid signature** that an existing OpenSSF Model Signing
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
| **Entropy** | Sources mixed, never chosen between; quantum origin attested, never assumed |
| **Signed** | DSSE PAE over the whole statement — attestation and metadata included |
| **Conformance** | 180 NIST ACVP FIPS 204 vectors, byte-exact, run offline on every test invocation |

### Identity & attribution: registering a PQC key off classical PKI, durably

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
`openai/privacy-filter` — one of the 39 signed repositories in the head stratum,
currently carrying an ECDSA P-256 Sigstore signature — then attacks the result
seven ways: artefact tampering, unsigned additions to an excluded directory,
signature stripping (with and without rewriting the declared suite), metadata
forgery, verification from 2031, and artefact substitution.

Runs in Colab with no API keys and no hardware; falls back cleanly and says so
when the network is unavailable. Regenerate with
`python scripts/demo/build_notebook.py --run`.

`qresp.signing` imports nothing from `qresp.audit` and knows nothing about
HuggingFace or machine learning. It signs bytes. That boundary is enforced by a
test. See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for what is and is not
protected, stated plainly in both directions.

## What it does

The tool walks the HuggingFace registry, finds signature files attached to
each model (if any), parses them, identifies the underlying signature
algorithm, and tags the model with one of five labels:

| Label | Meaning |
|---|---|
| `safe` | Post-quantum scheme: ML-DSA or SLH-DSA (NIST FIPS 204/205) |
| `vulnerable` | Classical scheme: RSA, ECDSA, Ed25519 — broken by Shor's algorithm |
| `unsigned` | No signature file present |
| `mixed` | Multiple signatures with disagreeing labels |
| `error` | Could not be assessed: unparseable signature, or repository unreachable |

The tool **never downloads model weights**. It checks only for signature
sidecar files (typically kilobytes), so a 1,000-model scan completes in
under 5 seconds and the full 20,000-repository audit in a few hours,
network-bound throughout.

---

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/adityasharma1307/qresp2
cd qresp2
pip install -e .
```

For analysis notebooks:

```bash
pip install -e ".[analysis]"
```

For development (tests, linter):

```bash
pip install -e ".[dev]"
```

For `qresp register` and `qresp trust-material` (OIDC login, the TUF client):

```bash
pip install -e ".[register]"
```

`sign`, `verify` (without `--registration`), and the audit commands need none
of this — `qresp.signing`'s core does not depend on `sigstore` at all.

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
| `qresp entropy` | `--check-revocations` (searches Rekor live) |
| Almost the whole test suite (1261 of 1318 tests) | `qresp scan` / `audit-npm` / `audit-pypi` (query the registries) |
| | The 57 skipped tests, and a handful that need a captured live fixture |

So a fresh clone with no network at all can still sign, verify signatures,
verify a registration you already hold the trust material for, and run
nearly the entire test suite.

---

## Usage

### Run a pilot scan (50 models)

```bash
qresp scan --n 50 --out data/pilot_2026-05-21.jsonl
```

### Run the head census (top 10,000 by downloads)

```bash
qresp scan --n 10000 --out data/head_$(date +%Y-%m-%d).jsonl --token $HF_TOKEN
```

### Run the long-tail sample

The tail is not a top-N slice, so it is drawn first and audited from a fixed id
list. The seed makes the draw reproducible byte for byte:

```bash
python scripts/audit/sample_longtail.py --k 10000 --seed 20260725
qresp scan-ids --ids data/longtail_sample_$(date +%Y-%m-%d).txt \
    --out data/longtail_$(date +%Y-%m-%d).jsonl --token $HF_TOKEN
```

See [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for the full procedure, including what
to do when it stops partway.

### Audit npm and PyPI

The same two-stratum design — a `head` of the most-downloaded packages and a
`tail` sampled at random from the rest, so the result describes the ecosystem
rather than its popular corner:

```bash
qresp audit-pypi --out data/pypi_$(date +%Y-%m-%d).jsonl

# npm publishes no ranking, so both inputs are produced locally first
python scripts/audit/fetch_npm_frame.py --out data/npm_frame.txt
python scripts/audit/rank_npm.py        --out data/npm_ranking.json
qresp audit-npm --ranking data/npm_ranking.json --frame data/npm_frame.txt \
    --out data/npm_$(date +%Y-%m-%d).jsonl
```

Both write a manifest beside the output recording the seed, the frame size and
a digest of the frame, so the sample is re-derivable rather than merely
described. Both resume if interrupted, and rows labelled `error` are retried on
re-run rather than counted — a package that could not be reached was not
checked, and folding those into "unsigned" would inflate the headline rate.

### Sign and verify an artefact

```bash
qresp sign ./my-model --out model.bundle.json --keys-out keys.json
qresp verify ./my-model --bundle model.bundle.json
```

Add `--deterministic` for byte-reproducible signatures. It is off by default:
FIPS 204 hedged signing mixes fresh randomness into every signature as a
defence against fault injection, and that margin is worth more than
reproducibility outside of test vectors and demos.

Resume is on by default — if interrupted, rerun the same command and it
picks up where it left off.

### With a HuggingFace token (higher rate limits)

```bash
qresp scan --n 1000 --out data/full_$(date +%Y-%m-%d).jsonl --token $HF_TOKEN
```

A token is optional for a 1,000-model scan and effectively required beyond
that. Get a free read-only token at https://huggingface.co/settings/tokens.

### Re-audit from scratch (ignore existing output)

```bash
qresp scan --n 1000 --out data/full_2026-07-06.jsonl --no-resume
```

---

## Output format

Each line of the JSONL output is one model record:

```json
{
  "model_id": "ibm-granite/granite-4.1-8b",
  "publisher": "ibm-granite",
  "downloads": 601933,
  "last_modified": "2026-05-04T17:36:29Z",
  "file_count": 16,
  "has_signature": true,
  "candidate_files": ["model.sig"],
  "sig_algorithm": "ecdsa_p256",
  "sig_format": "sigstore",
  "key_size_bits": null,
  "q_label": "vulnerable",
  "audit_ts": "2026-07-06T07:29:41.006257Z",
  "notes": "inferred_from_sigstore_fulcio_default"
}
```

---

## Statistical analysis

Run the included stats script to reproduce the Wilson confidence intervals
and power analysis:

```bash
python -m qresp.audit.stats data/full_2026-07-06.jsonl
```

Expected output:

```
n = 1000
Signed:        2 / 1000  (0.2%)   95% CI: [0.05%, 0.73%]
Unsigned:    998 / 1000  (99.8%)  95% CI: [99.27%, 99.95%]
Vulnerable:    2 / 1000  (0.20%)  95% CI: [0.055%, 0.726%]
PQ-safe:       0 / 1000  (0.0%)   95% CI: [0.00%, 0.38%]

Power analysis: to detect 1% PQ adoption (vs 0%) at 80% power,
minimum sample size needed = 615 models
=> Our n=1000 is sufficient to rule out even 1% PQ adoption.
```

For visualisations, open the analysis notebook:

```bash
jupyter lab notebooks/analysis.ipynb
```

---

## Signature detection coverage

Detection is filename-based (no weights are downloaded) and covers:

| Format | Patterns matched |
|---|---|
| Sigstore | `.sigstore`, `.sigstore.json`, `model.sig`, `signature.json` |
| in-toto | `.intoto.jsonl`, `.in-toto.jsonl`, `attestation.json` |
| GPG / OpenPGP | `.asc`, `.gpg`, `.pgp` |
| Generic | `.sig` (fallback) |

Cosign bundle files (`.cosign.bundle`) are not currently covered but were
not observed in the audited corpus.

---

## Project structure

Two halves, deliberately separable.

```
qresp2/
├── src/qresp/
│   ├── audit/          PHASE I -- surveying one registry
│   │   ├── detect.py       filename-based signature detection
│   │   ├── parse.py        Sigstore / OpenPGP / raw signature parsers
│   │   ├── scanner.py      resumable audit orchestration
│   │   ├── hf_client.py    HuggingFace API with retry and backoff
│   │   ├── model.py        record schema and classification rules
│   │   └── stats.py        Wilson intervals, stratified estimates, Fisher
│   ├── signing/        PHASE II -- signing anything, reusable
│   │   └── entropy/        attested entropy acquisition
│   └── cli.py
├── scripts/
│   ├── audit/          sampling, trimming, relabelling, the 20k runner
│   └── verify/         red team and coverage checks
├── tests/
│   ├── audit/          Phase I
│   ├── signing/        Phase II, including the package-boundary test
│   └── adversarial/    attempts to make the audit lie
├── data/               date-stamped datasets and sampling manifests
├── docs/               DATASETS.md, RUNBOOK.md, REGISTRATION-SPEC.md, report, figures
├── security/           responsible-disclosure material
├── SECURITY.md         how to report a vulnerability in this code
└── CONTRIBUTING.md     how the codebase is organised, and what a PR needs
```

**`qresp.signing` does not import `qresp.audit`, and never will.** The audit
answers a research question about one registry; the signing pipeline is meant
to be usable by anyone who needs post-quantum-ready signatures with honest
provenance -- for firmware, datasets, documents, container images, anything.
`tests/signing/test_package_boundary.py` fails the build if that separation is
broken, and also if `qresp.signing` acquires a dependency on `huggingface_hub`,
`transformers` or `datasets`.


---

## Citing this work

```bibtex
@misc{sharma2026qresp,
  author       = {Sharma, Aditya},
  title        = {{QResP}: Quantum-Resilient Provenance Audit for
                  Machine Learning Supply Chains},
  year         = {2026},
  howpublished = {CS F376 Design Project, BITS Pilani Dubai Campus},
  url          = {https://github.com/adityasharma1307/qresp},
}
```

---

## Licence

This project is released under the [MIT License](LICENSE).
