# QResP — Quantum-Resilient Provenance Audit

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Models audited](https://img.shields.io/badge/Repositories%20audited-20%2C000-green.svg)
![PQ-safe](https://img.shields.io/badge/PQ--safe%20repositories-0-red.svg)
![Tests](https://img.shields.io/badge/Tests-833%20passing-brightgreen.svg)
![FIPS 204](https://img.shields.io/badge/FIPS%20204%20ACVP-180%2F180-brightgreen.svg)

> Phase I and II of *Quantum-Resilient Provenance for Machine Learning Supply Chains*
> CS F376 Design Project, BITS Pilani Dubai Campus, 2025–26.
> Supervisor: Dr. Tamizharasan Periyasamy.

> **Working repository, currently private.** Phase I as published (report,
> figures, and the 2026-05-21 dataset) is archived at
> [adityasharma1307/qresp](https://github.com/adityasharma1307/qresp) and is not
> modified. Development continues here.
>
> **Before making this repository public**, read item 0 of
> [`docs/OPEN-QUESTIONS.md`](docs/OPEN-QUESTIONS.md). One file needs a decision
> at that moment, and it is the kind of decision that is easy to miss.

`qresp` does two things. It **audits** the cryptographic provenance of public
machine learning models on HuggingFace, classifying each by quantum
vulnerability; and it **signs** artefacts with a non-separable hybrid signature
that remains compatible with existing OpenSSF Model Signing verifiers.

The audit establishes that the gap is real and near-total. The signing pipeline
is a response to it, and is deliberately independent of both HuggingFace and
machine learning: it signs bytes, and works for anything that needs signing.

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
| **Default suite** | Ed25519 + ML-DSA-44 (ML-DSA-65/87 available) |
| **Digest** | SHA3-256, with SHA-256 alongside for OMS conformance |
| **Format** | OMS v1.0-compatible Sigstore bundle, validated against the published schemas |
| **Entropy** | Sources mixed, never chosen between; quantum origin attested, never assumed |
| **Signed** | DSSE PAE over the whole statement — attestation and metadata included |
| **Conformance** | 180 NIST ACVP FIPS 204 vectors, byte-exact, run offline on every test invocation |

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
protected, stated plainly in both directions, and
[`docs/OPEN-QUESTIONS.md`](docs/OPEN-QUESTIONS.md) for the decisions left
deliberately unmade.

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

> **Windows note:** if `qresp` is not found after install, the Python
> Scripts directory may not be on your PATH. Find it with:
> ```
> python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
> ```
> Then add the printed path to your PATH environment variable.

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
├── docs/               DATASETS.md, RUNBOOK.md, report, figures
└── security/           responsible-disclosure material
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
