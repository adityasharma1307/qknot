# Dataset provenance

Every audit output in this directory is named with the date of the HuggingFace
snapshot it was taken against, never a bare `full.jsonl`. This is deliberate.
See "Why the naming convention exists" below.

| File | Snapshot | n | Unsigned | Vulnerable | PQ-safe | Notes populated |
|------|----------|---|----------|------------|---------|-----------------|
| `full_2026-07-06.jsonl` | 2026-07-06 | 1,000 | 998 | 2 | 0 | yes |
| `pilot_2026-05-21.jsonl` | 2026-05-21 | 50 | 50 | 0 | 0 | n/a (no signed models) |
| `sample.jsonl` | 2026-05-20 | 6 | — | — | — | synthetic fixture, not a real scan |

`sample.jsonl` contains hand-built `example/*` records used for demos and
detector smoke-testing. It is not survey data and must not be pooled with the
real scans.

## The two 1,000-model snapshots

There are two distinct top-1,000 audits, seven weeks apart. They are **not**
interchangeable, and only one of them backs the published Phase I report.

**2026-05-21 — the published Phase I dataset.**
Signed models: `ibm-granite/granite-4.0-h-small` and `openai/privacy-filter`.
This is the corpus cited by `docs/report.pdf`, the figures in `docs/`, and the
results table in the README of the original repository. It carries
`"notes": null` on both signed records, because it predates the
note-propagation fix. It is **not stored in this repository** — it lives only in
the git history of <https://github.com/adityasharma1307/qresp>, which is
archived and not to be modified.

**2026-07-06 — the current re-scan (`full_2026-07-06.jsonl`).**
Signed models: `ibm-granite/granite-4.1-8b` and
`ibm-granite/granite-speech-4.1-2b`. Both carry
`"notes": "inferred_from_sigstore_fulcio_default"`, confirming the
note-propagation fix works end to end.

## Why the naming convention exists

The July scan was produced while fixing a `run_audit()` resume bug that had
appended a duplicate copy of every row onto the existing output, corrupting it
to n=2,000 with every label count doubled (see the `resume=False` docstring in
`src/qresp/scanner.py` and the defensive dedupe in `stats.py`). Re-running the
scan was the correct fix for the duplication. The side effect was that it hit a
live registry seven weeks later and silently replaced the published dataset at
the same filename.

Because the headline split happened to come out identical — 998 / 2 / 0 in both
snapshots — nothing looked wrong. The corpus had in fact turned over
substantially: `granite-4.0-h-small` and `openai/privacy-filter` both fell out
of the top 1,000, and by July there were **zero `openai/*` models in the
corpus at all**. Two different IBM Granite models had entered, also Sigstore
signed. Matching aggregate counts concealed a different underlying sample.

Two rules follow, and they are not optional:

1. **Date-stamp every audit output.** A scan is a measurement of a registry at
   an instant. A filename that omits the instant is not reproducible.
2. **Never re-run a scan onto the path of a published dataset.** Frozen results
   are append-only. A re-scan is a new observation, not a correction.

## Longitudinal note

Treated properly, the two snapshots are an asset rather than an accident. The
May-to-July turnover in which models are signed at all — while the aggregate
signing rate stayed pinned at 0.2% — is direct evidence that the near-total
absence of signing is a stable property of the registry and not an artefact of
one snapshot. Worth a sentence in the methods section when the report is
rewritten.
