# Dataset provenance

## Unit of analysis: the repository

**One row is one HuggingFace repository, not one model artefact.** A repo counts
as signed if it contains at least one recognised signature file anywhere in its
file tree.

This needs stating because the two are not the same thing, and the difference is
large in exactly the cases that matter most:

| Repo | Signature files | Counts as |
|---|---|---|
| `ibm-granite/granite-4.1-8b` | 1 (`model.sig`) | 1 signed repo |
| `kernels-community/relu` | 38 (`.sigstore`, one per compiled build target) | 1 signed repo |
| `ibm-granite/granitelib-rag-r1.0` | 33 (`model.sig`, one per LoRA adapter) | 1 signed repo |

Counting artefacts instead would report 39 signed repos as roughly 150 signed
objects and would make signing adoption look several times healthier than it is,
driven entirely by two publishers who happen to ship many build variants per
repo. The repo is also the unit a person actually chooses when they run
`from_pretrained`, and therefore the unit at which a supply-chain compromise
would reach them.

The cost of this choice is that a repo containing one signed artefact among
fifty unsigned ones is recorded as signed. No repo in the head stratum has that
shape, but the tail stratum has not been examined for it yet, and it should be
checked before the figure goes in the paper.

The download counts used for ranking are likewise per repo, so the head stratum
is internally consistent: top 10,000 repos by repo downloads.

Every audit output in this directory is named with the date of the HuggingFace
snapshot it was taken against, never a bare `full.jsonl`. This is deliberate.
See "Why the naming convention exists" below.

| File | Snapshot | n | Unsigned | Vulnerable | Error | PQ-safe | Notes populated |
|------|----------|---|----------|------------|-------|---------|-----------------|
| `head_10k_2026-07-25.jsonl` | 2026-07-25 | 10,000 | 9,961 | 36 | 3 | 0 | yes |
| `longtail_10k_2026-07-25.jsonl` | 2026-07-25 | 10,000 | 9,932 | 10 | 58 | 0 | yes |
| `full_2026-07-06.jsonl` | 2026-07-06 | 1,000 | 998 | 2 | 0 | 0 | yes |
| `pilot_2026-05-21.jsonl` | 2026-05-21 | 50 | 50 | 0 | 0 | 0 | n/a (no signed repos) |
| `sample.jsonl` | 2026-05-20 | 6 | — | — | — | — | synthetic fixture, not a real scan |

## Head stratum (`head_10k_2026-07-25.jsonl`)

Stratum A of the two-stratum design: the top 10,000 repos by all-time downloads,
audited as a census. 39 signed repos, 0.390%.

**The finding is concentration, not scarcity.** Signing is six organisations:

| Publisher | Signed repos |
|---|---|
| `ibm-granite` | 27 |
| `CohereLabs` | 5 |
| `kernels-community` | 4 |
| `openai` | 1 |
| `UmeAiRT` | 1 |
| `unsloth` | 1 |

IBM is 69% of all signing in the top 10,000, and `unsloth/granite-4.1-8b` is a
re-upload of an IBM model, so the concentration is higher still than the table
suggests. Adoption is not diffuse and rare; it is a handful of vendors with a
policy and effectively nobody else.

**Three repos could not be classified.** All three are gated `CohereLabs` repos
returning HTTP 401 for their signature files. So 39 repos are signed and 36 are
classifiable. (`UmeAiRT/ComfyUI-Auto-Installer-Assets` was a fourth until the
OpenPGP parser was corrected; it now resolves to `ecdsa_other` from its 64-byte
headerless signature.) See the sensitivity analysis below for why the three
remaining do not affect any conclusion.

**Trimmed from 10,002 rows.** The scan was run twice and `resume=True` added two
repos that had climbed into the top 10,000 between runs, making the output a
union of two snapshots rather than one census. `scripts/audit/trim_head_stratum.py`
restored the definition by keeping the top 10,000 by downloads with model_id as
a deterministic tiebreak. The two dropped repos
(`shieldstar/Qwen3.5-122B-A10B-int4-AutoRound-EC`, ranked 10,001 with 5,268
downloads, and `allenai/Llama-3.1-Tulu-3-8B-DPO`, ranked 10,002 with 5,266) were
both unsigned, so the headline count is unchanged. The untrimmed output is
preserved as `head_10k_2026-07-25.raw.jsonl`.

This is the same download-sort instability documented in
`scripts/audit/sample_longtail.py`: membership of "the top 10,000" is only well
defined at an instant, because download counts change continuously. It is why
the long-tail frame is enumerated by `createdAt` instead.

**Two repositories belong to neither stratum, and the paper should say so.**
The long-tail frame was built by excluding the head snapshot *as it then stood*
— 10,002 repositories — and the head was trimmed to 10,000 afterwards. The two
trimmed rows were therefore removed from the head without being returned to the
frame:

```
enumerated population   2,938,109
  head stratum             10,000
  long-tail frame       2,928,107
  ------------------------------
  unaccounted                   2
```

They are the two named above: ranks 10,001 and 10,002 by downloads, both
`unsigned`. The effect on every reported figure is nil — 2 / 2,938,109 is
0.00007%, and both would have been counted as unsigned in either stratum — but
the strata are stated as a partition of the registry, and for those two
repositories that statement is false. `scripts/verify/redteam_check.py` emits
this as a standing warning rather than letting it pass silently, and the
population `N` used by `stats.py` is the union of the strata (2,938,107), not
the enumerated count, so no estimate is computed over a denominator that
includes repositories nothing sampled.

Correcting it properly would mean rebuilding the frame and redrawing the
sample, which would change the realised draw for a change of two rows in three
million. Documenting it is the better trade.

## The manifest digests were recorded over CRLF (2026-07-26)

`longtail_manifest_2026-07-25.json` records SHA-256 digests of the sampling
frame and the drawn sample. Those digests were computed on Windows, over bytes
with **CRLF** line endings. Git stores the files with **LF**.

The consequence went unnoticed for a day: **every clone of this repository
failed the sample-digest check**, including on the machine that produced it,
because the working copy and the committed copy disagreed about newlines. A
verification step that fails for everyone is worse than no verification step —
it trains you to skip the one check that would catch real tampering.

`scripts/verify/redteam_check.py` now compares content under both newline
conventions and reports which matched:

```
[PASS] sample file matches manifest sha256
       sample: content matches; digest was recorded over CRLF line endings
```

This is not a weakening. The frame and sample are newline-delimited lists of
model ids; the ids are the draw, and the newline convention is a property of the
filesystem that wrote them. Altering any id changes the digest under both
conventions — verified by swapping a single id, which still fails.

A `.gitattributes` now pins line endings per file type, so the churn does not
recur. That matters beyond tidiness: a spurious full-file diff drags every line
back through GitHub's secret scanning, and these datasets legitimately contain
repository *names* shaped like credentials.

## Provenance backfill (2026-07-26)

Nine tail rows carried a resolved `sig_algorithm` and no note, because they
were scanned before the parsers emitted positive provenance
(`parsed_from_openpgp_packet`). They were re-scanned with
`scripts/audit/rescan_silent_rows.py` and the notes written back:

```
parsed_from_openpgp_packet: v4, pubkey_algo=1, hash_algo=10 (x2)
    [provenance backfilled 2026-07-26]
```

Per RFC 9580 §9.1, public-key algorithm `1` is RSA, which **confirms the
published `rsa_other` classification independently** rather than merely
annotating it. Hash algorithm `10` is SHA-512. The `(x2)` records that each
repository carries two signature files agreeing with each other.

**No label changed on any row.** Only the `notes` field was written; the label,
the algorithm and `audit_ts` are untouched, because the scan that produced them
happened on 25 July — what is new is the annotation, not the finding. Each
backfilled note says so in the data itself, so the dataset stays
self-describing. A pre-backfill copy is written to
`longtail_10k_2026-07-25.prebackfill-2026-07-26.jsonl` for anyone working
outside git; it is gitignored, because git already preserves the prior state:

```
git show c2035ba:data/longtail_10k_2026-07-25.jsonl
```

All aggregate statistics are byte-identical before and after.

### The three gated repositories were re-checked and remain unreadable

`CohereLabs/{command-a-vision-07-2025, aya-vision-8b, c4ai-command-r7b-12-2024}`
returned HTTP 401 again on 2026-07-26. They carry a signature file whose
algorithm cannot be determined, so they are counted as **signed** with an
unknown algorithm — never as unsigned, and never as evidence for or against
post-quantum adoption.

One caveat about this specific re-check, recorded because it bounds what may be
claimed: **the run was unauthenticated** (the HF client warned as much). An
unauthenticated 401 cannot distinguish "the repository is gated" from "no token
was presented". The gating is independently evident from HuggingFace's own
error text, which names the restriction explicitly, but a stronger claim —
"inaccessible even to an authenticated researcher" — would need an
authenticated attempt, and would then hold only for that token's access level.

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
the git history of <https://github.com/adityasharma1307/qknot-pilot>, which is
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
`src/qknot/audit/scanner.py` and the defensive dedupe in `stats.py`). Re-running the
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

---

## Long-tail stratum (`longtail_10k_2026-07-25.jsonl`)

Stratum B: 10,000 repos drawn uniformly at random from the 2,928,107 outside
the head, a sampling fraction of 0.341%. Seed 20260725, recorded with the frame
SHA-256 in `longtail_manifest_2026-07-25.json`.

10 signed repos, 0.100%. Nine are `Thireus` GGUF quantisations signed with
OpenPGP v4 RSA over SHA-512; one is `NbAiLab/borealis-270m-gguf`, headerless
RSA-4096 alongside an X.509 chain. As in the head, signing is a handful of
parties: the tail's ten come from **two** publishers.

58 repos could not be retrieved at scan time (deleted, renamed or gated between
the frame being built and the audit running). They are labelled `error`, not
`unsigned` -- see the note on coverage loss below.

### The head-versus-tail contrast

| | head | tail | ratio | Fisher exact |
|---|---|---|---|---|
| signed | 39 / 10,000 = 0.390% | 10 / 10,000 = 0.100% | 3.9x | p = 3.8e-05 |
| vulnerable | 36 / 10,000 = 0.360% | 10 / 10,000 = 0.100% | 3.6x | p = 1.5e-04 |
| post-quantum | 0 / 10,000 | 0 / 10,000 | n/a | p = 1 |

Popular models are roughly four times more likely to be signed than a randomly
drawn one, and **nothing in either stratum is post-quantum safe**. The null
result holds across a uniform draw from the whole registry, so it is not an
artefact of looking only at popular models.

### Coverage loss is not a finding about signing

`error` covers two situations that must never be pooled:

* **unparseable** -- the repo IS signed, but the algorithm could not be
  determined. Counts inside the signed subtotal.
* **unavailable** -- the repo could not be retrieved at all. Neither signed nor
  unsigned, because its files were never observed.

Labelling an unretrievable repo `unsigned` would convert absence of evidence
into evidence of absence, in the direction of this project's own conclusion.
`stats.py` reports the two separately and asserts
`signed + unsigned + unavailable = n`.

### Sensitivity to the three unclassified repos

Three gated `CohereLabs` repos return HTTP 401 for their signature files. Their
sibling repos, using the identical `signatures/<name>.sig` convention, parse as
Sigstore ECDSA P-256, and their file sizes (14-25 KB, scaling with repo file
count) are consistent with Sigstore bundles. That is publisher-convention
inference stacked on the Fulcio-convention inference already acknowledged in
Section 4.3, so they are left unclassified rather than guessed.

It does not matter. Every conclusion survives every treatment:

| Treatment | vulnerable (head) | Fisher p | PQ-safe (head) |
|---|---|---|---|
| unclassified (as published) | 36 / 10,000 = 0.360% | 1.5e-04 | 0 |
| vulnerable by convention | 39 / 10,000 = 0.390% | 3.8e-05 | 0 |
| **all three post-quantum** (worst case) | 36 / 10,000 = 0.360% | 1.5e-04 | 3 / 10,000, CI <= 0.088% |

The signed-rate contrast is identical in all three, because the repos are
already counted as signed and only their algorithm is open. Even under the most
hostile reading -- all three being ML-DSA -- post-quantum adoption in the head
would be 0.030% with an upper bound of 0.088%, and the tail would still be zero.

### Gated repos are not publicly auditable

That three signed repos cannot be verified by an unprivileged auditor is a
result in its own right. Signature provenance is not publicly checkable for
part of the registry, which limits what any third-party cryptographic-agility
inventory can establish.

---

## The sampling frame is not in this repository

`longtail_frame_2026-07-25.txt` is 108 MiB, above GitHub's 100 MiB hard limit,
and is therefore gitignored along with its `.partial` and `.cursor` checkpoints.

Nothing verifiable is lost. The frame is derived data, and
`longtail_manifest_2026-07-25.json` records its SHA-256
(`548a60fe...5eddb93`) along with the seed and the exact procedure. A reviewer
rebuilds it and checks the hash:

```
python scripts/audit/sample_longtail.py --seed 20260725 --head-ids data/head_10k_2026-07-25.jsonl
sha256sum data/longtail_frame_<date>.txt   # must match frame_sha256
```

Re-enumeration will not reproduce the frame byte for byte at a later date,
because the registry grows -- but the *published* frame's hash is fixed, and
`scripts/verify/redteam_check.py` re-derives the published sample from it and confirms
the seed regenerates the draw exactly.

If the frame must be archived, gzip brings it to roughly 30 MiB, under the hard
limit though still over the 50 MiB warning threshold. Zenodo or a release asset
is the better home for it.

---

## Verification

`scripts/verify/redteam_check.py` re-checks every claim above: sample integrity,
manifest hashes, seed reproducibility, the label partition, and that no
resolved algorithm lacks a provenance note. Run it before quoting any figure.

## Entropy samples (`data/entropy/`)

Three 125,000-byte samples analysed in [`BENCHMARKS.md`](BENCHMARKS.md) §5,
committed so the analysis can be re-run over the same input. Each `.bin` has a
`.json` manifest recording a SHA-256 of the sample, the collection window and
the request count.

Only the **beacon** sample is verifiable by a third party: its manifest records
every pulse index and `output_value`, so anyone can re-request those pulses
from NIST and confirm the bytes were not fabricated. The ANU sample carries no
such record, and `os.urandom` is by nature local. This is stated wherever the
samples are discussed because a reader is otherwise entitled to assume all
three are equally checkable.

`*.bin` is marked `binary` in `.gitattributes`. Git's heuristic would almost
certainly classify random data as binary anyway, but "almost certainly" is the
wrong standard for a file whose whole purpose is to hash to a recorded value —
a single CRLF translation on checkout would break the digest silently. The
round-trip through the object store was verified byte-identical for all three.

**No API key appears in any manifest.** The ANU key is read from `ANU_API_KEY`
or `--anu-key` and never written to disk. If you re-collect, keep it that way.

**These are samples, not a source of randomness.** Nothing in `qknot` reads
them; they exist to be analysed, and they are public, recorded, and stale.
Using them as key material would be catastrophic, which is the only reason this
sentence is here.

---

# Multi-ecosystem extension: PyPI and npm

**Written before any collection ran.** The decisions below fix the methodology
in advance so that a result cannot be arrived at by choosing definitions after
seeing the data.

## Unit of analysis: per-project, any release ever attested

**DECIDED. A project counts as attested if ANY release of it has ever carried
an attestation.** Not the latest release.

Three reasons, in order of weight:

1. **Comparability.** The HuggingFace study counts repositories, not files or
   revisions. Counting npm/PyPI per-release would measure a different quantity
   in each ecosystem and make the cross-ecosystem comparison — the entire point
   of running this — meaningless.
2. **npm's `latest` tag is mutable; PyPI's is not.** A per-latest-release
   definition would silently mean different things on the two hubs, and the
   difference would show up as an ecosystem effect that is really a definitional
   artefact.
3. **It measures adoption, not recency.** A project that attested every release
   through 2025 and has not shipped since is a project that adopted signing. A
   per-latest-release count would record it as unsigned, conflating "never
   adopted" with "not released lately" — the same conflation between *absent*
   and *unchecked* this project keeps refusing to make elsewhere.

The cost is stated too: per-project **overstates current practice**. A project
that attested once in 2023 and stopped counts as attested. Where that matters,
report the per-release figure alongside rather than switching definitions.

## Why not BigQuery

The task memo specified `bigquery-public-data.pypi.file_downloads`. That is not
used, and the substitute is better on three counts rather than merely cheaper:

- It needs no GCP project, no billing, and cannot run up a bill on a
  mis-scoped query over a very large table.
- The published ranking is a **dated artefact** that can be archived beside the
  scan. Re-running a BigQuery query later gives different numbers, because the
  underlying table advances; a reader could never reproduce the exact head
  stratum. A committed JSON they can.
- It removes a dependency on credentials nobody on this project has.

The cost is a dependency on a third party's query rather than our own. That is
recorded in the provenance, and the query they run is published.

## Population and strata

| | HuggingFace (done) | PyPI (planned) | npm (planned) |
|---|---|---|---|
| frame | HF API enumeration | `pypi.org/simple/` full index | CouchDB `_all_docs` |
| head | top 10,000 by downloads | top 10,000 from published ranking | **see open question** |
| tail | 10,000 random from remainder | 10,000 random from remainder | 10,000 random from remainder |
| attestation check | signature files in repo | PyPI Integrity API | npm registry metadata |

Sampling seed, frame digest and cursor are recorded exactly as for the
HuggingFace long tail, so the sample is re-derivable.

## npm: what is settled, and what is not

Probed 2026-07-30 against the live registry. Most of the plan's unknowns turned
out to be answerable without asking anyone.

### Settled — npm mirrors PyPI more closely than expected

**Attestation presence is one request per package.** The abbreviated packument
(`Accept: application/vnd.npm.install-v1+json`) returns every version with a
`dist.attestations` field present or absent. Same shape as PyPI's Simple API,
same cost — one request, not one per version.

    sigstore         40 versions, 32 attested,  ~65 KB
    @sigstore/sign   17 versions, 17 attested,  ~18 KB
    express         288 versions,  0 attested, ~353 KB

**Scoped packages work** with `%2f` encoding, in both the packument and the
attestation URL.

**The algorithm can be read off the certificate, exactly as on PyPI.** Fetching
`/-/npm/v1/attestations/{pkg}@{version}` returns *two* attestations:

| predicateType | verification material |
|---|---|
| `github.com/npm/attestation/.../publish/v0.1` | `publicKey` — npm's own registry key, by reference |
| `slsa.dev/provenance/v1` | `certificate` — a **Fulcio** cert |

The SLSA one carries a real certificate: **ECDSA P-256**, with the signer
identity in the SAN
(`https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main`).
So `key_algorithm_of_certificate` applies unchanged, and npm records can use the
same `SigAlgorithm`/`QLabel` vocabulary as the other two ecosystems.

Note the npm *publish* attestation references a key by ID rather than embedding
a certificate. It must be classified separately or excluded deliberately —
silently ignoring it would undercount, and silently folding it into the
provenance figure would double-count.

### Head stratum: DECIDED (2026-07-30) — two-stage

**Stage 1** produces a candidate pool from any popularity-ish source.
**Stage 2** (`scripts/audit/rank_npm.py`) measures *real* last-month downloads
over that pool — bulk for unscoped names, individually for scoped ones — and
ranks by the measured counts.

This preserves download-ranking across all three ecosystems, so head-vs-tail
ratios remain comparable.

#### The obstacle is scoping, not volume

An earlier estimate here said ranking the full frame would take "hours of
polling". Recomputed at the rate this project actually sustains (~20 req/s on
the PyPI scan): 3.5M ÷ 128 per bulk request ≈ 27,000 requests ≈ **23 minutes**.
Volume was never the problem.

The real obstacle is that npm's bulk endpoint **rejects scoped packages**, and
`@babel/*`, `@types/*` and similar are a large share of the most popular names.
Ranking only what the bulk endpoint accepts would bias the head towards
unscoped packages rather than towards popular ones — so scoped names are
queried individually, which is what makes a bounded candidate pool worth
having.

#### What stage 1 must and must not do

It does **not** need to rank well; stage 2 does the ranking. It only has to
avoid *losing* genuinely popular packages, so it should err large — a 50,000
pool for a 10,000 head leaves substantial slack.

**Residual caveat, one sentence for the paper:** a package with very high
downloads and near-zero presence in the candidate source would be missed. That
is an edge case, not a systematic bias — which is exactly what distinguishes
this from ranking a random subsample, where a 2.9% sample would have missed
~97% of the true top 10,000 because sampling probability is independent of
popularity.

#### Unmeasured candidates are excluded, not ranked last

A package the downloads API declines to answer for has **no** count, which is
not a count of zero. Sorting it to the bottom would turn a collection failure
into a claim about its popularity. `rank_npm.py` excludes them and reports how
many.

### Frame enumeration: SOLVED, and better than planned

`replicate.npmjs.com/_all_docs` returns **HTTP 400** — npm has restricted the
public CouchDB replication endpoint. Paging it is no longer possible at any
`limit`.

The replacement is stronger on the axis that matters here. The npm package
`all-the-package-names` publishes the full namespace as `names.json`, and a
**pinned version is a dated artefact** — fix the version and the exact frame is
reproducible indefinitely. `_all_docs` could never offer that: the namespace
advances between requests, so two people paging it obtain two different frames
and neither can reconstruct the other's.

Measured 2026-07-30, version 2.0.2517:

    4,290,079 names, 26 MB, ONE request, 11 seconds
    1,603,659 scoped (37.4%)

### The scoped fraction forces one more decision

npm's bulk downloads endpoint rejects scoped packages, and **37.4% of the
namespace is scoped**. Individually querying 1.6M scoped names at the ~20 req/s
this project sustains would take about 22 hours, which is not a reasonable load
to place on a free service for a stratification detail.

Ranking all *unscoped* names is by contrast cheap: 2.69M ÷ 128 ≈ 21,000 bulk
requests, roughly 18 minutes.

That leaves two self-consistent designs, and one inconsistent one to avoid:

| design | property |
|---|---|
| **A. unscoped-only population** — exclude scoped from *both* strata, define the study as covering npm's unscoped packages (62.6% of the namespace) | symmetric, needs no third party, fully reproducible; narrows the claim |
| **B. candidate pool** — a popularity-ish source supplies ~50k names *including* scoped ones, then stage 2 ranks them by measured downloads | covers the whole namespace; depends on an external candidate source |
| ~~C. head excludes scoped, tail includes them~~ | **rejected**: the strata would differ in composition as well as popularity, so any head/tail contrast would confound the two |

Design C is the trap worth naming, because it is what happens by default if the
bulk endpoint's limitation is worked around without noticing that it applies to
only one stratum.


## npm ranking, first run: a failure worth recording (2026-07-30)

The first execution of `rank_npm.py` measured **7,139 of 50,104 candidates**
and produced a file that looked like a clean ranking. It was not one.

`api.npmjs.org` rate-limits far more aggressively than `registry.npmjs.org`,
and began returning HTTP 429 at roughly batch 49 of 239. The script had no
throttle, no retry, and recorded each failed batch as unmeasured on the first
error.

**The damage was not the volume lost. It was that the losses correlated with
sort order.** The candidate pool is alphabetically sorted, so the batches that
completed before the rate limit engaged were the early-alphabet ones:

| first letter of measured name | count |
|---|---|
| c | 2,620 |
| a | 1,828 |
| b | 1,601 |
| everything else | 1,090 |

84% of survivors began with a, b or c. Scoped packages fared worse still: 228
measured out of 19,527, because each is an individual request and nearly all of
them fell after the limit engaged.

An incomplete ranking is merely weak. **A ranking whose losses track the sort
order is worse than a random subsample**, because the bias is invisible in the
output — the artefact reads as a legitimate top-7,139 and nothing in it says
"this is the top of the alphabet, not the top of npm." The top-20 confirms it:
`balanced-match`, `ignore`, `argparse`, `braces`, `cookie` — plausible-looking,
but with `semver`, `debug`, `chalk`, `tslib` and every `@types/*` absent.

### Fixes

1. **`single_downloads` now raises instead of returning `None`.** Swallowing
   `NpmError` made a throttled request indistinguishable from a package with no
   download data — the absent-versus-unchecked distinction, violated inside the
   client itself.
2. **Throttle** to a fixed shared rate (default 4 req/s) rather than firing as
   fast as the pool allows.
3. **Retry with exponential backoff**, so a 429 delays a batch rather than
   destroying it.
4. **Persist partial counts after every batch**, so a run resumes.
5. **Abort rather than write** when the measured fraction falls below 80%. The
   previous run's most dangerous property was that it produced a usable-looking
   file; the collector now refuses to.

The scan itself (`run_npm_audit.py`) behaved correctly throughout — 17,030
packages at 15–20/s, 134 recorded as `error` rather than `unsigned`. Only the
head stratum's *membership* was wrong, and it must be re-derived and re-scanned
into a fresh output file, because head/tail labels were assigned from the
broken ranking.

## npm unscoped ranking: complete and verified (2026-08-01)

**2,656,176 packages ranked by measured last-month downloads**, exhaustively over
every unscoped name in the pinned frame. No candidate pool, no sampling, no
proxy — `rank_npm.py --frame` queried npm's bulk downloads endpoint for all
2,686,420 unscoped names; the remaining 30,244 were answered "no download
record" and are excluded from the ranking rather than ranked last.

### Distribution

| rank | downloads/month |
|---|---|
| 1 (`semver`) | 3,407,401,012 |
| 100 | 748,069,027 |
| 1,000 | 151,675,806 |
| 5,000 | 5,783,091 |
| **10,000** | **869,769** |
| 50,000 | 9,822 |
| 100,000 | 1,741 |

**The head stratum threshold is 869,769 downloads/month.** That number is the
concrete answer to "what does *popular* mean here", and it is worth quoting: a
head defined this way is not an arbitrary cut.

### Verification

`check_ranking.py` run without `--partial`: **all 19 bellwethers present and
ranked** — `semver` 1, `minimatch` 4, `ms` 8, `chalk` 12, `commander` 13,
`glob` 18, `uuid` 41, `postcss` 45, `typescript` 55, `picocolors` 75, `react`
125, `lodash` 131, `eslint` 153, `express` 244, `axios` 280, `webpack` 666.

### Why this replaced the first attempt

The discarded search-derived pool put rank 10,000 at **157 downloads/month** and
omitted 25 of 30 top-tier packages including `lodash` and `express`. The
threshold ratio between the two rankings is roughly **5,500x**. A "top 10,000"
whose final member is essentially unused is not a head stratum, and nothing in
that file said so — which is why `check_ranking.py` now exists and fails
non-zero.
