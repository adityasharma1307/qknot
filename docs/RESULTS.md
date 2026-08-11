# QKnot — consolidated results

Everything measured, in one place, with the caveat that belongs beside it.
Every figure here is reproducible from a committed artefact; where a number
cannot be independently re-derived by a third party, that is said explicitly
rather than left to inference.

Last updated 2026-08-01 (after the bug sweep of that date — see "A note on
the 2026-08-01 correction" below). Source artefacts: `data/`, `results/`,
`docs/DATASETS.md`, `docs/BENCHMARKS.md`.

---

## 1. The headline

Across three ecosystems — HuggingFace, PyPI, and npm — sampled in two strata
each (a census of the top 10,000 by downloads, and a random draw of 10,000
from the remainder):

**Zero post-quantum signatures. In any stratum, of any ecosystem, out of
60,000 sampled artefacts.**

| ecosystem | registry N | combined signed | head (top 10k) | tail (random 10k) | head/tail ratio |
|---|---|---|---|---|---|
| **HuggingFace** | 2,928,107 | **0.101%** [0.039, 0.163] | 0.39% | 0.10% | 3.9× |
| **PyPI** | 860,900 | **8.907%** [8.363, 9.451] | 23.15% | 8.74% | 2.6× |
| **npm** | 4,290,079 | **3.681%** [3.315, 4.046] | 25.40% | 3.63% | 7.0× |

Head strata are a census (no sampling variance); all interval width is the
long-tail draw. Every attestation found, across all three ecosystems and every
stratum, is classical — ECDSA P-256 or RSA, read off the certificate or
signature rather than assumed. Each per-stratum 95% Wilson upper bound on
post-quantum adoption is **0.038%**: the null is not an artefact of small
samples, since adoption above roughly 4 in 10,000 would have been detected.

That a post-quantum signature *could* be detected was itself verified, not
assumed — a spliced ML-DSA-87 OID is caught by `pqc_oid.py` and recorded as a
finding rather than a parse error. The claim is "we found zero and could have
found one," not merely "we found zero."

**PyPI and npm remove the obvious rebuttal to the HuggingFace number.** On
HuggingFace alone, 0.10%–0.39% signing invites the reply that almost nothing
is signed there, so the post-quantum absence says little. PyPI and npm sign
26–87× more often (8.9% and 3.7% combined, against 0.1%) — normal ecosystem
behaviour, not a curiosity — and the post-quantum rate is still exactly zero.
**Even where signing is routine, post-quantum signing does not exist.**

### A note on the 2026-08-01 correction

Every number above was produced by `src/qknot/audit/stats.py` after a bug
sweep on 2026-08-01 that fixed a stratum double-count, a loader that could not
read `project`-keyed records, an error-retry that never retried, and a
provenance-version mismatch. Before that sweep the npm and PyPI figures had
never been run through this tool at all; the per-stratum head/tail rates
below were unaffected, but the cross-ecosystem "combined, weighted" row is
new as of this correction.

---

## 2. Ecosystem measurement

Two-stratum design over an enumerated population of **2,938,109** repositories:
a census of the top 10,000 by all-time downloads (head), and a random sample of
10,000 from the remaining 2,928,107 (long tail, seed 20260725, sampling
fraction 0.341%).

| | head | long tail | ratio | Fisher exact |
|---|---|---|---|---|
| signed | 39 / 10,000 = **0.390%** | 10 / 10,000 = **0.100%** | 3.9× | p = 3.8e-05 |
| vulnerable | 36 / 10,000 = 0.360% | 10 / 10,000 = 0.100% | 3.6× | p = 1.5e-04 |
| **post-quantum** | **0 / 10,000** | **0 / 10,000** | n/a | p = 1 |

### What these numbers mean, and what they don't

**Signing is rare, and popularity predicts it.** Repositories in the head are
3.9× more likely to be signed than those in the tail, and the difference is not
a sampling artefact (p = 3.8e-05). But "more likely" is doing light work here:
0.390% against 0.100%. Both strata are, in absolute terms, almost entirely
unsigned.

**Signing is concentrated to the point of being a single-vendor phenomenon.**
IBM accounts for **69% of all signing in the top 10,000**. In the long tail, 9
of the 10 signed repositories are `Thireus` GGUF quantisations. Strip out two
actors and the ecosystem's signing rate approaches zero. Any claim about
"adoption" that averages over these repositories describes a distribution that
does not exist.

**All observed signatures are classical.** Provenance backfill (2026-07-26)
confirmed public-key algorithm `1` under RFC 9580 §9.1 — RSA — with hash
algorithm `10`, SHA-512. RSA is broken by Shor's algorithm. Every signature
found in this study is, on the CNSA 2.0 timeline, already legacy.

### The three repositories we could not read

Three `CohereLabs` repositories (`command-a-vision-07-2025`, `aya-vision-8b`,
`c4ai-command-r7b-12-2024`) are gated and return HTTP 401 for their signature
files. They were re-checked and remain unreadable.

They are reported as **unclassified, not unsigned**. This distinction is not
pedantry — a study that silently folds "could not check" into "checked and
found nothing" is reporting a conclusion it did not reach. The worst case is
bounded and stated: if all three were post-quantum, the head rate would be
0.030% with an upper bound of 0.088%, and the tail would still be exactly zero.
The headline survives its own worst case.

### Credential-shaped identifiers

The scan surfaced **162 repository identifiers matching HuggingFace's token
format**. The precise claim is exactly that — *162 repository names match the
token format* — and never "162 tokens are leaked."

**No token was ever tested.** Testing a credential belonging to someone else
would be unauthorised access, and the finding does not require it. The full
list lives in `security/leaked_token_repos.PRIVATE.txt`, which is gitignored
and must not be committed or published. HuggingFace was notified and has not
responded.

---

## 2b. PyPI: the same absence, in an ecosystem where signing is common

Scanned 2026-07-30. Two strata of 10,000 from a frame of **860,900** projects:
head by downloads from a published ranking, tail sampled at random
(seed 20260730). Unit of analysis fixed in advance — per-project, any release
ever attested.

| | head | tail | ratio | Fisher exact |
|---|---|---|---|---|
| signed | 2,315 / 10,000 = **23.15%** | 874 / 10,000 = **8.74%** | 2.65× | **p = 1.6e-175** |
| vulnerable | 2,315 | 874 | — | — |
| **post-quantum** | **0** | **0** | n/a | — |
| could not check | **0** | **0** | — | — |

95% Wilson intervals: head 22.33–23.99%, tail 8.20–9.31%. Difference 14.41
percentage points (95% CI 13.41–15.40).

### This makes the post-quantum finding much stronger, not merely wider

On HuggingFace the natural objection is that signing is so rare — 0.39% and
0.10% — that the absence of post-quantum signatures says little. Perhaps
nobody has adopted *anything*.

PyPI removes that objection. **Signing here is roughly sixty times more common**
than on HuggingFace, across 2,869 distinct publishers, and **every one of the
3,189 attested projects uses ECDSA P-256. Not one uses a post-quantum
algorithm.**

The algorithm was not assumed from "PyPI uses Sigstore". It was read off the
Fulcio certificate embedded in each provenance document, and an unrecognised
key type would have been flagged for manual classification rather than
defaulted to classical. Zero were flagged.

So the claim is no longer "signing is rare, and what exists is classical". It is
**"even where signing is normal, post-quantum signing does not exist"** — which
is the version of the finding that survives the obvious rebuttal.

### Adoption is driven by mechanism, not by vendor

The two ecosystems concentrate in completely different ways, and the contrast
is more interesting than either number alone:

| | HuggingFace | PyPI |
|---|---|---|
| signed repositories/projects | 49 | 3,189 |
| distinct publishers | a handful | **2,869** |
| concentration | **69% IBM** — one vendor | **96% GitHub** — one *mechanism* |

HuggingFace signing is a single-vendor phenomenon: strip out IBM and Thireus
and it approaches zero. PyPI signing is not concentrated in any publisher —
the largest single repository accounts for 32 projects out of 3,189 — but
**96% of it arrives through GitHub Actions**, with Google Cloud Build at 3.8%
and GitLab at 0.1%.

That difference has a plain reading. PyPI's attestations come free with Trusted
Publishers: configure CI once, and every release is attested without a further
decision. HuggingFace signing requires a deliberate act per publisher. **Where
signing is a property of the pipeline, adoption is broad; where it is a
property of the publisher, adoption is one vendor.**

For a paper arguing that post-quantum provenance must be *deployable*, that is
the more useful finding than the raw rates: it identifies what actually moves
adoption, and it is the lever a post-quantum migration would have to pull.

### Completeness

**Zero errors across 20,000 projects.** Unlike the HuggingFace scan, which left
three gated repositories unclassified, every project here was checked and
classified — so the head and tail rates need no worst-case bounding. 812 ranked
projects had been deleted from the index since the ranking was published and
were skipped before sampling, which is recorded rather than silently absorbed.

---

## 2c. npm: the third ecosystem, and the same zero

Two strata of 10,000 from a frame of **4,290,079** packages: head by
downloads, tail sampled at random. Combined, weighted rate **3.681%**
[3.315, 4.046] — between HuggingFace's 0.101% and PyPI's 8.907%, and again
**zero post-quantum** in either stratum.

**npm tail: 121 deleted packages** (404 between frame and scan) — coverage
loss, reported rather than absorbed; the signed rate over the 9,879 actually
observed is 3.674%, materially unchanged.

### Composition is uniform where signing exists at all

Every signed artefact across **PyPI and npm** — both Sigstore/Fulcio
ecosystems — is **100% ECDSA P-256**, the certificate type Fulcio issues by
default. HuggingFace's signed set is mostly ECDSA P-256 with a handful of RSA,
reflecting its older, more heterogeneous signing practice. Adoption is driven
by mechanism, not vendor: PyPI's attestations arrive free with Trusted
Publishers (96% via GitHub Actions, configure CI once and every release is
attested); HuggingFace signing requires a deliberate act per publisher, and is
concentrated in a single vendor (IBM, 69% of head signing) as a result. **Where
signing is a property of the pipeline, adoption is broad; where it is a
property of the publisher, adoption is one vendor.**

---

## 3. Cost of the transition

Measured 2026-07-30, Windows 11, CPython 3.13.14, `--reps 250`, hybrid and
scaling at `ml-dsa-87` (the shipped default). Full detail in
[`BENCHMARKS.md`](BENCHMARKS.md); all 115 figures are re-derived from
`results/*.json` by `scripts/bench/check_docs.py` on every test run.

### Primitives

| algorithm | sign | signature | public key |
|---|---|---|---|
| Ed25519 | 0.088 ms | 64 B | 32 B |
| ML-DSA-44 | 16.198 ms | 2,420 B | 1,312 B |
| ML-DSA-65 | 27.878 ms | 3,309 B | 1,952 B |
| **ML-DSA-87** (default) | **33.845 ms** | **4,627 B** | 2,592 B |

Against the shipped default, Ed25519 signs **383× faster** and produces a
signature **72.3× smaller**. Two qualifications that both flatter the classical
side: `dilithium-py` is a readable reference implementation, not an optimised
one, and Ed25519 here is OpenSSL's C. This is not the cost of ML-DSA; it is the
cost of *this* implementation of it.

### The two results that matter

**Signature cost is flat; digest cost is not.**

| artefact | digest | signature | signature share |
|---|---|---|---|
| 1 MiB | 3.9 ms | 35.2 ms | 90% |
| 100 MiB | 213.9 ms | 36.1 ms | 14% |
| **7 GB** (extrapolated) | **15.3 s** | **0.036 s** | **0.235%** |

Across a hundred-fold change in artefact size the signature cost moves by 1.05×
— it is flat because you sign a digest, so the artefact cannot reach it. At
468 MB/s, hashing a 7 GB model takes 15 seconds against 36 milliseconds to
sign. **The post-quantum signature is 0.235% of the work, and that share falls
as models grow.** The objection that post-quantum signatures are too slow is
true of the primitive in isolation and false of the operation anyone actually
performs.

**Backward compatibility is nearly free — and it replicates.**

| configuration | sign | signature bytes |
|---|---|---|
| Ed25519 only | 3.25 ms | 64 |
| **hybrid** | **37.26 ms** | **4,691** |
| ML-DSA-87 only | 36.95 ms | 4,627 |

Adopting the hybrid over Ed25519 costs 34.0 ms and 4,627 bytes. But over ML-DSA
**alone** it costs **0.31 ms and exactly 64 bytes**.

Measured independently at two parameter sets on different days, the increment
was **+0.28 ms at ML-DSA-44** and **+0.31 ms at ML-DSA-87** — agreement to
within 0.03 ms across a run in which the post-quantum half more than doubled in
cost. The cost of the classical half does not depend on the post-quantum
parameter set, which makes this a structural property of the construction
rather than a fact about one configuration. It is the strongest practical
argument for a hybrid over a straight migration.

### Timing variation, and why the mean is not reported

| algorithm | median | max/min |
|---|---|---|
| Ed25519 | 0.088 ms | 1.2× |
| ML-DSA-44 | 16.2 ms | **16.0×** |
| ML-DSA-87 | 33.8 ms | **8.0×** |

ML-DSA rejection-samples until a candidate signature falls in bounds; the
number of attempts depends on key and message. **Ed25519's 1.2× spread is the
control** — it establishes the machine was quiet, so the ML-DSA spreads cannot
be dismissed as system noise. This is a secret-dependent timing channel and it
is why this backend is unsuitable for an online signing service; see
[`THREAT-MODEL.md`](THREAT-MODEL.md).

The variance is large enough to matter methodologically: at `--reps 50` an
earlier run produced an ML-DSA-65 median *above* ML-DSA-87, which is physically
impossible and was pure noise at 0.13 standard errors. The harness now notes
such inversions rather than passing them silently, and these figures are from
`--reps 250`, where the ladder holds.

---

## 4. Entropy sources

Three sources at a full 10⁶ bits each, against a deliberately broken control.

| source | H∞/bit | H∞/byte | χ² p | SP 800-22 |
|---|---|---|---|---|
| ANU QRNG | 0.9938 | 7.6584 | 0.249 | 5/5 ✓ |
| NIST beacon | 0.9961 | 7.6535 | 0.598 | 5/5 ✓ |
| `os.urandom` | 0.9953 | 7.6758 | 0.792 | 5/5 ✓ |
| repeating block (control) | **0.9961** | **7.8392** | **1.000** | 4/5 ✗ |

**The three real sources are statistically indistinguishable**, and that is the
honest result. A quantum optical source, a hash-chained beacon and a software
CSPRNG land within 0.002 per bit of each other because all three are
*conditioned output*. These tests cannot speak to the underlying physics.
Anyone reading the ANU row as evidence of quantum provenance has misread it.

**The control is the instructive row.** A repeating counter — zero actual
entropy — scores *higher* min-entropy than every real source and passes
chi-square at p = 1.000. MCV reads the frequency of the most common symbol;
chi-square reads the histogram. Neither reads *order*. Exactly one of five
tests (`frequency_within_block`, p = 0.000000) catches it.

Two consequences, both of which belong in the write-up: a min-entropy figure
published without a structural test beside it is worse than no figure, because
it looks like evidence; and a five-test subset catching the control by a single
test is a thin margin.

ANU's `runs` p-value of **0.030** is the lowest observed. It passes at α = 0.01
and would fail at α = 0.05. With twenty p-values in the table one low value is
unremarkable, but it is reported rather than rounded past.

### Only one sample is verifiable

The beacon manifest records every pulse index and `output_value`, so anyone can
re-fetch from NIST and confirm the sample byte-for-byte. **The ANU sample has
no such property** — it is 125,000 bytes this project asserts came from a
quantum source, and the service publishes no retrievable record. That is not a
criticism of ANU; it is the difference between a randomness *service* and a
randomness *beacon*, and it is the same distinction this project's provenance
argument turns on.

---

## 5. Correctness

| check | scope |
|---|---|
| FIPS 204 ACVP | 180 vendored vectors: keyGen, sigGen, sigVer across ML-DSA-44/65/87 |
| SP 800-22 subset | 4 tests; 3 reproduce published worked examples to 6 dp |
| `cumulative_sums` | validated by Monte Carlo over 20,000 random walks (agrees within 0.006) |
| Benchmark figures | 115 re-derived from JSON; 9/9 deliberate corruptions caught |
| Test suite | **1261 tests** passing offline (57 more skip without network/a fixture), plus ruff and mypy clean |

**The sigVer vectors are mostly negative** — signatures mutated so a correct
verifier must reject them. A `verify` that returned `True` unconditionally
would pass keyGen and sigGen and fail only here. A separate test asserts the
vector set actually contains both verdicts, because a positive-only conformance
suite proves far less than it appears to.

**The previous conformance evidence was validating the wrong algorithm.** It
ran round-3 Dilithium KATs against `dilithium_py.dilithium.Dilithium2`, while
the signing path calls `ml_dsa.ML_DSA_44`. These are different algorithms —
secret keys of 2,528 vs 2,560 bytes, and signatures do not cross-verify. The
old check passed for months and validated a module that was never called. A
test now pins the distinction so nobody re-points it on the assumption the two
are a renaming.

---

## 6. Design findings

Four errors found in this codebase, each of which had a wrong answer that
looked right:

**Time evidence has a direction.** A beacon proves a signature was made *no
earlier* than T (a LOWER bound). A transparency log proves it *already existed*
at T (an UPPER bound). Only an upper bound can rescue a signature made with an
algorithm later disallowed — and the rescue path was wired to the beacon, which
made it unreachable from any real bundle. Now encoded in a `Bound` enum with
`proves_not_after` returning `None` unless the bound is UPPER.

**Signatures covered the binding, not the payload.** Metadata was forgeable.
Fixed by signing the DSSE Pre-Authentication Encoding, which binds type and
body with explicit lengths — the artifact-signing analogue of the transcript
binding TLS 1.3 used against FREAK and Logjam.

**Manifests silently skipped files.** `.git`, `__pycache__` and symlinks were
excluded from the digest without recording that they had been — an unsigned
code-execution path. Exclusions are now bound into the digest (v2), and
symlinks are followed with `link_target` bound (v3). The second was found
because HuggingFace snapshots are symlink farms into a blob cache, so the
signer reported "no files found" on every real model.

**Verification tooling must distinguish "checked and fine" from "could not
check."** This recurs everywhere: the three gated repositories, the drift
checker's exit 2, the crash-versus-verdict bug in the notebook. A verifier that
reports success when it verified nothing is the failure it exists to prevent.

---

## 7. Context: the July 2026 HAWK result

On 2026-07-28 Anthropic reported that its Claude Mythos Preview model found a
previously unknown attack on **HAWK-256**, a NIST post-quantum signature
candidate, exploiting an unused symmetry in its lattice structure and cutting
the operation count from ~2⁶⁴ to ~2³⁸. A separate result sped up an attack on
7-round AES by 200–800×.

**Neither touches this work.** QKnot signs with ML-DSA (FIPS 204). HAWK is a
different, unstandardised, undeployed scheme, and Anthropic states the attack
does not extend to other NIST candidates or to lattice cryptography generally.
NIST's real parameter sets remain out of reach: HAWK-512 falls from 2¹⁵⁰ to
2¹⁰⁸, HAWK-1024 from 2²⁸⁸ to 2¹⁸². The AES result targets a deliberately
weakened research variant, not the deployed cipher.

What it does do is make three of this project's arguments concrete rather than
hypothetical:

1. **Crypto-agility is not a design nicety.** `algorithms.py` carries
   `disallowed_after_date` because algorithms get retired. HAWK-256 survived
   multiple rounds of expert review and lost roughly half its effective key
   strength in 60 hours.
2. **The hybrid has an answer to "why pay twice?"** A reviewed lattice scheme
   can lose margin unexpectedly. Under a non-separable hybrid, a break in the
   post-quantum half does not cost you the signature.
3. **It motivates the temporal finding directly.** If an algorithm breaks at
   time T, whether a signature is still trustworthy depends on *when it was
   made*. A signature provable only as "no earlier than X" is indistinguishable
   from a forgery produced after the break. Only an upper bound rescues it —
   which is precisely what §6 describes.

This is a motivating example for an introduction, not evidence for a claim.
Read Anthropic's own writeup rather than the secondary coverage; several
outlets ran "AI cracks post-quantum crypto" over a result that breaks nothing
deployed.

---

## 8. The mechanism, validated live

§1–2c establish that the deployed ecosystem has no post-quantum path — Rekor
v2 is `hashedrekord`-only, ML-DSA has no externalised prehash, and mainstream
certificate tooling could not parse a post-quantum certificate for most of
the audit window. QKnot's answer is to bootstrap one from the classical PKI
that already exists, and that answer is implemented and verified against live
infrastructure, not only simulated:

* A real registration was produced against **live Fulcio and Rekor** — a real
  short-lived certificate over a P-256 key, a real transparency-log entry
  with its checkpoint and signed entry timestamp — and verified through the
  full eight-step chain, including the **temporal rescue**: verified at an
  instant past the classical algorithm's disallow date, the ML-DSA binding
  still holds because the log timestamp proves it predates the deprecation
  (`tests/signing/test_registration_fixture.py`).
* **Cross-implementation FIPS 204 evidence.** The ML-DSA-87 signature made at
  capture time on one machine verifies under a **separate installation** of
  the backend on another — interoperability evidence rather than
  self-consistency. Stated at its true weight: one capture, one parameter
  set, not a conformance campaign; the vendored ACVP vectors remain the
  systematic check.
* The revocation-search adapter was separately validated against live Rekor
  (`scripts/verify/check_revocation_search.py`): 5/5 index entries fetched
  and authenticated on production data, 0 unauthenticated.

---

## 9. Reproducing

```bash
python scripts/bench/latency.py --reps 50 --sizes 1 10 100 --out results/bench.json
python scripts/bench/collect_entropy.py --source all
python scripts/bench/randomness.py --out results/randomness.json
python scripts/bench/check_docs.py     # re-derives all 115 figures
python -m pytest -q                    # 1261 pass offline, 57 skip
```

Scan reproduction, dataset provenance, and the CRLF-digest and backfill
incidents are documented in [`DATASETS.md`](DATASETS.md).

## 10. Known limitations

- **One sequence per entropy source, not the 100 SP 800-22 recommends.** Live
  beacon collection for the full suite would need 136 days of output that does
  not yet exist.
- **Five of fifteen SP 800-22 tests implemented.** The subset is verified
  against published worked examples; the remaining ten are not implemented and
  are listed by name in `results/randomness.json`.
- **Benchmarks are single-machine, pure-Python.** No cross-platform or
  optimised-implementation comparison. liboqs would be one to two orders of
  magnitude faster.
- **Each scan is a single point in time** (HuggingFace 2026-07-25, PyPI and
  npm 2026-07-30). No longitudinal trend for any of the three, and nothing
  here generalises to model hubs other than HuggingFace.
- **Three gated repositories remain unclassified**, bounded as described in §2.
- **SP 800-90B assesses raw noise sources.** Every sample here is conditioned
  output, so these estimates cannot validate an entropy source and are not
  offered as doing so.
