# QResP — consolidated results

Everything measured, in one place, with the caveat that belongs beside it.
Every figure here is reproducible from a committed artefact; where a number
cannot be independently re-derived by a third party, that is said explicitly
rather than left to inference.

Last updated 2026-07-29. Source artefacts: `data/`, `results/`,
`docs/DATASETS.md`, `docs/BENCHMARKS.md`.

---

## 1. The headline

Across 20,000 HuggingFace repositories sampled in two strata from a population
of 2,938,109:

**Not one carried a post-quantum signature. Not one.**

That is the finding the rest of this document supports. It is not a claim that
signing is rare — it is a claim that the signing which exists is, without
exception in this sample, built on primitives a cryptographically relevant
quantum computer breaks.

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

## 3. Cost of the transition

Measured 2026-07-28, Windows 11, Intel Core i7-13xxx, CPython 3.13.14 in a
clean virtualenv. Full detail in [`BENCHMARKS.md`](BENCHMARKS.md); all 115
figures are re-derived from `results/*.json` by `scripts/bench/check_docs.py`
on every test run.

### Primitives

| algorithm | sign | signature | public key |
|---|---|---|---|
| Ed25519 | 0.044 ms | 64 B | 32 B |
| ML-DSA-44 | 18.82 ms | 2,420 B | 1,312 B |
| ML-DSA-65 | 30.52 ms | 3,309 B | 1,952 B |
| ML-DSA-87 | 42.97 ms | 4,627 B | 2,592 B |

Ed25519 signs **428× faster** and produces a signature **37.8× smaller**. Two
qualifications that both flatter the classical side: `dilithium-py` is a
readable reference implementation, not an optimised one, and Ed25519 here is
OpenSSL's C. This is not the cost of ML-DSA; it is the cost of *this*
implementation of it.

### The two results that matter

**Signature cost is flat; digest cost is not.**

| artefact | digest | signature | signature share |
|---|---|---|---|
| 1 MiB | 10.3 ms | 19.6 ms | 66% |
| 100 MiB | 295.5 ms | 19.0 ms | 6% |
| **7 GB** (extrapolated) | **21.2 s** | **0.019 s** | **0.09%** |

At 338 MB/s, hashing a 7 GB model takes 21 seconds; signing the digest takes 19
milliseconds. **The post-quantum signature is 0.09% of the work, and that share
falls as models grow.** The objection that post-quantum signatures are too slow
is true of the primitive in isolation and false of the operation anyone
actually performs.

**Backward compatibility is nearly free.**

| configuration | sign | signature bytes |
|---|---|---|
| Ed25519 only | 6.68 ms | 64 |
| **hybrid** | **27.89 ms** | **2,484** |
| ML-DSA-44 only | 27.61 ms | 2,420 |

Adopting the hybrid over Ed25519 costs 21.2 ms and 2,420 bytes. But over
ML-DSA **alone** it costs **0.28 ms and 64 bytes**. Once you are paying for a
post-quantum signature, keeping every verifier that exists today working is
essentially free — which is the practical argument for a hybrid over a straight
migration.

### Timing variation, and why the mean is not reported

| algorithm | median | max/min |
|---|---|---|
| Ed25519 | 0.044 ms | 1.2× |
| ML-DSA-44 | 18.8 ms | **11.5×** |

ML-DSA rejection-samples until a candidate signature falls in bounds; the
number of attempts depends on key and message. **Ed25519's 1.2× spread is the
control** — it establishes that the machine was quiet, so ML-DSA-44's 11.5×
cannot be dismissed as system noise. This is a secret-dependent timing channel
and it is why this backend is unsuitable for an online signing service; see
[`THREAT-MODEL.md`](THREAT-MODEL.md).

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
| Test suite | **880 tests**, plus ruff and mypy clean |

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

**Neither touches this work.** QResP signs with ML-DSA (FIPS 204). HAWK is a
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

## 8. Reproducing

```bash
python scripts/bench/latency.py --reps 50 --sizes 1 10 100 --out results/bench.json
python scripts/bench/collect_entropy.py --source all
python scripts/bench/randomness.py --out results/randomness.json
python scripts/bench/check_docs.py     # re-derives all 115 figures
python -m pytest -q                    # 880 tests
```

Scan reproduction, dataset provenance, and the CRLF-digest and backfill
incidents are documented in [`DATASETS.md`](DATASETS.md).

## 9. Known limitations

- **One sequence per entropy source, not the 100 SP 800-22 recommends.** Live
  beacon collection for the full suite would need 136 days of output that does
  not yet exist.
- **Five of fifteen SP 800-22 tests implemented.** The subset is verified
  against published worked examples; the remaining ten are not implemented and
  are listed by name in `results/randomness.json`.
- **Benchmarks are single-machine, pure-Python.** No cross-platform or
  optimised-implementation comparison. liboqs would be one to two orders of
  magnitude faster.
- **The scan is a single point in time** (2026-07-25) on one hub. No
  longitudinal trend, and nothing here generalises to PyPI, npm, or model hubs
  other than HuggingFace.
- **Three gated repositories remain unclassified**, bounded as described in §2.
- **SP 800-90B assesses raw noise sources.** Every sample here is conditioned
  output, so these estimates cannot validate an entropy source and are not
  offered as doing so.
