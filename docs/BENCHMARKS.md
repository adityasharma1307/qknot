# Benchmarks

Task 8 of the Phase II memo. Three questions:

1. What does hybrid signing cost?
2. How does that cost scale with the size of a real model?
3. Do the entropy sources behave the way the pipeline assumes?

**Measured 2026-07-28** on Windows 11, Intel Core i7-13xxx (32 threads),
CPython 3.13.14 in a clean virtualenv, `cryptography` 49.0.0, `dilithium-py`
from PyPI. Full machine details are recorded in `results/bench.json` alongside
every figure.

Regenerate with:

```bash
python scripts/bench/latency.py --reps 50 --sizes 1 10 100 --out results/bench.json
python scripts/bench/collect_entropy.py --source all
python scripts/bench/randomness.py --out results/randomness.json
python scripts/bench/check_docs.py     # every figure below, re-derived from the JSON
```

The last command is not optional bookkeeping. Every number in this document was
transcribed by hand out of `results/*.json`, and during that transcription two
search-and-replace operations silently failed to match, leaving stale figures in
prose that read as authoritative. `check_docs.py` re-derives all 115 of them and
exits non-zero on any disagreement; `pytest tests/bench` runs it, including a
test that deliberately corrupts a figure to confirm the checker can still fail.
Exit code 2 means *could not check* and is reported separately from exit 1,
*checked and wrong* — a verifier that cannot tell those apart is the failure it
exists to prevent.

---

## 1. Primitives

Median of 40 repetitions, **each over a different message**. That detail is not
incidental — see "The trap in benchmarking ML-DSA" below.

| algorithm | keygen | sign | verify | signature | public key | secret key |
|---|---|---|---|---|---|---|
| Ed25519 | 0.025 ms | **0.044 ms** | 0.068 ms | **64 B** | 32 B | 32 B |
| ML-DSA-44 | 4.23 ms | **18.82 ms** | 4.70 ms | **2,420 B** | 1,312 B | 2,560 B |
| ML-DSA-65 | 7.05 ms | 30.52 ms | 7.79 ms | 3,309 B | 1,952 B | 4,032 B |
| ML-DSA-87 | 11.08 ms | 42.97 ms | 11.38 ms | 4,627 B | 2,592 B | 4,896 B |

**Ed25519 signs 428× faster and produces a signature 37.8× smaller.** That is
the headline cost of the transition, and it is not a small one.

Two qualifications, both of which cut in the same direction:

- **This is pure Python.** `dilithium-py` is a readable reference
  implementation, not an optimised one. liboqs' C implementation is one to two
  orders of magnitude faster. Nothing here should be read as the cost of ML-DSA;
  it is the cost of *this* implementation.
- **Ed25519 here is OpenSSL.** The comparison is optimised C against interpreted
  Python, so the 428× ratio flatters the classical side considerably.

### Signing time varies by a factor of eleven

| algorithm | sign p25 | median | p75 | max/min |
|---|---|---|---|---|
| Ed25519 | 0.043 ms | 0.044 ms | 0.045 ms | 1.2× |
| ML-DSA-44 | 11.0 ms | 18.8 ms | 26.9 ms | **11.5×** |
| ML-DSA-65 | 23.6 ms | 30.5 ms | 45.4 ms | **7.8×** |
| ML-DSA-87 | 30.7 ms | 43.0 ms | 61.3 ms | **7.2×** |

**Ed25519's 1.2× spread is the control.** A constant-time implementation over a
fixed-size input should show almost none, and it doesn't — so the machine was
quiet and the harness is measuring what it claims to. Against that baseline,
ML-DSA-44's **11.5×** cannot be attributed to system noise.

ML-DSA signing rejects candidate signatures until one falls within bounds, and
the number of attempts depends on the key and the message. It is the same
secret-dependent variation that makes this backend unsuitable for an online
signing service — see [`THREAT-MODEL.md`](THREAT-MODEL.md). Reporting a mean
would hide it.

---

## 2. Scaling with artefact size

| artefact | digest | total sign | signature only | digest share | throughput |
|---|---|---|---|---|---|
| 1 MiB | 10.3 ms | 29.8 ms | 19.6 ms | 35% | 97 MB/s |
| 10 MiB | 34.3 ms | 54.3 ms | 20.0 ms | 63% | 291 MB/s |
| 100 MiB | 295.5 ms | 314.5 ms | 19.0 ms | **94%** | 338 MB/s |

**The signature cost is flat — 19–20 ms at every size — while the digest grows
linearly.** That is the whole result in one line. Throughput climbs with size
because per-call overhead amortises; it settles around 338 MB/s.

Extrapolating:

| model | digest | signature | signature share |
|---|---|---|---|
| 1 GB | 3.0 s | 0.019 s | 0.62% |
| **7 GB** | **21.2 s** | **0.019 s** | **0.09%** |
| 70 GB | 211.8 s | 0.019 s | 0.009% |

For any artefact worth signing, the cost is the hash, not the cryptography — and
the share *falls* as models grow. The objection that post-quantum signatures are
too slow is true of the primitive in isolation and false of the operation anyone
actually performs.

---

## 3. Hybrid overhead

Over a 1 MiB artefact, so the digest is common to all three rows:

| configuration | sign | verify | signature bytes |
|---|---|---|---|
| Ed25519 only | 6.68 ms | 6.20 ms | 64 |
| **hybrid** | **27.89 ms** | **12.01 ms** | **2,484** |
| ML-DSA-44 only | 27.61 ms | 11.38 ms | 2,420 |

Adopting the hybrid over Ed25519 alone costs **21.2 ms (4.2×) and 2,420 bytes**.

The more useful comparison is the third row: **the hybrid costs only 0.28 ms
more than ML-DSA alone.** Once you are paying for a post-quantum signature, the
Ed25519 half — and therefore backward compatibility with every verifier that
exists today — is essentially free. That is the strongest practical argument for
the hybrid over a straight ML-DSA migration.

### These figures are the ML-DSA-44 configuration, which is no longer the default

**The shipped default is now `ed25519+ml-dsa-87`** (see
[`OPEN-QUESTIONS.md`](OPEN-QUESTIONS.md) §7). The table above was measured
against `ed25519+ml-dsa-44` and is left exactly as measured rather than
rescaled, because a rescaled number is not a measurement.

What transfers to the default configuration, and what does not:

| | -44 (measured) | -87 (default) |
|---|---|---|
| cost of adding the Ed25519 half | +0.28 ms, +64 B | **+64 B exactly**; time increment unchanged in kind |
| hybrid signature size | 2,484 B | **4,691 B** (4,627 + 64), exact — sizes are spec-fixed |
| hybrid sign time over 1 MiB | 27.89 ms measured | **~52 ms, extrapolated, not measured** |

The size row is exact because FIPS 204 fixes signature lengths. **The time row
is an extrapolation** — 27.89 ms plus the 24.15 ms primitive difference between
-44 and -87 — and is labelled as such because nobody ran it. Re-run
`scripts/bench/latency.py` with the hybrid configured for -87 before quoting a
measured figure for the default.

The *argument* survives the change unaltered, and that is the point worth
keeping: the Ed25519 half costs 64 bytes and a fraction of a millisecond
whatever the ML-DSA parameter set, so backward compatibility remains close to
free at CNSA 2.0 strength. What changes is the absolute post-quantum cost, and
the reason to accept it is compliance, not performance.

The ordering is checked automatically: the hybrid computes the ML-DSA signature
*and* an Ed25519 one, so it cannot be faster than either component. `latency.py`
asserts this, along with the parameter-set ladder and the specification's fixed
signature sizes, and refuses to report results that violate them.

---

## 4. End-to-end CLI

| | median |
|---|---|
| interpreter startup (`python -c pass`) | 45.4 ms |
| `qresp sign` | 244.7 ms |
| `qresp verify` | 205.4 ms |

Startup is 19% of an invocation; the rest is import time for `cryptography`,
`dilithium-py` and the CLI framework. Note that **`qresp sign` on a 1 MiB
artefact takes 245 ms against 28 ms for the same work through the API** — nearly
90% of a one-shot invocation is process and import overhead, not signing.
Anyone signing a thousand artefacts should loop inside one process.

---

## 5. Entropy sources

### What these tests can and cannot establish

**They cannot validate an entropy source.** SP 800-90B assesses a *raw noise
source*, and every sample available here is conditioned:

| source | what it returns |
|---|---|
| `os.urandom` | CSPRNG output, seeded from the OS pool |
| ANU | post-processed detector counts, not raw measurements |
| NIST beacon | the output of a hash chain |

A good hash produces output indistinguishable from random regardless of how much
entropy went into it, so a high score is guaranteed and says nothing about the
physics. What these tests *can* do is catch gross failure — a stuck source, a
truncated transfer, a transport that returned the same block twice. For a
pipeline that fetches randomness over HTTP from two third parties, that is a
genuinely useful smoke test, and it is the only claim made here.

### Sample sizes, and why the beacon is awkward

SP 800-22 wants ≥10⁶ bits per sequence, ideally 100 sequences.

| source | per fetch | fetches for 10⁶ bits | wall clock |
|---|---|---|---|
| ANU | 8,192 bits | 123 | minutes |
| beacon (live) | 512 bits | 1,954 | **32.6 hours** |
| beacon (history) | 512 bits | 1,954 | ~30 minutes |

Live beacon collection is infeasible: the full 100-sequence suite would need 136
days of output that does not exist yet. The beacon's history is retrievable by
pulse index, so the same bits can be had in half an hour — and every pulse index
is recorded, so a reader can re-fetch any of them and confirm the sample was not
fabricated. That verifiability is the beacon's whole purpose.

**One sequence per source, not 100.** The arithmetic above is why.

### Results

All three sources at a full 10⁶ bits, against a deliberately broken control.
p-values, α = 0.01:

| source | monobit | freq. block | runs | cusum fwd | cusum bwd | |
|---|---|---|---|---|---|---|
| ANU QRNG | 0.084 | 0.098 | 0.030 | 0.091 | 0.111 | 5/5 ✓ |
| NIST beacon | 0.919 | 0.526 | 0.412 | 0.254 | 0.308 | 5/5 ✓ |
| `os.urandom` | 0.488 | 0.365 | 0.493 | 0.374 | 0.366 | 5/5 ✓ |
| repeating block (control) | 0.879 | **0.000** | 0.949 | 1.000 | 1.000 | 4/5 ✗ |

Min-entropy, SP 800-90B Most Common Value estimate:

| source | H∞ per bit | H∞ per byte | χ² p | uniform? |
|---|---|---|---|---|
| ANU QRNG | 0.9938 | 7.6584 | 0.249 | yes |
| NIST beacon | 0.9961 | 7.6535 | 0.598 | yes |
| `os.urandom` | 0.9953 | 7.6758 | 0.792 | yes |
| repeating block (control) | **0.9961** | **7.8392** | **1.000** | yes |

**The three real sources are statistically indistinguishable.** A quantum
optical source, a hash-chained government beacon, and a software CSPRNG all land
within 0.002 of each other per bit. That is the expected result, and it is worth
stating as the finding it is: **these tests cannot tell the sources apart,
because all three are conditioned output.** Anyone reading the ANU row as
evidence of quantum provenance has misread it.

ANU's `runs` p-value of **0.030** is the lowest figure in the table. It passes
at α = 0.01 and would fail at α = 0.05. With twenty p-values in the table, one
low value is unremarkable — but reporting it rather than rounding past it is the
point of showing p-values instead of ticks.

### The control is the most instructive row

**The deliberately broken source scores *higher* min-entropy than all three real
sources, and passes chi-square with p = 1.000.** A repeating block of bytes
0–255 has a perfectly uniform histogram and zero actual entropy.

That is not a defect in the estimator — it is what MCV measures. MCV looks at
the frequency of the most common symbol; chi-square looks at the histogram.
Neither looks at *order*. A counter is maximally uniform and completely
predictable.

Only `frequency_within_block` catches it, and only because the structure is
visible within a 128-bit window. Three of the five tests wave it through, and
both entropy estimates rank it top.

Two things follow, and both belong in the write-up:

1. **A min-entropy number without a structural test beside it is worse than no
   number**, because it looks like evidence.
2. **This subset is thin.** One test out of five catching the control is a
   narrow margin. The full fifteen-test battery would catch it several ways
   over; see below for why that was not available.

### Collection notes

Both public services failed repeatedly during collection, which is why the
collector retries:

- **ANU** returned HTTP 500 on the unauthenticated endpoint, then HTTP 429
  (rate limit) after ~100 requests with a key, then completed on a later run
  with three more transient failures absorbed by the retry logic. Final sample:
  125,000 bytes over 21 requests plus earlier resumed data.
- **The NIST beacon** dropped the connection twice mid-collection. Retries
  recovered both. Final sample: 125,000 bytes from chain 2, pulses
  1,878,255–1,879,296, every index recorded in the manifest so a reader can
  re-fetch and confirm.

### Only one of these samples is verifiable

The beacon manifest records every pulse index and its `output_value`, so a
reader can re-fetch those pulses from NIST and confirm byte-for-byte that the
sample is what it claims to be. **The ANU sample has no such property.** It is
125,000 bytes that this project asserts came from a quantum source; the service
publishes no retrievable record, so the assertion is unfalsifiable.

That is not a criticism of ANU — it is the difference between a randomness
*service* and a randomness *beacon*, and it is the same distinction the
provenance argument in this project turns on. A value you cannot independently
re-derive is a value you are trusting someone about. Both samples are committed
under `data/entropy/` with their manifests so a reader can at least confirm the
analysis was run over the bytes shown, but only the beacon supports the
stronger claim.

An earlier version of the collector abandoned the run on the first error and
lost 99% and 53% of the two samples respectively. Free public services return
500s and reset connections as a matter of course; a collector that treats that
as fatal never completes.

---

## 6. Why the SP 800-22 battery here is four tests, not fifteen

The obvious approach is an existing implementation. `nistrng` was tried and
abandoned after three defects surfaced in an afternoon, each of which would have
put a wrong number in the tables above:

1. **Cumulative sums overflowed.** The ±1 random walk was accumulated in the
   `int8` array its packing function returns, wrapping at 127. On 100,000 bits
   the correct max |S_k| was **724**; computing it raised **2,021 overflow
   warnings** and returned `passed=True, score=0.9994` from wrapped arithmetic.

2. **A passing p-value was reported as a failure.** Random Excursion returned
   0.683 — far above any sensible α — and was flagged failed.

3. **Results were inverted on structured input.** Non-Overlapping Template
   Matching scored `os.urandom` at 0.0 and the repeating block at 0.34, exactly
   backwards.

It reported `os.urandom` as failing **four of ten** tests. A suite that cannot
recognise the system CSPRNG cannot support a claim about anything else.

So [`src/qresp/signing/entropy/sp800_22.py`](../src/qresp/signing/entropy/sp800_22.py)
implements four tests — monobit, frequency within block, runs, cumulative sums —
each validated in `tests/signing/test_sp800_22.py`. Three reproduce the worked
examples printed in SP 800-22 Rev. 1a to six decimal places. The fourth
(cumulative sums) did not match the recalled constant, so rather than trust
either the implementation or the recollection, it is validated against the
empirical tail probability of 20,000 simulated random walks — agreeing to within
0.006 and converging in the tail where the α = 0.01 decision is made.

**Four verified tests are worth more than fifteen unverified ones.** The eleven
not implemented are listed in the JSON output so the gap is explicit.

This is also a finding in its own right: a widely available Python
implementation of a NIST statistical suite produces confidently wrong results,
and nothing about its output signals that.

---

## The trap in benchmarking ML-DSA

Worth recording because the first version of the harness fell into it and
produced an **impossible** result: the hybrid appeared four times *faster* than
ML-DSA alone, which cannot be, since the hybrid computes that same signature and
an Ed25519 one besides.

The cause: in deterministic mode, ML-DSA's rejection-sampling iteration count is
a fixed function of (key, message). Signing one fixed message a thousand times
performs the identical computation a thousand times — it measures how lucky that
message was, not what the algorithm costs. The luck is large; one key over eight
messages:

```
10.2  10.6  15.4  20.1  20.7  35.0  38.4  57.7  ms        5.7x spread
```

The hybrid and ML-DSA-only configurations sign *different* payloads, because the
algorithm binding differs and so the statement differs. The ML-DSA-only payload
drew an unlucky one.

`measure()` now passes the repetition index to the callable and every benchmark
varies its input with it, so what is reported is a sample of the distribution
over messages. Anyone benchmarking a rejection-sampling signature scheme should
check this first.

---

## Reproducing

```bash
pip install -e ".[dev]"
python scripts/bench/latency.py --reps 50 --sizes 1 10 100 --out results/bench.json
python scripts/bench/collect_entropy.py --source all --bits 1000000
python scripts/bench/randomness.py --out results/randomness.json
pytest tests/signing/test_sp800_22.py -q      # 32 tests validating the statistics
```

`latency.py` records the platform, CPU, Python version and library versions
alongside every result, and exits non-zero if any physical invariant fails.
