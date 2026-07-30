# Citations and source integration

Every claim below was verified against the primary source, not against a
summary. Line numbers refer to extracted text of each PDF and are given so the
check can be repeated rather than taken on trust.

**The PDFs are not committed.** They live locally under `docs/sources/`
(gitignored): 33 MB of binaries made every commit slow over a mounted
filesystem, and a citation record needs stable identifiers, not bytes. This
file is therefore the interim record and will be **superseded by
`references.bib` with DOIs**, at which point each entry below should carry its
DOI and the line references become redundant.

Until then, reproducing a check means re-obtaining the PDF named in each
section and extracting its text; filenames are given throughout for that
purpose.

LaTeX comes later; this is the staging document. Prior writeup for context:
`docs/report.pdf`.

**Reading key**

| mark | meaning |
|---|---|
| ✅ | verified verbatim in the primary source, quote and location given |
| ⚠️ | **scope boundary** — the source does *not* support a nearby, tempting claim |
| ❓ | could not verify from the source provided; do not cite until checked |

---

## 1. Governance and regulation

### 1.1 The three tiers must not be blended

The single most common error available here is quoting one date as "the"
post-quantum deadline. There are three regimes, they cover different systems,
and they give different dates.

| regime | applies to | signature deadline | status |
|---|---|---|---|
| **CNSA 2.0** | National Security Systems only | 2027-01-01 exclusive use, software/firmware signing | final |
| **EO 14412 / OMB M-26-15** | civilian federal HVAs, high-impact systems | **2031-12-31** | final memorandum |
| **NIST IR 8547** | technical timeline both reference | 2030 deprecated / 2035 disallowed | **Initial Public Draft** |

**M-26-15 explicitly excludes national security systems** — ✅ line 21:

> "This memorandum does not apply to national security systems."

So CNSA 2.0 and M-26-15 are disjoint in scope. A sentence implying one
timeline governs both is wrong.

### 1.2 The operative civilian date for this project is 2031, not 2030

QResP is a signing tool, so Phase 4 governs it, not Phase 3.

✅ line 274:

> "Phase 3 (Prioritized Migration – 2028 - 2030): The prioritized migration
> phase should migrate to the use of PQC **for key establishment** all HVAs,
> high impact systems…"

✅ line 318:

> "Phase 4 (**Signature Migration – 2031**): The signature migration phase
> should migrate to the use of PQC **for digital signatures** all HVAs, high
> impact systems, systems with highly sensitive data… Ensure that all systems
> are cryptographically agile."

✅ line 323 — a fifth phase the task memo did not mention, worth having:

> "Phase 5 (Full Migration – 2035): The final phase should focus on completing
> the migration of remaining systems…"

The 2030 date at line 98 is the *overall* objective — "mitigating as much
quantum risk as feasible by December 31, 2030" — not a signature deadline.
Citing it as one conflates Phase 3 with Phase 4.

**Note the last clause of Phase 4: "Ensure that all systems are
cryptographically agile."** That is an explicit federal requirement for the
property `algorithms.py` implements, and it is a stronger hook for the
governance chapter than the deadline itself.

### 1.3 IR 8547 is a draft, and OMB hedges on it

✅ line 540, footnote 14:

> "For more information, see NIST IR 8547, available at
> `https://csrc.nist.gov/pubs/ir/8547/ipd`."

The `/ipd` suffix is Initial Public Draft. ✅ line 326 shows OMB itself
hedging — "align their plans with NIST Internal Report (IR) 8547" — and the
memo's own phrasing elsewhere admits no successor exists yet. Cite as a draft
everywhere.

### 1.4 M-26-15 describes exactly this project's architecture — with a caveat that must travel with it

✅ lines 535-537, verbatim:

> "**For Digital Signatures:** A hybrid signature involves creating two
> distinct signatures on the same data—one with a traditional algorithm and
> one with a PQC algorithm. The verifier…"

✅ lines 522-529:

> "A hybrid architecture is an implementation model that combines a traditional
> cryptographic algorithm, such as ECDH or ECDSA, with a PQC algorithm, such as
> FIPS 203 ML-KEM or FIPS 204 ML-DSA. Compromising the security of the
> operation requires an attacker to break both the classical and the PQC
> schemes if properly implemented."

⚠️ **The task memo asked to cite this as "strong, direct governance
validation." The same paragraph continues, and it does not read as
endorsement** — ✅ lines 527-529:

> "…however, because it introduces its own risks and complexities, agencies
> considering this approach should perform a thorough evaluation of its
> tradeoffs, as it is **an intricate and resource-intensive stopgap**."

Quoting the first half without the second is selective, and a reviewer
checking the source will find it immediately. The honest framing, which is
still favourable:

> OMB M-26-15 describes precisely this construction — two distinct signatures
> over the same data, both validated — while characterising hybrid deployment
> as an intricate and resource-intensive stopgap requiring per-agency tradeoff
> evaluation. QResP's measurements speak directly to that tradeoff: §3 of
> RESULTS.md quantifies the cost as 64 bytes and 0.28 ms over ML-DSA alone,
> which is the evaluation the memorandum asks agencies to perform.

That turns the caveat into the paper's opening rather than something to hide
from.

---

## 2. Physical security and timing (`THREAT-MODEL.md`)

### 2.1 Azouaoui (NXP) — ML-DSA physical security

Source is a slide deck: *"Recent Contributions to the Physical Security of
ML-DSA"*, Melissa Azouaoui, NXP PQC Team, © 2024. ✅ title verified page 1.

Use for the leakage-resistance argument and for the "we rely on liboqs rather
than hand-rolling constant-time code" position: real hardened ML-DSA
implementations are specialised, ongoing engineering work.

⚠️ **Do not cite fault-injection/DFA material as corroborating this project's
timing finding.** The deck covers both side-channel *and* fault injection
(✅ line 255 "Fault Attacks (FA)"), and they are different threat categories.
QResP observes passive timing variance on a software implementation; DFA is
active fault injection on embedded hardware. Cite DFA only if a
fault-injection subsection is added to the threat model.

**✅ The underlying papers are now supplied and identified.** Exact titles —
the task memo's short forms were close but not citable as written:

| memo short form | actual title | file |
|---|---|---|
| "Protecting Dilithium against Leakage (TCHES 2023)" | **Protecting Dilithium against Leakage — Revisited: Sensitivity Analysis and Improved Implementations**, Azouaoui, Bronchain, Cassiers, Hoffmann, Kuzovkova, Renes, Schneider et al. | `2022-1406.pdf` |
| "Bronchain et al. (TCHES 2024)" | **Exploiting Small-Norm Polynomial Multiplication with Physical Attacks: Application to CRYSTALS-Dilithium**, Bronchain, Azouaoui, ElGhamrawy, Renes, Schneider (NXP) | `2023-1545.pdf` |
| — (not in memo) | **From MLWE to RLWE: A Differential Fault Attack on Randomized & Deterministic Dilithium**, TCHES 2023(4):262-286, DOI `10.46586/tches.v2023.i4.262-286` | `TCHES2023_4_11.pdf` |
| — | **A Generic Framework for Side-Channel Attacks against LWE-based Cryptosystems**, Hermelink, Streit, Mårtensson, Petri (MPI-SP) | `2024-1211.pdf` |
| — | **LWE with Side Information: Attacks and Concrete Security Estimation**, Dachman-Soled, Ducas, Gong, Rossi | `2020-292.pdf` |

⚠️ **`TCHES2023_4_11.pdf` is the DFA paper** — "Differential Fault Attack on
Randomized & Deterministic Dilithium". This is the ElGhamrawy material the task
memo correctly said must **not** be cited as validating this project's passive
timing finding. Now that it is in the repo, the temptation is greater, so the
boundary is restated: active fault injection on embedded hardware is a
different threat class from passive timing observation of a software
implementation.

Two supplied papers are **tangential** and should not be cited for the
signature threat model: `2025-812.pdf` (Post-Quantum Cryptography in eMRTDs —
travel documents, PAKE/PKI) and `TCHES2022_4_14.pdf` (Post-Quantum
Authenticated Encryption against Chosen-Ciphertext Side-Channel Attacks — KEM,
not signatures). Azouaoui is an author on both, which is presumably why they
travelled with the set.

❓ **Still missing:** the masked-implementation references (Migliore 2019,
Azouaoui 2022, Coron 2023/2024) named in the task memo for the
"why we rely on liboqs rather than hand-rolled hardening" argument. Not among
the uploads.

### 2.2 Systematic Timing Leakage Analysis — the scope boundary is the point

Source: *"PQDSS Candidates: Tooling and Lessons Learned"* (✅ page 1), a slide
deck on the NIST **additional signatures** round.

⚠️ **ML-DSA is not in this study.** Verified by count in both the deck and
the full paper: `dilithium` and `ml-dsa` appear **0 times**. The 15 primitives
are NIST **additional-signatures** (PQDSS) candidates — SNOVA, Preon, LESS,
Mirath, PERK, UOV and others. **This paper says nothing about ML-DSA's
constant-time properties and must never be cited as if it does.**

**✅ Full paper now supplied**, resolving both open flags — and correcting
both. Adjonyo, Bardin, Bellini, Dione, Al Ameen, Merget, Recoules et al.,
*Systematic Timing Leakage Analysis of NIST PQDSS Candidates: Tooling and
Lessons Learned*.

**Scale**, ✅ lines 78-82:

> "Our method allowed us to analyze **302 instances of 15 primitives**… we
> reported the **26 most critical issues** to the respective authors, among
> which **5 have been already acknowledged as critical vulnerabilities and
> fixed** by their developers, namely the alerts from SNOVA and Preon from
> round 1 and LESS (2 alerts) and Mirath from round 2."

⚠️ **The task memo's "Binsec/Rel had 0% false positives across 22 alerts" is
not what the paper says.** Two errors: the count is **26 reported issues**, not
22, and the precision claim is qualified. ✅ lines 94-96, verbatim:

> "…faster, has better code coverage, and flags more issues, Binsec/Rel2
> achieves a much higher precision with respect to its constant-time policy. In
> particular, **on a small subset of benchmarks for which we manually checked**,
> Binsec/Rel2 always raises alerts that are actual constant-time violations,
> while **67% of TIMECOP alerts turned out not to be actual constant-time
> violations**."

So: Binsec/Rel2 raised no false positives *on a manually-checked subset*, and
the 67% figure is TIMECOP's false-positive rate, not Binsec's. Citable
sentence:

> Binsec/Rel2 raised no false positives on the subset the authors manually
> verified, against a 67% false-positive rate for TIMECOP.

Adopt `Binsec/Rel2` and `dudect` as named acceptance criteria for the liboqs
backend; `side_channel_resistant = True` must rest on measurement, not build
flags. ✅ toolchain published at `github.com/Crypto-TII/pqdss-ct-toolchain`.

**⚠️ The PERK framing in the task memo is not supported — but the paper gives
something better.** There is no PERK developer-response narrative; PERK appears
only as tested instances (✅ lines 395-404, one `!` on `perk-128-short-5`).
What the paper does contain is a *general methodological* finding, ✅ lines
257-262:

> "Another common source of irrelevant CT violations is found in algorithms
> using **rejection sampling**… This **inherently creates a variable execution
> time**, as a different number of sampling operations are performed based on a
> secret. **This variable execution time is usually not exploitable, as the
> secret is typically not used directly.**"

That is stronger than a single-candidate anecdote: it is the authors' general
position on rejection sampling, and it corroborates this project's own
reasoning about ML-DSA's 11.5× spread.

⚠️ **But cite it for the reasoning, not as a finding about ML-DSA** — ML-DSA is
not in the tested set (below). And note the direction of difference honestly:
the paper says such variance is *usually not exploitable*, whereas
`THREAT-MODEL.md` takes the more conservative line that it disqualifies the
pure-Python backend from online signing. QResP is stricter than this source,
not supported by it. Saying so is better than implying agreement.

---

## 3. Crypto-agility examples (`RESULTS.md` §7)

### 3.1 Two HAWK results, independently sourced, must not be merged

✅ van Gent & Pulles (CWI), *"HAWK: Having Automorphisms Weakens Key"*,
lines 7-12:

> "…a nontrivial automorphism of the underlying integer lattice. Knowledge of
> such a nontrivial automorphism speeds up the key recovery attack on HAWK **at
> least quadratically, which would halve the number of security bits**. Luo et
> al. (ASIACRYPT 2024) recently found an automorphism that breaks omSVP…"

| | existing §7 entry | this paper |
|---|---|---|
| mechanism | unrelated | known nontrivial lattice automorphism, building on Luo et al. ASIACRYPT 2024 |
| shape | exponential reduction (~2⁶⁴ → ~2³⁸) | **quadratic** speedup, halves security bits |
| source | AI-system result, specific date | CWI academic paper |

⚠️ Both support "algorithm margin erodes faster than expected." **They are
different results and neither corroborates the other.** Present as two
independently-sourced instances, distinguished by citation and by mechanism.
Two independent examples is a stronger argument than one; conflating them
would be a factual error a HAWK-aware reviewer would catch instantly.

---

## 4. Fail-stop signatures — future work only

✅ Lines 17-21: the construction is `FSS.SPHINCS` — "SPHINCS+ (now
standardized as SLH-DSA) augmented with a fail-stop mechanism", developed via
Lamport signatures as the running example.

⚠️ **This does not resolve the classical-identity caveat and must not be
presented as doing so.** The mechanism depends on compressing hash functions
admitting multiple valid preimages — a property of hash-based chain
constructions (WOTS+/XMSS/FORS/SPHINCS+). It does not extend to discrete-log
schemes (Ed25519, ECDSA P-256 — this project's identity anchor) or to lattice
schemes (ML-DSA). Making it apply is new research.

Future Work wording:

> Detecting a classical-identity forgery in the wild — as opposed to bounding
> when it could have occurred — requires a fail-stop mechanism. These exist
> today for hash-based signatures (FSS.SPHINCS) but not for the discrete-log
> or lattice schemes this design depends on; constructing one is future work
> and is not attempted here.

### 4.1 Flame — the historical motivating example

✅ Lines 27-32:

> "Take the example of Flame [26], a malware that exploited forged Microsoft
> certificates… Flame was exploiting collisions on MD5 thanks to a forensic
> tool for collision attack to MD5. **But what if the research world had not
> caught up with the attack?**"

This is the Introduction's motivating example, and it is a better one than any
hypothetical: a real forged code-signing certificate, exploiting a break in an
algorithm that was already known to be weakening, undetected until independent
cryptanalysis caught up. It motivates the temporal-trust-boundary mechanism
directly — the question "when was this signed, relative to when the algorithm
fell?" is exactly what nobody could answer about Flame at the time.

---

## 4b. Measured: strict DER rules out most commercial TSAs

Not a citation but a measurement, recorded here because it is the kind of
concrete deployment fact a paper section on ecosystem friction can use.

Probed 2026-07-30, eight public RFC 3161 authorities, one request each
(`scripts/verify/probe_tsa.py`):

| authority | result |
|---|---|
| `tsa.swisssign.net` | ✅ parses |
| `ts.ssl.com` | ✅ parses |
| `freetsa.org/tsr` | ✅ parses |
| `timestamp.digicert.com` | ❌ non-canonical DER |
| `timestamp.apple.com/ts01` | ❌ non-canonical DER |
| `rfc3161.ai.moda` | ❌ non-canonical DER |
| `timestamp.sectigo.com` | connection reset |
| `timestamp.entrust.net` | connection reset |

**Three of eight — including DigiCert and Apple — emit a CMS
`SignedData::certificates` SET that is not sorted in DER order.** RFC 5652
types that field as a `SET OF`; DER requires the elements of a SET OF to be
sorted by encoding. `rfc3161-client` enforces this and rejects the whole
response with `InvalidSetOrdering`.

⚠️ **`sigstore-python` verifies with the same parser**, so this is not
peculiar to QResP: a strict-DER verifier cannot consume timestamps from a large
share of the commercial TSA population, including two of the most widely
deployed. Worth stating carefully in the paper — the claim is *these responses
are not canonical DER*, not *these TSAs are broken*; they are widely trusted and
interoperate fine with lenient parsers.

The point for the paper is the gap itself: specification conformance and
deployed practice have diverged far enough that a correct verifier is the one
that struggles. Loosening the parser would trade a real property — that a
signed structure has exactly one valid encoding — for compatibility, which is
the trade this project exists to argue against.

## 5. Newly identified sources — related work, not requested

Four uploads were not in the task memo. Two are directly load-bearing.

### 5.1 Atlas (Intel Labs) — the closest related system ⚠️ read before submitting

✅ *"Atlas: A Framework for ML Lifecycle Provenance & Transparency"*,
Spoczynski, Melara, Szyller (Intel Labs), arXiv 2502.19567v2.

**Known to the author since early July; not yet integrated.** It remains the
nearest neighbour to QResP and the highest-priority related-work gap. A USENIX
reviewer in ML supply chain will know it, so related work must state explicitly
what QResP does that Atlas does not — on current evidence, direction-typed
temporal evidence and algorithm-lifetime rescue. **That differentiation claim
must be checked against Atlas's actual mechanisms before it is written**, not
asserted from the abstract.

### 5.2 Kalu et al. — industry interview study of software signing

✅ *"An Industry Interview Study of Software Signing for Supply Chain
Security"*, USENIX Security '25.

Same venue, adjacent topic, one cycle earlier. Two uses: qualitative evidence
for *why* signing adoption is low, complementing this project's quantitative
0.39%/0.10% measurement; and a venue-fit signal — USENIX has recently accepted
work on exactly this problem.

### 5.3 Wang et al. — backdooring merged models

✅ *"From Purity to Peril: Backdooring Merged Models From 'Harmless' Benign
Components"*, USENIX Security '25. Threat motivation: model merging composes
components whose provenance is unverified. Cite in the introduction for why
artifact-level provenance matters in ML specifically.

### 5.4 Poisoned Acoustics — marginal

*"Poisoned Acoustics: Targeted Data Poisoning Attacks on Acoustic Vehicle
Classification"* (Dahme, preprint). Data-poisoning threat, not supply-chain
provenance. Weak fit; include only if the introduction needs a second
poisoning example, and note it is a non-peer-reviewed preprint.

---

## 6. Open flags

1. **❓ Binsec/Rel false-positive figure and PERK case study** — not
   extractable from the slide deck; verify before writing.
2. **❓ The five TCHES/masking papers** — named in the task memo, not
   resolvable from the NXP deck. Fetch DOIs individually.
3. **⚠️ Atlas is uncited** and is the closest prior system. Highest-priority
   related-work gap.
4. **⚠️ M-26-15 calls hybrid a "stopgap."** Quote both halves.
5. **✅ Registry regime DECIDED (2026-07-30): M-26-15.** The classical
   entries must move from `2030-12-31` to **`2031-12-31`**, the Phase 4
   signature-migration deadline, since QResP is a signing tool and Phase 3's
   2030 date governs key establishment. Pending change, not yet applied:

   | file:line | field | from | to |
   |---|---|---|---|
   | `algorithms.py:89` (`ed25519`) | `disallowed_after` | `2030-12-31` | `2031-12-31` |
   | `algorithms.py:100` (`ecdsa-p256`) | `disallowed_after` | `2030-12-31` | `2031-12-31` |
   | `algorithms.py:110` (`ecdsa-p384`) | `disallowed_after` | `2030-12-31` | `2031-12-31` |
   | `algorithms.py:118`, `:126` (RSA) | `disallowed_after` | `2030-12-31` | `2031-12-31` |
   | all classical entries | `source` | SP 800-131A Rev.2 | OMB M-26-15 Phase 4 (2026), implementing EO 14412 |
   | new field | `regime` | — | `omb-m-26-15` |

   The `regime` field stays, because the date is regime-dependent: an NSS
   deployment is on CNSA 2.0 (2027) and would need different data. Encoding
   one date with no statement of which regulation it comes from is what
   produced this ambiguity.

   **This feeds the rescue branch and now the registration-statement call
   site, so the value is load-bearing twice.** `test_algorithms.py` will need
   its date assertions updated in the same change.

6. **❓ Masked-implementation references still missing** — Migliore 2019,
   Coron 2023/2024, named in the task memo for the liboqs-over-hand-rolling
   argument, are not among the uploads.
