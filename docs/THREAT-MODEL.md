# Threat model for `qresp.signing`

This document states what the signing pipeline protects against, what it does
not, and why the second list is not empty. It exists because the most common
way a cryptographic tool fails is not a broken primitive but a correct
primitive used outside the conditions it assumes.

---

## Summary

| | Offline release signing | Online signing service |
|---|---|---|
| **Supported** | yes, the target use case | **no** |
| Ed25519 backend | safe | safe |
| ML-DSA via `dilithium-py` | safe | **refused at runtime** |
| ML-DSA via liboqs | safe | safe (interface specified, not implemented) |

`sign()` requires an explicit `exposure` argument and raises
`BackendUnsuitable` if a non-constant-time backend is used online. That is a
hard error, not a warning.

---

## What is protected

**Artefact tampering.** Any change to a signed artefact changes its SHA3-256
digest, which changes the algorithm binding, which invalidates every signature.
For multi-file artefacts the manifest is length-prefixed and path-sorted, so
renaming or restructuring is detected as well as editing.

This includes files whose *contents* are deliberately not hashed. `.git`,
`__pycache__` and symlinks are excluded from hashing for good reasons, but every
excluded path is recorded — with its reason, and for a symlink its target — and
that list is bound into the manifest digest. Adding a file under `__pycache__`,
adding a symlink, or repointing an existing one all change the digest.

An earlier revision merely skipped them, leaving no trace, so all three were
invisible to verification:

```
clean tree              6b3cd61b...
+ __pycache__ payload   6b3cd61b...   unchanged, verification passed
+ symlink out of tree   6b3cd61b...   unchanged, verification passed
+ .git/hooks payload    6b3cd61b...   unchanged, verification passed
```

`__pycache__` made that a code-execution path: CPython loads a `.pyc` whose
header matches its source, so an attacker could add executable content to a
signed model and the signature would still verify. Fixed, with the three
attacks retained as regression tests in `tests/signing/test_digest.py`.

**Signature stripping.** The distinctive protection. A hybrid bundle carries
both Ed25519 and ML-DSA signatures, and both sign a binding that commits to the
*set* of algorithms in use. Deleting the post-quantum signature leaves a
classical signature attesting that two algorithms were present; editing the
declared suite to match changes the binding and invalidates what remains.
See `src/qresp/signing/combiner.py`.

**Future quantum forgery.** Ed25519 falls to Shor. ML-DSA rests on
Module-LWE, for which no efficient quantum algorithm is known. Because the
combiner prevents stripping, an artefact remains protected by the ML-DSA
signature even against an adversary who can forge the Ed25519 one.

**Undisclosed entropy substitution.** Every key records where its seed came
from, whether any quantum source contributed, and which contributions a third
party can independently verify. A PRNG-derived key cannot claim quantum
provenance. See `src/qresp/signing/entropy/`.

**Provenance-metadata forgery.** Signatures are computed over the DSSE
pre-authentication encoding of the entire in-toto statement, so the entropy
attestation, backend descriptors, signer notes and subject name are all covered.
An attacker cannot set `sideChannelResistant: true` on a backend that is not,
delete a note recording a PRNG fallback, or relabel a signature as covering a
different artefact — each invalidates every signature, in *all* verification
modes rather than only STRICT.

This closes a gap present in earlier revisions, where signatures covered the
algorithm binding alone and this metadata travelled inside the envelope while
being protected by nothing — the worst arrangement, since it looked signed. The
forgeries are exercised in `tests/signing/test_payload_coverage.py`, which
retains each attack as a regression test.

Note the two properties this does *not* provide, both below: the claims are
tamper-evident but self-asserted, and the signer's identity is unestablished.

---

## What is NOT protected

### Signer identity

`verify()` reads the public keys from the bundle itself, so it establishes *that
someone signed this*, **not** *that the expected party signed it*. An attacker
who re-signs a bundle with their own freshly generated keys produces something
that verifies cleanly.

Identity binding is a trust-anchor problem, not a signature-format problem.
Sigstore solves it with certificate chains and a transparency log; a
key-distribution scheme (pinned keys, a keyring, TOFU) would solve it too. This
package deliberately does not pick one, because the choice belongs to the
deployment. It should not be mistaken for a property provided here.

The practical consequence: a QResP bundle proves integrity, algorithm
non-separability and provenance metadata *relative to a public key you already
trust*. Establishing that trust is the caller's job.

### Signed metadata is tamper-evident, not witnessed

Signatures cover the entropy attestation, backend descriptors and signer notes
(see below), so nobody can alter them in transit. They remain **self-asserted**:
a signer who wants to claim a quantum entropy source they never used can write
that claim and sign it. No signature scheme fixes this — it is the same trust
placed in any signed statement about a process the verifier did not witness.

The one exception is the NIST beacon contribution, which records a pulse index
and value that a third party can re-fetch from NIST and check. That contribution
is externally verifiable; the rest is attested.

`verify()` reports these under `report["signed_claims"]` with a `_note` making
the distinction explicit.

### Upper bounds on signing time

The temporal trust boundary (`src/qresp/signing/temporal.py`) can only *rescue*
a post-deadline classical signature given an **upper** bound — evidence the
signature already existed before the algorithm's deadline.

The entropy attestation carries a NIST beacon pulse, which is a **lower** bound:
it proves the signature was made no *earlier* than the pulse. That is sufficient
to convict a signer who used a deprecated algorithm after its deadline, and
insufficient to establish that any signature predates one.

So a bundle produced by this package cannot, on its own evidence, have a
classical signature rescued after 2030. Obtaining an upper bound requires
publishing the signature to a transparency log and passing the inclusion proof
to `verify(time_evidence=...)`; this package does not perform that publishing
step. See the module docstring for why the two directions are not
interchangeable.

### Fault injection, when `--deterministic` is used

FIPS 204 defines two signing modes. **Hedged** (the default here and in the
standard) mixes 32 fresh random bytes into every signature; **deterministic**
uses a fixed zero value. Hedged is the recommended mode because the randomness
frustrates fault-injection attacks that recover key material by inducing errors
across repeated signings of the same message.

The cost of hedging is that signing is **not reproducible**: the same key over
the same artefact produces different signature bytes each time, so two bundles
are never byte-identical. Key generation is deterministic from the seed in
either mode; only the signature differs.

`--deterministic` (or `sign(deterministic=True)`) trades the fault-injection
margin for byte-reproducibility. It is the right choice for test vectors, a
demo notebook someone re-runs, and benchmark artefacts. It is the wrong choice
for release signing. When used, the bundle records the fact in its notes, so a
verifier can see which mode produced it.

### Timing side channels, for the pure-Python ML-DSA backend

`dilithium-py` states plainly that it "has not been designed to be secure
against any form of side-channel attack". That warning is about timing, not
correctness: the library reproduces NIST's ACVP FIPS 204 vectors byte for byte
across key generation, signing and verification
(`tests/signing/test_fips204_acvp.py`, 180 vectors, run on every test
invocation).

An earlier revision cited `run_ml_dsa_kats.py`, which ran round-3 **Dilithium**
KATs against the round-3 Dilithium module -- a different algorithm from the
ML-DSA the backend actually signs with, and therefore no evidence about it. See
`tests/signing/fips204_vectors/PROVENANCE.md`.

ML-DSA signing uses **rejection sampling**. It generates a candidate signature,
checks whether it falls within bounds, and retries if not. The number of
retries depends on secret key material, so signing duration leaks information
about the key.

Measured on this implementation:

```
60 signatures, one key, different messages
min 9.8 ms | median 19.1 ms | max 85.3 ms      8.7x spread

two different keys
key A median 19.6 ms | key B median 21.3 ms    1.6 ms separation
```

### Why we did not write our own implementation

It would be strictly worse. **Python cannot express constant-time code**:
arbitrary-precision integers take time proportional to their magnitude, the
garbage collector fires unpredictably, and bytecode dispatch is not under the
program's control. A hand-written implementation would inherit exactly this
exposure and add unvalidated NTT arithmetic, rejection bounds and byte
encodings on top — each a place to introduce a correctness bug that produces
signatures verifiable only by itself.

`dilithium-py` at least has published KATs and years of scrutiny from people
reading it against the specification.

### Why we did not add random delay

Injecting noise is the intuitive countermeasure and does not work. Averaging
suppresses zero-mean noise as 1/sqrt(N) while the secret-dependent signal stays
fixed, so an attacker simply collects more traces.

Measured, adding 0–50 ms of uniform random delay against the 1.6 ms signal
above — roughly 30x the leak:

| traces per key | attacker identifies the key correctly |
|---|---|
| 1 | 56.0% |
| 10 | 71.3% |
| 50 | 87.3% |
| 200 | **100.0%** |

Reproduced with `scripts/verify/measure_timing_leak.py`, 30 samples per key,
150 trials per row, noise ~9x the 5.3 ms signal.

Two hundred traces is complete recovery. Noise raises the number of traces
required by a constant factor; it does not close the channel. Doubling the
delay roughly quadruples the traces needed, which an attacker who can request
signatures obtains in minutes.

A noise wrapper is also *worse than nothing*, because it permits the claim
"side-channel mitigated", which invites exactly the deployment it cannot
protect.

### What does work: bound the exposure

A timing attack requires an adversary who can trigger signing operations and
measure each one.

**Offline release signing does not provide that.** A maintainer signs a release
on their own machine, at a moment of their choosing, and publishes the bundle.
There is no interface through which an attacker submits messages or observes
durations. An adversary able to time the signing loop already has code
execution on the signing host, and would take the key directly rather than
recover it through a statistical channel.

**An online signing service does provide it.** An endpoint that signs on
request lets the attacker choose the messages, control the timing, and collect
unlimited traces. Pure Python is disqualified there, and the library refuses.

This is scoping, not mitigation. The channel still exists; the workflow does
not expose it. Stating that honestly is worth more than a countermeasure that
does not work.

### Other exclusions

**Key storage.** Secret keys are returned as bytes. Storage, permissions and
HSM integration are the caller's responsibility.

**Power and electromagnetic analysis.** Out of scope entirely. Physical access
to the signing host defeats this and every software countermeasure.

**Beacon signature verification.** `verify_pulse_signature` is a documented
contract, not an implementation. The attestation records everything a third
party needs to check a NIST beacon pulse independently, and never claims the
check has been performed.

**Manifest completeness for OMS bundles.** A repo classified as
manifest-covered is trusted to have a complete manifest; the tool does not open
the DSSE payload to confirm every artefact is enumerated.

---

## For production use

Implement `SignatureBackend` over `liboqs-python`, whose ML-DSA is C with
constant-time discipline. The contract is specified in
`src/qresp/signing/backends.py::LibOqsBackend`. An implementation must:

1. set `side_channel_resistant = True` only after confirming the liboqs build
   used its constant-time options — the property belongs to the build, not the
   API;
2. record the liboqs version and build flags in `describe()`;
3. pass the same FIPS 204 KATs, so swapping backends cannot silently change
   signature semantics.

---

## Reproducing the measurements

```
python scripts/verify/run_ml_dsa_kats.py --limit 4     # functional correctness
python scripts/verify/measure_timing_leak.py           # the timing evidence above
```

Both are cited in the paper's limitations section. The timing numbers are
hardware-dependent; the *shape* of the result — spread proportional to
rejection-sampling iterations, and attack accuracy rising with trace count
despite added noise — is not.

---

## Identity registration: what it protects, and whom it does not

`signing/registration.py` binds an OIDC identity to a long-term post-quantum
key by way of a statement signed with a Fulcio-certified ECDSA P-256 key:

```
OIDC -> Fulcio certificate over P-256
     -> registration: "identity X vouches for ML-DSA key K"
     -> artefacts signed with hybrid(Ed25519, K)
```

P-256 is not a preference. It is the only algorithm that clears both
constraints at once: Fulcio certifies it, and it has an externalised prehash so
Rekor v2 will log the entry. Ed25519 fails the second; Ed25519ph fails the
first. The deployed identity ecosystem leaves exactly one usable path.

### The asymmetry, stated plainly

**Artefact integrity is post-quantum secure. Identity assurance is not.** An
adversary who breaks P-256 can forge a registration and therefore the binding
between a name and a key, even though they cannot forge the ML-DSA signature
over the artefact itself.

This is not hidden by the design; it is *concentrated* by it. One statement per
key carries the classical assumption instead of every artefact signature
carrying it. That makes the caveat easy to state precisely, easy to audit — one
object to check rather than thousands — and easy to replace wholesale if a
post-quantum CA appears.

### The boundary condition

**Only identities registered before P-256's deprecation deadline are
protected.** The mechanism is not retroactive.

An identity first appearing *after* P-256 is broken gains nothing: an adversary
who can forge P-256 can mint a registration for a key they control, and the
statement carries no property distinguishing it from an honest one. Registering
early is what buys the protection, and there is no way to buy it late.

Such an identity needs a **non-cryptographic bootstrap** — pinning, or
trust-on-first-use, or an out-of-band channel. That is a *complement* to this
mechanism, not a competitor: it addresses the population this mechanism cannot
reach, by different means and with different assumptions.

### One abstraction, two applications

Registration timestamps are assessed by `temporal.assess` — the same function,
the same `Bound`-typed evidence, the same soft-warn and hard-fail thresholds
that artefact signatures go through. "Was this signature made while its
algorithm was still trusted?" is one question, whether the signature covers a
model or a key-ownership claim.

`assess_registration` is a named call into that function and nothing more.
`tests/signing/test_registration.py` asserts the two paths produce *identical*
findings for identical evidence, so divergence is a test failure rather than a
silent gap: if the identity layer ever developed a window the artefact layer
does not have, an attacker would use it.

Note what is assessed: the algorithm the **statement** is signed with (P-256),
not the post-quantum key it vouches for. Checking the registered algorithm
would report the reassuring answer forever, since ML-DSA has no deadline.

### Out of scope: hardware-rooted identity

A TPM- or HSM-backed device attestation, or a post-quantum-capable CA, would
root identity in something an adversary with a quantum computer cannot forge.
That is the structural fix for the asymmetry above and it is **explicitly out of
scope here**, consistent with how this document treats hardware attestation
elsewhere. It is recorded as future work rather than gestured at as a mitigation
this project provides.
