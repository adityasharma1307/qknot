# QResP key registration: authenticating a PQC key off classical PKI, durably

This is an implementation spec, not prose. It defines the registration
statement, the proof-of-possession, the transparency anchoring, and the
verification algorithm — the last including the temporal rescue that is the
point of the whole design.

It composes existing modules and adds no new cryptography:

* `signing/registration.py` — the statement and the identity cross-check.
* `signing/transparency.py` — the RFC 3161 / log upper bound (opaque-byte
  hashing, so the log never sees ML-DSA).
* `signing/temporal.py` — `assess`, now evaluating the registration's timestamp
  against the deprecation date.

## 0. The one idea

Fulcio attests `classical_key ↔ identity`. It will not attest an ML-DSA key.
So we use the classical attestation, **while it is still valid**, to vouch for
the ML-DSA key, and we log that vouching in transparency. The log timestamp
proves the vouching happened before the classical algorithm was deprecated, so
the binding survives the classical algorithm's death. The PQC key is *born*
from classical PKI and *outlives* it.

## 1. The registration statement

A DSSE envelope. `payloadType` is the registration media type; the payload is
canonical JSON.

    payloadType: application/vnd.qresp.key-registration+json

    payload:
      {
        "specVersion":   "1",
        "identity":      "alice@example.com",         // OIDC subject
        "issuer":        "https://accounts.google.com",// OIDC issuer
        "classicalKey":  { "algorithm": "ecdsa-p256",
                           "publicKey": "<base64 SPKI>" },
        "pqcKey":        { "algorithm": "ml-dsa-87",
                           "publicKey": "<base64 raw>" },
        "created":       "2026-08-01T00:00:00Z",       // RFC 3339, UTC
        "notAfter":      "2028-08-01T00:00:00Z",       // optional self-limit
        "recoveryKey":   { "algorithm": "ed25519",     // optional; see s.5.1
                           "publicKey": "<base64 SPKI>" }
      }

`recoveryKey`, if present, is authorised AT REGISTRATION TIME -- while the
primary classical anchor is still valid -- to sign a revocation for this
`(identity, pqcKey)` binding at any future time, including after
`classicalKey`'s algorithm is disallowed. It should be a DIFFERENT classical
family than `classicalKey`, so the two do not break on the same date; a
recovery key on the same broken algorithm buys nothing. **Concretely, under
EO 14412 / OMB M-26-15 the registry disallows ecdsa-p256 AND ed25519 on the
same date (2031-12-31), so ed25519 is NOT an independent recovery key for a
p256 primary -- they die together.** The genuinely independent choice is the
ML-DSA key itself (no disallow date) or an algorithm under a different regime;
whichever is chosen, `binding_trust` evaluates it on its own date. Because it sits inside the PAE-covered payload, it is fixed by the
classical signature at registration and cannot be added or altered afterwards
-- section 5.1 states the property the verifier must actually confirm rather
than assume.

**Two signatures over the same `PAE(payloadType, payload)`**, which DSSE
supports natively:

    signatures:
      - keyid: "<fingerprint of classicalKey>"
        sig:   "<base64>"
        # verification material: the Fulcio cert chain for classicalKey
        cert:  "<base64 DER>"
      - keyid: "<fingerprint of pqcKey>"
        sig:   "<base64>"
        # no cert: this key is what is being registered; nothing vouches for
        # it yet, which is the entire reason this statement exists

The classical signature carries a Fulcio cert (identity attestation). The PQC
signature is bare. Requiring **both** is the proof of possession: the classical
one says "identity X asserts this", the PQC one says "and X holds the PQC
private key". One without the other lets an attacker register a public key they
do not control, or claim an identity they do not hold.

## 2. Anchoring in transparency

Log **`SHA-256(PAE(payloadType, payload))`** as the `hashedrekord`, and reuse
`signatures[0]` -- the Fulcio-backed classical signature -- directly as the
entry's `signature.content`. **No fresh signing step over the hash**: this is
the same DSSE-to-hashedrekord construction Rekor v2 uses generally, and the
registration statement gets no special treatment.

Precision matters because it is load-bearing: inclusion-proof verification
requires byte-exact agreement on what was hashed. It is the PAE of the payload,
not the whole envelope with its signatures -- so the hash is a function of the
signed claim alone, and adding or reordering signatures cannot change it.
`SignedRegistration.signed_bytes` (registration.py:181) already returns exactly
`pae(payloadType, payload)`, so the hashed pre-image is already in hand.

The artefact-bundle submission path and the registration submission path share
this hashing, so it MUST be one function, not two copies -- a second copy is
where the two paths silently disagree on the pre-image and an inclusion proof
stops validating for a reason nobody can see.

Keep the **inclusion proof** and the **signed entry timestamp (SET)**. Its
`integratedTime` is the upper bound `T`: the registration existed by `T`.

## 3. The registration bundle (self-contained)

Everything a verifier needs, so verification is offline:

    {
      "envelope":       <the DSSE registration statement>,
      "classicalChain": [<Fulcio leaf>, <intermediates>],
      "inclusionProof": <Rekor Merkle inclusion proof>,
      "entryTimestamp": <Rekor SET>
    }

## 4. Verification algorithm

Inputs: the registration bundle; trusted Fulcio roots; the trusted log public
key; the verification instant `now`; and a deprecation policy giving, per
classical algorithm, its disallow date `D` (e.g. NIST IR 8547: ECDSA P-256
disallowed 2035-01-01).

**Validate configuration before touching attacker-controlled bytes.** Empty
trust roots or an absent log key are a configuration error and must raise
before any parsing — the discipline already in `transparency.verify_timestamp`.

    1. Parse the DSSE envelope. Require payloadType == the registration media
       type. Recompute pae = PAE(payloadType, payload).

    2. Verify the classical signature over `pae` with the public key in the
       Fulcio leaf. Fail -> REJECT.

    3. Verify the Fulcio chain to a trusted root. Extract identity (SAN) and
       issuer (OIDC claim). Fail -> REJECT.

    4. Cross-check payload against the cert: payload.identity == SAN identity,
       payload.issuer == issuer. Mismatch -> REJECT.
       (This is registration.verify_registration today.)

    5. Verify the PQC signature over the SAME `pae` with payload.pqcKey. Fail
       -> REJECT. Steps 2 and 5 together are proof of possession of both keys.

    6. Verify transparency: the digest PARSED FROM the proven entry body (a
       hashedrekord's spec.data.hash) equals SHA-256(PAE(payloadType, payload))
       -- never a free-standing digest field, which would let a real proof be
       rebound to a different registration; the inclusion proof validates
       against the log key; the log's checkpoint/SET is valid.
       Extract T = integratedTime. Any failure -> the registration has no
       trustworthy time, so treat as un-rescuable in step 7.

    7. TEMPORAL DECISION, on the classical algorithm's disallow date D:
         a. now < D                     -> classical attestation still valid.
                                           TRUSTED (basis: direct).
         b. now >= D  AND  T < D  AND
            step 6 succeeded             -> classical attestation is dead now,
                                           but the timestamp proves the binding
                                           existed while it was alive.
                                           TRUSTED (basis: rescued-by-timestamp).
         c. now >= D  AND (T >= D or no
            valid timestamp)             -> nothing proves the binding predates
                                           the classical algorithm's death.
                                           REJECT.

    8. Revocation: reject if the log holds a revocation statement (section 5)
       for (identity, pqcKey) whose revokedAt is <= the artifact's signing time.
       A registration with a later-superseding revocation is not trusted for
       signatures made after revokedAt.

    9. Output: a trusted binding { identity, pqcKey, validAsOf: T,
       basis: direct | rescued }. The caller may now verify an artifact's
       ML-DSA signature against pqcKey.

Step 7 is `temporal.assess` with the registration's `T` as the upper bound and
`D` as the deprecation boundary — the same code that rescues an artifact
signature, evaluating a key binding instead.

## 5. Revocation

A DSSE envelope, `payloadType: application/vnd.qresp.key-revocation+json`:

    { "identity": ..., "pqcKeyFingerprint": ..., "reason": ...,
      "revokedAt": "<RFC 3339>" }

Signed **by the classical/Fulcio identity only** — deliberately NOT by the PQC
key. You revoke precisely when the PQC key may be compromised, so requiring its
signature would make a compromised key un-revocable. An attacker holding the
PQC key alone cannot forge a revocation; an attacker holding the OIDC identity
can, which is the same root-of-trust limit as everything else here.

Log it. Verifiers in step 8 honour the earliest valid revocation for a key.

### 5.1 Recovery-key revocation, for after the primary anchor breaks

Step 7's rescue handles forged registrations and forged revocations
symmetrically: both carry a log timestamp `T`, and both fail the rescue when
`T >= D`. The asymmetry it does NOT handle is a *legitimate* signer who finds
their PQC key compromised through some channel unrelated to the classical
break, AFTER their classical anchor's algorithm is disallowed. Their genuine
revocation would carry `T >= D` and be rejected by the very logic that
correctly rejects forgeries. Missing re-registration after the break costs only
availability; missing a genuine post-break revocation leaves a
known-compromised key trusted forever. That is the real gap, and it is why
`recoveryKey` exists.

A revocation may therefore be signed by either:

* the original `classicalKey` — unchanged, subject to the same step-7 temporal
  logic as any classical signature; or
* the `recoveryKey`, if one was designated in the registration. A
  recovery-key-signed revocation is honoured **regardless of the primary
  `classicalKey`'s disallow date**, because the recovery key's authorisation
  was itself established and logged before the primary broke.

Two checks the verifier MUST make, neither optional:

1. **The recovery key was actually designated.** Reject a recovery-key
   revocation for a binding whose logged registration carried no `recoveryKey`,
   or a different one. Do not trust any signature that merely verifies — verify
   it against the recovery key fixed in the original, PAE-covered, logged
   payload.
2. **The recovery key's OWN algorithm is evaluated on ITS OWN date.** Run the
   step-7 temporal decision again, against the recovery key's algorithm and its
   disallow date `D_r`, not the primary's. If the recovery algorithm is also
   past `D_r` with no rescuing timestamp, the revocation is rejected — which is
   exactly why a recovery key on a different, independently-timed family than
   the primary is a documented RECOMMENDATION, not merely an option.

## 6. Trust roots and residual risk, stated plainly

* **The root is the OIDC IdP.** Compromise X's OIDC (not their keys) and you can
  register your key as X. This inherits Sigstore's trust model exactly — no
  weaker, no stronger. It must be stated in any user-facing threat model.
* **Detection, not prevention, for rogue registrations.** Because every
  registration is logged, X or a monitor can *detect* a registration X did not
  make — the Certificate Transparency model. Monitoring is a burden on X, not
  automatic.
* **The rescue depends on an honest deprecation policy `D`.** If a verifier is
  configured with the wrong `D`, step 7 decides wrongly. `D` should come from a
  cited, dated source (NIST IR 8547) and be recorded in the verification output.
* **First registration has no prior anchor.** The very first binding for an
  identity is trusted on the OIDC attestation alone; there is no
  transparency-of-transparency. This is the base case and cannot be otherwise.
* **Recovery after the primary classical anchor is disallowed requires a
  pre-authorised recovery key, designated at registration time, ideally on an
  independently-timed algorithm (section 5.1).** Without one, a compromised PQC
  key discovered after the primary anchor's disallow date cannot be revoked
  through this mechanism — recovery in that case requires an out-of-band
  process. This is a stated, resolved limitation, not an open question: the
  `recoveryKey` field closes it for anyone who plans ahead, and the base case
  (no recovery key designated) is the explicit sibling of the "no prior anchor"
  limit above, not a fix for it. **Out of scope, future work:** recovery-key
  rotation, M-of-N recovery, and recovery when no recovery key was ever
  designated.

## 7. CLI surface, and the true size of `register`

### `qresp verify-registration` -- BUILT

Offline and complete (src/qresp/cli.py). Resolves the whole chain and names the
basis it trusted -- direct or rescued-by-timestamp -- rather than a bare yes.
`--at` asks how the binding looks at a future instant; `--artifact-signed-at`
additionally runs notAfter and revocation and prints the authorised PQC key.

### `qresp register` -- BUILT as a thin orchestrator behind a client seam

An earlier note under-scoped this as two sockets. It is a small protocol, and
`signing/register.py` now implements all of it as a THIN orchestrator -- it
composes the sealed pieces and reimplements no checkpoint/SET/chain math:

    1. OIDC + Fulcio: certify the classical key (FulcioClient)         [SEAM]
    2. classical keygen (ephemeral P-256)                              [OURS]
    3. hold the long-term PQC key                                      [OURS]
    4. build the dual-signed registration envelope (classical + PQC)   [OURS]
       identity + issuer taken FROM the cert, never free-typed
    5. submit a hashedrekord (digest = rekord_preimage, signature =
       the classical DSSE signature) to the log (RekorClient)          [SEAM]
    6. fetch the inclusion proof + checkpoint/SET (the client response) [SEAM]
    7. map the response into a LogEntry (log_entry_from_rekor, shared)  [OURS]
    8. assemble the RegistrationBundle AND verify it end to end before
       returning -- a bundle that logs but does not verify is a failure [OURS]
       (revocation stays a SEPARATE path, as before)

The two network operations (steps 1 and 5-6) live behind a Protocol seam
(`FulcioClient`, `RekorClient`), so the orchestration is pure, offline-tested
logic (`test_register.py`, fake clients minting the same trust stack): the
emitted bundle verifies to a DIRECT binding, identity comes from the cert, the
temporal rescue holds, and the mandatory round-trip REFUSES an unverifiable
bundle. The real-network adapter and the one-time capture are
`scripts/register/capture_registration.py`, run on a machine with network +
browser OIDC; the captured bundle is locked by `test_registration_fixture.py`
(skips until present). That capture is the only step that cannot run offline.

### Still a composition step: artefact verification end to end

`qresp verify --registration` in the sense of "verify an artefact's hybrid
signature, authorised by a trusted binding" is not yet a single command. The
pieces exist -- `verify_registration_chain` -> `authorize_for_artifact` yields
the trusted PQC key, and the existing `verify` checks a hybrid signature -- but
composing them into one artefact-plus-registration verdict is an unbuilt step.

`qresp verify` must report *what it checked and how the PQC key was trusted*, so
a verdict never hides its basis -- which is what this whole design exists to avoid.

## 8. Acceptance criteria for the implementation (adversarial, not "it verifies")

Each fix guards against a specific failure, so each needs a test that exercises
that failure -- a passing "verification succeeds" test proves nothing about
what the fix prevents. Matches the standard in `test_digest.py` /
`test_payload_coverage.py`.

**Fix 1 -- hashing precision.**
* A registration bundle's inclusion proof validates against an independently
  recomputed `SHA-256(PAE(payloadType, payload))` -- assert the exact byte
  equality of the pre-image, not merely that verification returns true.
* The artefact and registration paths call ONE shared hashing function; a test
  imports both entry points and asserts they resolve to the same callable (or
  produce identical digests on identical input), so a future copy is caught.

**Fix 2 -- notAfter, keyed to signing time.**
* A registration whose `notAfter` is in the past REJECTS an artefact signed
  after that date.
* The same registration still PARSES and inspects cleanly under
  `qresp verify --registration` -- ruled inapplicable, never reported corrupt
  or unparseable.
* The check uses the artefact's signing time `S`, not the verifier's `now`: a
  test with `S <= notAfter < now` must ACCEPT, proving `now` is not consulted.

**Fix 3 -- recovery key.**
* A revocation signed by a designated `recoveryKey` AFTER the primary
  `classicalKey`'s disallow date is HONOURED.
* A recovery-key revocation whose recovery algorithm is ALSO past its own
  disallow date, with no rescuing timestamp, is REJECTED (its own step-7 check).
* A recovery-key revocation for a binding that designated NO recovery key, or a
  different one, is REJECTED -- the verifier matches against the recovery key in
  the original logged payload, not any signature that happens to verify.
* Adversarial: a `recoveryKey` field spliced into a registration AFTER signing
  breaks the classical signature over the PAE-covered payload and is REJECTED.
  Confirm this against the actual envelope structure; do not assume it.

**Global.** The full suite passes after every change. The task is not complete
until the specific adversarial tests above exist, not just general
happy-path coverage.

## 9. Status after expert review (2026-08-01)

The review found two soundness holes; both are fixed with adversarial tests, and
the ordered "seal the trust logic" pass is done except one item that needs real
network-captured bytes.

| item | status |
|---|---|
| Bug 1 -- classical sig bound to the Fulcio leaf, SPKI equality | **fixed** (`1e0b5ff`); adversarial test: cert for key B, payload names key A -> reject |
| Bug 2 -- digest parsed from the proven leaf, no free digest field | **fixed** (`9829792`); adversarial tests: rebind a real proof -> reject; swap the body -> inclusion fails |
| Gap 3 -- STH format | **superseded**: fake `qresp-sth-v1` RETIRED; `verify_checkpoint` verifies the REAL Rekor note, tests sign the same real format |
| Gap 4 -- `register` framed as its real 8-step protocol, not two sockets | **done** (section 7) |
| single-sig `KeyRegistration` marked transitional | **done** |
| artefact-plus-registration as one command | **noted as an unbuilt composition step** (section 7) |
| **integration fixture from a REAL Fulcio leaf + REAL Rekor inclusion** | **DONE -- all checks pass on production bytes** |
| Residual 2 -- production soundness of `verify_log_entry` (real checkpoint + SET) | **done** (`bd676ea`); composed end-to-end on real bytes |
| Residual 1 -- path discovery in `verify_chain` (unordered CA pool) | **done** (`0e029df`); validates the real leaf from the raw pool |
| Residual 3 -- a real registration through full section 4 | **done** (`c5fe2f8`); real Fulcio cert + Rekor entry, trusted binding + temporal rescue on production bytes |

### Production parity: verified, 2026-08-02

A real Sigstore bundle was captured (`sigstore sign`) and every production-byte
consumer was run against it (`scripts/verify/check_sigstore_fixture.py`; locked
in as `tests/signing/test_sigstore_fixture.py`, which skips if the fixture is
absent). All five checks passed on FIRST contact with production bytes:

* `fulcio.verify_chain` validated a real Fulcio leaf -- empty subject, EKU, SCT,
  the identity in the SAN and the issuer in the private 1.1/1.8 extension -- and
  extracted `aditya.137.sharma@gmail.com` via `https://github.com/login/oauth`.
* `rekor.verify_inclusion_root` reconstructed the checkpoint root of a real
  **2,199,132,077-entry** tree from a 16-hash proof: the RFC 6962 inner/border
  split and `leaf_hash = SHA-256(0x00 || body)` are Rekor-correct.
* `hashedrekord_digest` parsed the digest out of Rekor's REAL entry body -- the
  Bug-2 parser reads the production shape, not only the test double.
* The REAL checkpoint note signature verified under the Rekor key: the root is
  the log's own claim, so the qresp-sth-v1 test double's job is covered by
  working code against a real SET.

### Second review pass (2026-08-02): residuals 1 and 2 closed

The reviewer classified the residuals more sharply. Residual 2 was NOT "polish":
it was a hole in the **production soundness of `verify_log_entry`**, because the
only signed-tree-head format that function accepted was a home-grown test double
-- so a real adapter would either reject real Rekor material or fake a signature
around a real root. Residual 1 was an **API-honesty** gate, not a forgery hole:
wrong intermediate order failed closed for honest inputs, but the ordering had to
be done outside the module. Both are now closed, in `src/`:

* **Residual 2 -- `verify_log_entry` authenticates real Rekor material.**
  `rekor.verify_checkpoint` parses and verifies a REAL Rekor checkpoint
  (Go-sumdb signed note) and RETURNS the `(tree_size, root)` the log signed; the
  inclusion proof must reconstruct THAT signed root, not a submitted field.
  `rekor.verify_set` verifies the SET (`inclusionPromise`), so `integratedTime`
  -- the number the whole temporal rescue turns on -- is the log's signed claim,
  not an unauthenticated field (this went one step beyond the literal ask: a
  verified root with an unverified time would have left the softest input to the
  rescue open). `logID == SHA-256(log key)` binds the entry to the trusted log.
  The `qresp-sth-v1` fake format is RETIRED, not hidden: unit tests now sign the
  SAME real formats with a test key (`tests/signing/_rekor_doubles.py`). Real
  bytes taught one thing offline tests could not -- a sharded log has TWO
  indices: the SET signs the GLOBAL `logIndex`, the Merkle proof uses the
  shard-local `inclusionProof.logIndex` (`proof_index < tree_size <= log_index`).
  `LogEntry` now carries both. Locked by
  `test_sigstore_fixture.py::TestComposedVerifyLogEntryOnRealBytes`, which runs
  `verify_log_entry` end-to-end on the real entry.

* **Residual 1 -- `verify_chain` does path discovery.** It takes the
  intermediates and the trusted roots as UNORDERED pools and finds
  leaf -> intermediate(s) -> root itself (`_build_path`, length-capped and
  loop-guarded), so a TUF `trusted_root.json` CA pool is passed as-is. The two
  pools stay separate on purpose -- collapsing to one would let a bundle supply
  its own anchors -- and trusted roots index first, so a look-alike cannot shadow
  a real root. The duplicate path builders in the harness and script are deleted.
  Locked by `test_fulcio_chain.py::TestPathDiscovery`; the production fixture now
  validates the real leaf from the raw unordered pool.

### Residual 3: CLOSED -- a real registration verifies on production bytes (2026-08-02)

3. **The `register` orchestrator is built** (`signing/register.py`) as a thin
   8-step composition behind a `FulcioClient`/`RekorClient` seam, with a shared
   `log_entry_from_rekor` mapper and a MANDATORY round-trip verify before it
   returns a bundle. Tested offline against fake clients (`test_register.py`):
   DIRECT binding, identity-from-cert, temporal rescue, round-trip gate.

   And now proven on PRODUCTION bytes. One real registration was captured end to
   end against live Fulcio + Rekor (`scripts/register/capture_registration.py`):
   a real Fulcio cert over a real P-256 key, a real Rekor entry (checkpoint +
   SET), run through `verify_registration_chain` with no special cases.
   `test_registration_fixture.py` RUNS (3 passed): full section 4 -> trusted
   binding; a tampered-payload rejection; and the temporal rescue past the
   classical disallow date. The ML-DSA-87 signature made at capture time verifies
   in a SEPARATE backend install -- real cross-implementation FIPS-204 interop.

   Three honest fixes the real capture surfaced, none in the trust core: the
   REST client normalises Rekor's HEX rootHash/hashes to the base64 the bundle
   format uses (the verifier reconstructs the SIGNED checkpoint root, so a
   mis-decode failed loudly, not silently); `verify_log_entry` allows a 1-minute
   clock-skew on the "not in the future" sanity check (a real entry landed 0.4s
   ahead of the local clock; immaterial to the rescue's multi-year windows); and
   `register` verifies as of a fresh instant taken after the network round-trip.

   All three residuals are now closed in `src/`. The product surface on top of
   them is built too: `qresp register`, `qresp verify --registration` (the
   composed verdict), and `--check-revocations` (the live search).

### 9.1 Revocation search, and the limit it exposed (2026-08-02)

`authorize_for_artifact` takes revocations as input, which is the right offline
API. The live search (`signing/revocation_search.py`, `--check-revocations`)
finds them, authenticating every candidate through the SAME `verify_log_entry`
path -- inclusion proof, signed checkpoint, SET -- so a "revocation" that the
log does not carry is worth nothing.

**The honesty rule is the whole feature.** A search returns an OUTCOME, never a
bare list, because these are different answers:

| outcome | meaning | conclusive? |
|---|---|---|
| `found` | authenticated revocations exist for this key | yes |
| `none-found` | searched; none | yes |
| `supplied` | the caller provided them; no search run | yes |
| `not-searched` | nobody looked | **no** |
| `failed` | the search broke, or candidates could not be examined | **no** |

Collapsing `failed`/`not-searched` into "no revocations" would hand a clean
verdict to anyone who can make the search fail -- block the network, rate-limit
the verifier -- which is far cheaper than attacking any of the cryptography. The
CLI therefore prints `revocations: NOT ESTABLISHED` rather than staying silent,
and `AuthorisedArtefact.revocation_status_is_conclusive` makes a caller branch
on it.

Two subtler cases are also inconclusive rather than clear, both tested:

* a candidate NAMING this key that fails to authenticate. It may be a real
  revocation whose proof someone damaged precisely so it would be skipped;
* the **suppression** direction generally: silently ignoring an unreadable
  candidate is the same unearned all-clear reached from the other side.

**A STRUCTURAL LIMIT, stated plainly.** Rekor's `hashedrekord` stores a DIGEST,
not the document. The log can prove a given revocation was logged and when, but
it cannot hand a verifier a statement it has never seen. So a revocation needs a
DISTRIBUTION channel as well as a log -- a published feed, a repository, an
internal service -- and the log's job is to authenticate and timestamp what that
channel serves. That is the right division (the channel need not be trusted,
because a statement it serves is only honoured once the log proves it), but it
is a real deployment requirement, not something the log provides for free. When
entries exist whose statements cannot be obtained, the outcome is `failed`, not
`none-found`.
