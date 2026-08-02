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

## 7. CLI surface to build

    qresp register --identity-token <OIDC>  --pqc-key <path>
                   --classical-key <path or keyless>  --log <rekor url>
      -> emits a registration bundle (section 3)

    qresp verify --artifact <path> --bundle <artifact bundle>
                 --registration <registration bundle>
                 --policy <deprecation policy>  --at <now>
      -> resolves the full chain (sections 4 + the artifact's hybrid
         signature) and prints a verdict naming the basis: direct or
         rescued-by-timestamp, and the validAsOf time.

`qresp verify` must report *what it checked and how the PQC key was trusted*,
in the same spirit as the current verifier — a verdict that hides its basis is
the thing this whole design exists to avoid.

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
