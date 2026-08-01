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
        "notAfter":      "2028-08-01T00:00:00Z"        // optional self-limit
      }

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

Log `SHA-256(DSSE envelope)` as a `hashedrekord`. Rekor accepts a hash and a
signature over it; it never parses the ML-DSA signature inside, because to the
log the envelope is opaque bytes. Same property that makes RFC 3161 TSAs
algorithm-agnostic.

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

    6. Verify transparency: the logged hash equals SHA-256(envelope); the
       inclusion proof validates against the log key; the SET is valid.
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
