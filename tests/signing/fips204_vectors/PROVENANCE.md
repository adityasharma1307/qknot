# Vendored NIST ACVP test vectors for ML-DSA (FIPS 204)

Copied verbatim from the `assets/` directory of
[GiacomoPope/dilithium-py](https://github.com/GiacomoPope/dilithium-py), which
redistributes NIST's ACVP-Server vectors. Retrieved 2026-07-16, vendored
2026-07-27.

```
ML-DSA-keyGen-FIPS204/{prompt,expectedResults}.json     75 vectors
ML-DSA-sigGen-FIPS204/{prompt,expectedResults}.json     60 vectors
ML-DSA-sigVer-FIPS204/{prompt,expectedResults}.json     45 vectors
                                                       ---
                                                       180 total, 2.5 MiB
```

`internalProjection.json` is **not** vendored: it holds intermediate values for
debugging an implementation, which is not what these are used for here, and it
roughly triples the size.

## SHA-256 of every vendored file

```
635a05104f40b9578d4618a4b05308a742d706362655344f22a12d491a58a87f  ML-DSA-keyGen-FIPS204/expectedResults.json
c90cd9411b567a17a1e2755693ccd4fa48eeb6875be4ef463ed33e9a23103f25  ML-DSA-keyGen-FIPS204/prompt.json
1b78baf274be78c76dfefb46362e5fe58bb3a6859db86b3bd126e4cbc7ef3eb8  ML-DSA-sigGen-FIPS204/expectedResults.json
da759fd966f267a59327e9597a2a6ecb61d02a2e83584c9f6690d48419448287  ML-DSA-sigGen-FIPS204/prompt.json
73196368b70a5f1b6f9f190c572dd97bb46c20a1e86786a41064a4b80d1ef2e9  ML-DSA-sigVer-FIPS204/expectedResults.json
69f5327f0525fe9bc085d090214691f97c8cd45ff1d66afbf8263c322fe2602d  ML-DSA-sigVer-FIPS204/prompt.json
```

## Why these replaced the round-3 Dilithium KATs

The previous evidence for FIPS 204 conformance ran
`PQCsignKAT_Dilithium{2,3,5}.rsp` against
`dilithium_py.dilithium.Dilithium{2,3,5}`.

Both halves of that are the **round-3 Dilithium** submission. The backend this
project signs with is `dilithium_py.ml_dsa.ML_DSA_44`, which is **ML-DSA
(FIPS 204)**. They are different algorithms, not a renaming — measured on the
installed library:

| | Dilithium2 (round 3) | ML-DSA-44 (FIPS 204) |
|---|---|---|
| secret key | 2528 bytes | 2560 bytes |
| public key | 1312 bytes | 1312 bytes |
| signature | 2420 bytes | 2420 bytes |
| cross-verification | a Dilithium2 signature does **not** verify under ML-DSA-44 |

FIPS 204 changed the message encoding (a domain-separating
`0x00 || len(ctx) || ctx` prefix), the length of `tr`, and introduced the
hedged/deterministic `rnd`. A round-3 KAT exercises none of that.

So the old check passed, and validated a module the signing path never calls.
The claim "the ML-DSA backend reproduces the FIPS 204 known-answer tests byte
for byte" was not supported by what was being run. It is now.

`tests/signing/test_fips204_acvp.py::TestTheSchemesAreDistinct` pins both
measurements above, so nobody re-points the suite at the round-3 vectors on the
assumption that they are interchangeable.

## Why vendoring, rather than fetching

The vectors ship in dilithium-py's **source tree**, not its published wheel, so
`pip install dilithium-py` gives the implementation without them. Reproducing
the conformance claim previously required cloning that repository — meaning the
claim was, in practice, verified once and cited thereafter.

They are public NIST test data, redistributed under dilithium-py's licence, so
vendoring costs 2.5 MiB and buys a conformance check that runs in the ordinary
`pytest` invocation on any machine, offline.

## What the three files establish, and the trap in them

| File | Question |
|---|---|
| `keyGen` | does seed -> (pk, sk) match NIST byte for byte? |
| `sigGen` | does signing match NIST byte for byte? |
| `sigVer` | are **invalid** signatures rejected? |

`sigVer` is the one that earns its place. Its vectors are largely negative —
signatures mutated so a correct verifier must reject them. An implementation
whose `verify` returned `True` unconditionally would pass `keyGen` and `sigGen`
and fail only here. A test asserting the vectors contain both verdicts guards
against that class of vector file being silently replaced by an all-positive one.

**These vectors target the *internal* interface** (`ML-DSA.Sign_internal`,
FIPS 204 Alg. 7), which takes the message exactly as given. The public `sign()`
implements the external interface and prepends the context prefix first. Routing
the vectors through `sign()` fails all 60 sigGen cases — which is what happened
on the first run, and it looks like a broken implementation rather than a wrong
entry point.

Because ACVP validates the internal algorithm while `qknot.signing` calls the
external one, `TestTheExternalWrapper` additionally asserts the composition:
`sign(msg, ctx)` must equal `_sign_internal(0x00 || len(ctx) || ctx || msg)`.
Without that link, the path actually used in production would be unvalidated.

## Running it

```bash
pytest tests/signing/test_fips204_acvp.py -q     # 185 tests, ~7 s
python scripts/verify/run_fips204_acvp.py        # standalone report
```
