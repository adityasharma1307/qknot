# Vendored OMS v1.0 schemas

Copied verbatim from [ossf/model-signing-spec](https://github.com/ossf/model-signing-spec),
`main` branch. Apache-2.0.

    schemas/v1.0/*.json      -> the four OMS schemas
    test-vectors/v1.0/valid  -> vectors/
    algorithm-registry.md    -> the registry as published

## Upstream state when vendored

| Repository | Last commit | Notes |
|---|---|---|
| `ossf/model-signing-spec` | **2026-05-15** | source of every file here |
| `sigstore/model-transparency` | 2026-07-13 | reference implementation, not vendored |

Those dates come from the GitHub archive timestamps, which stamp every file
with the commit date of the ref. Each repository shows one uniform timestamp,
and the two differ, which is what confirms they are genuine commit dates rather
than download artefacts.

The spec was therefore already about two months old when it was retrieved on
2026-07-26. That matters: the relevant question is not "has it changed in the
last few days" but "has anything landed since 15 May".

## Why vendored rather than fetched

So `tests/signing/test_oms_compatibility.py` runs offline and against a fixed
revision. A compatibility claim is only meaningful relative to a specific
version of the spec; testing against `main` would mean the claim silently
changes meaning whenever upstream does.

## Detecting upstream drift

    python scripts/verify/check_oms_upstream.py

Fetches the live spec, compares it byte for byte with these copies, and checks
whether the three gaps this project reports are still open:

1. `signature` closed to an `algorithm` field, so hybrid verification is
   undefined
2. hash enums admit no SHA-3
3. the registry names no post-quantum algorithm

Exit codes: `0` no drift, `1` drift detected, `2` upstream unreachable.
The `2` is deliberately distinct from `0` -- "could not check" and "checked and
fine" are different states, and conflating them is how a stale claim survives
into a submission.

## Drift check run 2026-07-26: NO DRIFT

`scripts/verify/check_oms_upstream.py` reached upstream and reported:

```
upstream HEAD : a0c91e2c9302  2026-05-15T01:56:15Z
subject       : Add OMS v1.0 specification (#9)

  [SAME]  algorithm-registry.md
  [SAME]  predicate.schema.json
  [SAME]  statement.schema.json
  [SAME]  envelope.schema.json
  [SAME]  bundle.schema.json

  [OPEN]  registry names no post-quantum algorithm
  [OPEN]  signature is still closed to an algorithm field
  [OPEN]  hash enums remain ['blake2b', 'blake3', 'sha256']
```

All five vendored files are byte-identical to upstream, and **all three reported
gaps remain open**. The upstream commit date confirms the 2026-05-15 figure
recorded above from archive timestamps, which were inferred rather than read
from git — two independent methods agreeing on the date.

The spec has therefore had no commit in the ten weeks to 2026-07-26. The claim
"OMS v1.0 has no post-quantum path" is current as of that date, not merely as of
when these files were vendored.

### A wrong URL nearly read as a withdrawn spec

The checker previously pointed at `github.com/openssf/model-signing-spec` and
got a flat HTTP 404 on every file. The GitHub organisation is **`ossf`**, not
`openssf` — the project is called "OpenSSF" in all its prose, which is precisely
how the mistake survived.

Worth recording because of how the failure presented: a 404 on every path is
equally consistent with "the specification has been withdrawn", which would have
been a dramatic and completely false finding. The script's refusal to treat
unreachable as "no drift" (exit code 2, `Nothing was verified. This is not the
same as 'no drift'`) is what kept a wrong URL from becoming a wrong conclusion.

## When a gap closes

`TestSpecGapsWeAreReporting` in `test_oms_compatibility.py` asserts that OMS
**rejects** what this project needs. Those tests are designed to fail when
OpenSSF fixes the spec.

**That failure is the signal to revise the paper, not to patch the test.**

If it happens, in order:

1. Record what changed and when, here.
2. Revise the spec proposal -- the contribution shifts from reporting a gap to
   providing a reference implementation of the fix, which is still a
   contribution but a different one.
3. Restate the Phase I motivation as historical: "as of 2026-05-15, OMS had no
   post-quantum path", with the date, rather than in the present tense.
4. Re-vendor with `--update` only once the paper reflects the new state.

Running the drift check before submission is worth more than running it often.
