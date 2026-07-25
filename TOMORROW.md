# Where we left off — 2026-07-25

218 tests passing, red team clean (0 failures, 4 warnings, all understood).

## Done today

**Phase I repo rebuilt as `qresp2`.** The published `qresp` repo is untouched
and archived. Datasets are date-stamped; `data/DATASETS.md` records provenance
for all of them.

**The 20,000-repo stratified audit ran.** Head is a census of the top 10,000 by
downloads; the tail is a uniform random draw of 10,000 from the 2,928,107
outside it, seed 20260725, and `scripts/redteam_check.py` confirms the seed
regenerates the published draw byte for byte from the frame.

| | head | tail | ratio | Fisher exact |
|---|---|---|---|---|
| signed | 39 / 10,000 = 0.390% | 10 / 10,000 = 0.100% | 3.9x | p = 3.8e-05 |
| vulnerable | 36 / 10,000 = 0.360% | 10 / 10,000 = 0.100% | 3.6x | p = 1.5e-04 |
| post-quantum | 0 | 0 | n/a | p = 1 |

**Task 4 (QRNG) is complete.** `src/qresp/qrng.py`, `qresp entropy` CLI,
42 tests.

## Bugs found and fixed

* **OpenPGP parser read the wrong byte.** It took offset 3 of a v4 signature
  packet, which is the hash algorithm, not the public-key algorithm. Because
  hash ids 1/2/3 collide with public-key ids 1/2/3, every modern SHA-256
  signature came back unparseable and legacy SHA-1 ones reported as RSA. The
  GPG detection path had never worked. Fixed, with a byte-exact regression test
  built from a real Thireus artefact.
* **Rate limits were recorded as findings.** A 429 during signature fetch was
  written to the dataset as a permanent `error` record and then skipped forever
  by resume. Transient failures now leave no record, so resume retries them.
* **The tenacity retry was dead code.** It named the builtin `ConnectionError`
  and `TimeoutError`; nothing the HTTP stack raises inherits from those.
* **Enumeration had no checkpointing.** A connection reset lost 1.44M
  enumerated ids. Now checkpointed per page.
* **Unretrievable repos were labelled `unsigned`.** 58 tail repos that had been
  deleted or gated counted as evidence of non-signing. Now `error`.
* **The head stratum had 10,002 rows**, a union of two snapshots. Trimmed.

## Open questions for you

1. **ML-DSA-44 vs 65.** Task 5 locks 44 as default with `--security-level=44|87`.
   The Phase II ablation design (configs B/C/D) and the AffixIO citation both
   use 65, which the flag does not offer. Unresolved; blocks Task 5.

2. **ANU requires an API key now.** The memo locks ANU as "public HTTPS API, no
   auth". ANU has migrated to `api.quantumnumbers.anu.edu.au`, which needs a
   free key, and is retiring the unauthenticated endpoint. Both are supported
   and the deprecation is surfaced in the attestation, but Task 7 wants a Colab
   notebook "fully reproducible without hardware QRNG access", which a keyed
   default breaks. Options: register a key; ride the legacy endpoint while it
   lasts; or let the notebook fall back to PRNG and present the resulting
   attestation as the demonstration. I lean to the third.

3. **Three gated CohereLabs repos** stay unclassified. The sensitivity table in
   `DATASETS.md` shows every conclusion survives all three treatments,
   including the worst case where all three are post-quantum. Recommend
   reporting as a limitation rather than inferring.

## Next up

* **Task 5** — hybrid signing. Needs the OMS `algorithm-registry.md` field
  names before the bundle schema is finalised; my fetches of the spec repo came
  back empty, so that needs doing from your side or another source.
* **Task 2** — the Section 4.3 sentence, whenever the report is rebuilt.
* `reconcile_labels` returns `ERROR` for `[VULNERABLE, ERROR]`, discarding a
  known-vulnerable signature. Latent: 0 repos currently affected.
* Positive provenance notes: a direct parse currently records no note, so
  "parsed" and "note lost" look identical in the data.

## Running things

```
python -m pytest -q                          # 218 tests
python scripts/redteam_check.py              # full verification, re-derives the draw
python stats.py --head data/head_10k_2026-07-25.jsonl \
                --tail data/longtail_10k_2026-07-25.jsonl \
                --manifest data/longtail_manifest_2026-07-25.json
```

The 108 MiB sampling frame is gitignored (over GitHub's 100 MiB limit) and
regenerable; its SHA-256 is in the manifest.
