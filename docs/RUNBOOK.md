# Runbook: the 20,000-model stratified audit

Everything below runs on your machine.

## 0. Use PowerShell, not cmd

The commands below are PowerShell. If your prompt looks like
`C:\...\qresp2>` you are in cmd.exe, and `$env:VAR = "..."` will fail with
"The filename, directory name, or volume label syntax is incorrect."

```
powershell -NoExit
```

Then, once inside PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Windows blocks unsigned `.ps1` files by default; this unblocks them for the
current window only, which is the narrowest scope that works.

To stay in cmd instead, set the variable with `set HF_TOKEN=hf_...` and invoke
the script as
`powershell -ExecutionPolicy Bypass -File scripts\audit\run_20k_audit.ps1 -Step estimate`.

## 1. Set the token

```powershell
$env:HF_TOKEN = "hf_xxxxxxxxxxxxxxxxxxxx"
```

Read-only scope is enough — get one at <https://huggingface.co/settings/tokens>.
This is set for the current window only, which is intentional: it keeps the
token out of your shell history file and out of the repo. `.env` and `*.token`
are gitignored, but the simplest way not to leak a credential is not to write
it down.

## 2. Measure before committing

```powershell
.\scripts\audit\run_20k_audit.ps1 -Step estimate
```

Pages the registry five times and projects the total request count and wall
clock from what it actually observes. Writes nothing. My own estimate is
roughly 12,000–13,000 requests, but that rests on an assumed registry size,
so trust this output over my arithmetic.

## 3. Run it

```powershell
.\scripts\audit\run_20k_audit.ps1
```

Four steps, in order. It prompts once after the estimate before doing anything
expensive.

| Step | What it does | Output |
|---|---|---|
| 1 head | Audits the top 10,000 by downloads | `data\head_10k_<date>.jsonl` |
| 2 sample | Enumerates the registry, draws 10,000 ids | `data\longtail_sample_<date>.txt` + frame + manifest |
| 3 tail | Audits those 10,000 ids | `data\longtail_10k_<date>.jsonl` |
| 4 stats | Three-block stratified analysis | `logs\stats_<date>.txt` |

Step 2 is the long one. It pages through the whole registry, because that is
what a genuinely uniform draw costs. Safe to leave running; it logs progress
every 100 pages.

## If it stops

Rerun the same command. Steps 1 and 3 resume, and step 2 reuses the frame
without re-enumerating.

```powershell
.\scripts\audit\run_20k_audit.ps1 -Step tail
```

Models that hit a rate limit or a dropped connection are deliberately **not**
written to the output, so rerunning retries exactly those and nothing else.
If the counts come up short, that is the mechanism working, not a failure.

If you see `Aborting: N consecutive transient failures`, the network or the
token is in trouble rather than any individual model. Wait, then rerun the same
step. Nothing is lost.

## Things not to do

**Do not concatenate the two strata.** The combined estimate weights them by
population size: the head is a census of 10,000, the tail is a 10,000-model
draw from millions. Merging the files would treat those as equally weighted and
produce a number that means nothing.

**Do not change `-Seed` or `-Date` mid-run.** The seed defines which sample you
drew, and the date is how the steps find each other's output.

**Do not rerun a scan onto a path that already holds a finished dataset.** This
is the rule that came out of the 2026-05-21 dataset being overwritten in place;
see `docs\DATASETS.md`.

## Filename deviation, flagged

The Phase I memo specifies `data\head_10k.jsonl` and
`data\longtail_10k.jsonl`. The script writes date-stamped names instead, for the
reason in `docs\DATASETS.md` — an undated filename is exactly what let the July
re-scan overwrite the published May dataset. To follow the memo literally,
remove `_$Date` from the three path assignments near the top of
`scripts\audit\run_20k_audit.ps1`.

## Afterwards

```powershell
python -m qresp.audit.stats --head data\head_10k_<date>.jsonl `
                --tail data\longtail_10k_<date>.jsonl `
                --manifest data\longtail_manifest_<date>.json
```

Send me `logs\stats_<date>.txt` and the manifest and I will pick up from there.
Nothing touches `report.tex`.

---

## Purging the account list from history (do this before going public)

`security/leaked_token_repos.redacted.json` was removed from the working tree
and the index on 2026-08-02 (see `docs/OPEN-QUESTIONS.md` §0). That is **not
sufficient on its own**: the file had already been pushed to `origin/main`, so
the blob is in the remote's history and a normal deletion leaves it recoverable
by anyone who can read the repository. The moment visibility flips, "recoverable
by anyone who can read the repository" means the public.

This is the one step that cannot be automated from a sandbox: it rewrites every
commit and needs a force-push with your credentials.

### The procedure

Work on a **fresh clone**, so a mistake costs nothing:

```bash
# 1. mirror-clone somewhere scratch
cd /tmp
git clone --mirror https://github.com/adityasharma1307/qresp2.git qresp2-purge.git
cd qresp2-purge.git

# 2. purge the blob from every commit on every ref
pip install git-filter-repo          # once
git filter-repo --invert-paths \
    --path security/leaked_token_repos.redacted.json --force

# 3. confirm it is gone from ALL history, not just the tip
git log --all --oneline -- security/leaked_token_repos.redacted.json
#    ^ must print NOTHING

# 4. confirm the PRIVATE list was never there either
git rev-list --all --objects | grep -i PRIVATE
#    ^ must print NOTHING

# 5. push the rewritten history back
git remote add origin https://github.com/adityasharma1307/qresp2.git
git push --force --mirror origin
```

Then **re-clone fresh** for ongoing work, or run the same `filter-repo` in your
working copy — the old clone's objects still contain the blob locally.

### Two things people get wrong here

**GitHub keeps unreachable objects.** After a force-push, the old commits are
unreferenced but not immediately deleted, and on a public repository they can
still be fetched *by SHA* by anyone who knows it. If this repository was ever
public with the file present, ask GitHub Support to run garbage collection
before considering the removal complete. If it has only ever been private (the
case here), the exposure was limited to collaborators and the rewrite is
sufficient — but do the rewrite **before** flipping visibility, not after.

**Forks and caches.** A rewrite does not touch forks, and it does not touch any
mirror or archive that pulled the repository earlier. Confirm no forks exist
before relying on the purge.

### Verifying it worked, from a stranger's position

```bash
git clone https://github.com/adityasharma1307/qresp2.git /tmp/qresp2-check
cd /tmp/qresp2-check
git log --all --oneline -- security/leaked_token_repos.redacted.json   # nothing
git rev-list --all --objects | grep -iE 'PRIVATE|redacted'             # nothing
```

Both must print nothing. Until they do, do not make the repository public.
