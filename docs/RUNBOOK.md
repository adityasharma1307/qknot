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

## History purge (done before public release)

A normal deletion commit is **not** enough for files already pushed: the blob
stays recoverable from history. Before this repository went public, both
classes of material were purged from every commit with `git filter-repo` and
force-pushed while the remote was still private.

### What was purged

| Pass | Paths | Why |
|---|---|---|
| 1 | `security/leaked_token_repos.redacted.json` | Aggregated 147 account names (see incident log) |
| 2 | Internal working notes: `docs/OPEN-QUESTIONS.md`, `docs/PAPER-SPRINT-PLAN.md`, `docs/EXPERT-REPORT-*.md`, `docs/TASK-D.md`, `docs/Phase2_Decision_Memo.docx`, `docs/RESULTS-FINAL.md` | Not public-facing; paper plan named unsubmitted venue/strategy |

Local copies of the disclosure lists may still exist on the author's machine
under `security/` (gitignored). They are not in git history.

### Re-verify any time (must print nothing)

```powershell
git log --all --oneline -- security/leaked_token_repos.redacted.json
git log --all --oneline -- docs/OPEN-QUESTIONS.md
git log --all --oneline -- docs/PAPER-SPRINT-PLAN.md
git log --all --oneline -- docs/EXPERT-REPORT-04-residual-3-closed.md
git rev-list --all --objects | Select-String -Pattern "redacted|OPEN-QUESTIONS|PAPER-SPRINT|EXPERT-REPORT|PRIVATE"
```

Or from a fresh clone (stranger's view):

```bash
git clone https://github.com/adityasharma1307/qresp.git /tmp/qresp-check
cd /tmp/qresp-check
# same commands as above — each must print nothing
```

### If you ever need the procedure again

```bash
git clone --mirror https://github.com/adityasharma1307/qresp.git qresp-purge.git
cd qresp-purge.git
pip install git-filter-repo
git filter-repo --invert-paths --path path/to/remove --force
git remote add origin https://github.com/adityasharma1307/qresp.git
git push --force --mirror origin
```

Then re-clone for ongoing work. Do not leave a bare `qresp.git/` mirror inside
the working tree (also remove extracted `qresp-0.1.0/` sdist trees). A helper
for local junk is `scripts/publish/local_cleanup.ps1`.

If the repo was ever public with a purged file present, ask GitHub Support to
GC unreachable objects; a private-only rewrite is enough for collaborator-only
exposure.
