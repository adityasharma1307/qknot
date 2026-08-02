# Incident log: repository names matching the HuggingFace access-token format

**Date found:** 2026-07-25
**Found by:** Aditya Sharma, incidental to the QResP Phase II registry enumeration
**Status:** reported to security@huggingface.co on 2026-07-25. **No reply as of
2026-08-02.** Absent confirmation that the credentials were remediated, the
account list is NOT published -- see "Publication decision" below.
**Full identifiers:** `security/leaked_token_repos.PRIVATE.txt` (gitignored,
local only, never committed -- verified absent from all git history)
**Redacted evidence:** removed from git (tip and history) on 2026-08-02 and
gitignored. A local copy may still exist on the author's machine only — it is
not part of the published repository. It listed 147 distinct account names;
the repository names those accounts hold are public on HuggingFace, so the
8-character prefixes were never the exposure — the account list was. See
"Publication decision".

---

## Summary

162 public HuggingFace repositories, across 147 distinct accounts, have
repository names that exactly match the format of a HuggingFace user access
token: the literal prefix `hf_` followed by 34 alphanumeric characters.

These were found while enumerating the entire model registry (2,938,107 repo
ids) to build a sampling frame for the QResP stratified audit. They were not
sought; the pattern surfaced when GitHub's push protection blocked a commit
containing one of them, which the random sample had happened to draw.

## Why this looks like credential exposure rather than coincidence

**The lengths cluster on one value.** 161 of 162 have exactly 34 characters
after the `hf_` prefix. One has 41. Freely chosen repository names do not
concentrate on a single length; a token format does.

**The prefix is not a common naming choice.** `hf_` followed by high-entropy
mixed-case alphanumerics is not a plausible human naming convention for a model
repository, and none of these names contain the words, versions or separators
that normal model names do.

**The most likely mechanism is a mis-filled form field.** A user prompted for a
token pastes it, then pastes the same clipboard contents into a "repository
name" field, or a script creating repos programmatically passes the token where
the name argument belongs. The result is a public repository whose name is a
credential.

**Twelve accounts have more than one.** `Amina-DS`, `Fasenok`, `JamesG101`,
`Lepertery`, `LouayN`, `Micoze`, `OrbelinaML`, `Sathvik077`, `aadickk`,
`ashwink2718`, `ct685`, `satouyuuba`. Repeated occurrences on one account point
to a repeatable workflow error rather than a one-off slip, which suggests the
underlying interface or tutorial is inviting the mistake.

## What has NOT been established

**No token was tested.** Whether any of these strings is a live, valid
credential has not been checked and must not be. Attempting authentication with
another person's token would be unauthorised access regardless of how the token
was obtained.

Consequently the correct claim is: *162 repository names match the access-token
format*, not *162 tokens are leaked*. Some may be revoked, expired, or strings
that merely resemble the format. That uncertainty belongs in any report.

## Scope

| | |
|---|---|
| Registry size enumerated | 2,938,107 repos |
| Token-shaped repo names | 162 |
| Distinct accounts affected | 147 |
| Rate | 0.0055% of repos |
| Snapshot date | 2026-07-25 |
| Detection pattern | `^[^/]+/hf_[A-Za-z0-9]{25,}$` |

The rate is low, but the population is the entire public registry, and each
instance is a plaintext credential-shaped string in a public namespace that is
indexed, mirrored and scraped.

## How this was found, and what it says about detection

GitHub's secret scanner caught this on push. HuggingFace evidently did not
catch it at repository-creation time, which is the point at which it would be
cheapest to prevent: a name matching `hf_[A-Za-z0-9]{34}` could be rejected
outright, and any existing match auto-revoked and the owner notified.

That asymmetry is the substance of the report. One platform blocks the pattern
on the way in; the other has 162 instances of it live in a public namespace.

## Suggested disclosure

Send to HuggingFace security (`security@huggingface.co`, or the security
advisory process on their GitHub org). Suggested content:

> While enumerating the public model registry for academic research on
> cryptographic provenance in ML supply chains (BITS Pilani Dubai, CS F376), I
> identified 162 public repositories across 147 accounts whose names match the
> HuggingFace user access token format exactly: `hf_` followed by 34
> alphanumeric characters. 161 of 162 share that exact length.
>
> I have not tested whether any of these are valid credentials and do not
> intend to. I am reporting the pattern so that you can verify and, if
> appropriate, revoke and notify the affected accounts.
>
> The full list is available on request. I have withheld it from all public
> artefacts of this research.
>
> Two suggestions: reject repository names matching the token pattern at
> creation time, and extend secret scanning to repository metadata rather than
> file contents alone.

Withhold the full list until they ask, then send it over whatever channel they
nominate.

## Handling in the research artefacts

One of these repos, `prince99/hf_…`, was drawn into the Stratum B random sample
and therefore appears in `data/longtail_10k_2026-07-25.jsonl` and
`data/longtail_sample_2026-07-25.txt`.

It has been retained rather than redacted. Removing it would break the
invariant that the audited set equals the drawn set exactly, which
`scripts/verify/redteam_check.py` asserts and on which the reproducibility of the
seeded draw depends. The identifier is already public on HuggingFace, so the
dataset discloses nothing new.

The remaining 161 appear only in the sampling frame, which is gitignored for
being over GitHub's file size limit — so they are not published.

If HuggingFace revokes these tokens, the repos may be renamed or deleted, at
which point the dataset row becomes a historical record of a repo that no
longer exists. That is expected and is exactly why the audit records registry
churn rather than silently dropping it.

## Publication decision (2026-08-02)

`security/leaked_token_repos.redacted.json` is not in the published repository:
it was deleted from the tree, purged from git history with `git filter-repo`,
and listed in `.gitignore` so it cannot be re-added by accident. A local copy
may remain on the author's machine for disclosure to HuggingFace only. The
reasoning, recorded 2026-07-27 and applied unchanged:

The redaction itself was sound -- 8 characters of a 34-character random suffix
is not brute-forcible, and the file contained no complete token-shaped string.
The exposure was never the prefixes. It was the **account names**, because the
repositories those accounts hold are already public on HuggingFace: a reader
could visit each account, list its public repositories, and recover the full
credential-shaped names unaided.

So the file's value was *aggregation* -- 2.9 million repositories distilled to
162 candidates -- and aggregation serves an attacker exactly as well as a
defender. Publishing it while any of those credentials may still be live would
turn a research artefact into a curated target list.

Nothing scientific is lost. This incident log records the method and the counts
without naming a single account, so every claim the paper makes remains fully
supported. The claim stays **"162 repository names match the token format"** --
never "162 tokens are leaked". No token was ever tested, deliberately: testing
another person's credential is unauthorised access regardless of intent.

If HuggingFace later confirms remediation, the decision can be revisited and the
file restored from the local copy, cited alongside their response.

## Follow-up

- [x] Report to HuggingFace security -- sent 2026-07-25
- [ ] Record the response and any revocation in this file (no reply yet)
- [x] Decide publication of the redacted list -- REMOVED, 2026-08-02
- [ ] Decide whether to include as an incidental finding in the paper. It is
      genuinely relevant to ML supply-chain security and arose from a census
      rather than a sample, which is a methodological argument for enumerating
      the whole registry. Do not name accounts if it is included.
