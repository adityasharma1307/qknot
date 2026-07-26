# Disclosure email draft — HuggingFace security

**To:** security@huggingface.co
**Cc:** (optional) Dr. Tamizharasan Periyasamy, project supervisor
**Subject:** 162 public repositories with names matching the user access token format

---

Hello,

I am a final-year Computer Science student at BITS Pilani Dubai Campus. While
enumerating the public model registry for an academic study of cryptographic
provenance in ML supply chains, I found a pattern that looks like accidental
credential exposure and wanted to bring it to you directly.

**What I found**

162 public model repositories, across 147 distinct accounts, have repository
names matching the HuggingFace user access token format exactly: the literal
prefix `hf_` followed by 34 alphanumeric characters.

161 of the 162 have exactly 34 characters after the prefix. That uniformity is
what makes me think this is not coincidence — freely chosen repository names do
not cluster on a single length. Twelve of the accounts have more than one such
repository, which suggests a repeatable workflow error rather than isolated
slips. My guess is that users are pasting a token into the repository name
field, or that a script is passing a token where the name argument belongs.

**What I have not done**

I have not tested whether any of these strings is a valid credential, and I do
not intend to. Attempting authentication with someone else's token would be
unauthorised access regardless of how the token became visible.

So the accurate statement is that 162 repository names match the token format —
not that 162 tokens are live. Some may already be revoked or expired, or may be
strings that merely resemble the format. Verifying that is something only you
can do safely.

**How I found it**

Incidentally. I enumerated the full registry (2,938,107 repository ids as of
2026-07-25) to build a sampling frame for a stratified audit of model signing.
One of these repositories was drawn into my random sample, and GitHub's push
protection blocked my commit because it recognised the name as a token. That is
what prompted me to check the rest of the frame.

**What I can send you**

I have the complete list of the 162 repository identifiers. I have deliberately
kept it out of every public artefact of my research, including my GitHub
repository. I will send it over whatever channel you prefer — please just tell
me where.

**Two suggestions**

1. Reject repository names matching the access token pattern at creation time.
   This appears to cost nothing and would prevent the entire class.
2. Extend secret scanning to repository metadata, not only file contents.
   GitHub's scanner caught this pattern on the way in; the same string is
   currently live in your public namespace.

**One thing I should flag**

My research may be submitted for academic publication. If this finding is
included, it would appear only as aggregate statistics — counts and the
detection pattern — with no account names, no repository names, and no
credential material. I would be glad to share the relevant section with you
before submission if that would be useful, and I am happy to delay publication
of this particular finding if you would like time to act on it.

Thank you for your time.

Aditya Sharma
B.E. Computer Science, BITS Pilani Dubai Campus
f20230265@dubai.bits-pilani.ac.in

---

## Notes before sending

* Check whether HuggingFace prefers a different intake. They have a
  `security@huggingface.co` address and a security policy on their GitHub
  organisation; if there is a published `SECURITY.md` or a HackerOne programme,
  use that instead and mention you are following their stated process.
* Do not attach the list to the first email. Wait for them to nominate a
  channel.
* Keep a copy of what you sent and when, in the incident log.
* If you get no reply in 14 days, send one polite follow-up. If still nothing,
  the finding is aggregate and anonymised, so publication remains reasonable —
  but note the attempted contact in the paper.
