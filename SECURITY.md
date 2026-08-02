# Security policy

This project is research software released **AS IS**. Liability and warranty
limits for the author, supervisor, and institution are stated in
[`DISCLAIMER.md`](DISCLAIMER.md).

## Reporting a vulnerability in QResP itself

If you find a security issue in this code — a soundness bug in the signature
or registration verification, a way to make `verify` accept something it
should reject, or anything else with security impact — please report it
privately rather than opening a public issue.

**Email:** f20230265@dubai.bits-pilani.ac.in
**Subject line:** please start with `[QResP security]` so it doesn't get lost.

Include:

- what you found and why it matters (a forged verdict, a bypass, a crash on
  untrusted input, etc.)
- the smallest input/command that reproduces it
- which command or module is affected (`qresp sign`, `qresp verify`,
  `qresp register`, the audit scanners, ...)

I'll acknowledge within a few days. This is a student research project, not a
funded security team with an SLA — please be patient, and thank you for
reporting responsibly rather than exploiting or disclosing first.

### Scope

In scope: anything under `src/qresp/`, the CLI, and the verification logic
specifically — soundness of `qresp verify`, `qresp verify-registration`,
`qresp verify --registration`, and the revocation search.

Out of scope: the audit datasets under `data/` (these are measurements, not
attack surface), and third-party services QResP talks to (Sigstore, Fulcio,
Rekor, HuggingFace, npm, PyPI) — report issues in those directly to their own
security contacts.

## An unrelated finding, already handled

During the audit, this project found 162 public HuggingFace repository names
matching the token format (`hf_` + 34 characters) — a likely sign of
accidental credential exposure by those repositories' owners, not a
vulnerability in QResP. That was reported to security@huggingface.co
directly; see `security/INCIDENT-2026-07-25-token-shaped-repo-names.md` for
the full record, including what was and was not published and why.

## Supported versions

This is a research/reference implementation (Alpha, see the badges in
[README.md](README.md)), not a hardened production security product. There is
currently one line of development (`main`); security fixes land there.
