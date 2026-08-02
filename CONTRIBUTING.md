# Contributing

This started as a university design project and has grown past that scope.
Contributions, bug reports and questions are welcome — this file is mostly so
a pull request doesn't have to guess at conventions the codebase already
follows.

## Setting up

```bash
git clone https://github.com/adityasharma1307/qresp
cd qresp
pip install -e ".[dev,analysis,register]"
```

`dev` gets you the test suite and linters; `register` gets you `qresp
register` / `qresp trust-material` (OIDC + the TUF client); `analysis` gets
you the notebook dependencies. None of the three are needed for `qresp sign`
/ `qresp verify` or the audit commands.

## Running the checks

```bash
python -m pytest              # ~1256 pass offline; 57 skip (need network or a fixture)
ruff check src/ tests/ scripts/
mypy src/qresp/signing         # strict=true on signing/; looser on audit/ and cli.py, see pyproject.toml
```

Tests that genuinely need a socket are marked `allow_network` and skip by
default (`tests/conftest.py` closes the network otherwise) — if you add one,
mark it, and explain in the test why it can't be an offline fixture instead.

## The two halves stay separated

`qresp.signing` does not import anything from `qresp.audit`, and does not
depend on `huggingface_hub`, `transformers` or `datasets`.
`tests/signing/test_package_boundary.py` fails the build if that's violated.
The signing/identity half is meant to be usable by anyone who needs
post-quantum-ready signatures with honest provenance — firmware, datasets,
container images, anything that isn't a HuggingFace model. If a change to
`qresp.signing` only makes sense in terms of ML models or HuggingFace, it
probably belongs in `qresp.audit` instead, or as a thin adapter on top.

## Verifiers report what they didn't check, not just what passed

This is the one convention worth internalising before writing a verification
path: a verdict must distinguish "checked, and it was fine" from "not
checked" from "checked, and it failed" — never collapse the first two.
Concretely: `error` rows in audit data are not `unsigned` (an unreachable
repository was never examined, so it isn't known to be unsigned);
`revocation_status_is_conclusive` is `False` when the search couldn't be
completed, and the CLI prints `NOT ESTABLISHED` rather than staying silent;
`covers this sig: not checked` is a real, distinct outcome from "covers this
sig: yes". If you're adding a check, ask what it should report when it
*can't* run — a network failure, a malformed input, a missing file — and make
that outcome distinguishable from a clean pass. `docs/REGISTRATION-SPEC.md`
section 9.1 and `tests/signing/test_revocation_search.py` are the fullest
worked example.

## Tests read as documentation

Test names and docstrings in this codebase tend to state the property being
defended, not just the mechanism ("it never claims an all-clear it did not
earn" rather than "test_find_revocations_2"). New tests should follow that —
a test file should be readable as a description of what could go wrong and
why the code prevents it.

## Live-network validation scripts

`scripts/verify/*.py` validate specific adapters against real Sigstore/Rekor
infrastructure rather than fakes — they're how residual claims in
`docs/REGISTRATION-SPEC.md` get demonstrated instead of merely asserted. They
are not part of the test suite (they need live network and sometimes OIDC)
but if you touch a REST adapter (`src/qresp/signing/sigstore_clients.py`,
`fulcio.py`, `rekor.py`), running the matching script against real
infrastructure before opening a PR is worth doing — offline fakes can't catch
a mismatch between what the client assumes and what the live API actually
returns.

## Security issues

Please don't open a public issue for a security-relevant bug (a soundness gap
in a verifier, a bypass, etc.) — see [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the project's [MIT License](LICENSE).
