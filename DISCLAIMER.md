# Disclaimer and limitation of liability

**Important.** This document is provided for transparency and risk allocation.
It is not legal advice. If you need legal advice for a specific use of this
work, consult a qualified lawyer in your jurisdiction.

## Nature of the project

QKnot (this software, its documentation, datasets, reports, figures, incident
notes, and related academic materials) is a **student research and educational
project** produced in connection with CS F376, BITS Pilani Dubai Campus
(2025–26). It is released as an **Alpha research / reference implementation**,
not as a commercial product, not as certified security equipment, and not as
professional security, legal, or compliance services.

## Persons and institutions covered

To the maximum extent permitted by applicable law, the following are **not
liable** for any claim, damage, or other liability arising from this work or
from reliance on it (collectively, the “Covered Parties”):

- the student author, **Aditya Sharma**;
- the project supervisor, **Dr. Tamizharasan Periyasamy**;
- **BITS Pilani Dubai Campus**, Birla Institute of Technology and Science
  (Pilani), and their officers, employees, and agents;
- any other contributor who submits code or documentation to this repository
  under the project license.

Naming a supervisor or institution does **not** mean they warrant the
software, endorse every claim, or accept liability for third-party use.

## No warranty

THE SOFTWARE AND ALL ASSOCIATED MATERIALS ARE PROVIDED **“AS IS” AND “AS
AVAILABLE”**, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
NON-INFRINGEMENT, ACCURACY, COMPLETENESS, SECURITY, OR FREEDOM FROM ERRORS OR
VULNERABILITIES.

In particular, and without limiting the foregoing:

- Cryptographic code may contain bugs. Passing tests, FIPS vectors, or live
  Sigstore checks does **not** guarantee correctness or fitness for
  production, regulated, or high-stakes use.
- Audit results are **measurements of public registries at particular times**,
  not guarantees about the present or future state of any package, publisher,
  or platform.
- Identity registration inherits the limits of OIDC providers, Fulcio, Rekor,
  and your trust configuration; see `docs/THREAT-MODEL.md` and
  `docs/REGISTRATION-SPEC.md`.

## No professional advice; no certification

Nothing in this repository is legal, regulatory, compliance, export-control,
or professional security advice. Using QKnot does **not** make an organisation
“compliant,” “post-quantum ready,” or certified under any standard. Supervisors
and the university are not providing consulting services by virtue of this
academic project being public.

## Third-party systems and data

This project discusses and may interact with third-party systems (including
but not limited to HuggingFace, npm, PyPI, Sigstore, Fulcio, Rekor, NIST
Beacon, and timestamp authorities). Covered Parties:

- do not control those systems;
- are not responsible for their availability, policies, or security;
- make no claim of affiliation with or endorsement by those parties unless
  expressly stated.

Public registry audits and incidental findings (for example, repository names
matching credential formats) are research observations about **publicly
visible** data. They are **not** accusations of intentional wrongdoing, not
proof that any credential is valid or live, and not an invitation to access
accounts without authorisation. Responsible disclosure practices are described
in `SECURITY.md` and `security/INCIDENT-2026-07-25-token-shaped-repo-names.md`.

## Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL ANY
COVERED PARTY BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS, DATA,
GOODWILL, OR BUSINESS OPPORTUNITY, ARISING OUT OF OR RELATED TO:

- the software or materials;
- use of, inability to use, or reliance on the software or materials;
- audit findings, threat models, or security-related statements;
- third-party systems, packages, or identities discussed or measured here;

WHETHER IN CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY, OR
OTHERWISE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

If liability cannot be fully excluded in your jurisdiction, it is limited to
the greater of (a) the amount you paid for the software (typically zero) or
(b) the minimum amount required by mandatory law.

## Acceptable use

You are solely responsible for ensuring that your use of this software and of
any data you process with it complies with applicable law, third-party terms of
service, and ethical norms (including computer misuse, privacy, and
unauthorised access laws). Do not use this software to attack systems, test
credentials you do not own, or process data you are not allowed to process.

## Relationship to the MIT License

The software is also licensed under the MIT License in `LICENSE`. That license
already disclaims warranties and limits liability for the authors and copyright
holders. **This disclaimer supplements** the MIT License for research context,
named academic parties, and audit/disclosure materials. If there is a conflict
on a pure licensing grant of rights, the MIT License controls; if there is a
conflict on research/disclaimer wording, the stricter limitation in favour of
the Covered Parties applies to the extent allowed by law.

## Contact

Project contact for non-security questions: the author via the repository or
the email listed in `pyproject.toml` / `SECURITY.md`. Security reports: see
`SECURITY.md`.
