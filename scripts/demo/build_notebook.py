"""Generate notebooks/qresp_demo.ipynb.

WHY A GENERATOR RATHER THAN AN EDITED .ipynb
============================================
A notebook is JSON with source split into arrays of strings. Editing one by hand
means fighting escaping, and a diff of a hand-edited notebook is unreadable --
outputs, execution counts and metadata churn alongside the actual change. Here
the cells are plain Python strings, the diff is the text, and the notebook is a
build artefact that can be regenerated and re-executed.

    python scripts/demo/build_notebook.py          # write the notebook
    python scripts/demo/build_notebook.py --run    # write, then execute it

Task 7 of the Phase II memo. Decisions taken 2026-07-27:

  * signs `openai/privacy-filter` -- the one signed openai repo in the head
    stratum, already Sigstore/ECDSA-P256, so the demo shows a classical
    signature and a hybrid one over the same artefact;
  * the typosquat scenario uses a **synthetic** attacker built in the notebook.
    The registry does contain lookalike names, but they appear to be legitimate
    derivative work and naming them would assert bad faith on no evidence;
  * entropy is the NIST beacon (no API key, works in Colab) plus the system
    CSPRNG, which is exactly the split `mix_entropy` enforces;
  * signing is deterministic so a reader re-running the notebook gets identical
    bytes. Production signing is hedged; the notebook says so.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "notebooks" / "qresp_demo.ipynb"

CELLS: list[tuple[str, str]] = []


def md(text: str) -> None:
    CELLS.append(("markdown", text.strip("\n")))


def code(text: str) -> None:
    CELLS.append(("code", text.strip("\n")))


# ===========================================================================
md(r"""
# QResP — quantum-resilient provenance, end to end

**Phase II, Task 7.** CS F376 Design Project, BITS Pilani Dubai.

This notebook signs a **real HuggingFace model** with a non-separable hybrid
signature, verifies it, and then attacks it five different ways to show what the
construction does and does not protect.

It runs in Colab with no API keys and no hardware.

## What the audit found, in one line

Of **20,000** HuggingFace repositories surveyed (a census of the top 10,000 by
downloads plus a uniform random sample of 10,000 from the remaining 2.9M):

| | signed | post-quantum |
|---|---|---|
| head stratum | 39 / 10,000 | **0** |
| long tail | 10 / 10,000 | **0** |

Every signature found is breakable by Shor's algorithm. `openai/privacy-filter`
— the artefact this notebook signs — is one of the 39, and its signature is
**ECDSA P-256**.

So the demo is not hypothetical. It takes a model that is signed today with a
classically-secure scheme and shows what signing it for the post-quantum
transition looks like instead.
""")

code(r"""
# Setup. Makes the notebook self-sufficient in any kernel: Colab, a local
# venv, or the interpreter VS Code happens to have selected.
#
# Note `%pip`, not `!pip`. The magic installs into the kernel *running this
# notebook*; the shell escape installs into whatever `pip` resolves to on PATH,
# which is frequently a different interpreter. That difference is precisely how
# a notebook ends up reporting "No module named cryptography" for a package you
# can see is installed.
import importlib.util, sys, pathlib

REQUIRED = {                      # import name -> pip name
    "cryptography": "cryptography",
    "dilithium_py": "dilithium-py",
    "pydantic": "pydantic",       # qresp.audit.model
    "requests": "requests",
    "jsonschema": "jsonschema",
    "huggingface_hub": "huggingface_hub",
    "typer": "typer",             # the qresp CLI
    "rich": "rich",               # ditto
}
missing = [pip for mod, pip in REQUIRED.items() if importlib.util.find_spec(mod) is None]
if missing:
    print(f"installing into {sys.executable}: {' '.join(missing)}")
    %pip install --quiet {" ".join(missing)}

def _find_qresp():
    try:
        import qresp  # noqa: F401
        return "already importable"
    except ImportError:
        pass
    # Opened from a clone? Add its src/ rather than re-downloading. Search from
    # the notebook's directory too: VS Code runs with cwd=notebooks/.
    seeds = [pathlib.Path.cwd(), *pathlib.Path.cwd().parents]
    for base in seeds:
        for candidate in (base / "src", base / "qresp2" / "src"):
            if (candidate / "qresp" / "__init__.py").is_file():
                sys.path.insert(0, str(candidate))
                import qresp  # noqa: F401
                return f"local checkout at {candidate}"
    return None

REPO_ROOT = None
_status = _find_qresp()
if _status is None:
    !git clone --quiet https://github.com/adityasharma1307/qresp2.git
    sys.path.insert(0, "qresp2/src")
    import qresp  # noqa: F401
    _status = "cloned"

import qresp
REPO_ROOT = pathlib.Path(qresp.__file__).resolve().parents[2]

import qresp.signing as _s
print(f"qresp      : {_status}")
print(f"kernel     : {sys.executable}")
print(f"repo root  : {REPO_ROOT}")
""")

# ===========================================================================
md(r"""
---
## 1. The artefact, and the signature it already has

`openai/privacy-filter` carries a `model.sig` — a Sigstore bundle. Our audit
classified it `vulnerable` because Sigstore's Fulcio default is ECDSA P-256.

Downloading the full model is slow in Colab, so `LIGHT = True` fetches the
configuration, tokenizer and signature files only. **The manifest records
exactly what was signed either way**, so nothing is misrepresented — the
notebook prints the file list it actually covered.
""")

code(r"""
import os, socket
from pathlib import Path

MODEL = "openai/privacy-filter"
LIGHT = True   # False downloads the weights too (slower, same code path)
NET_TIMEOUT = 10  # seconds

# Fail fast rather than hang. A reader behind a proxy or an offline Colab would
# otherwise wait on the default multi-minute socket timeout with no output, which
# reads as a broken notebook rather than as "no network".
os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", str(NET_TIMEOUT))

def _reachable(host, port=443, timeout=5):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False

patterns = None if not LIGHT else ["*.json", "*.txt", "*.sig", "*.model", "*.md"]

try:
    # Import first, and report an ImportError as an ImportError. Catching it
    # alongside socket errors made a missing package print "Could not reach
    # HuggingFace", which sends you debugging the network instead of pip.
    from huggingface_hub import snapshot_download
    if not _reachable("huggingface.co"):
        raise ConnectionError("huggingface.co is not reachable from this runtime")
    local = Path(snapshot_download(MODEL, allow_patterns=patterns))
    ONLINE = True
except ImportError as exc:
    raise SystemExit(
        f"huggingface_hub is not installed in this kernel ({sys.executable}).\n"
        f"Re-run the setup cell at the top, which installs it with %pip."
    ) from exc
except Exception as exc:
    # Genuinely offline, or the repo moved. The notebook continues on a
    # synthetic artefact so every later cell still runs and still means
    # something -- an offline reader should not get a wall of red.
    print(f"Could not reach HuggingFace ({type(exc).__name__}); using a local stand-in.")
    # Built as a symlink farm on purpose: that is the shape huggingface_hub
    # produces (snapshots/<rev>/x -> ../../blobs/<sha>), and signing it was
    # broken until the manifest learned to follow links. An offline stand-in
    # that used plain files would exercise an easier layout than the real one.
    import shutil
    root = Path("hf-stand-in"); shutil.rmtree(root, ignore_errors=True)
    blobs, local = root / "blobs", root / "snapshots" / "rev"
    blobs.mkdir(parents=True); local.mkdir(parents=True)
    payload = {
        "config.json": b'{"architectures": ["DistilBertForTokenClassification"]}',
        "tokenizer.json": b'{"version": "1.0"}',
        "model.safetensors": b"synthetic weights" * 2048,
    }
    for i, (name, data) in enumerate(payload.items()):
        (blobs / f"blob{i}").write_bytes(data)
        try:
            os.symlink(os.path.relpath(blobs / f"blob{i}", local), local / name)
        except (OSError, NotImplementedError):
            (local / name).write_bytes(data)   # Windows without developer mode
    ONLINE = False

files = sorted(p.relative_to(local).as_posix() for p in local.rglob("*") if p.is_file())
print(f"{MODEL if ONLINE else 'synthetic artefact'}: {len(files)} files")
for f in files[:12]:
    print("   ", f)
if len(files) > 12:
    print(f"    ... and {len(files) - 12} more")
""")

code(r"""
# The existing signature, read with the project's own audit parser.
from qresp.audit.parse import parse_signature
from qresp.audit.model import SigFormat

sig = local / "model.sig"
if sig.is_file():
    result = parse_signature(sig.read_bytes(), SigFormat.SIGSTORE)
    print(f"existing signature : {result.algorithm.value}")
    print(f"provenance         : {result.notes}")
    print()
    print("ECDSA P-256 rests on the elliptic-curve discrete log problem, which")
    print("Shor's algorithm solves. This signature protects against tampering")
    print("today and against nothing at all once a CRQC exists.")
else:
    print("No model.sig in the downloaded subset (or offline); skipping.")
""")

# ===========================================================================
md(r"""
---
## 2. Entropy, with evidence rather than assertion

A key seeded from a quantum source and one seeded from `os.urandom` are
indistinguishable by inspection — both are 32 uniform-looking bytes. So a claim
of quantum provenance is unfalsifiable unless something is recorded.

Two kinds of source, and conflating them is catastrophic:

- **secret** (`os.urandom`, a QRNG) — provides *unpredictability*
- **public** (the NIST randomness beacon) — provides *verifiability* and a
  *timestamp*, and **no unpredictability whatsoever**, because everyone can read it

The beacon is therefore mixed in as the HKDF **salt**, never as key material.
`mix_entropy` raises if the only sources available are public — a hard error,
because a key derived from public values alone is computable by anyone.
""")

code(r"""
from qresp.signing.entropy.backends import SystemEntropyBackend
from qresp.signing.entropy.beacon import NistBeaconBackend
from qresp.signing.entropy.mixing import mix_entropy

# The beacon needs no API key, but it does need network. Probe first so an
# offline runtime degrades in a second instead of blocking on a socket.
sources = [SystemEntropyBackend()]
if _reachable("beacon.nist.gov"):
    sources.append(NistBeaconBackend(timeout=NET_TIMEOUT))
else:
    print("NIST beacon unreachable; continuing with the system CSPRNG alone.")
    print("The attestation will record that, which is the point of having one.\n")
result = mix_entropy(sources, n_bytes=32, context=b"qresp-demo")
att = result.attestation

print(f"KDF                    : {att.kdf}")
print(f"quantum-seeded         : {att.is_quantum_seeded}")
print(f"externally verifiable  : {att.verifiable_contributors}")
print(f"not_before             : {att.not_before}")
for c in att.contributions:
    print(f"  - {c.backend:14} role={c.role:7} quantum={c.is_quantum}")
for n in att.notes:
    print(f"  note: {n}")
""")

md(r"""
`quantum_seeded` is **False** here, and that is the honest answer: the beacon is
quantum-sourced but *public*, so it contributes no secrecy. Counting it would let
a key claim quantum provenance while every unpredictable bit came from the system
CSPRNG. The attestation records what happened rather than what sounds best.

What the beacon *does* buy is a pulse index and value anyone can re-fetch from
NIST, plus `not_before` — a lower bound on when this key could have existed.
""")

code(r"""
# Anyone can check the beacon contribution independently.
pulse = next((c.reference for c in att.contributions
              if c.role == "public" and c.reference), None)
if pulse:
    print(f"pulse index : {pulse.get('pulse_index')}")
    print(f"timestamp   : {pulse.get('timestamp')}")
    print(f"verify at   : {pulse.get('verify_url')}")
    print()
    print("Fetch that URL, compare outputValue with the salt recorded above.")
    print("That is the difference between a claim and evidence.")
else:
    print("Beacon unreachable; the seed came from the system CSPRNG alone.")
    print("The attestation says so, which is the entire point.")
""")

# ===========================================================================
md(r"""
---
## 3. Sign it

Two algorithms, one artefact:

- **Ed25519** — what verifiers can check *today*. Shor-breakable.
- **ML-DSA-44** (FIPS 204) — what survives a quantum adversary.

Both sign the DSSE pre-authentication encoding of the same in-toto statement,
which contains a **binding** committing to the *set* of algorithms in use. That
is what makes the pair inseparable, and section 5 attacks it.

`deterministic=True` makes the notebook reproducible: re-run it and you get
identical signature bytes. Production signing is **hedged** — FIPS 204 mixes 32
fresh random bytes per signature to frustrate fault-injection attacks — and the
bundle records which mode produced it.
""")

code(r"""
from qresp.signing.backends import Exposure
from qresp.signing.sign import keygen, sign, verify, VerifyMode
from qresp.signing.bundle import build_bundle, parse_bundle

keys = keygen(suite=["ed25519", "ml-dsa-44"], seed=result.seed)
signed = sign(local, keys,
              exposure=Exposure.OFFLINE,      # release signing, not a service
              context=b"model-release",
              subject_name=MODEL,
              deterministic=True)

for alg in signed.binding.algorithms:
    print(f"{alg:11} signature {len(signed.signatures[alg]):>5} bytes   "
          f"key {keys.keys[alg].fingerprint[:16]}")
print()
print(f"digest ({signed.digest_algorithm}) : {signed.digest}")
print(f"files covered      : {len(signed.manifest)}")
print(f"suite bound        : {signed.binding.suite}")
for note in signed.notes:
    print(f"note: {note}")
""")

md(r"""
Note the size asymmetry, which is the practical cost of the transition:
**64 bytes** of Ed25519 against **2,420 bytes** of ML-DSA-44. Task 8 measures
that across all parameter sets.

`exposure=OFFLINE` is not decoration. The pure-Python ML-DSA backend is not
constant-time — signing duration depends on secret data through rejection
sampling — so `sign()` **refuses** to run it in an `ONLINE` exposure where an
attacker could submit messages and time the responses:
""")

code(r"""
from qresp.signing.backends import BackendUnsuitable
try:
    sign(local, keys, exposure=Exposure.ONLINE)
    print("accepted -- this should not happen")
except BackendUnsuitable as exc:
    print("REFUSED, as designed:\n")
    print(str(exc)[:400])
""")

# ===========================================================================
md(r"""
---
## 4. Verify

The report says *what was checked*, not merely "valid". A caller verifying in
CLASSICAL mode against a hybrid bundle should be able to see that no
post-quantum signature was consulted.
""")

code(r"""
bundle = build_bundle(signed)
report = verify(local, parse_bundle(bundle), mode=VerifyMode.STRICT,
                context=b"model-release")

print(f"verified           : {report['verified']}")
print(f"mode               : {report['mode']}")
print(f"algorithms checked : {report['algorithms_checked']}")
print(f"quantum resistant  : {report['quantum_resistant']}")
print(f"binding enforced   : {report['binding_enforced']}")
print()
for f in report["temporal"]["findings"]:
    print(f"  {f}")
""")

# ===========================================================================
md(r"""
---
## 5. The same thing, from a terminal

Everything above used the Python API, which is the wrong shape for the person
this tool is actually for: someone with a model directory and a release to cut.
`qresp sign` and `qresp verify` are that interface.

The cells below run the real commands through `subprocess` so the output is
genuine rather than transcribed, and so they work identically on Windows, macOS
and Linux. After `pip install -e .` the invocation is simply `qresp sign ...`.

Unlike the API section above, `qresp sign` is not given a seed, so it draws
entropy live. **If you see a line like `Entropy source anu unavailable: ANU
returned HTTP 500`, that is the design working, not a failure.** A source went
down, `mix_entropy` skipped it, signing continued on the sources that remained,
and the reason was written into the attestation. The alternative -- silently
substituting and claiming provenance that was never established -- is the thing
this project exists to avoid.
""")

code(r"""
import subprocess

# After `pip install -e .` this is just `qresp`. Spelled out here so it runs in
# a Colab session where the package was cloned rather than installed.
QRESP = [sys.executable, "-m", "qresp"]

# PYTHONIOENCODING forces the child to *write* UTF-8, and the explicit encoding
# below makes us *read* it as UTF-8. Both halves are needed on Windows, where
# the default console codec is cp1252 and `subprocess(text=True)` decodes with
# it. The CLI's output tables use box-drawing characters, which cp1252 has no
# mapping for, so capturing them crashed with UnicodeDecodeError -- on Windows
# only, which is exactly the kind of bug a Linux-only test run never sees.
ENV = dict(os.environ,
           PYTHONPATH=str(REPO_ROOT / "src"),
           PYTHONIOENCODING="utf-8")

def run(*args, show=None):
    # Distinguishes "the tool ran and rejected something" from "the tool failed
    # to start". Both exit non-zero, and conflating them is dangerous in exactly
    # this notebook: a crashed interpreter would otherwise print
    #   exit code: 1   (non-zero = a release script stops here)
    # and read as a successful demonstration of tamper detection.
    print("$ qresp " + " ".join(show or args))
    r = subprocess.run(QRESP + list(args), capture_output=True, env=ENV,
                       text=True, encoding="utf-8", errors="replace")
    print(r.stdout or r.stderr)
    if "Traceback (most recent call last)" in r.stderr:
        raise RuntimeError(
            "the CLI crashed rather than returning a verdict, so the exit code "
            "below is NOT a verification result. Re-run the setup cell."
        )
    return r

_ = run("sign", str(local),
        "--out", "cli.bundle.json",
        "--keys-out", "cli.keys.json",
        "--name", MODEL,
        "--context", "model-release",
        "--deterministic",
        show=["sign", "./model", "--out", "cli.bundle.json",
              "--keys-out", "cli.keys.json", "--name", MODEL,
              "--context", "model-release", "--deterministic"])
""")

code(r"""
verified = run("verify", str(local),
               "--bundle", "cli.bundle.json",
               "--context", "model-release",
               show=["verify", "./model", "--bundle", "cli.bundle.json",
                     "--context", "model-release"])
print(f"exit code: {verified.returncode}   (0 = verified)")
""")

md(r"""
### The exit code is the point

A verification tool that prints "FAILED" and exits 0 is useless in a pipeline.
`qresp verify` exits **1** on any failure, so it composes with `&&`, with CI,
and with a release script that must stop.
""")

code(r"""
# Tamper, then verify again -- this is what a CI gate would catch.
import shutil
ci = Path("ci-artefact"); shutil.rmtree(ci, ignore_errors=True)
shutil.copytree(local, ci, symlinks=False)     # resolve links into real files
next(p for p in ci.rglob("*") if p.is_file()).write_bytes(b"BACKDOORED")

bad = run("verify", str(ci), "--bundle", "cli.bundle.json",
          "--context", "model-release",
          show=["verify", "./tampered-model", "--bundle", "cli.bundle.json",
                "--context", "model-release"])
print(f"exit code: {bad.returncode}   (non-zero = a release script stops here)")
""")

md(r"""
### What the CLI refuses to do

Secret keys are never written to disk. `--keys-out` exports the **public** keys
only, and the command says so on every run. A tool that quietly dropped a
private key next to the artefact would be the most dangerous kind of
convenience.
""")

code(r"""
import json as _j
exported = _j.loads(Path("cli.keys.json").read_text())
print("exported key material:")
print(_j.dumps(exported, indent=2)[:400])
print()
text = Path("cli.keys.json").read_text().lower()
print(f"contains 'secret' or 'private': {('secret' in text) or ('private' in text)}")
""")

# ===========================================================================
md(r"""
---
## 6. Five attacks

### 6.1 Tamper with the artefact
""")

code(r"""
import shutil
from qresp.signing.sign import VerificationFailed

tampered = Path("tampered"); shutil.rmtree(tampered, ignore_errors=True)
shutil.copytree(local, tampered)
target = next(p for p in tampered.rglob("*") if p.is_file())
target.write_bytes(b"BACKDOORED")
print(f"modified {target.relative_to(tampered)}\n")

try:
    verify(tampered, parse_bundle(bundle), context=b"model-release")
    print("ACCEPTED -- this should not happen")
except VerificationFailed as exc:
    print("REJECTED:", str(exc).splitlines()[-1])
""")

md(r"""
### 6.2 Unsigned additions in an excluded directory

`.git`, `__pycache__` and symlinks are deliberately **not** hashed. An earlier
version of this code simply skipped them, which meant adding a file to one did
not change the digest — and CPython loads a `.pyc` whose header matches its
source, so that was an unsigned code-execution path behind a signature that
verified cleanly.

Excluded paths are now recorded — name, reason, and for a symlink its target —
and that list is bound into the digest. The contents are still never read.
""")

code(r"""
shutil.rmtree(tampered, ignore_errors=True); shutil.copytree(local, tampered)
(tampered / "__pycache__").mkdir(exist_ok=True)
(tampered / "__pycache__" / "loader.cpython-311.pyc").write_bytes(b"<malicious bytecode>")

try:
    verify(tampered, parse_bundle(bundle), context=b"model-release")
    print("ACCEPTED -- this should not happen")
except VerificationFailed as exc:
    print("REJECTED:", str(exc).splitlines()[-1])
    print("\nThe .pyc was never hashed. Its *name* was, and that is enough.")
""")

md(r"""
### 6.3 Signature stripping — the attack the paper is about

An attacker deletes the ML-DSA signature and presents a bundle carrying only
Ed25519. No forgery, no key compromise, no computation: the post-quantum
protection is removed by dropping a JSON field.

A verifier that merely checks "every signature present is valid" accepts it.
""")

code(r"""
import copy
stripped_bundle = copy.deepcopy(bundle)
stripped_bundle["dsseEnvelope"]["signatures"] = [
    s for s in stripped_bundle["dsseEnvelope"]["signatures"] if s["keyid"] != "ml-dsa-44"
]
stripped = parse_bundle(stripped_bundle)
print(f"signatures remaining: {sorted(stripped.signatures)}")
print(f"suite still declares: {stripped.binding.algorithms}\n")

try:
    verify(local, stripped, mode=VerifyMode.STRICT, context=b"model-release")
    print("STRICT   ACCEPTED -- this should not happen")
except VerificationFailed as exc:
    print("STRICT   REJECTED:", str(exc).splitlines()[-1][:100])

r = verify(local, stripped, mode=VerifyMode.CLASSICAL, context=b"model-release")
print(f"CLASSICAL ACCEPTED  (verified={r['verified']}, "
      f"quantum_resistant={r['quantum_resistant']})")
print("\nCLASSICAL accepting it is CORRECT, and is why STRICT exists: that mode")
print("does not consult the binding, so it offers exactly what Ed25519 offers.")
for w in r["warnings"]:
    print(f"  warning: {w}")
""")

md(r"""
Now the attacker's second move: strip the signature **and** edit the declared
suite so the bundle is internally consistent again.
""")

code(r"""
import base64, json as _json
forged = copy.deepcopy(stripped_bundle)
stmt = _json.loads(base64.b64decode(forged["dsseEnvelope"]["payload"]))
stmt["subject"][0]["algorithmBinding"]["algorithms"] = ["ed25519"]
stmt["subject"][0]["algorithmBinding"]["suite"] = "ed25519"
forged["dsseEnvelope"]["payload"] = base64.b64encode(
    _json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode()).decode()

try:
    verify(local, parse_bundle(forged), mode=VerifyMode.STRICT, context=b"model-release")
    print("ACCEPTED -- this should not happen")
except VerificationFailed as exc:
    print("REJECTED:", str(exc).splitlines()[-1][:120])
    print("\nEditing the suite changes the binding, and the surviving Ed25519")
    print("signature was made over the old one. There is no consistent forgery.")
""")

md(r"""
### 6.4 Metadata forgery

The entropy attestation and backend descriptors travel inside the envelope. An
earlier revision signed only the binding, so those fields *looked* signed and
were freely editable — an attacker could set `sideChannelResistant: true` on a
backend that is not, or delete the note recording a PRNG fallback.

Signatures now cover the DSSE PAE of the whole statement.
""")

code(r"""
lie = copy.deepcopy(bundle)
stmt = _json.loads(base64.b64decode(lie["dsseEnvelope"]["payload"]))
stmt["subject"][0]["backends"]["ml-dsa-44"]["sideChannelResistant"] = True
stmt["subject"][0]["notes"] = ["signed on a certified HSM"]
lie["dsseEnvelope"]["payload"] = base64.b64encode(
    _json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode()).decode()

try:
    verify(local, parse_bundle(lie), mode=VerifyMode.STRICT, context=b"model-release")
    print("ACCEPTED -- this should not happen")
except VerificationFailed as exc:
    print("REJECTED:", str(exc).splitlines()[0][:110])
""")

md(r"""
### 6.5 The temporal boundary — verifying in 2031

Once an algorithm breaks, an attacker forges a signature *and claims it is old*.
Every old signature under that algorithm becomes indistinguishable from a fresh
forgery. So a signature does not decay because it is old; it decays because new
forgeries become equally plausible.

Here is the same bundle, verified with the clock moved past Ed25519's 2030
transition deadline.
""")

code(r"""
from datetime import datetime, timezone
future = datetime(2031, 6, 1, tzinfo=timezone.utc)

r = verify(local, parse_bundle(bundle), mode=VerifyMode.CLASSICAL,
           context=b"model-release", now=future)
print("HYBRID bundle in 2031:")
for f in r["temporal"]["findings"]:
    print(f"  {f}")
print(f"  critical: {r['temporal']['critical']}")
""")

code(r"""
# The same artefact signed with Ed25519 ALONE, seen from 2031.
classical_only = sign(local, keygen(suite=["ed25519"], seed=result.seed),
                      exposure=Exposure.OFFLINE, context=b"model-release",
                      subject_name=MODEL, deterministic=True)
r2 = verify(local, classical_only, mode=VerifyMode.CLASSICAL,
            context=b"model-release", now=future)
print("CLASSICAL-ONLY bundle in 2031:")
for f in r2["temporal"]["findings"]:
    print(f"  {f}")
print(f"  critical: {r2['temporal']['critical']}")
print()
print("Same artefact, same clock. The hybrid holds because ML-DSA is still")
print("current; the classical-only signature has stopped being evidence.")
""")

# ===========================================================================
md(r"""
---
## 7. It is still valid OpenSSF Model Signing

The claim is an **extension**, not a fork: an unmodified OMS verifier must be
able to read this bundle, validate it, and find the signature it understands.
Validated here against the published v1.0 schemas, unmodified.
""")

code(r"""
import jsonschema, glob, os

# REPO_ROOT was resolved in the setup cell from qresp.__file__, so this works
# regardless of the working directory -- VS Code runs notebooks with cwd set to
# the notebook's own folder, where the old relative paths found nothing.
schema_dir = None
for cand in (REPO_ROOT / "tests" / "signing" / "oms_schemas",
             pathlib.Path("qresp2/tests/signing/oms_schemas"),
             pathlib.Path("tests/signing/oms_schemas")):
    if cand and os.path.isdir(cand):
        schema_dir = str(cand)
        break

if schema_dir:
    load = lambda n: _json.load(open(f"{schema_dir}/{n}", encoding="utf-8"))
    statement, predicate, envelope = (load("statement.schema.json"),
                                      load("predicate.schema.json"),
                                      load("envelope.schema.json"))
    resolver = jsonschema.RefResolver.from_schema(
        statement, store={s["$id"]: s for s in (statement, predicate)})
    jsonschema.validate(bundle["dsseEnvelope"], envelope)
    jsonschema.validate(_json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"])),
                        statement, resolver=resolver)
    print("VALID against unmodified OMS v1.0 schemas.")
    keyids = {s.get("keyid") for s in bundle["dsseEnvelope"]["signatures"]}
    print(f"signatures carried : {sorted(keyids)}")
    print(f"legacy verifier finds ed25519: {'ed25519' in keyids}")
else:
    print("Schemas not found (run from the repository); skipping.")
""")

md(r"""
**The gap this exposes, and the reason for the spec proposal.** OMS `signature`
objects are `additionalProperties: false`, and the specification says `keyid`
"is not used for verification". So a conformant OMS bundle can *carry* an ML-DSA
signature that no verifier can *identify*.

OMS can transport a hybrid signature and cannot describe one. That is what the
algorithm binding works around, and what the proposal to OpenSSF asks them to
fix.
""")

# ===========================================================================
md(r"""
---
## 8. Why any of this matters: the substitution scenario

A user runs `from_pretrained("openai/privacy-filter")`. What stops them running
a different artefact under a name they trust?

Today, for 99.9% of the registry: nothing. Nothing is signed, so there is
nothing to check.

Below, an attacker publishes a lookalike. **This is synthetic** — built in this
notebook, under a name nobody owns. The registry does contain repositories with
similar names, and they appear to be legitimate derivative work; naming them
here would assert bad faith on no evidence.
""")

code(r"""
evil = Path("openai-inc--privacy-filter"); shutil.rmtree(evil, ignore_errors=True)
shutil.copytree(local, evil)
(evil / "config.json").write_text(
    '{"architectures": ["DistilBertForTokenClassification"], "_backdoor": true}')

print("Scenario: a user believes they fetched the model signed above.\n")

# (a) attacker ships the genuine bundle with a modified artefact
try:
    verify(evil, parse_bundle(bundle), context=b"model-release")
    print("(a) genuine bundle, modified artefact : ACCEPTED -- should not happen")
except VerificationFailed:
    print("(a) genuine bundle, modified artefact : REJECTED (digest mismatch)")

# (b) attacker re-signs with their own hybrid keys -- a valid bundle for a
#     DIFFERENT signer, which is why identity binding is a separate problem
evil_keys = keygen(suite=["ed25519", "ml-dsa-44"], seed=b"\xee" * 32)
evil_signed = sign(evil, evil_keys, exposure=Exposure.OFFLINE,
                   context=b"model-release", subject_name=MODEL, deterministic=True)
r = verify(evil, evil_signed, mode=VerifyMode.STRICT, context=b"model-release")
print(f"(b) attacker's own bundle             : ACCEPTED (verified={r['verified']})")
print()
print("(b) is not a flaw in the signature -- it is the trust-anchor problem.")
print("Compare the key fingerprints:")
print(f"    expected signer : {keys.keys['ed25519'].fingerprint[:24]}")
print(f"    this bundle     : {evil_keys.keys['ed25519'].fingerprint[:24]}")
""")

md(r"""
**Read that second result carefully.** A QResP bundle proves integrity,
algorithm non-separability and covered provenance metadata *relative to a public
key you already trust*. It does **not** establish that the expected party signed.

That is a trust-anchor problem, not a signature-format one, and it is
deliberately out of scope here — Sigstore solves it with certificate chains and
a transparency log, and adopting it is the project's recorded next step
(`docs/OPEN-QUESTIONS.md`, items 2 and 3). Claiming otherwise would be exactly
the kind of overclaim this project has tried to avoid.
""")

# ===========================================================================
md(r"""
---
## Summary

| Attack | Result |
|---|---|
| modify a signed file | rejected |
| add an unsigned `.pyc` to `__pycache__` | rejected |
| strip the ML-DSA signature | rejected in STRICT; accepted in CLASSICAL, with warnings |
| strip **and** rewrite the declared suite | rejected |
| forge the entropy attestation or backend claims | rejected |
| present a classical-only signature in 2031 | critical finding; hybrid unaffected |
| substitute the artefact under a trusted bundle | rejected |
| re-sign with the attacker's own keys | **accepted — identity is out of scope** |

**What this demonstrates.** A hybrid signature is not two signatures side by
side. Placed side by side it is broken by deleting a field. Binding the
algorithm set into what both algorithms sign is what makes it hold, and the
binding fits inside an unmodified OMS bundle.

**What it does not.** Identity binding, and whether the signer's own claims
about their entropy were true. Both are stated in `docs/THREAT-MODEL.md` rather
than papered over.

### Reproducing

```bash
git clone https://github.com/adityasharma1307/qresp2
cd qresp2 && pip install -e ".[dev]"
pytest -q                                        # 833 tests
python scripts/verify/run_fips204_acvp.py        # 180 NIST ACVP vectors
```
""")


NOTEBOOK_REQUIRES = ["cryptography", "dilithium_py", "requests", "jsonschema"]


def _missing_dependencies() -> list[str]:
    """What the notebook imports and this interpreter cannot provide.

    Checked before execution so a missing package is one clear message rather
    than a cascade: the real failure is the first cell that cannot import, and
    every later cell then fails on a NameError for a variable that cell never
    got to define.
    """
    import importlib.util

    pip_names = {"dilithium_py": "dilithium-py"}
    return [pip_names.get(m, m) for m in NOTEBOOK_REQUIRES
            if importlib.util.find_spec(m) is None]


def build() -> dict:
    cells = []
    for index, (kind, source) in enumerate(CELLS):
        cell = {"cell_type": kind, "id": f"cell-{index:02d}", "metadata": {},
                "source": source.splitlines(keepends=True)}
        if kind == "code":
            cell["outputs"] = []
            cell["execution_count"] = None
        cells.append(cell)
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python",
                           "name": "python3"},
            "language_info": {"name": "python", "version": "3.10"},
            "colab": {"provenance": [], "toc_visible": True},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true",
                        help="Execute the notebook after writing it.")
    parser.add_argument("--save-executed", type=Path, default=None,
                        help="Write the executed copy (with outputs) here. The "
                             "committed notebook stays output-free: outputs are "
                             "machine- and date-specific, and they turn every "
                             "diff into noise.")
    args = parser.parse_args()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8")
    code_cells = sum(1 for k, _ in CELLS if k == "code")
    print(f"wrote {OUT}  ({len(CELLS)} cells, {code_cells} executable)")

    if args.run:
        try:
            import nbformat
            from nbclient import NotebookClient
        except ImportError as exc:
            # A bare ModuleNotFoundError traceback here reads as "the script is
            # broken", when the notebook itself is fine and only the *executor*
            # is absent. Say which, and how to fix it.
            raise SystemExit(
                f"Cannot execute the notebook: {exc.name} is not installed.\n"
                f"\n"
                f"    pip install nbclient nbformat ipykernel\n"
                f"    # or: pip install -e \".[dev]\"\n"
                f"\n"
                f"The notebook has already been written to\n"
                f"    {OUT}\n"
                f"and is valid without these -- they are only needed to run it "
                f"headlessly from the terminal. Opening it in Jupyter or Colab "
                f"needs none of them."
            ) from None

        # Execute under THIS interpreter, not whatever is registered as the
        # "python3" kernelspec.
        #
        # Those are routinely different on Windows, where `python` may resolve
        # to the Microsoft Store shim while a registered kernel points at some
        # other install. The result is baffling: the script runs happily under
        # interpreter A, the notebook executes under interpreter B, and cells
        # fail on packages that are demonstrably installed. Writing a throwaway
        # kernelspec for sys.executable removes the ambiguity.
        missing = _missing_dependencies()
        if missing:
            raise SystemExit(
                f"The notebook needs {', '.join(missing)}, which "
                f"{sys.executable} cannot import.\n\n"
                f"    pip install {' '.join(missing)}\n\n"
                f"Checked against the interpreter that will run the kernel, so "
                f"this is what the notebook will actually see."
            )

        with tempfile.TemporaryDirectory() as spec_root:
            spec_dir = pathlib.Path(spec_root) / "share" / "jupyter" / "kernels" / "qresp"
            spec_dir.mkdir(parents=True)
            (spec_dir / "kernel.json").write_text(json.dumps({
                "argv": [sys.executable, "-m", "ipykernel_launcher",
                         "-f", "{connection_file}"],
                "display_name": "qresp (this interpreter)",
                "language": "python",
            }), encoding="utf-8")
            os.environ["JUPYTER_PATH"] = str(pathlib.Path(spec_root) / "share" / "jupyter")

            nb = nbformat.read(OUT, as_version=4)
            client = NotebookClient(nb, timeout=900, kernel_name="qresp",
                                    resources={"metadata": {"path": str(ROOT)}},
                                    allow_errors=True)
            client.execute()
        if args.save_executed:
            nbformat.write(nb, args.save_executed)
            print(f"executed copy -> {args.save_executed}")
        failures = [(i, o) for i, c in enumerate(nb.cells)
                    for o in c.get("outputs", []) if o.get("output_type") == "error"]
        for index, out in failures:
            print(f"\nCELL {index} RAISED {out['ename']}: {out['evalue']}")
        print(f"\n{len(failures)} cell(s) raised.")
        return 1 if failures else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
