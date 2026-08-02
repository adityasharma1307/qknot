"""QResP command-line interface.

Two halves, and the commands mirror them.

MEASURE an ecosystem -- how much is signed, and would any of it survive a
quantum adversary:

  qresp scan --n 1000 --out data/hf.jsonl --token $HF_TOKEN
  qresp audit-npm  --ranking data/npm_ranking.json --frame data/npm_frame.txt \
                   --out data/npm.jsonl
  qresp audit-pypi --out data/pypi.jsonl
  qresp summarise  --in data/hf.jsonl

RESPOND -- sign an artefact so the post-quantum half cannot be stripped, bind
the post-quantum key to an identity through classical PKI, and verify both
together:

  qresp sign ./my-model --out model.bundle.json --context model-release
  qresp trust-material --out ./trust                   # once, or when it goes stale
  qresp register --out ./my-registration \
                 --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub
  qresp verify ./my-model --bundle model.bundle.json --context model-release \
               --registration ./my-registration/bundle.json \
               --fulcio-roots ./trust/fulcio_roots.pem --log-key ./trust/rekor.pub

The last one is the point of the whole design: it reports not merely that a
signature is valid, but WHOSE it is and on what basis that attribution still
holds -- `direct`, or `rescued-by-timestamp` once the classical algorithm has
been disallowed.
"""
from __future__ import annotations

import contextlib
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

# The audit stack is imported lazily, inside the commands that use it.
#
# `qresp.signing` deliberately depends on nothing from `qresp.audit` -- a
# boundary a test enforces -- so that the signing half is reusable for any
# artefact. Importing the audit modules here quietly undid that for anyone
# using the CLI: `qresp sign`, a pure signing operation, would not start
# without `tenacity`, `huggingface_hub` and `pydantic` installed. Someone who
# wants to sign a firmware image should not need a HuggingFace client.
#
# Caught by running the demo notebook in a bare environment, where the CLI
# crashed on `tenacity` while signing a local directory.
if TYPE_CHECKING:
    from .audit.model import QLabel

app = typer.Typer(
    help=(
        "QResP: Quantum-Resilient Provenance for software supply chains.\n\n"
        "Two halves. AUDIT measures how much of an ecosystem is signed, and "
        "whether any of it would survive a quantum adversary -- across "
        "HuggingFace, npm and PyPI. SIGN/VERIFY is the response: hybrid "
        "signatures whose post-quantum half cannot be stripped, an identity "
        "bound to a post-quantum key through classical PKI, and a verdict that "
        "always names how it decided.\n\n"
        "  audit:  scan, scan-ids, audit-npm, audit-pypi, summarise\n"
        "  sign:   entropy, sign, verify\n"
        "  identity: trust-material, register, verify-registration\n\n"
        "Every command explains itself with --help; the verification commands "
        "also state what they did NOT check."
    ),
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    n: int = typer.Option(50, "--n", help="Number of top-downloaded models to audit."),
    out: Path = typer.Option(Path("data/audit.jsonl"), "--out", help="Output JSONL file."),
    token: str | None = typer.Option(
        None, "--token", envvar="HF_TOKEN",
        help="HuggingFace API token. Optional, but raises rate limits.",
    ),
    no_resume: bool = typer.Option(
        False, "--no-resume",
        help="Re-audit all models, even if they already exist in the output file.",
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """Audit the top-N HuggingFace models for signing and PQC readiness.

    Walks the most-downloaded models and records, per model, whether it carries
    a signature at all and whether that signature would survive a quantum
    adversary. Results append to a JSONL file and re-running RESUMES rather than
    starting over (--no-resume forces a re-audit).

    A token is optional but strongly recommended: without one the HuggingFace
    API rate-limits quickly, and a rate-limited scan produces `error` rows, not
    `unsigned` ones. Those are different claims -- a model that could not be
    checked is not a model that is unsigned -- and only the second belongs in a
    reported rate.

    For the long-tail half of the sample, see `scan-ids`; for other ecosystems,
    `audit-npm` and `audit-pypi`.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
        # stdout, not the logging default of stderr: progress messages are not
        # errors, and shells that treat native stderr as failure would abort on
        # the first INFO line.
        stream=sys.stdout,
    )

    from .audit.hf_client import HfClient
    from .audit.scanner import run_audit

    client = HfClient(token=token)
    label_counter: Counter[QLabel] = Counter()

    with Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing models", total=n)
        for record in run_audit(client, n=n, out_path=out, resume=not no_resume):
            label_counter[record.q_label] += 1
            progress.update(task, advance=1, description=f"Last: {record.model_id[:40]}")

    _print_summary(label_counter, out)


@app.command("scan-ids")
def scan_ids(
    ids_file: Path = typer.Option(
        ..., "--ids", help="Newline-delimited model ids, as written by "
                           "scripts/audit/sample_longtail.py.",
    ),
    out: Path = typer.Option(Path("data/longtail.jsonl"), "--out",
                             help="Output JSONL file."),
    token: str | None = typer.Option(
        None, "--token", envvar="HF_TOKEN",
        help="HuggingFace API token. Strongly recommended at this scale.",
    ),
    no_resume: bool = typer.Option(
        False, "--no-resume",
        help="Re-audit every id, even those already in the output file.",
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """Audit an explicit list of model ids (the Stratum B long-tail sample).

    The sample membership is fixed in advance by the sampling script and is not
    re-derived here. Every id in the file is audited, including ones that turn
    out to be deleted or gated, because dropping them would shrink the
    denominator and invalidate the sampling fraction.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
        # stdout, not the logging default of stderr: progress messages are not
        # errors, and shells that treat native stderr as failure would abort on
        # the first INFO line.
        stream=sys.stdout,
    )

    model_ids = [
        line.strip()
        for line in ids_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not model_ids:
        console.print(f"[red]No ids found in {ids_file}[/red]")
        raise typer.Exit(1)

    duplicates = len(model_ids) - len(set(model_ids))
    if duplicates:
        console.print(
            f"[yellow]Warning: {duplicates} duplicate ids in {ids_file}. "
            f"A draw without replacement should not contain any.[/yellow]"
        )

    if not token:
        console.print(
            "[yellow]No token supplied. A scan of this size will very likely be "
            "rate limited; pass --token or set HF_TOKEN.[/yellow]"
        )

    from .audit.hf_client import HfClient
    from .audit.scanner import run_audit_ids

    client = HfClient(token=token)
    label_counter: Counter[QLabel] = Counter()

    with Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing sample", total=len(model_ids))
        for record in run_audit_ids(
            client, model_ids, out_path=out, resume=not no_resume
        ):
            label_counter[record.q_label] += 1
            progress.update(task, advance=1, description=f"Last: {record.model_id[:40]}")

    _print_summary(label_counter, out)


@app.command("audit-npm")
def audit_npm(
    out: Path = typer.Option(..., "--out",
                             help="JSONL output. Re-running RESUMES into the "
                                  "same file rather than starting over."),
    ranking: Path = typer.Option(
        ..., "--ranking",
        help="The download ranking, from scripts/audit/rank_npm.py. A file, "
             "never a live fetch: a stratum is only reproducible if its exact "
             "inputs are preserved."),
    frame: Path = typer.Option(
        ..., "--frame",
        help="The sampling frame: one package name per line, from the "
             "registry's _all_docs (scripts/audit/fetch_npm_frame.py)."),
    head: int = typer.Option(10_000, "--head", help="Size of the head stratum."),
    tail: int = typer.Option(10_000, "--tail", help="Size of the tail stratum."),
    seed: int = typer.Option(20260730, "--seed",
                             help="Sampling seed. Recorded in the manifest so "
                                  "the tail is re-derivable."),
    workers: int = typer.Option(8, "--workers",
                                help="Concurrent requests. Keep this modest: "
                                     "the npm registry is a free public "
                                     "service."),
    limit: int | None = typer.Option(None, "--limit",
                                     help="Stop after N packages. For a smoke "
                                          "test before committing to a full run."),
) -> None:
    """Audit npm for signing and post-quantum readiness (two strata).

    Scans a `head` of the most-downloaded packages and a `tail` sampled at
    random from the rest, because reporting only the head would describe the
    popular packages and call it the ecosystem.

    npm publishes no ranking, so BOTH inputs are produced locally and passed in
    (--ranking, --frame). A manifest beside the output records the seed, the
    frame size and a digest of the frame, so the sample can be re-derived
    rather than taken on trust.

    Resumable: interrupt it and re-run. A 20,000-package scan over a public API
    will be interrupted at some point. Rows labelled `error` are NOT treated as
    done -- re-running retries them, because a package that could not be reached
    was not checked, and counting it as unsigned would inflate the finding.
    """
    from .audit.registry_scan import run_npm_audit

    try:
        run_npm_audit(out=out, ranking_path=ranking, frame_path=frame,
                      head_size=head, tail_size=tail, seed=seed,
                      workers=workers, limit=limit, echo=console.print)
    except (OSError, ValueError) as exc:
        console.print(f"[red]scan could not start: {exc}")
        raise typer.Exit(2) from None


@app.command("audit-pypi")
def audit_pypi(
    out: Path = typer.Option(..., "--out",
                             help="JSONL output. Re-running RESUMES into the "
                                  "same file rather than starting over."),
    ranking_url: str = typer.Option(
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json",
        "--ranking-url", help="Where to fetch the download ranking from."),
    ranking_cache: Path | None = typer.Option(
        None, "--ranking-cache",
        help="Where to cache the ranking. Default: <out>.ranking.json. Cached "
             "deliberately -- re-fetching per run would silently change the "
             "head stratum mid-scan."),
    head: int = typer.Option(10_000, "--head", help="Size of the head stratum."),
    tail: int = typer.Option(10_000, "--tail", help="Size of the tail stratum."),
    seed: int = typer.Option(20260730, "--seed",
                             help="Sampling seed. Recorded in the manifest so "
                                  "the tail is re-derivable."),
    workers: int = typer.Option(8, "--workers",
                                help="Concurrent requests. Keep this modest: "
                                     "PyPI is a free public service."),
    limit: int | None = typer.Option(None, "--limit",
                                     help="Stop after N projects. For a smoke "
                                          "test before committing to a full run."),
) -> None:
    """Audit PyPI for signing and post-quantum readiness (two strata).

    Scans a `head` of the most-downloaded projects and a `tail` sampled at
    random from the rest of the namespace. The ranking is fetched once and
    cached; the frame is the live index at scan time, and its size and digest
    go into a manifest beside the output so the tail is re-derivable.

    Resumable, and `error` rows are retried on re-run rather than counted as
    recorded: a project that could not be reached was not checked, and treating
    it as unsigned would inflate the very rate this reports.
    """
    from .audit.registry_scan import run_pypi_audit

    try:
        run_pypi_audit(out=out, ranking_url=ranking_url,
                       ranking_cache=ranking_cache, head_size=head,
                       tail_size=tail, seed=seed, workers=workers,
                       limit=limit, echo=console.print)
    except (OSError, ValueError) as exc:
        console.print(f"[red]scan could not start: {exc}")
        raise typer.Exit(2) from None


@app.command()
def entropy(
    n_bytes: int = typer.Option(32, "--bytes", help="How much entropy to draw."),
    backend: str | None = typer.Option(
        None, "--backend",
        help="LEGACY single-source mode: anu, system, ibm, usb. Omit to mix "
             "all available sources, which is the recommended path.",
    ),
    no_beacon: bool = typer.Option(
        False, "--no-beacon", help="Skip the NIST beacon when mixing."),
    on_qrng_failure: str = typer.Option(
        "fallback", "--on-qrng-failure",
        help="Non-interactive behaviour when the quantum source fails: "
             "wait, fallback, or abort. Ignored when a human can be prompted.",
    ),
    out: Path | None = typer.Option(
        None, "--out", help="Write the attestation record to this JSON file.",
    ),
    show_entropy: bool = typer.Option(
        False, "--show-entropy",
        help="Print the raw bytes. Off by default: entropy destined for a key "
             "should not land in a terminal scrollback or CI log.",
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """Draw attested entropy and print the attestation record.

    The record states where the bytes actually came from, which is what lets a
    verifier tell a quantum-seeded key from one that fell back to the system
    CSPRNG. Falling back is sound -- ML-DSA's security rests on Module-LWE
    hardness, not on the seed's physical origin -- but it must be visible
    rather than assumed.

    Two modes, and the default changed for a reason. Mixing every available
    source is strictly better than choosing one: the result is at least as
    strong as the strongest input, so there is no downgrade to reason about,
    and the attestation it produces is the format the verifier's temporal
    layer can read. `--backend` selects a single source and yields the older
    attestation shape, which carries no `not_before` and is therefore invisible
    to `evidence_from_attestation`.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
        stream=sys.stdout,
    )

    if backend is None:
        _entropy_mixed(n_bytes, no_beacon, out, show_entropy)
        return

    console.print(
        "[yellow]--backend selects one source and produces the legacy "
        "attestation, which carries no timestamp and cannot supply time "
        "evidence to a verifier. Omit --backend to mix sources instead.[/yellow]"
    )

    from .signing.entropy import OnFailure, QrngUnavailable, get_entropy

    try:
        policy = OnFailure(on_qrng_failure)
    except ValueError:
        console.print(
            f"[red]Invalid --on-qrng-failure {on_qrng_failure!r}.[/red] "
            f"Choose from: {', '.join(p.value for p in OnFailure)}"
        )
        raise typer.Exit(2) from None

    try:
        result = get_entropy(n_bytes=n_bytes, backend=backend, on_failure=policy)
    except QrngUnavailable as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from None
    except NotImplementedError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(3) from None
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from None

    att = result.attestation
    if att.is_quantum:
        console.print(f"[green]Quantum entropy from '{att.backend}'.[/green]")
    else:
        console.print(
            f"[yellow]Entropy came from '{att.backend}', not a quantum source."
            f"{' Fell back from ' + att.requested_backend + '.' if att.fallback_used else ''}"
            f"[/yellow]"
        )
    if att.endpoint_deprecated:
        console.print(
            "[yellow]Used the unauthenticated ANU endpoint, which ANU is "
            "retiring. Set ANU_API_KEY to use the current service.[/yellow]"
        )

    console.print_json(att.to_json())
    if show_entropy:
        console.print(f"\nraw: {result.raw.hex()}")
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(att.to_json() + "\n", encoding="utf-8")
        console.print(f"\nAttestation written to {out}")


def _entropy_mixed(
    n_bytes: int, no_beacon: bool, out: Path | None, show_entropy: bool
) -> None:
    """The recommended path: combine every source that responds."""
    from .signing.entropy.mixing import NoSecretEntropy, default_sources, mix_entropy

    try:
        result = mix_entropy(default_sources(use_beacon=not no_beacon),
                             n_bytes=n_bytes, context=b"qresp-cli-entropy")
    except NoSecretEntropy as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from None
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from None

    att = result.attestation
    if att.is_quantum_seeded:
        console.print(f"[green]Quantum entropy contributed secret material: "
                      f"{att.quantum_contributors}.[/green]")
    else:
        console.print("[yellow]No quantum source contributed secret material; "
                      "the seed's unpredictability is from the system CSPRNG. "
                      "This is sound, and it is recorded rather than assumed.[/yellow]")
    if att.verifiable_contributors:
        console.print(f"[green]Independently checkable: "
                      f"{att.verifiable_contributors}[/green]")
    else:
        console.print("[yellow]No externally verifiable contribution, so this "
                      "attestation carries no timestamp a verifier can use.[/yellow]")
    for note in att.notes:
        console.print(f"[yellow]note: {note}")

    console.print_json(att.to_json())
    if show_entropy:
        console.print(f"\nraw: {result.seed.hex()}")
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(att.to_json() + "\n", encoding="utf-8")
        console.print(f"\nAttestation written to {out}")


@app.command()
def summarise(
    inp: Path = typer.Option(..., "--in", help="JSONL audit dataset to summarise."),
) -> None:
    """Print summary statistics for an audit dataset (any ecosystem).

    Reads a JSONL file written by `scan`, `scan-ids`, `audit-npm` or
    `audit-pypi` and prints the label distribution.

    `error` rows are reported as their own category and never folded into
    `unsigned`: they are projects that could not be checked, and merging the two
    would inflate the headline rate. Re-run the corresponding scan to retry them
    before quoting any number from this table.
    """
    if not inp.exists():
        console.print(f"[red]File not found:[/red] {inp}")
        raise typer.Exit(code=1)

    from .audit.model import QLabel

    label_counter: Counter[QLabel] = Counter()
    n_models = 0
    with inp.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                label_counter[QLabel(obj["q_label"])] += 1
                n_models += 1
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    _print_summary(label_counter, inp, n_models=n_models)


def _print_summary(
    counter: Counter[QLabel],
    path: Path,
    n_models: int | None = None,
) -> None:
    """Pretty-print a summary table to the console."""
    total = n_models if n_models is not None else sum(counter.values())
    if total == 0:
        console.print("[yellow]No records to summarise.[/yellow]")
        return

    table = Table(title=f"Audit summary :: {path.name}  (n = {total})")
    table.add_column("Quantum-vulnerability label", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Share", justify="right")
    # display in a stable, meaningful order
    from .audit.model import QLabel

    for lbl in [QLabel.SAFE, QLabel.VULNERABLE, QLabel.UNSIGNED, QLabel.MIXED, QLabel.ERROR]:
        cnt = counter.get(lbl, 0)
        pct = (cnt / total * 100.0) if total else 0.0
        table.add_row(lbl.value, str(cnt), f"{pct:5.1f}%")
    console.print(table)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
# The signing pipeline is the project's reusable half, and until now it had no
# CLI at all -- it was reachable only by importing the package. These two
# commands exist so that signing an artefact does not require writing Python,
# which is the difference between a library and a tool someone else can adopt.
@app.command("sign")
def sign_artefact(
    target: Path = typer.Argument(..., help="File or directory to sign."),
    out: Path = typer.Option(Path("signature.bundle.json"), "--out",
                             help="Where to write the OMS-compatible bundle."),
    keys_out: Path | None = typer.Option(
        None, "--keys-out", help="Write the PUBLIC keys here (JSON)."),
    suite: str = typer.Option("ed25519+ml-dsa-87", "--suite",
                              help="Algorithms, '+'-separated."),
    name: str = typer.Option("artefact", "--name",
                             help="Subject name recorded in the statement."),
    context: str = typer.Option("", "--context",
                                help="Domain separation, e.g. 'model-release'."),
    exposure: str = typer.Option("offline", "--exposure",
                                 help="offline | online. See docs/THREAT-MODEL.md."),
    seed_hex: str | None = typer.Option(
        None, "--seed", help="Hex seed for reproducible keys. Omit to draw "
                             "attested entropy (network, with PRNG fallback)."),
    no_beacon: bool = typer.Option(
        False, "--no-beacon", help="Skip the NIST beacon (offline use)."),
    deterministic: bool = typer.Option(
        False, "--deterministic",
        help="Byte-reproducible signatures (FIPS 204 deterministic mode). "
             "Off by default: hedged signing defends against fault injection."),
) -> None:
    """Sign a file or directory with a non-separable hybrid signature.

    Signs with a classical and a post-quantum algorithm at once, in a way the
    post-quantum half CANNOT be stripped from: both algorithms sign a value
    committing to the set of algorithms in use, so deleting one signature leaves
    the other attesting to its absence. The obvious hybrid -- two independent
    signatures side by side -- is broken by deleting a JSON field.

    The output is an OpenSSF Model Signing v1.0-compatible Sigstore bundle, so
    an existing OMS verifier still accepts it. Works on any artefact, not just
    models: a directory is digested via its manifest.

    --context is domain separation. A signature made with one context will not
    verify under another, which stops a signature over a model being replayed as
    a signature over something else. Use the same value when verifying.

    Keys: omit --seed to draw attested entropy (network, with a documented
    fallback to the system CSPRNG); pass --seed for reproducible keys. With
    --keys-out only PUBLIC keys are written. To have an identity vouch for the
    post-quantum key, see `register`.
    """
    from .signing.backends import BackendUnsuitable, Exposure
    from .signing.bundle import build_bundle, bundle_to_json
    from .signing.sign import keygen, sign

    algorithms = [a.strip() for a in suite.split("+") if a.strip()]
    try:
        chosen = Exposure(exposure.lower())
    except ValueError:
        console.print(f"[red]--exposure must be 'offline' or 'online', got {exposure!r}")
        raise typer.Exit(2) from None

    if seed_hex:
        try:
            keys = keygen(suite=algorithms, seed=bytes.fromhex(seed_hex))
        except ValueError as exc:
            console.print(f"[red]bad --seed: {exc}")
            raise typer.Exit(2) from None
        console.print("[yellow]Keys derived from an explicit seed: reproducible, "
                      "and only as secret as that seed.")
    else:
        from .signing.entropy.mixing import default_sources

        keys = keygen(suite=algorithms,
                      entropy_sources=default_sources(use_beacon=not no_beacon))

    try:
        signed = sign(target, keys, exposure=chosen, context=context.encode(),
                      subject_name=name, deterministic=deterministic)
    except BackendUnsuitable as exc:
        console.print(f"[red]{exc}")
        raise typer.Exit(1) from None

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(bundle_to_json(build_bundle(signed)), encoding="utf-8")

    table = Table(title="Signed", show_header=True, header_style="bold")
    for column in ("algorithm", "signature", "key"):
        table.add_column(column)
    for algorithm in signed.binding.algorithms:
        table.add_row(algorithm, f"{len(signed.signatures[algorithm])} B",
                      keys.keys[algorithm].fingerprint[:16])
    console.print(table)
    console.print(f"digest ({signed.digest_algorithm}): {signed.digest}")
    if signed.manifest is not None:
        console.print(f"files hashed: {len(signed.manifest)}")
        if signed.manifest.excluded:
            console.print(f"[yellow]paths excluded (names bound into the digest, "
                          f"contents not hashed): {signed.manifest.exclusion_summary()}")
    for note in signed.notes:
        console.print(f"[yellow]note: {note}")
    console.print(f"[green]bundle -> {out}")

    if keys_out:
        keys_out.parent.mkdir(parents=True, exist_ok=True)
        keys_out.write_text(json.dumps(keys.public_keys(), indent=2), encoding="utf-8")
        console.print(f"[green]public keys -> {keys_out}")
    console.print("[bold red]Secret keys were NOT written. They exist only in "
                  "this process and are gone now.[/bold red] Pass --seed to "
                  "reproduce them.")


def _load_cert_pool(path: Path) -> list[bytes]:
    """Certificates from a DER/PEM file, a directory of them, or a TUF
    trusted_root.json. The pool is unordered; verify_chain discovers the path."""
    import base64 as b64

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    if path.is_file() and path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        return [b64.b64decode(cert["rawBytes"])
                for ca in data.get("certificateAuthorities", [])
                for cert in ca.get("certChain", {}).get("certificates", [])]
    paths = sorted(path.iterdir()) if path.is_dir() else [path]
    out: list[bytes] = []
    for p in paths:
        raw = p.read_bytes()
        try:
            out.extend(c.public_bytes(Encoding.DER)
                       for c in x509.load_pem_x509_certificates(raw))
        except (ValueError, TypeError):
            out.append(raw)
    return out


def _verify_with_registration(
    target: Path, artefact: Any, registration: Path,
    fulcio_roots: Path | None, log_key: Path | None,
    mode: Any, context: str, artefact_signed_at: str | None,
    at: str | None = None, check_revocations: bool = False,
    rekor_url: str = "https://rekor.sigstore.dev",
) -> None:
    """The composed verdict: a valid artefact, attributed to an identity."""
    from datetime import datetime

    from .signing.composed import (
        SigningTimeSource,
        verify_artefact_against_registration,
    )
    from .signing.registration import RegistrationError
    from .signing.registration_chain import RegistrationBundle
    from .signing.sign import VerificationFailed

    if fulcio_roots is None or log_key is None:
        console.print("[red]--registration requires --fulcio-roots and "
                      "--log-key: attribution needs a trust store, and this "
                      "command will not invent one.")
        raise typer.Exit(2)

    try:
        reg_bundle = RegistrationBundle.from_dict(
            json.loads(registration.read_text(encoding="utf-8")))
        roots = _load_cert_pool(fulcio_roots)
        key_der = log_key.read_bytes()
        signed_at = (datetime.fromisoformat(
            artefact_signed_at.replace("Z", "+00:00"))
            if artefact_signed_at else None)
        as_of = (datetime.fromisoformat(at.replace("Z", "+00:00"))
                 if at else None)
    except (OSError, ValueError, RegistrationError) as exc:
        console.print(f"[red]could not read inputs: {exc}")
        raise typer.Exit(2) from None

    # Revocations. Either we look, or the verdict says we did not -- it never
    # claims a key is live merely because nobody checked.
    search = None
    if check_revocations:
        from .signing.registration import HybridRegistration, _key_fingerprint
        from .signing.revocation_search import find_revocations
        from .signing.sigstore_clients import RekorRevocationSearchClient

        payload = HybridRegistration.from_payload(reg_bundle.envelope.payload)
        console.print(f"  searching {rekor_url} for revocations of "
                      f"{payload.identity} ...")
        search = find_revocations(
            payload.identity, _key_fingerprint(payload.pqc_key.public_key),
            client=RekorRevocationSearchClient(rekor_url),
            log_public_key=key_der, now=as_of)

    try:
        verdict = verify_artefact_against_registration(
            target, artefact, reg_bundle, fulcio_roots=roots,
            log_public_key=key_der, mode=mode, context=context.encode(),
            revocation_search=search,
            artefact_signed_at=signed_at, now=as_of)
    except VerificationFailed as exc:
        console.print("[bold red]VERIFICATION FAILED[/bold red]")
        console.print(str(exc))
        raise typer.Exit(1) from None
    except RegistrationError as exc:
        # The signature may well be valid; what failed is the attribution.
        console.print("[bold red]NOT ATTRIBUTABLE[/bold red]")
        console.print(str(exc))
        raise typer.Exit(1) from None

    report = verdict.artefact_report
    basis_colour = "green" if verdict.basis.value == "direct" else "yellow"
    console.print("[bold green]VERIFIED AND ATTRIBUTED[/bold green]")
    console.print(f"  signed by         : [bold]{verdict.identity}[/bold] "
                  f"(via {verdict.issuer})")
    console.print(f"  key               : {verdict.pqc_algorithm}, vouched for "
                  f"by that identity")
    console.print(f"  basis             : [{basis_colour}]{verdict.basis.value}")
    console.print(f"  registered by     : "
                  f"{verdict.registration_logged_at.isoformat()} "
                  f"(the log's integratedTime)")
    console.print(f"  mode              : {report['mode']}")
    console.print(f"  algorithms checked: {report['algorithms_checked']}")
    console.print(f"  quantum resistant : {report['quantum_resistant']}")

    if verdict.coverage_checked:
        console.print(f"  covers this sig   : yes, at "
                      f"{verdict.signing_time.isoformat()} "  # type: ignore[union-attr]
                      f"({verdict.signing_time_source.value})")
    else:
        console.print("  [yellow]covers this sig   : not checked -- the artefact "
                      "carries no trustworthy signing time. The registration "
                      "sets no notAfter and no revocation was supplied, so "
                      "there was nothing to rule on; this is 'unchecked', not "
                      "'passed'.")
    # Revocation status, always stated -- including when it was not established.
    outcome = verdict.revocation_search.outcome.value
    if verdict.revocation_status_is_conclusive:
        console.print(f"  revocations       : {outcome} "
                      f"({verdict.revocation_search.candidates_examined} log "
                      f"entr(ies) examined)")
    else:
        console.print(f"  [yellow]revocations       : NOT ESTABLISHED "
                      f"({outcome}). {verdict.revocation_search.detail}")
        if not check_revocations:
            console.print("  [yellow]                    pass --check-revocations "
                          "to search the log.")

    if verdict.signing_time_source is SigningTimeSource.SUPPLIED:
        console.print("  [yellow]note              : the signing time was "
                      "asserted on the command line, not proven.")
    for finding in report["temporal"]["findings"]:
        colour = "red" if finding.startswith("[critical]") else "yellow"
        console.print(f"    [{colour}]{finding}")
    for warning in report["warnings"]:
        console.print(f"  [yellow]warning: {warning}")


@app.command("verify")
def verify_artefact(
    target: Path = typer.Argument(..., help="File or directory to verify."),
    bundle: Path = typer.Option(..., "--bundle", help="The signature bundle."),
    mode: str = typer.Option("strict", "--mode", help="strict | classical | pqc."),
    context: str = typer.Option("", "--context", help="Must match signing."),
    registration: Path | None = typer.Option(
        None, "--registration",
        help="A registration bundle. Given this, the verdict also says WHO the "
             "signing key belongs to, and on what basis. Needs --fulcio-roots "
             "and --log-key."),
    fulcio_roots: Path | None = typer.Option(
        None, "--fulcio-roots",
        help="Trusted Fulcio roots (DER/PEM file or directory). Your trust "
             "store; required with --registration."),
    log_key: Path | None = typer.Option(
        None, "--log-key",
        help="The transparency log's public key (DER). Required with "
             "--registration."),
    artefact_signed_at: str | None = typer.Option(
        None, "--artefact-signed-at",
        help="ASSERT when the artefact was signed (RFC 3339), so notAfter and "
             "revocation can be ruled on. Labelled as an assertion in the "
             "output -- it is not evidence."),
    at: str | None = typer.Option(
        None, "--at",
        help="Judge the attribution as of this RFC 3339 instant instead of now "
             "-- for asking how it will look after the classical algorithm is "
             "disallowed. Only meaningful with --registration."),
    check_revocations: bool = typer.Option(
        False, "--check-revocations",
        help="Search the transparency log for revocations of the registered "
             "key. WITHOUT this, the verdict says revocation was NOT CHECKED "
             "rather than pretending the key is live."),
    rekor_url: str = typer.Option(
        "https://rekor.sigstore.dev", "--rekor-url",
        help="The log to search with --check-revocations."),
) -> None:
    """Verify an artefact against a bundle, and report what was checked.

    With --registration, this answers the question that actually matters:
    not merely "is this signature valid" but "whose signature is it, and can
    that attribution still be trusted". The registration's PQC key must be the
    very key the artefact was signed under -- otherwise a valid signature and a
    valid registration would be two unrelated facts.
    """
    from .signing.bundle import parse_bundle
    from .signing.sign import VerificationFailed, VerifyMode, verify

    try:
        chosen = VerifyMode(mode.lower())
    except ValueError:
        console.print(f"[red]--mode must be strict, classical or pqc; got {mode!r}")
        raise typer.Exit(2) from None

    try:
        parsed = parse_bundle(json.loads(bundle.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        console.print(f"[red]could not read the bundle: {exc}")
        raise typer.Exit(2) from None

    # With --registration, the artefact and the identity are verified together
    # and the join between them is enforced. Without it, this is the plain
    # "is the signature valid" check, unchanged.
    if registration is not None:
        _verify_with_registration(
            target, parsed, registration, fulcio_roots, log_key,
            chosen, context, artefact_signed_at, at,
            check_revocations, rekor_url)
        return
    if (fulcio_roots is not None or log_key is not None
            or artefact_signed_at or at):
        console.print("[yellow]--fulcio-roots/--log-key/--artefact-signed-at "
                      "--at only apply with --registration; ignoring them.")

    try:
        report = verify(target, parsed, mode=chosen, context=context.encode())
    except VerificationFailed as exc:
        console.print("[bold red]VERIFICATION FAILED[/bold red]")
        console.print(str(exc))
        raise typer.Exit(1) from None

    console.print("[bold green]VERIFIED[/bold green]")
    console.print(f"  mode              : {report['mode']}")
    console.print(f"  algorithms checked: {report['algorithms_checked']}")
    console.print(f"  quantum resistant : {report['quantum_resistant']}")
    console.print(f"  binding enforced  : {report['binding_enforced']}")
    temporal = report["temporal"]
    console.print(f"  time evidence     : {temporal['evidence']} "
                  f"(trusted={temporal['evidence_trusted']}, "
                  f"bound={temporal['evidence_bound']})")
    for finding in temporal["findings"]:
        colour = "red" if finding.startswith("[critical]") else "yellow"
        console.print(f"    [{colour}]{finding}")
    for warning in report["warnings"]:
        console.print(f"  [yellow]warning: {warning}")
    entropy = report["signed_claims"]["entropy"]
    if entropy:
        console.print(f"  entropy (claimed) : quantum_seeded={entropy['quantum_seeded']} "
                      f"verifiable={entropy['externally_verifiable_sources']}")


@app.command("verify-registration")
def verify_registration_cmd(
    bundle: Path = typer.Option(..., "--bundle",
                                help="The registration bundle JSON."),
    fulcio_roots: Path = typer.Option(
        ..., "--fulcio-roots",
        help="A file or directory of trusted Fulcio root certificates (DER or "
             "PEM). Never hardcoded: this is your trust store."),
    log_key: Path = typer.Option(..., "--log-key",
                                 help="The transparency log's public key (DER)."),
    at: str | None = typer.Option(
        None, "--at", help="Verify as of this RFC 3339 instant, for asking how "
                           "the binding will look in the future. Default: now."),
    artifact_signed_at: str | None = typer.Option(
        None, "--artifact-signed-at",
        help="If given, also check notAfter and revocation against this "
             "artefact signing time and print the authorised PQC key."),
) -> None:
    """Verify a key registration and report how the PQC key was trusted.

    Resolves the whole chain -- proof of possession, Fulcio identity,
    transparency inclusion, and the temporal decision -- and names the basis it
    trusted (direct, or rescued-by-timestamp) rather than a bare yes. A verdict
    that hides its basis is what this design exists to avoid.
    """
    import base64
    from datetime import datetime

    from .signing.registration import RegistrationError
    from .signing.registration_chain import (
        RegistrationBundle,
        verify_registration_chain,
    )

    def _load_certs(path: Path) -> list[bytes]:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        paths = sorted(path.iterdir()) if path.is_dir() else [path]
        out: list[bytes] = []
        for p in paths:
            raw = p.read_bytes()
            try:                                   # PEM may hold several
                certs = x509.load_pem_x509_certificates(raw)
                out.extend(c.public_bytes(Encoding.DER) for c in certs)
            except (ValueError, TypeError):
                out.append(raw)                    # already DER
        return out

    try:
        parsed = RegistrationBundle.from_dict(
            json.loads(bundle.read_text(encoding="utf-8")))
        roots = _load_certs(fulcio_roots)
        key_der = log_key.read_bytes()
        now = datetime.fromisoformat(at.replace("Z", "+00:00")) if at else None
    except (OSError, ValueError, RegistrationError) as exc:
        console.print(f"[red]could not read inputs: {exc}")
        raise typer.Exit(2) from None

    try:
        binding = verify_registration_chain(
            parsed, fulcio_roots=roots, log_public_key=key_der, now=now)
    except RegistrationError as exc:
        console.print("[bold red]REGISTRATION NOT TRUSTED[/bold red]")
        console.print(str(exc))
        raise typer.Exit(1) from None

    console.print("[bold green]REGISTRATION TRUSTED[/bold green]")
    console.print(f"  identity        : {binding.identity}")
    console.print(f"  issuer          : {binding.issuer}")
    console.print(f"  pqc algorithm   : {binding.pqc_algorithm}")
    basis_colour = "green" if binding.basis.value == "direct" else "yellow"
    console.print(f"  basis           : [{basis_colour}]{binding.basis.value}")
    console.print(f"  valid as of     : {binding.valid_as_of.isoformat()} "
                  f"(the log's integratedTime)")
    console.print(f"  pqc public key  : "
                  f"{base64.b64encode(binding.pqc_public_key).decode()[:32]}...")

    if artifact_signed_at is not None:
        from .signing.registration import NotYetRegistered
        from .signing.registration_chain import authorize_for_artifact

        signing_time = datetime.fromisoformat(
            artifact_signed_at.replace("Z", "+00:00"))
        try:
            key = authorize_for_artifact(binding, signing_time)
        except (NotYetRegistered, RegistrationError) as exc:
            console.print(f"  [red]does NOT cover an artefact signed at "
                          f"{artifact_signed_at}: {exc}")
            raise typer.Exit(1) from None
        console.print(f"  [green]covers the artefact; verify its signature "
                      f"against {base64.b64encode(key).decode()[:32]}...")


@app.command("register")
def register_cmd(
    out: Path = typer.Option(..., "--out",
                             help="Directory to write bundle.json and the PQC "
                                  "key files into."),
    pqc_algorithm: str = typer.Option("ml-dsa-87", "--pqc-algorithm",
                                      help="The long-term PQC algorithm to register."),
    pqc_public_key: Path | None = typer.Option(
        None, "--pqc-public-key",
        help="An EXISTING PQC public key to register (raw bytes). With "
             "--pqc-secret-key. If omitted, a fresh pair is generated."),
    pqc_secret_key: Path | None = typer.Option(
        None, "--pqc-secret-key", help="The matching PQC secret key (raw bytes)."),
    not_after: str | None = typer.Option(
        None, "--not-after",
        help="Optional RFC 3339 self-limit: the registration does not cover "
             "artefacts signed after this instant."),
    identity_token: str | None = typer.Option(
        None, "--identity-token",
        help="Skip the interactive OIDC flow and use this token."),
    oauth_force_oob: bool = typer.Option(
        False, "--oauth-force-oob",
        help="Out-of-band OIDC: print a URL and read back a code. Use on a "
             "machine with no usable browser (WSL, containers, servers)."),
    log_key: Path | None = typer.Option(
        None, "--log-key",
        help="The transparency log's public key (DER). STRONGLY preferred: this "
             "is your trust store. If omitted it is fetched from the log, which "
             "is fine for producing a bundle but is not third-party trust."),
    fulcio_roots: Path | None = typer.Option(
        None, "--fulcio-roots",
        help="A file or directory of trusted Fulcio roots (DER/PEM), or a TUF "
             "trusted_root.json. If omitted, the chain Fulcio returns is used, "
             "which does NOT establish independent trust."),
) -> None:
    """Register a PQC key against your OIDC identity, and log it.

    Runs the eight-step protocol: OIDC -> Fulcio certificate over an ephemeral
    classical key -> a dual-signed registration naming your PQC key -> a
    transparency-log entry -> a self-contained bundle. The bundle is VERIFIED
    end to end before it is written; a registration that logs but does not
    verify is a failure, and this command exits non-zero.

    RESIDUAL RISK, briefly. The binding is only as good as the OIDC identity
    that anchored it: whoever controls that account at registration time can
    register a key as you. The rescue only works for registrations logged
    BEFORE the classical algorithm's disallow date -- registering after it
    proves nothing, so register early. And transparency is only useful if
    someone looks: monitor the log for registrations naming your identity.
    """
    import base64 as b64
    from datetime import datetime, timezone

    from .signing.backends import get_backend
    from .signing.register import register
    from .signing.registration import RegistrationError
    from .signing.sigstore_clients import (
        FulcioRestClient,
        RekorRestClient,
        SigstoreClientError,
        acquire_identity_token,
        rekor_public_key_der,
    )

    def _load_certs(path: Path) -> list[bytes]:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        if path.is_file() and path.suffix == ".json":       # TUF trusted_root
            data = json.loads(path.read_text(encoding="utf-8"))
            return [b64.b64decode(cert["rawBytes"])
                    for ca in data.get("certificateAuthorities", [])
                    for cert in ca.get("certChain", {}).get("certificates", [])]
        paths = sorted(path.iterdir()) if path.is_dir() else [path]
        out_ders: list[bytes] = []
        for p in paths:
            raw = p.read_bytes()
            try:
                out_ders.extend(c.public_bytes(Encoding.DER)
                                for c in x509.load_pem_x509_certificates(raw))
            except (ValueError, TypeError):
                out_ders.append(raw)
        return out_ders

    # The long-term PQC key: the thing being registered. Supplied or generated.
    backend = get_backend(pqc_algorithm)
    if pqc_public_key is not None or pqc_secret_key is not None:
        if pqc_public_key is None or pqc_secret_key is None:
            console.print("[red]--pqc-public-key and --pqc-secret-key must be "
                          "given together.")
            raise typer.Exit(2)
        pqc_pub, pqc_sk = pqc_public_key.read_bytes(), pqc_secret_key.read_bytes()
        generated = False
    else:
        pqc_pub, pqc_sk = backend.keygen()
        generated = True

    try:
        token = acquire_identity_token(
            force_oob=oauth_force_oob, supplied=identity_token)
        log_key_der = (log_key.read_bytes() if log_key
                       else rekor_public_key_der())
        fulcio = FulcioRestClient(token)
        rekor = RekorRestClient()
        console.print(f"  identity        : {fulcio.subject}")

        if fulcio_roots is not None:
            roots = _load_certs(fulcio_roots)
        else:
            # Learn the CA pool from a throwaway certification, so register's
            # own verification has roots. Not independent trust -- say so.
            probe_pub, probe_sk = get_backend("ecdsa-p256").keygen()
            probe = fulcio.certify(probe_pub, probe_sk)
            roots = list(probe.intermediate_ders) or [probe.leaf_der]
            console.print("  [yellow]trust roots taken from Fulcio's own reply "
                          "(--fulcio-roots not given): this proves the chain is "
                          "self-consistent, not that it is trusted.")

        bundle = register(
            pqc_algorithm=pqc_algorithm, pqc_public_key=pqc_pub,
            pqc_secret=pqc_sk, fulcio=fulcio, rekor=rekor,
            fulcio_roots=roots, log_public_key=log_key_der,
            not_after=not_after)
    except (SigstoreClientError, OSError, ValueError) as exc:
        console.print(f"[bold red]REGISTRATION FAILED[/bold red]\n{exc}")
        raise typer.Exit(2) from None
    except RegistrationError as exc:
        # The step-8 gate: it logged, but it does not verify. Not a success.
        console.print(f"[bold red]REGISTRATION NOT VERIFIABLE[/bold red]\n{exc}")
        raise typer.Exit(1) from None

    out.mkdir(parents=True, exist_ok=True)
    (out / "bundle.json").write_text(
        json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
    (out / "rekor_key.der").write_bytes(log_key_der)
    for i, der in enumerate(roots):
        (out / f"fulcio_root_{i}.der").write_bytes(der)
    if generated:
        (out / f"{pqc_algorithm}.pub").write_bytes(pqc_pub)
        secret_path = out / f"{pqc_algorithm}.key"
        secret_path.write_bytes(pqc_sk)
        with contextlib.suppress(OSError):  # e.g. a Windows mount; not fatal
            secret_path.chmod(0o600)

    from .signing.registration_chain import verify_registration_chain

    binding = verify_registration_chain(
        bundle, fulcio_roots=roots, log_public_key=log_key_der,
        now=datetime.now(timezone.utc))
    console.print("[bold green]REGISTERED[/bold green]")
    console.print(f"  identity        : {binding.identity}")
    console.print(f"  issuer          : {binding.issuer}")
    console.print(f"  pqc algorithm   : {binding.pqc_algorithm}")
    console.print(f"  basis           : [green]{binding.basis.value}")
    console.print(f"  logged at       : {binding.valid_as_of.isoformat()} "
                  f"(the log's integratedTime -- the upper bound the rescue "
                  f"turns on)")
    console.print(f"  bundle          : {out / 'bundle.json'}")
    if generated:
        console.print(f"  [yellow]PQC SECRET KEY written to "
                      f"{out / f'{pqc_algorithm}.key'} -- this is long-term key "
                      f"material. Move it somewhere safe; anyone holding it can "
                      f"sign as you for the life of this registration.")


@app.command("trust-material")
def trust_material_cmd(
    out: Path = typer.Option(..., "--out",
                             help="Directory to write fulcio_roots.pem and "
                                  "rekor.pub into."),
    staging: bool = typer.Option(
        False, "--staging",
        help="Sigstore's staging instance instead of production. Only "
             "useful for testing against staging Fulcio/Rekor."),
) -> None:
    """Fetch a real trust store for --fulcio-roots/--log-key.

    Without this, `register` falls back to trusting whatever certificate
    chain Fulcio itself returned in the moment (self-consistent, not
    independently trusted), and `verify --registration` / `verify-registration`
    simply refuse to run without a trust store at all. Most people do not have
    a Fulcio CA pool and a Rekor public key lying around, so this pulls both
    from Sigstore's production TUF root -- the same mechanism `sigstore-python`
    itself uses to bootstrap trust, not a QResP-specific shortcut.

    This is a CONVENIENCE, not the only path. `--fulcio-roots` also accepts a
    TUF `trusted_root.json` file directly (fetch it by any means you trust,
    e.g. from a machine that already has one cached, or from
    https://tuf-repo-cdn.sigstore.dev under TUF's own signature checks) and
    QResP will parse it the same way this command does internally.
    """
    import base64 as b64

    try:
        from sigstore._internal.tuf import DEFAULT_TUF_URL, STAGING_TUF_URL, TrustUpdater
    except ImportError:
        console.print(
            "[red]`sigstore` is not installed.[/red] `pip install sigstore` "
            "(or `pip install qresp\\[register]`), then rerun this command. "
            "Alternatively, fetch a TUF trusted_root.json yourself and pass "
            "it directly as --fulcio-roots to register/verify -- no "
            "conversion needed, QResP reads that format natively.")
        raise typer.Exit(2) from None

    url = STAGING_TUF_URL if staging else DEFAULT_TUF_URL
    console.print(f"  fetching and verifying the TUF trust root from {url} ...")
    try:
        trusted_root_path = TrustUpdater(url).get_trusted_root_path()
    except Exception as exc:  # noqa: BLE001 -- TUF/network failures vary by version
        console.print(
            f"[red]could not fetch/verify the TUF trust root: {exc}[/red]\n"
            "  This needs network access to tuf-repo-cdn.sigstore.dev. If a "
            "trusted_root.json is available some other way (a machine that "
            "does have access, sigstore-python's own cache), pass it "
            "directly as --fulcio-roots instead of running this command.")
        raise typer.Exit(1) from None

    data = json.loads(Path(trusted_root_path).read_text(encoding="utf-8"))
    ca_certs = [b64.b64decode(cert["rawBytes"])
                for ca in data.get("certificateAuthorities", [])
                for cert in ca.get("certChain", {}).get("certificates", [])]
    rekor_keys = [b64.b64decode(tlog["publicKey"]["rawBytes"])
                  for tlog in data.get("tlogs", [])
                  if tlog.get("publicKey", {}).get("rawBytes")]
    if not ca_certs or not rekor_keys:
        console.print(
            f"[red]parsed {trusted_root_path} but found no CA certificates "
            f"or no Rekor key -- the TUF target's shape may have changed "
            f"since this command was written. The raw file is at "
            f"{trusted_root_path}; pass it directly as --fulcio-roots "
            f"(it is accepted as-is) while this gets fixed.")
        raise typer.Exit(1)
    if len(rekor_keys) > 1:
        console.print(f"  [yellow]{len(rekor_keys)} Rekor keys in the trust "
                       f"root (log key rotation history); writing the first. "
                       f"If verification of an OLDER entry fails on the key, "
                       f"inspect {trusted_root_path} for the others.")

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    out.mkdir(parents=True, exist_ok=True)
    roots_path = out / "fulcio_roots.pem"
    with roots_path.open("wb") as f:
        for der in ca_certs:
            f.write(x509.load_der_x509_certificate(der).public_bytes(Encoding.PEM))
    key_path = out / "rekor.pub"
    key_path.write_bytes(rekor_keys[0])

    console.print(f"[green]wrote {len(ca_certs)} Fulcio CA certificate(s) -> "
                  f"{roots_path}")
    console.print(f"[green]wrote the Rekor public key -> {key_path}")
    console.print("\n  Use them with:")
    console.print(f"    qresp register --out ./my-registration "
                  f"--fulcio-roots {roots_path} --log-key {key_path}")
    console.print(f"    qresp verify ./artefact --bundle bundle.json "
                  f"--registration ./my-registration/bundle.json \\\n"
                  f"        --fulcio-roots {roots_path} --log-key {key_path} "
                  f"--check-revocations")


# The __main__ guard MUST stay at the end of this file. It used to sit in the
# middle, before the signing commands were defined, so `python -m qresp.cli`
# invoked the app with only the audit commands registered and reported
# "No such command: sign" -- while the installed `qresp` console script, which
# imports the whole module first, worked fine. A confusing split found while
# wiring `register`.
if __name__ == "__main__":
    app()
