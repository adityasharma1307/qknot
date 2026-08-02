"""QResP command-line interface.

Usage examples (after `pip install -e .`):

  qresp scan --n 50 --out data/pilot.jsonl
  qresp scan --n 1000 --out data/full.jsonl --token $HF_TOKEN
  qresp summarise --in data/pilot.jsonl
"""
from __future__ import annotations

import contextlib
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

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
    help="QResP: Quantum-Resilient Provenance audit for ML model registries.",
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
    """Run the audit on the top-N HuggingFace models."""
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
    """Print summary statistics for an existing audit dataset."""
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
    """Sign an artefact with a non-separable hybrid signature."""
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


@app.command("verify")
def verify_artefact(
    target: Path = typer.Argument(..., help="File or directory to verify."),
    bundle: Path = typer.Option(..., "--bundle", help="The signature bundle."),
    mode: str = typer.Option("strict", "--mode", help="strict | classical | pqc."),
    context: str = typer.Option("", "--context", help="Must match signing."),
) -> None:
    """Verify an artefact against a bundle, and report what was checked."""
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


# The __main__ guard MUST stay at the end of this file. It used to sit in the
# middle, before the signing commands were defined, so `python -m qresp.cli`
# invoked the app with only the audit commands registered and reported
# "No such command: sign" -- while the installed `qresp` console script, which
# imports the whole module first, worked fine. A confusing split found while
# wiring `register`.
if __name__ == "__main__":
    app()
