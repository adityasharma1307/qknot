"""QResP command-line interface.

Usage examples (after `pip install -e .`):

  qresp scan --n 50 --out data/pilot.jsonl
  qresp scan --n 1000 --out data/full.jsonl --token $HF_TOKEN
  qresp summarise --in data/pilot.jsonl
"""
from __future__ import annotations

import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from .hf_client import HfClient
from .model import QLabel
from .qrng import OnFailure, QrngUnavailable, get_entropy
from .scanner import run_audit, run_audit_ids

app = typer.Typer(
    help="QResP: Quantum-Resilient Provenance audit for ML model registries.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    n: int = typer.Option(50, "--n", help="Number of top-downloaded models to audit."),
    out: Path = typer.Option(Path("data/audit.jsonl"), "--out", help="Output JSONL file."),
    token: Optional[str] = typer.Option(
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
                           "scripts/sample_longtail.py.",
    ),
    out: Path = typer.Option(Path("data/longtail.jsonl"), "--out",
                             help="Output JSONL file."),
    token: Optional[str] = typer.Option(
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
    backend: str = typer.Option(
        "anu", "--backend", help="Entropy source: anu, system, ibm, usb.",
    ),
    on_qrng_failure: str = typer.Option(
        "fallback", "--on-qrng-failure",
        help="Non-interactive behaviour when the quantum source fails: "
             "wait, fallback, or abort. Ignored when a human can be prompted.",
    ),
    out: Optional[Path] = typer.Option(
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

    The record states which backend actually served the bytes, which is what
    lets a verifier tell a quantum-seeded key from one that fell back to the
    system CSPRNG. Falling back is sound -- ML-DSA's security rests on
    Module-LWE hardness, not on the seed's physical origin -- but it must be
    visible rather than assumed.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
        stream=sys.stdout,
    )

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


@app.command()
def summarise(
    inp: Path = typer.Option(..., "--in", help="JSONL audit dataset to summarise."),
) -> None:
    """Print summary statistics for an existing audit dataset."""
    if not inp.exists():
        console.print(f"[red]File not found:[/red] {inp}")
        raise typer.Exit(code=1)

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
    n_models: Optional[int] = None,
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
    for lbl in [QLabel.SAFE, QLabel.VULNERABLE, QLabel.UNSIGNED, QLabel.MIXED, QLabel.ERROR]:
        cnt = counter.get(lbl, 0)
        pct = (cnt / total * 100.0) if total else 0.0
        table.add_row(lbl.value, str(cnt), f"{pct:5.1f}%")
    console.print(table)


if __name__ == "__main__":
    app()
