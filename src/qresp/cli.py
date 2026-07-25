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
from .scanner import run_audit

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
