"""Audit scanner.

Orchestrates the audit pipeline:

    HfClient -> detect_signature_files() -> parse_signature() -> classify -> ModelRecord

The scanner is deliberately written to be resumable: each ModelRecord is
appended to the output JSONL file as soon as it is produced. If the process
crashes or is interrupted, re-running it will skip model_ids already present
in the output file.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .detect import detect_signature_files
from .hf_client import HfClientProtocol, ModelSummary
from .model import (
    ModelRecord,
    QLabel,
    SigAlgorithm,
    SigFormat,
    classify_algorithm,
    reconcile_labels,
)
from .parse import parse_signature

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# The core per-model audit step
# ---------------------------------------------------------------------------
def audit_model(client: HfClientProtocol, summary: ModelSummary) -> ModelRecord:
    """Run the full audit on a single model and return the resulting record.

    Network errors during signature-file download are caught and logged;
    affected signatures are recorded with algorithm=UNKNOWN so the model
    still appears in the dataset with a clear `error` label.
    """
    now = datetime.now(timezone.utc)
    candidates = detect_signature_files(summary.filenames)
    candidate_names = [name for name, _ in candidates]

    # Fast path: no signature files at all
    if not candidates:
        return ModelRecord(
            model_id=summary.model_id,
            publisher=summary.publisher,
            downloads=summary.downloads,
            last_modified=summary.last_modified,
            file_count=len(summary.filenames),
            has_signature=False,
            candidate_files=[],
            sig_algorithm=SigAlgorithm.NONE,
            sig_format=SigFormat.NONE,
            key_size_bits=None,
            q_label=QLabel.UNSIGNED,
            audit_ts=now,
            notes=None,
        )

    # Slow path: at least one candidate. Download and parse each.
    per_sig_results: list[tuple[SigAlgorithm, SigFormat, Optional[int], Optional[str]]] = []
    notes_accum: list[str] = []
    for name, fmt in candidates:
        try:
            raw = client.fetch_file(summary.model_id, name)
        except Exception as exc:
            log.warning("Fetch failed for %s/%s: %s", summary.model_id, name, exc)
            per_sig_results.append(
                (SigAlgorithm.UNKNOWN, fmt, None, f"fetch_failed: {exc!s}")
            )
            continue

        result = parse_signature(raw, fmt)
        per_sig_results.append((result.algorithm, fmt, result.key_size_bits, result.notes))

    # Reconcile multiple signature files. If they disagree, the model gets
    # the `mixed` label and we keep all the diagnostic notes for review.
    labels = [classify_algorithm(a) for a, _, _, _ in per_sig_results]
    final_label = reconcile_labels(labels)

    # Choose a "representative" algorithm/format for the report. When the model
    # has multiple signatures, prefer the first non-error, non-unknown one;
    # otherwise fall back to the first entry.
    primary_algo = SigAlgorithm.UNKNOWN
    primary_fmt = candidates[0][1]
    primary_size: Optional[int] = None
    for algo, fmt, size, note in per_sig_results:
        # Always keep the diagnostic note, even when the algorithm was
        # successfully classified -- notes like "inferred_from_sigstore_fulcio_default"
        # document a heuristic attribution and must not be silently dropped
        # just because the algorithm itself was resolved.
        if note:
            notes_accum.append(note)
        if primary_algo == SigAlgorithm.UNKNOWN and algo not in (SigAlgorithm.UNKNOWN, SigAlgorithm.NONE):
            primary_algo = algo
            primary_fmt = fmt
            primary_size = size
    if primary_algo == SigAlgorithm.UNKNOWN and per_sig_results:
        # No useful parse; expose the first format we saw.
        primary_fmt = per_sig_results[0][1]

    return ModelRecord(
        model_id=summary.model_id,
        publisher=summary.publisher,
        downloads=summary.downloads,
        last_modified=summary.last_modified,
        file_count=len(summary.filenames),
        has_signature=True,
        candidate_files=candidate_names,
        sig_algorithm=primary_algo,
        sig_format=primary_fmt,
        key_size_bits=primary_size,
        q_label=final_label,
        audit_ts=now,
        notes="; ".join(notes_accum) if notes_accum else None,
    )


# ---------------------------------------------------------------------------
# Bulk audit with resume support
# ---------------------------------------------------------------------------
def _load_already_seen(jsonl_path: Path) -> set[str]:
    """Return the set of model_ids already written to the output file."""
    if not jsonl_path.exists():
        return set()
    seen: set[str] = set()
    with jsonl_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                seen.add(json.loads(line)["model_id"])
            except (json.JSONDecodeError, KeyError):
                continue  # ignore corrupted lines, don't lose progress
    return seen


def run_audit(
    client: HfClientProtocol,
    n: int,
    out_path: Path,
    resume: bool = True,
) -> Iterator[ModelRecord]:
    """Run the audit on the top-N models, streaming records to ``out_path``.

    Yields each ModelRecord as it is produced, so callers can show progress.

    Args:
        client: the HuggingFace client (real or fixture).
        n: how many top-downloaded models to audit.
        out_path: JSONL file to append to.
        resume: if True (default), skip model_ids already present in the output.
            If False, the file is truncated and rebuilt from scratch -- this
            is what "start over" means. Opening in append mode while also
            not skipping already-seen models would duplicate every row already
            in the file (each re-audited model_id would appear twice), which
            silently corrupted a prior full.jsonl into n=2000 with doubled
            counts across every label. resume=False must reset the file.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    already_seen = _load_already_seen(out_path) if resume else set()
    log.info("Resuming with %d models already audited", len(already_seen))

    summaries: Iterable[ModelSummary] = client.list_top_models(n)
    write_mode = "a" if resume else "w"
    with out_path.open(write_mode, encoding="utf-8") as out:
        for summary in summaries:
            if summary.model_id in already_seen:
                continue
            record = audit_model(client, summary)
            out.write(record.model_dump_json() + "\n")
            out.flush()
            yield record
