"""Audit scanner.

Orchestrates the audit pipeline:

    HfClient -> detect_signature_files() -> parse_signature() -> classify -> ModelRecord

UNIT OF ANALYSIS
    One ModelRecord is one *repository*, not one model artefact. A repo is
    labelled signed if it carries at least one recognised signature file
    anywhere in its tree, however many that is: `kernels-community/relu` has 38
    `.sigstore` files for its build matrix and `granitelib-rag-r1.0` has 33
    `model.sig` files for its LoRA adapters, and each is a single row. Counting
    artefacts instead would inflate apparent adoption several-fold on the
    strength of two publishers' packaging habits. See docs/DATASETS.md.

The scanner is deliberately written to be resumable: each ModelRecord is
appended to the output JSONL file as soon as it is produced. If the process
crashes or is interrupted, re-running it will skip model_ids already present
in the output file.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from .detect import detect_signature_files
from .hf_client import (
    HfClientProtocol,
    ModelSummary,
    TransientFetchError,
    is_transient,
)
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

    Failures during signature-file download are split into two kinds:

      * Transient (rate limiting, connection loss, 5xx). These say nothing
        about the model, so no record is produced at all -- ``TransientFetchError``
        is raised and the caller leaves the model absent from the output so
        that resume re-attempts it. Recording a 429 as a finding would let our
        own request rate masquerade as a property of the registry.

      * Permanent (missing file, refused oversize, malformed content). These
        are genuine facts about the repo, recorded with algorithm=UNKNOWN and
        an `error` label so the row count is preserved.

    Raises:
        TransientFetchError: if any signature file failed for a transient reason.
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
    per_sig_results: list[tuple[SigAlgorithm, SigFormat, int | None, str | None]] = []
    for name, fmt in candidates:
        try:
            raw = client.fetch_file(summary.model_id, name)
        except Exception as exc:
            if is_transient(exc):
                # Do not write a record. The model must stay absent from the
                # output so resume picks it up again; a partial record here
                # would be indistinguishable from a real parse failure and
                # would be skipped forever.
                log.warning(
                    "Transient failure for %s/%s (%s). Leaving unrecorded for retry.",
                    summary.model_id, name, exc,
                )
                raise TransientFetchError(summary.model_id, exc) from exc
            log.warning("Fetch failed for %s/%s: %s", summary.model_id, name, exc)
            per_sig_results.append(
                (SigAlgorithm.UNKNOWN, fmt, None, f"fetch_failed: {exc!s}")
            )
            continue

        # The parsers promise never to raise on malformed input, and are tested
        # against hostile bytes. This wrapper is the belt to that braces: a
        # signature file is attacker-controlled content, and a single unhandled
        # exception here would propagate out of the audit loop and abort an
        # entire 20,000-repo run. One unparseable file must cost one record, not
        # the scan. (A JSON array in a .sig did exactly this before the parsers
        # were hardened.)
        try:
            result = parse_signature(raw, fmt)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all
            log.error(
                "Parser raised on %s/%s (%s). This is a bug in the parser; "
                "recording as unparseable so the scan continues.",
                summary.model_id, name, exc,
            )
            per_sig_results.append(
                (SigAlgorithm.UNKNOWN, fmt, None, f"parser_crashed: {exc!s}")
            )
            continue
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
    primary_size: int | None = None
    raw_notes: list[str] = []
    for algo, fmt, size, note in per_sig_results:
        # Always keep the diagnostic note, even when the algorithm was
        # successfully classified -- notes like "inferred_from_sigstore_fulcio_default"
        # document a heuristic attribution and must not be silently dropped
        # just because the algorithm itself was resolved.
        #
        # Deduplicate, though. A repo with 37 signature files previously got the
        # identical note 37 times joined by "; ", which made the column useless
        # for grouping and bloated the dataset for no information. Multiplicity
        # is still worth keeping, so it is recorded as a count rather than by
        # repetition; insertion order is preserved so the first note a reader
        # sees is the first the scanner formed.
        if note:
            raw_notes.append(note)
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
        notes=_format_notes(raw_notes),
    )


def _format_notes(notes: list[str]) -> str | None:
    """Collapse repeated notes, keeping multiplicity as a count.

    A repo with 37 signature files previously produced the same note 37 times
    joined by "; ", which made the column useless for grouping and wasted 3.4 KB
    across the published dataset. The count is kept because "this heuristic fired
    on every one of 37 signatures" is genuinely different from "it fired once".
    Insertion order is preserved, so the first note a reader sees is the first
    the scanner formed.
    """
    counts: dict[str, int] = {}
    for note in notes:
        counts[note] = counts.get(note, 0) + 1
    if not counts:
        return None
    return "; ".join(
        note if count == 1 else f"{note} (x{count})" for note, count in counts.items()
    )


def unavailable_record(model_id: str, cause: BaseException | str) -> ModelRecord:
    """Record for a repo whose metadata could not be retrieved permanently.

    Deleted, renamed, or gated repos are labelled ERROR rather than UNSIGNED.
    The distinction matters for the survey: `unsigned` is a claim that we looked
    and found no signature, while these are repos we could not look at. Counting
    them as unsigned would inflate the very statistic the project reports.

    They stay in the dataset so the realised sample size continues to match the
    sampling frame recorded in the manifest.
    """
    return ModelRecord(
        model_id=model_id,
        publisher=model_id.split("/")[0] if "/" in model_id else "(individual)",
        downloads=0,
        last_modified=None,
        file_count=0,
        has_signature=False,
        candidate_files=[],
        sig_algorithm=SigAlgorithm.UNKNOWN,
        sig_format=SigFormat.NONE,
        key_size_bits=None,
        q_label=QLabel.ERROR,
        audit_ts=datetime.now(timezone.utc),
        notes=f"metadata_unavailable: {cause!s}",
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


def _stream_records(
    client: HfClientProtocol,
    make_summaries: Callable[
        [set[str]], Iterable[ModelSummary | ModelRecord | TransientFetchError]
    ],
    out_path: Path,
    resume: bool,
    max_consecutive_transient: int,
) -> Iterator[ModelRecord]:
    """Shared audit loop for both the top-N and explicit-id entry points.

    `make_summaries` receives the set of already-audited model_ids and returns
    the summaries to process. Passing the set in lets the id-list path skip
    metadata requests for models that are already done, which on a resumed
    20,000-model run is the difference between one request per remaining model
    and one per model in the whole sample.

    The iterable may yield, in place of a summary:

      * ``TransientFetchError`` -- metadata fetch failed for a transient reason.
        Yielding rather than raising keeps one unreachable repo from aborting
        the whole run while still routing it through the deferral accounting.
      * ``ModelRecord`` -- an already-decided outcome that needs no auditing,
        such as a repo that has been deleted since the sampling frame was built.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    already_seen = _load_already_seen(out_path) if resume else set()
    log.info("Resuming with %d models already audited", len(already_seen))

    write_mode = "a" if resume else "w"
    deferred: list[str] = []
    consecutive = 0

    def _defer(model_id: str, exc: BaseException) -> None:
        """Record a transient failure without writing anything to the output."""
        nonlocal consecutive
        deferred.append(model_id)
        consecutive += 1
        if max_consecutive_transient and consecutive >= max_consecutive_transient:
            raise RuntimeError(
                f"Aborting: {consecutive} consecutive transient failures, "
                f"most recently {model_id}. The registry is likely "
                f"unreachable or the token is being throttled hard. "
                f"{len(deferred)} models left unrecorded; rerun to resume."
            ) from exc

    with out_path.open(write_mode, encoding="utf-8") as out:
        for item in make_summaries(already_seen):
            if isinstance(item, TransientFetchError):
                _defer(item.model_id, item)
                continue
            if item.model_id in already_seen:
                continue
            if isinstance(item, ModelRecord):
                # Already decided upstream; no signature files to fetch.
                consecutive = 0
                out.write(item.model_dump_json() + "\n")
                out.flush()
                yield item
                continue
            try:
                record = audit_model(client, item)
            except TransientFetchError as exc:
                # Deliberately write nothing: absence is what makes the model
                # eligible for retry on the next resume.
                _defer(item.model_id, exc)
                continue
            consecutive = 0
            out.write(record.model_dump_json() + "\n")
            out.flush()
            yield record

    if deferred:
        log.warning(
            "%d models were left unrecorded after transient failures and will be "
            "retried on the next run: %s%s",
            len(deferred),
            ", ".join(deferred[:5]),
            " ..." if len(deferred) > 5 else "",
        )


def run_audit(
    client: HfClientProtocol,
    n: int,
    out_path: Path,
    resume: bool = True,
    max_consecutive_transient: int = 50,
) -> Iterator[ModelRecord]:
    """Run the audit on the top-N models, streaming records to ``out_path``.

    This is the Stratum A (head) entry point. Yields each ModelRecord as it is
    produced, so callers can show progress.

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
        max_consecutive_transient: abort after this many transient failures in
            a row. Skipping transient failures is right for an isolated 429,
            but if the network has gone away entirely then quietly skipping
            every remaining model would produce a run that looks complete and
            is not. Set to 0 to disable the guard.

    Raises:
        RuntimeError: if `max_consecutive_transient` failures occur in a row.
    """
    return _stream_records(
        client,
        lambda _already: client.list_top_models(n),
        out_path,
        resume,
        max_consecutive_transient,
    )


def run_audit_ids(
    client: HfClientProtocol,
    model_ids: Iterable[str],
    out_path: Path,
    resume: bool = True,
    max_consecutive_transient: int = 50,
) -> Iterator[ModelRecord]:
    """Audit an explicit list of model ids, streaming records to ``out_path``.

    This is the Stratum B (long-tail) entry point. Unlike ``run_audit``, the
    membership of the sample is decided in advance by
    ``scripts/audit/sample_longtail.py`` and must not be re-derived here: the whole
    validity of the random draw depends on auditing exactly the ids that were
    drawn, including any that turn out to be empty or unreachable.

    Ids already present in the output are skipped *before* their metadata is
    requested, so resuming a partially-complete run costs nothing for work
    already done.
    """

    def _summaries(
        already_seen: set[str],
    ) -> Iterator[ModelSummary | ModelRecord | TransientFetchError]:
        for model_id in model_ids:
            if model_id in already_seen:
                continue
            try:
                yield client.get_model_summary(model_id)
            except TransientFetchError as exc:
                yield exc
            except Exception as exc:
                if is_transient(exc):
                    log.warning("Transient metadata failure for %s: %s", model_id, exc)
                    yield TransientFetchError(model_id, exc)
                else:
                    # A permanently unavailable repo (deleted, gated, renamed)
                    # must stay in the output, or the denominator silently
                    # shrinks and the sampling fraction stops meaning what the
                    # manifest says it means.
                    #
                    # But it must NOT be labelled `unsigned`. Routing it through
                    # audit_model with an empty file list would do exactly that,
                    # because no candidate files means the unsigned fast path.
                    # A repo we cannot see is unobservable, not unsigned;
                    # recording it as unsigned turns absence of evidence into
                    # evidence of absence, and biases the result in the
                    # direction of this project's own conclusion.
                    log.warning("Metadata unavailable for %s: %s", model_id, exc)
                    yield unavailable_record(model_id, exc)

    return _stream_records(
        client, _summaries, out_path, resume, max_consecutive_transient
    )
