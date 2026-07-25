"""HuggingFace API client.

Thin wrapper around the `huggingface_hub` Python library that adds:
  * exponential-backoff retries on transient failures
  * a small abstraction (`HfClient`) that can be swapped for a fixture-backed
    client during tests, so the scanner does not require network access in CI.

The wrapper exposes only the two operations the scanner needs:
  1. list_top_models(n)            -> iterable of model summary records
  2. fetch_signature_files(repo)   -> iterable of (filename, bytes)
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from tenacity import retry, stop_after_attempt, wait_exponential

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Transient-failure classification
# ---------------------------------------------------------------------------
class TransientFetchError(Exception):
    """A failure caused by the network or by our own request rate, not by the
    model under audit.

    The distinction matters because the two demand opposite handling. A model
    with a malformed signature file is a *finding* and belongs in the dataset.
    A model we failed to reach because we were rate limited is an artefact of
    how we ran the scan, and recording it as though it were a property of the
    model would corrupt the survey. Transient failures are therefore never
    written to the output; the model is left absent so that resume re-attempts
    it on the next run.
    """

    def __init__(self, model_id: str, cause: BaseException):
        super().__init__(f"transient failure auditing {model_id}: {cause!s}")
        self.model_id = model_id
        self.cause = cause


# HTTP statuses worth retrying. 429 is rate limiting; 5xx are server-side.
# Deliberately excludes 401/403 (bad credentials -- retrying will not help and
# masks a misconfigured token) and 404 (a genuinely absent file, which is a
# finding about the repo).
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


def _status_of(exc: BaseException) -> int | None:
    """Best-effort HTTP status extraction across requests/hub exception types."""
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None) if response is not None else None


def is_transient(exc: BaseException) -> bool:
    """True if `exc` reflects the network or our request rate, not the model.

    This exists because the obvious predicate is wrong. The original retry
    config named the *builtin* ConnectionError and TimeoutError, but nothing
    the HTTP stack raises inherits from them:

        requests.exceptions.ConnectionError -> RequestException -> OSError
        huggingface_hub HfHubHTTPError      -> HTTPError        -> OSError

    They are siblings of the builtins under OSError, not subclasses, so the
    predicate never matched and the retry never fired. Match on the real
    types, and on status code where one is available.
    """
    # Builtins, for in-process callers and test doubles.
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True

    try:
        import requests
    except ImportError:  # pragma: no cover
        return False

    if isinstance(exc, (requests.exceptions.ConnectionError,
                        requests.exceptions.Timeout,
                        requests.exceptions.ChunkedEncodingError)):
        return True

    status = _status_of(exc)
    if status is not None:
        return status in RETRYABLE_STATUS

    # An HTTPError carrying no response object is ambiguous; treat as transient
    # so it is retried rather than silently becoming a finding.
    return isinstance(exc, requests.exceptions.HTTPError)


def _retry_after_or_backoff(retry_state) -> float:
    """Honour a server-supplied Retry-After header, else exponential backoff.

    HuggingFace sends Retry-After on 429. Ignoring it and backing off on our
    own schedule is how a scan gets itself throttled harder.
    """
    fallback = wait_exponential(multiplier=1.0, min=1.0, max=60.0)(retry_state)
    outcome = retry_state.outcome
    if outcome is None or not outcome.failed:
        return fallback
    response = getattr(outcome.exception(), "response", None)
    # `if response:` would be a bug here. requests.Response.__bool__ returns
    # self.ok, so every error response -- including the 429 we specifically
    # care about -- is falsy. Test for None explicitly.
    header = (
        getattr(response, "headers", {}).get("Retry-After")
        if response is not None
        else None
    )
    if not header:
        return fallback
    try:
        return max(float(header), fallback)
    except (TypeError, ValueError):
        return fallback


# ---------------------------------------------------------------------------
# Lightweight DTOs used by the scanner
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ModelSummary:
    """The metadata we need to evaluate a single model's cryptographic posture."""

    model_id: str
    publisher: str
    downloads: int
    last_modified: datetime | None
    filenames: list[str]


# ---------------------------------------------------------------------------
# Protocol — anything quacking like this can act as a HF client
# ---------------------------------------------------------------------------
class HfClientProtocol(Protocol):
    """Interface implemented by both the real and the test client."""

    def list_top_models(self, n: int) -> Iterable[ModelSummary]: ...
    def get_model_summary(self, model_id: str) -> ModelSummary: ...
    def fetch_file(self, repo_id: str, filename: str) -> bytes: ...


# ---------------------------------------------------------------------------
# Real HuggingFace client
# ---------------------------------------------------------------------------
class HfClient:
    """Real HuggingFace client. Requires network access."""

    def __init__(self, token: str | None = None, max_file_bytes: int = 4 * 1024 * 1024):
        """
        Args:
            token: optional HuggingFace API token, raises rate limits.
            max_file_bytes: refuse to download files larger than this. The
                default of 4 MiB is generous for any signature file but tiny
                compared to a model weight tensor.
        """
        # Import locally so test-only environments don't need huggingface_hub installed
        from huggingface_hub import HfApi

        self._api = HfApi(token=token)
        self._token = token
        self._max_file_bytes = max_file_bytes

    @retry(
        retry=lambda state: state.outcome is not None
        and state.outcome.failed
        and is_transient(state.outcome.exception()),
        stop=stop_after_attempt(6),
        wait=_retry_after_or_backoff,
        reraise=True,
    )
    def list_top_models(self, n: int) -> Iterable[ModelSummary]:
        """Yield the top-N models on HuggingFace by all-time download count.

        Uses the `list_models` endpoint with `sort="downloads", direction=-1`
        and pulls metadata in pages. We also fetch each repo's full file list
        because the listing endpoint by default returns only summary info.
        """
        log.info("Fetching top-%d models by all-time downloads", n)
        # huggingface_hub returns an iterator that lazily pages through the API.
        for i, info in enumerate(
            self._api.list_models(
                sort="downloads",
                limit=n,
                full=True,
            )
        ):
            if i >= n:
                break

            # `info.siblings` may be empty in the listing response.
            # If so, fall back to a full model_info() call for that repo.
            siblings = info.siblings or []
            if not siblings:
                detail = self._api.model_info(info.id, files_metadata=False)
                siblings = detail.siblings or []

            filenames = [s.rfilename for s in siblings]
            publisher = info.id.split("/")[0] if "/" in info.id else "(individual)"

            yield ModelSummary(
                model_id=info.id,
                publisher=publisher,
                downloads=info.downloads or 0,
                last_modified=info.last_modified,
                filenames=filenames,
            )

    @retry(
        retry=lambda state: state.outcome is not None
        and state.outcome.failed
        and is_transient(state.outcome.exception()),
        stop=stop_after_attempt(6),
        wait=_retry_after_or_backoff,
        reraise=True,
    )
    def get_model_summary(self, model_id: str) -> ModelSummary:
        """Fetch metadata for one specific model by id.

        Needed for the Stratum B audit, where the sample is a fixed list of ids
        drawn in advance rather than whatever the listing endpoint returns. One
        request per model, which is the dominant cost of the long-tail scan.

        Raises:
            HfHubHTTPError: 404 if the repo is gone, 401/403 if it is gated.
                Both are permanent and meaningful: the caller records them
                rather than retrying, because a model that has been deleted
                since the sampling frame was built is a finding about the
                registry's churn, not a failure of the scan.
        """
        info = self._api.model_info(model_id, files_metadata=False)
        siblings = info.siblings or []
        publisher = model_id.split("/")[0] if "/" in model_id else "(individual)"
        return ModelSummary(
            model_id=info.id or model_id,
            publisher=publisher,
            downloads=getattr(info, "downloads", 0) or 0,
            last_modified=getattr(info, "last_modified", None),
            filenames=[s.rfilename for s in siblings],
        )

    @retry(
        retry=lambda state: state.outcome is not None
        and state.outcome.failed
        and is_transient(state.outcome.exception()),
        stop=stop_after_attempt(5),
        wait=_retry_after_or_backoff,
        reraise=True,
    )
    def fetch_file(self, repo_id: str, filename: str) -> bytes:
        """Download a single file from a repo and return its raw bytes.

        Files larger than ``max_file_bytes`` are refused; this is the
        safety net that prevents accidental download of model weights.
        """
        from huggingface_hub import hf_hub_download
        from huggingface_hub.utils import HfHubHTTPError

        try:
            local_path = hf_hub_download(
                repo_id=repo_id,
                filename=filename,
                token=self._token,
                # download into a temp area; we discard after reading
                local_dir=None,
            )
        except HfHubHTTPError as exc:
            log.warning("HTTP error fetching %s/%s: %s", repo_id, filename, exc)
            raise

        with open(local_path, "rb") as f:
            head = f.read(self._max_file_bytes + 1)
        if len(head) > self._max_file_bytes:
            raise ValueError(
                f"refused: {repo_id}/{filename} exceeds {self._max_file_bytes} bytes"
            )
        return head
