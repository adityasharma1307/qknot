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
from typing import Optional, Protocol

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lightweight DTOs used by the scanner
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ModelSummary:
    """The metadata we need to evaluate a single model's cryptographic posture."""

    model_id: str
    publisher: str
    downloads: int
    last_modified: Optional[datetime]
    filenames: list[str]


# ---------------------------------------------------------------------------
# Protocol — anything quacking like this can act as a HF client
# ---------------------------------------------------------------------------
class HfClientProtocol(Protocol):
    """Interface implemented by both the real and the test client."""

    def list_top_models(self, n: int) -> Iterable[ModelSummary]: ...
    def fetch_file(self, repo_id: str, filename: str) -> bytes: ...


# ---------------------------------------------------------------------------
# Real HuggingFace client
# ---------------------------------------------------------------------------
class HfClient:
    """Real HuggingFace client. Requires network access."""

    def __init__(self, token: Optional[str] = None, max_file_bytes: int = 4 * 1024 * 1024):
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
        retry=retry_if_exception_type((ConnectionError, TimeoutError)),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1.0, min=1.0, max=30.0),
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
        retry=retry_if_exception_type((ConnectionError, TimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1.0, min=1.0, max=10.0),
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
