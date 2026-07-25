"""A fixture-backed HfClient for tests.

Implements the same protocol as the real HfClient, but reads from the
hand-crafted fixtures in `fixtures_models.py` instead of touching the network.
"""
from __future__ import annotations

from collections.abc import Iterable

from qresp.hf_client import HfClientProtocol, ModelSummary


class FakeHfClient(HfClientProtocol):
    """In-memory HfClient used by the test suite."""

    def __init__(
        self,
        fixtures: list[tuple[ModelSummary, dict[str, bytes]]],
    ):
        self._summaries = [s for s, _ in fixtures]
        self._bytes: dict[tuple[str, str], bytes] = {}
        for summary, files in fixtures:
            for name, content in files.items():
                self._bytes[(summary.model_id, name)] = content

    def list_top_models(self, n: int) -> Iterable[ModelSummary]:
        yield from self._summaries[:n]

    def get_model_summary(self, model_id: str) -> ModelSummary:
        for s in self._summaries:
            if s.model_id == model_id:
                return s
        raise FileNotFoundError(f"no such model: {model_id}")

    def fetch_file(self, repo_id: str, filename: str) -> bytes:
        try:
            return self._bytes[(repo_id, filename)]
        except KeyError as exc:
            raise FileNotFoundError(f"{repo_id}/{filename}") from exc
