"""Force-tests for scanner resilience under rate limiting and connection loss.

Pre-flight requirement for the 20,000-model stratified audit. A run that size
will be rate-limited and will drop connections; the questions these tests
answer are (a) does progress survive, and (b) does a transient failure get
baked into the dataset as if it were a finding.

These are deliberately adversarial. Several of them assert current *broken*
behaviour and are marked xfail so the suite stays green while documenting
exactly what needs fixing before the real run. Read the xfail reasons.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests
from huggingface_hub.utils import HfHubHTTPError

from qresp.hf_client import (
    HfClientProtocol,
    ModelSummary,
    _retry_after_or_backoff,
    is_transient,
)
from qresp.model import QLabel
from qresp.scanner import run_audit, run_audit_ids

SIGSTORE_BUNDLE = json.dumps(
    {
        "verificationMaterial": {
            "x509CertificateChain": {"certificates": [{"rawBytes": "ZmFrZQ=="}]}
        },
        "messageSignature": {"signature": "c2ln"},
    }
).encode()


def _summary(i: int, *, signed: bool = False) -> ModelSummary:
    return ModelSummary(
        model_id=f"org{i}/model{i}",
        publisher=f"org{i}",
        downloads=1000 - i,
        last_modified=datetime(2026, 1, 1, tzinfo=timezone.utc),
        filenames=["model.sig", "config.json"] if signed else ["config.json"],
    )


class FlakyClient(HfClientProtocol):
    """Client that fails in a controlled, reproducible way.

    Args:
        n_models: population size.
        signed_at: indices whose repos carry a signature file.
        raise_on_list_at: raise while *listing* once cursor reaches this index.
        raise_on_fetch_for: model_ids whose fetch_file raises.
        exc: the exception instance to raise.
    """

    def __init__(
        self,
        n_models: int = 10,
        signed_at: set[int] = frozenset(),
        raise_on_list_at: int | None = None,
        raise_on_fetch_for: set[str] = frozenset(),
        raise_on_summary_for: set[str] = frozenset(),
        exc: Exception | None = None,
    ):
        self.n_models = n_models
        self.signed_at = set(signed_at)
        self.raise_on_list_at = raise_on_list_at
        self.raise_on_fetch_for = set(raise_on_fetch_for)
        self.raise_on_summary_for = set(raise_on_summary_for)
        self.exc = exc or ConnectionError("simulated drop")
        self.list_calls = 0
        self.fetch_calls: list[str] = []
        self.summary_calls: list[str] = []

    def list_top_models(self, n):
        self.list_calls += 1
        for i in range(min(n, self.n_models)):
            if self.raise_on_list_at is not None and i == self.raise_on_list_at:
                raise self.exc
            yield _summary(i, signed=i in self.signed_at)

    def get_model_summary(self, model_id: str) -> ModelSummary:
        self.summary_calls.append(model_id)
        if model_id in self.raise_on_summary_for:
            raise self.exc
        for i in range(self.n_models):
            if f"org{i}/model{i}" == model_id:
                return _summary(i, signed=i in self.signed_at)
        raise FileNotFoundError(model_id)

    def fetch_file(self, repo_id: str, filename: str) -> bytes:
        self.fetch_calls.append(repo_id)
        if repo_id in self.raise_on_fetch_for:
            raise self.exc
        return SIGSTORE_BUNDLE


def _rows(path: Path, tolerant: bool = False) -> list[dict]:
    """Parse the JSONL output. With tolerant=True, damaged lines are skipped
    the same way _load_already_seen() skips them."""
    out = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            if not tolerant:
                raise
    return out


def _rate_limit_error() -> HfHubHTTPError:
    """A realistic HTTP 429 as huggingface_hub surfaces it."""
    response = requests.Response()
    response.status_code = 429
    response.reason = "Too Many Requests"
    response.headers["Retry-After"] = "60"
    return HfHubHTTPError("429 Client Error: Too Many Requests", response=response)


# ---------------------------------------------------------------------------
# What already works
# ---------------------------------------------------------------------------
class TestProgressSurvives:
    def test_listing_failure_midrun_preserves_completed_records(self, tmp_path: Path):
        """A drop while paginating must not lose already-written records."""
        out = tmp_path / "audit.jsonl"
        client = FlakyClient(n_models=10, raise_on_list_at=6)

        with pytest.raises(ConnectionError):
            list(run_audit(client, n=10, out_path=out))

        rows = _rows(out)
        assert len(rows) == 6, "records completed before the drop must be on disk"
        assert [r["model_id"] for r in rows] == [f"org{i}/model{i}" for i in range(6)]

    def test_resume_continues_from_partial_output(self, tmp_path: Path):
        """Re-running after a drop picks up where it stopped, no duplicates."""
        out = tmp_path / "audit.jsonl"
        with pytest.raises(ConnectionError):
            list(run_audit(FlakyClient(n_models=10, raise_on_list_at=6), n=10, out_path=out))

        healthy = FlakyClient(n_models=10)
        list(run_audit(healthy, n=10, out_path=out, resume=True))

        rows = _rows(out)
        ids = [r["model_id"] for r in rows]
        assert len(ids) == 10
        assert len(set(ids)) == 10, "resume must not duplicate rows"
        assert healthy.list_calls == 1

    def test_output_stays_parseable_after_abrupt_stop(self, tmp_path: Path):
        """Every line must be complete JSON. No half-written trailing record."""
        out = tmp_path / "audit.jsonl"
        with pytest.raises(ConnectionError):
            list(run_audit(FlakyClient(n_models=10, raise_on_list_at=3), n=10, out_path=out))
        for line in out.read_text().splitlines():
            if line.strip():
                json.loads(line)  # raises if truncated

    def test_corrupt_line_does_not_lose_progress(self, tmp_path: Path):
        """A damaged line is skipped on resume rather than aborting the run."""
        out = tmp_path / "audit.jsonl"
        list(run_audit(FlakyClient(n_models=4), n=4, out_path=out))
        with out.open("a") as f:
            f.write('{"model_id": "truncated/mod\n')

        list(run_audit(FlakyClient(n_models=6), n=6, out_path=out, resume=True))
        ids = [r["model_id"] for r in _rows(out, tolerant=True)]
        assert len(set(ids)) == 6


# ---------------------------------------------------------------------------
# What is broken and blocks the 20k run
# ---------------------------------------------------------------------------
class TestRateLimitHandling:
    def test_rate_limited_model_is_not_permanently_recorded_as_error(self, tmp_path: Path):
        out = tmp_path / "audit.jsonl"
        client = FlakyClient(
            n_models=3,
            signed_at={1},
            raise_on_fetch_for={"org1/model1"},
            exc=_rate_limit_error(),
        )
        list(run_audit(client, n=3, out_path=out))

        rows = {r["model_id"]: r for r in _rows(out)}
        assert "org1/model1" not in rows, (
            "a 429 is a statement about our request rate, not about the model. "
            "It must not be committed to the dataset."
        )

    def test_resume_retries_a_previously_rate_limited_model(self, tmp_path: Path):
        out = tmp_path / "audit.jsonl"
        list(
            run_audit(
                FlakyClient(
                    n_models=3,
                    signed_at={1},
                    raise_on_fetch_for={"org1/model1"},
                    exc=_rate_limit_error(),
                ),
                n=3,
                out_path=out,
            )
        )

        recovered = FlakyClient(n_models=3, signed_at={1})
        list(run_audit(recovered, n=3, out_path=out, resume=True))

        assert "org1/model1" in recovered.fetch_calls, "resume must re-attempt it"
        row = {r["model_id"]: r for r in _rows(out)}["org1/model1"]
        assert row["q_label"] == QLabel.VULNERABLE.value


    def test_permanent_failure_is_still_recorded_as_a_finding(self, tmp_path: Path):
        """A genuinely missing file is a fact about the repo, not about us. It
        must still be written, otherwise resume would loop on it forever."""
        out = tmp_path / "audit.jsonl"
        client = FlakyClient(
            n_models=3,
            signed_at={1},
            raise_on_fetch_for={"org1/model1"},
            exc=FileNotFoundError("org1/model1/model.sig"),
        )
        list(run_audit(client, n=3, out_path=out))

        row = {r["model_id"]: r for r in _rows(out)}["org1/model1"]
        assert row["q_label"] == QLabel.ERROR.value
        assert "fetch_failed" in (row["notes"] or "")

    def test_404_is_treated_as_permanent_not_transient(self):
        """404 must not be retried or deferred: the file really is absent."""
        response = requests.Response()
        response.status_code = 404
        assert not is_transient(HfHubHTTPError("404", response=response))

    def test_auth_failure_is_permanent(self):
        """401/403 means a bad token. Retrying hides the misconfiguration."""
        for code in (401, 403):
            response = requests.Response()
            response.status_code = code
            assert not is_transient(HfHubHTTPError(str(code), response=response))

    def test_run_aborts_after_sustained_transient_failure(self, tmp_path: Path):
        """If the network is gone, skipping every model would yield a run that
        looks complete and is not."""
        out = tmp_path / "audit.jsonl"
        client = FlakyClient(
            n_models=20,
            signed_at=set(range(20)),
            raise_on_fetch_for={f"org{i}/model{i}" for i in range(20)},
            exc=_rate_limit_error(),
        )
        with pytest.raises(RuntimeError, match="consecutive transient failures"):
            list(run_audit(client, n=20, out_path=out, max_consecutive_transient=5))
        assert _rows(out) == [], "nothing should have been committed"

    def test_isolated_transient_failure_does_not_abort_the_run(self, tmp_path: Path):
        """One 429 in the middle must not kill an overnight scan."""
        out = tmp_path / "audit.jsonl"
        client = FlakyClient(
            n_models=10,
            signed_at={4},
            raise_on_fetch_for={"org4/model4"},
            exc=_rate_limit_error(),
        )
        records = list(run_audit(client, n=10, out_path=out, max_consecutive_transient=5))
        assert len(records) == 9
        assert "org4/model4" not in {r["model_id"] for r in _rows(out)}


class TestStratumBIdList:
    """run_audit_ids audits exactly the drawn sample, no more and no less."""

    def test_audits_exactly_the_given_ids(self, tmp_path: Path):
        out = tmp_path / "tail.jsonl"
        ids = ["org7/model7", "org2/model2", "org9/model9"]
        records = list(run_audit_ids(FlakyClient(n_models=10), ids, out_path=out))

        assert [r.model_id for r in records] == ids, "order must follow the draw"
        assert {r["model_id"] for r in _rows(out)} == set(ids)

    def test_resume_skips_metadata_requests_for_completed_models(self, tmp_path: Path):
        """The whole point of pre-filtering: a resumed run must not pay a
        metadata request for work already done."""
        out = tmp_path / "tail.jsonl"
        ids = [f"org{i}/model{i}" for i in range(6)]
        list(run_audit_ids(FlakyClient(n_models=10), ids[:4], out_path=out))

        second = FlakyClient(n_models=10)
        list(run_audit_ids(second, ids, out_path=out, resume=True))

        assert second.summary_calls == ["org4/model4", "org5/model5"], (
            f"expected only the 2 outstanding models, got {second.summary_calls}"
        )
        assert len({r["model_id"] for r in _rows(out)}) == 6

    def test_deleted_model_is_recorded_not_dropped(self, tmp_path: Path):
        """A repo that vanished between sampling and auditing stays in the
        output. Dropping it would shrink the denominator and quietly invalidate
        the sampling fraction recorded in the manifest."""
        out = tmp_path / "tail.jsonl"
        ids = ["org1/model1", "gone/deleted-model", "org3/model3"]
        list(run_audit_ids(FlakyClient(n_models=10), ids, out_path=out))

        rows = {r["model_id"]: r for r in _rows(out)}
        assert set(rows) == set(ids), "all three ids must appear"
        assert rows["gone/deleted-model"]["file_count"] == 0

    def test_deleted_model_is_error_not_unsigned(self, tmp_path: Path):
        """A repo we could not look at is unobservable, not unsigned.

        Labelling it `unsigned` would turn absence of evidence into evidence of
        absence, inflating the headline statistic in the direction of this
        project's own conclusion. That is the bias a reviewer looks for first.
        """
        out = tmp_path / "tail.jsonl"
        list(run_audit_ids(FlakyClient(n_models=10), ["gone/deleted-model"], out_path=out))

        row = _rows(out)[0]
        assert row["q_label"] == QLabel.ERROR.value
        assert row["has_signature"] is False
        assert "metadata_unavailable" in (row["notes"] or "")

    def test_vanished_repos_do_not_inflate_the_unsigned_count(self, tmp_path: Path):
        """The statistic that matters: unsigned must count only repos actually
        inspected and found to carry no signature."""
        out = tmp_path / "tail.jsonl"
        ids = [f"org{i}/model{i}" for i in range(5)] + [f"gone/x{i}" for i in range(3)]
        list(run_audit_ids(FlakyClient(n_models=5), ids, out_path=out))

        rows = _rows(out)
        assert len(rows) == 8, "denominator must be preserved"
        labels = Counter(r["q_label"] for r in rows)
        assert labels[QLabel.UNSIGNED.value] == 5
        assert labels[QLabel.ERROR.value] == 3

    def test_transient_metadata_failure_defers_without_aborting(self, tmp_path: Path):
        out = tmp_path / "tail.jsonl"
        ids = [f"org{i}/model{i}" for i in range(5)]
        client = FlakyClient(
            n_models=10,
            raise_on_summary_for={"org2/model2"},
            exc=_rate_limit_error(),
        )
        records = list(run_audit_ids(client, ids, out_path=out, max_consecutive_transient=5))

        assert len(records) == 4
        assert "org2/model2" not in {r["model_id"] for r in _rows(out)}

        recovered = FlakyClient(n_models=10)
        list(run_audit_ids(recovered, ids, out_path=out, resume=True))
        assert "org2/model2" in {r["model_id"] for r in _rows(out)}

    def test_sustained_metadata_failure_aborts(self, tmp_path: Path):
        out = tmp_path / "tail.jsonl"
        ids = [f"org{i}/model{i}" for i in range(20)]
        client = FlakyClient(
            n_models=20, raise_on_summary_for=set(ids), exc=_rate_limit_error()
        )
        with pytest.raises(RuntimeError, match="consecutive transient failures"):
            list(run_audit_ids(client, ids, out_path=out, max_consecutive_transient=4))


class TestRetryPredicate:
    """Regression tests for the dead-predicate bug.

    The original decorators named the *builtin* ConnectionError and
    TimeoutError. Nothing the HTTP stack raises inherits from those, so the
    retry never fired. These tests pin the real hierarchy so the mistake
    cannot be reintroduced."""

    @pytest.mark.parametrize(
        "exc_type",
        [
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
            HfHubHTTPError,
        ],
    )
    def test_real_network_errors_do_not_subclass_the_builtins(self, exc_type):
        assert not issubclass(exc_type, (ConnectionError, TimeoutError)), (
            f"{exc_type.__name__} does not inherit from the builtin error types, "
            "which is precisely why naming those builtins in the retry predicate "
            "was a no-op"
        )

    @pytest.mark.parametrize(
        "exc",
        [
            requests.exceptions.ConnectionError("dropped"),
            requests.exceptions.ReadTimeout("slow"),
            requests.exceptions.ConnectTimeout("slow"),
            ConnectionError("builtin"),
            TimeoutError("builtin"),
        ],
    )
    def test_network_errors_are_classified_transient(self, exc):
        assert is_transient(exc)

    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
    def test_retryable_statuses_are_transient(self, code):
        response = requests.Response()
        response.status_code = code
        assert is_transient(HfHubHTTPError(str(code), response=response))

    def test_non_http_error_is_not_transient(self):
        assert not is_transient(ValueError("refused: exceeds max bytes"))
        assert not is_transient(FileNotFoundError("missing.sig"))


class TestRetryAfter:
    def test_retry_after_header_is_honoured(self):
        response = requests.Response()
        response.status_code = 429
        response.headers["Retry-After"] = "120"
        exc = HfHubHTTPError("429", response=response)

        class Outcome:
            failed = True

            def exception(self):
                return exc

        class State:
            outcome = Outcome()
            attempt_number = 1
            idle_for = 0.0

        assert _retry_after_or_backoff(State()) >= 120

    def test_missing_header_falls_back_to_backoff(self):
        response = requests.Response()
        response.status_code = 503
        exc = HfHubHTTPError("503", response=response)

        class Outcome:
            failed = True

            def exception(self):
                return exc

        class State:
            outcome = Outcome()
            attempt_number = 2
            idle_for = 0.0

        wait = _retry_after_or_backoff(State())
        assert 0 < wait <= 60
