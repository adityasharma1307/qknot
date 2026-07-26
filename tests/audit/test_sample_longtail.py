"""Tests for the Stratum B sampling procedure.

The sampling logic is a methods-section artifact, so it is tested like one:
the properties that matter are reproducibility, uniformity, and disjointness
from Stratum A.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "audit" / "sample_longtail.py"
spec = importlib.util.spec_from_file_location("sample_longtail", SCRIPT)
sl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sl)


@pytest.fixture
def frame() -> list[str]:
    return [f"org{i % 97}/model{i}" for i in range(50_000)]


class TestDraw:
    def test_same_seed_reproduces_the_draw(self, frame):
        assert sl.draw_sample(frame, 1000, seed=20260725) == \
               sl.draw_sample(frame, 1000, seed=20260725)

    def test_different_seed_changes_the_draw(self, frame):
        a = sl.draw_sample(frame, 1000, seed=1)
        b = sl.draw_sample(frame, 1000, seed=2)
        assert a != b

    def test_draw_is_order_independent(self, frame):
        """The seed must survive a reshuffled frame, because enumeration order
        is not guaranteed stable between runs. This is why draw_sample sorts."""
        import random as _r
        shuffled = frame[:]
        _r.Random(999).shuffle(shuffled)
        assert sl.draw_sample(frame, 500, seed=42) == sl.draw_sample(shuffled, 500, seed=42)

    def test_draw_is_without_replacement(self, frame):
        sample = sl.draw_sample(frame, 5000, seed=7)
        assert len(sample) == len(set(sample)) == 5000

    def test_oversized_draw_is_refused(self, frame):
        with pytest.raises(SystemExit):
            sl.draw_sample(frame[:100], 10_000, seed=1)

    def test_draw_is_uniform_across_the_frame(self, frame):
        """A uniform draw should spread across the frame rather than clumping.
        Split the sorted frame into 10 bins; each should get roughly a tenth."""
        sample = set(sl.draw_sample(frame, 10_000, seed=20260725))
        ordered = sorted(frame)
        bin_size = len(ordered) // 10
        counts = [
            sum(1 for m in ordered[i * bin_size:(i + 1) * bin_size] if m in sample)
            for i in range(10)
        ]
        expected = 10_000 / 10
        # Generous tolerance: this catches a systematically broken draw
        # (e.g. taking a contiguous slice), not ordinary sampling noise.
        for c in counts:
            assert 0.8 * expected < c < 1.2 * expected, f"bin counts skewed: {counts}"


class TestExclusion:
    def test_head_ids_are_excluded_from_the_frame(self, tmp_path: Path):
        head = tmp_path / "head.jsonl"
        head.write_text(
            '{"model_id": "org1/model1"}\n{"model_id": "org2/model2"}\n', encoding="utf-8"
        )
        head_ids = sl.load_head_ids(head)
        assert head_ids == {"org1/model1", "org2/model2"}

        population = ["org1/model1", "org2/model2", "org3/model3", "org4/model4"]
        frame = [m for m in population if m not in head_ids]
        assert frame == ["org3/model3", "org4/model4"]

        sample = sl.draw_sample(frame, 2, seed=1)
        assert not (set(sample) & head_ids), "strata must be disjoint"

    def test_plain_id_list_is_accepted(self, tmp_path: Path):
        head = tmp_path / "head.txt"
        head.write_text("org1/model1\norg2/model2\n\n", encoding="utf-8")
        assert sl.load_head_ids(head) == {"org1/model1", "org2/model2"}


class _FakeResponse:
    def __init__(self, ids, next_url=None, status=200, retry_after=None):
        self._ids = ids
        self.status_code = status
        self.headers = {}
        if next_url:
            self.headers["Link"] = f'<{next_url}>; rel="next"'
        if retry_after:
            self.headers["Retry-After"] = str(retry_after)

    def json(self):
        return [{"id": i} for i in self._ids]

    def raise_for_status(self):
        if self.status_code >= 400:
            raise sl.requests.exceptions.HTTPError(str(self.status_code))


class _ScriptedSession:
    """Replays a scripted sequence of responses and exceptions."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestEnumerationResilience:
    def test_connection_error_is_retried_not_fatal(self, monkeypatch):
        """A dropped connection mid-crawl must not end the enumeration. This is
        the failure that lost 1.4M enumerated ids on the first live run."""
        monkeypatch.setattr(sl.time, "sleep", lambda *_: None)
        session = _ScriptedSession([
            _FakeResponse(["a/1"], next_url="u2"),
            sl.requests.exceptions.ConnectionError("reset by peer"),
            _FakeResponse(["a/2"], next_url=None),
        ])
        assert list(sl.enumerate_population(session)) == ["a/1", "a/2"]

    def test_gives_up_after_repeated_failures(self, monkeypatch):
        monkeypatch.setattr(sl.time, "sleep", lambda *_: None)
        session = _ScriptedSession(
            [sl.requests.exceptions.ConnectionError("down")] * (sl.MAX_PAGE_ATTEMPTS + 2)
        )
        with pytest.raises(RuntimeError, match="checkpointed"):
            list(sl.enumerate_population(session))

    def test_rate_limit_backoff_escalates(self, monkeypatch):
        """Repeating the same Retry-After forever is how a crawl livelocks."""
        waits = []
        monkeypatch.setattr(sl.time, "sleep", lambda s: waits.append(s))
        session = _ScriptedSession([
            _FakeResponse([], status=429, retry_after=10),
            _FakeResponse([], status=429, retry_after=10),
            _FakeResponse(["a/1"], next_url=None),
        ])
        assert list(sl.enumerate_population(session)) == ["a/1"]
        assert waits == [10.0, 20.0], f"expected escalating backoff, got {waits}"

    def test_checkpoint_callback_receives_each_page(self, monkeypatch):
        monkeypatch.setattr(sl.time, "sleep", lambda *_: None)
        session = _ScriptedSession([
            _FakeResponse(["a/1", "a/2"], next_url="cursor-2"),
            _FakeResponse(["a/3"], next_url=None),
        ])
        seen = []
        list(sl.enumerate_population(session, on_page=lambda ids, nxt, pg: seen.append((ids, nxt, pg))))
        assert seen == [(["a/1", "a/2"], "cursor-2", 0), (["a/3"], None, 1)]

    def test_checkpoint_fires_before_ids_are_yielded(self, monkeypatch):
        """The cursor must be durable before the consumer sees the ids, or a
        crash mid-page would advance past data that was never saved."""
        monkeypatch.setattr(sl.time, "sleep", lambda *_: None)
        order = []
        session = _ScriptedSession([_FakeResponse(["a/1"], next_url=None)])
        for _ in sl.enumerate_population(
            session, on_page=lambda *_a: order.append("checkpoint")
        ):
            order.append("yield")
        assert order == ["checkpoint", "yield"]

    def test_resume_starts_from_the_saved_cursor(self, monkeypatch):
        monkeypatch.setattr(sl.time, "sleep", lambda *_: None)
        session = _ScriptedSession([_FakeResponse(["a/9"], next_url=None)])
        list(sl.enumerate_population(session, start_url="https://saved/cursor"))
        assert session.calls == ["https://saved/cursor"], (
            "a resumed crawl must hit the saved cursor, not the first page"
        )


class TestSessionRetries:
    def test_adapter_is_configured_for_transport_retries(self):
        session = sl.build_session(token=None)
        adapter = session.get_adapter("https://huggingface.co/api/models")
        retry = adapter.max_retries
        assert retry.total >= 5
        assert 429 in retry.status_forcelist
        assert retry.backoff_factor > 0
        assert retry.respect_retry_after_header

    def test_token_becomes_an_auth_header(self):
        assert sl.build_session("hf_abc").headers["Authorization"] == "Bearer hf_abc"

    def test_no_token_means_no_auth_header(self):
        assert "Authorization" not in sl.build_session(None).headers


class TestPagination:
    def test_next_link_is_extracted(self):
        class R:
            headers = {"Link": '<https://huggingface.co/api/models?cursor=abc>; rel="next"'}
        assert sl._next_url(R()) == "https://huggingface.co/api/models?cursor=abc"

    def test_absent_link_terminates_pagination(self):
        class R:
            headers = {}
        assert sl._next_url(R()) is None

    def test_unrelated_link_rel_is_ignored(self):
        class R:
            headers = {"Link": '<https://example.com/prev>; rel="prev"'}
        assert sl._next_url(R()) is None
