"""The ranking collector's backoff, which is where the last two runs died.

Run one lost 86% of candidates because a single 429 marked a batch unmeasured
forever. Run two retried 404s six times each and backed off per-thread, so
three workers kept hammering at full rate while the fourth slept.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from qresp.audit.npm_client import NpmError

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "rank_npm", ROOT / "scripts" / "audit" / "rank_npm.py")
assert _spec and _spec.loader
rank_npm = importlib.util.module_from_spec(_spec)
sys.modules["rank_npm"] = rank_npm
_spec.loader.exec_module(rank_npm)


@pytest.fixture
def throttle():
    return rank_npm.Throttle(per_second=1000.0)      # fast: not what is tested


class TestPermanentFailuresAreNotRetried:
    def test_a_404_raises_on_the_first_attempt(self, throttle):
        calls = []

        def call():
            calls.append(1)
            raise NpmError("404 not found", status=404)

        with pytest.raises(NpmError):
            rank_npm.with_retry(call, throttle, "x", attempts=6)
        assert len(calls) == 1, "a 404 cannot become a 200 by asking again"

    def test_a_429_is_retried_up_to_the_limit(self, throttle, monkeypatch):
        monkeypatch.setattr(rank_npm.time, "sleep", lambda _s: None)
        calls = []

        def call():
            calls.append(1)
            raise NpmError("HTTP 429", status=429)

        with pytest.raises(NpmError):
            rank_npm.with_retry(call, throttle, "x", attempts=4)
        assert len(calls) == 4

    def test_a_transient_failure_that_clears_returns_the_value(self, throttle,
                                                               monkeypatch):
        monkeypatch.setattr(rank_npm.time, "sleep", lambda _s: None)
        state = {"n": 0}

        def call():
            state["n"] += 1
            if state["n"] < 3:
                raise NpmError("HTTP 429", status=429)
            return 42

        assert rank_npm.with_retry(call, throttle, "x") == 42


class TestBackoffIsGlobalNotPerThread:
    """The bug in run two: one worker sleeping does not reduce the request rate."""

    def test_a_429_widens_the_shared_interval_for_everyone(self, throttle,
                                                           monkeypatch):
        monkeypatch.setattr(rank_npm.time, "sleep", lambda _s: None)
        before = throttle.rate

        def call():
            raise NpmError("HTTP 429", status=429)

        with pytest.raises(NpmError):
            rank_npm.with_retry(call, throttle, "x", attempts=3)
        assert throttle.rate < before
        assert throttle.penalties >= 1

    def test_a_404_does_not_slow_everyone_down(self, throttle):
        """It is not congestion, so treating it as congestion punishes the run."""
        before = throttle.rate

        def call():
            raise NpmError("404", status=404)

        with pytest.raises(NpmError):
            rank_npm.with_retry(call, throttle, "x")
        assert throttle.rate == before
        assert throttle.penalties == 0

    def test_the_pace_never_falls_below_the_floor(self, monkeypatch):
        """Otherwise a long 429 storm drives the run to a standstill."""
        monkeypatch.setattr(rank_npm.time, "sleep", lambda _s: None)
        t = rank_npm.Throttle(per_second=4.0, floor_per_second=0.5)
        for _ in range(200):
            t.penalise(0.0)
        assert t.rate >= 0.5 - 1e-9

    def test_recovery_never_exceeds_the_requested_pace(self):
        t = rank_npm.Throttle(per_second=4.0)
        for _ in range(10_000):
            t.relax()
        assert t.rate <= 4.0 + 1e-9


class TestAPenaltyIsWaitedOutOnce:
    """The stall: penalise() pauses everyone, so sleeping again doubles it.

    `throttle.penalise(p)` pushes the SHARED next-allowed time forward by `p`,
    and the retrying thread's next `throttle.wait()` already blocks until then.
    An additional `time.sleep(p)` in the retry loop waited out the same penalty
    a second time. With six workers and a delay escalating to 120s, the run
    produced no output for long enough to look hung.
    """

    def test_the_retry_loop_does_not_sleep_on_its_own(self, monkeypatch):
        """Neutralise the throttle entirely; any remaining sleep is the loop's.

        A first version of this test asserted that no sleep exceeded a second,
        which failed for the right reason: `Throttle.wait` legitimately sleeps
        out the penalty it was just given. Distinguishing the two by DURATION
        cannot work when both wait the same interval -- that is precisely the
        double-wait being tested for. So the throttle is stubbed out instead,
        and any sleep that survives came from the retry loop.
        """
        slept: list[float] = []
        monkeypatch.setattr(rank_npm.time, "sleep", lambda s: slept.append(s))

        class Recording(rank_npm.Throttle):
            def wait(self) -> None:      # the schedule, neutralised
                return None

        throttle = Recording(per_second=1000.0)
        state = {"n": 0}

        def call():
            state["n"] += 1
            if state["n"] < 3:
                raise NpmError("HTTP 429", status=429)
            return "ok"

        assert rank_npm.with_retry(call, throttle, "x") == "ok"
        assert slept == [], (
            f"retry loop slept on its own; the shared throttle had already "
            f"scheduled the same wait: {slept}")
        assert throttle.penalties == 2, "the penalty must still be applied"

    def test_the_penalty_still_reaches_the_shared_schedule(self):
        """Removing the sleep must not remove the backoff."""
        throttle = rank_npm.Throttle(per_second=1000.0)
        before = throttle.rate

        def call():
            raise NpmError("HTTP 429", status=429)

        with pytest.raises(NpmError):
            rank_npm.with_retry(call, throttle, "x", attempts=2)
        assert throttle.penalties >= 1
        assert throttle.rate < before
