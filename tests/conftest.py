"""Suite-wide guards.

WHY THE NETWORK IS BLOCKED HERE
===============================
Several CLI tests exercise the entropy command, whose backends fall back to
live HTTP when a source is unavailable -- `NistBeaconBackend` and the ANU
backend each build a `requests.Session` with a **30 second** timeout
(`entropy/beacon.py`, `entropy/backends.py`). Nothing in those tests is about
network reachability; they check CLI plumbing, that a fallback happens, and
that the attestation does not overclaim.

Left unguarded, that has three consequences, and the third is the serious one:

1.  The suite is slow, paying real round trips for nothing.
2.  It hangs where DNS blackholes rather than refuses -- observed here, where
    the full run stalled indefinitely while the same file passed in 12 seconds
    on its own.
3.  **It is not deterministic.** A test that passes because a public beacon
    happened to answer, and fails on a train, is not testing the code. Worse,
    it could pass for the wrong reason: a fallback path that is never taken
    when the network is up is a fallback path that is never tested.

So the network is closed by default and every test runs the offline path --
which, for a signing tool that must work in an air-gapped release pipeline, is
the path that actually matters.

Any test that genuinely needs a socket must say so with
`@pytest.mark.allow_network`, which makes the dependency visible in the source
rather than implicit in whether CI has connectivity.
"""
from __future__ import annotations

import socket
import time

import pytest


class NetworkBlockedError(OSError):
    """Raised instead of making a real connection during tests."""


def _blocked(*args: object, **kwargs: object) -> None:
    raise NetworkBlockedError(
        "network access is blocked during tests. If this is a unit test, inject "
        "a fake session (both entropy backends accept `session=`). If the test "
        "genuinely needs the network, mark it @pytest.mark.allow_network."
    )


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest,
               monkeypatch: pytest.MonkeyPatch) -> None:
    """Close the network for every test unless it opts out.

    `getaddrinfo` is patched as well as `connect`, and that is the important
    half: a blocked-but-routed network fails at name resolution and can sit
    there for the full timeout, which is precisely the hang this fixture
    exists to prevent. Refusing at resolution makes the failure immediate and
    legible instead of slow and mysterious.
    """
    if request.node.get_closest_marker("allow_network"):
        return

    monkeypatch.setattr(socket.socket, "connect", _blocked, raising=False)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked, raising=False)
    monkeypatch.setattr(socket, "create_connection", _blocked, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked, raising=False)


@pytest.fixture(autouse=True)
def no_sleeping(request: pytest.FixtureRequest,
                monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `time.sleep` a no-op. Unit tests must not wait on wall clock.

    `get_entropy` retries an unavailable source `max_attempts` times with
    exponential backoff (entropy/backends.py), so a single failed source sleeps
    2s then 4s before falling back -- six seconds per invocation, in a test that
    is checking a printed message. Several such tests turned a 12 second file
    into a 40 second one and made the suite look like it had hung.

    Blocking the network alone did not fix this, which was the useful surprise:
    the calls then failed *immediately*, and the backoff sleeps ran exactly as
    before. Fast failure and no waiting are separate properties.

    Under `OnFailure.WAIT` the retry loop has no attempt ceiling at all -- it is
    documented as retrying "until the backend recovers" -- so a test that ever
    selects that policy would hang indefinitely rather than slowly. Nothing does
    today; this makes sure nothing can.
    """
    if request.node.get_closest_marker("allow_sleeping"):
        return
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
