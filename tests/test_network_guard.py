"""The suite-wide network block must actually be on.

Lives in its own `test_*.py` rather than beside the fixture in conftest.py,
because `python_files = ["test_*.py"]` in pyproject.toml means pytest never
collects conftest.py -- tests written there pass when run explicitly and are
silently skipped by every ordinary run. That is the same class of failure these
tests exist to catch, so putting them in the uncollected file would have been
an unusually direct way to get it wrong.
"""
from __future__ import annotations

import socket
import time

import pytest

from tests.conftest import NetworkBlockedError


@pytest.mark.offline
def test_the_network_guard_is_active() -> None:
    """A guard nobody checks is a guard that can quietly stop working.

    The default suite is networked. `@pytest.mark.offline` must still close
    sockets, or a fallback test that thinks it is offline will call a live
    beacon and pass for the wrong reason.
    """
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("beacon.nist.gov", 443)

    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("beacon.nist.gov", 443), timeout=1)


@pytest.mark.allow_network
def test_the_opt_out_marker_restores_the_network() -> None:
    """The escape hatch must work, or it is a trap.

    A marker that silently did nothing would leave a future author believing
    their test had network access while it quietly took the offline path --
    passing for the wrong reason. Checking that resolution is *attempted* is
    enough; whether it succeeds depends on the machine, and this test must not
    itself depend on connectivity.
    """
    try:
        socket.getaddrinfo("localhost", 80)
    except NetworkBlockedError:                       # pragma: no cover
        pytest.fail("@pytest.mark.allow_network did not lift the block")
    except OSError:
        pass                                     # resolution attempted; fine


def test_sleeping_is_a_no_op() -> None:
    """The backoff guard must be on, for the same reason as the network one.

    Six seconds of real sleep hidden inside a retry loop is invisible in a
    passing test report -- it shows up only as a suite that mysteriously takes
    forty seconds. If the fixture stopped applying, nothing would fail.
    """
    started = time.monotonic()
    time.sleep(5)
    assert time.monotonic() - started < 1, (
        "time.sleep really slept; the no_sleeping fixture is not applying"
    )
