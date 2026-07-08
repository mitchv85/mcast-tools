"""Thread-safety tests for the stats classes' rate-sample machinery.

The bug these guard against (field-reported, v0.1.0–v0.2.1): the send/recv
worker thread appends (ts, count) samples to `rate_samples` while the
dashboard thread iterates it inside current_pps(). Every deque mutation —
including plain append — invalidates live iterators in CPython, raising
`RuntimeError: deque mutated during iteration`.

The reproduction shape matters and was itself hard-won: the walk in
current_pps() breaks at the first sample newer than the sliding-window
cutoff, so the race window only exists while the deque holds a long
prefix of samples OLDER than the window. A fast writer destroys that
shape by evicting the stale prefix; the faithful (and worst-case) shape
is a stale-majority deque — which is exactly what a low-rate,
long-running field process produces. The hammer below appends STALE
samples so the walk stays full-length for the whole test, making the
pre-fix failure deterministic-in-practice (tripped in ~20 ms across
runs) without any timing sensitivity in CI.
"""
import threading
import time

import pytest

from mcast_tools.receiver import ReceiverStats
from mcast_tools.sender import SenderStats


@pytest.mark.parametrize(
    "make_stats,counter",
    [
        (SenderStats, "packets_sent"),
        (ReceiverStats, "packets_recv"),
    ],
    ids=["sender", "receiver"],
)
def test_current_pps_survives_concurrent_appends(make_stats, counter):
    stats = make_stats()
    stats.started_at = time.monotonic()
    now = time.monotonic()
    # Stale-majority shape: everything older than the sliding window.
    for i in range(2000):
        stats.record_rate_sample(now - 1000 + i * 0.001, i)

    stop = threading.Event()
    errs: list[BaseException] = []
    walks = [0]
    n = [2000]

    def writer():
        while not stop.is_set():
            n[0] += 1
            setattr(stats, counter, n[0])
            # Stale appends keep the reader's walk full-length forever —
            # the maximal race surface for the pre-fix code.
            stats.record_rate_sample(now - 500, n[0])

    def reader():
        try:
            while not stop.is_set():
                stats.current_pps()
                walks[0] += 1
        except BaseException as e:  # noqa: BLE001 — the assertion target
            errs.append(e)
            stop.set()

    tw = threading.Thread(target=writer)
    tr = threading.Thread(target=reader)
    t0 = time.monotonic()
    tw.start(); tr.start()
    while time.monotonic() - t0 < 1.5 and not stop.is_set():
        time.sleep(0.01)
    stop.set(); tw.join(); tr.join()

    assert not errs, f"stats race resurfaced: {errs[0]!r}"
    assert walks[0] > 0, "reader made no progress — test is not exercising the walk"


@pytest.mark.parametrize(
    "make_stats,counter",
    [
        (SenderStats, "packets_sent"),
        (ReceiverStats, "packets_recv"),
    ],
    ids=["sender", "receiver"],
)
def test_current_pps_math(make_stats, counter, monkeypatch):
    """Regression guard for the snapshot rewrite: same math as v0.2.1."""
    NOW = 1_000_000.0
    monkeypatch.setattr(time, "monotonic", lambda: NOW)
    stats = make_stats()
    stats.started_at = NOW - 60
    # One sample beyond the 5s window (skipped by the walk), then two
    # inside it: 300 packets over 3 seconds = 100 pps.
    stats.record_rate_sample(NOW - 10, 0)
    stats.record_rate_sample(NOW - 4, 100)
    stats.record_rate_sample(NOW - 1, 400)
    assert stats.current_pps() == pytest.approx(100.0)


def test_current_pps_all_stale_returns_zero(monkeypatch):
    NOW = 1_000_000.0
    monkeypatch.setattr(time, "monotonic", lambda: NOW)
    stats = SenderStats()
    for i in range(10):
        stats.record_rate_sample(NOW - 100 + i, i)
    assert stats.current_pps() == 0.0
