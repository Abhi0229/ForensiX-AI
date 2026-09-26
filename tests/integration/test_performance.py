"""Integration performance smoke (STEP 15) -- approximate, not a benchmark.

Exercises the hot paths (bulk insert with per-event hashing, full-table query,
whole-chain verification, correlation, behavioral analysis) at 100 and 1000
events against a throwaway database and records rough wall-clock timings. The
assertions use deliberately loose ceilings: the goal is to catch a pathological
regression (minutes, not milliseconds), not to police exact latency.
"""

import time
from datetime import datetime, timedelta

from backend.ai import behavior as behavior_mod
from backend.ai.correlator import correlate_database
from backend.database import db as _db
from backend.database.models import Event
from backend.integrity import verifier
from backend.processing.pipeline import EventPipeline

_SOURCES = ("Windows", "FileSystem", "USB", "Defender", "Browser")
_TYPES = ("LOGON", "FILE_CREATED", "USB_CONNECTED", "THREAT_DETECTED",
          "BROWSER_VISIT")


def _make_events(n, *, start=datetime(2026, 9, 1, 0, 0, 0)):
    """N deterministic, well-formed events spread one minute apart."""
    events = []
    for i in range(n):
        events.append(Event(
            timestamp=start + timedelta(minutes=i),
            source=_SOURCES[i % len(_SOURCES)],
            event_type=_TYPES[i % len(_TYPES)],
            description=f"synthetic event {i}",
            severity="INFO" if i % 5 else "HIGH",
            user="alice" if i % 2 else "bob",
            device="HOST1",
            file_path=f"C:/data/file_{i}.bin"))
    return events


def _time(label, fn):
    t0 = time.perf_counter()
    out = fn()
    dt = time.perf_counter() - t0
    print(f"[perf] {label}: {dt:.3f}s")
    return out, dt


def test_insert_100_events():
    events = _make_events(100)
    result, dt = _time("insert 100", lambda: EventPipeline().process(events))
    assert result.inserted == 100
    assert dt < 30.0


def test_insert_1000_events_and_query():
    events = _make_events(1000)
    result, dt = _time("insert 1000", lambda: EventPipeline().process(events))
    assert result.inserted == 1000
    assert dt < 60.0
    rows, dtq = _time("query 1000", lambda: list(_db.get_events(limit=1000)))
    assert len(rows) == 1000
    assert dtq < 10.0


def test_hash_verification_over_1000_events():
    assert EventPipeline().process(_make_events(1000)).inserted == 1000
    result, dt = _time("verify chain 1000", verifier.verify_chain)
    assert result.valid is True
    assert result.checked_events == 1000
    assert result.hashed_events == 1000
    assert dt < 30.0


def test_correlation_over_1000_events():
    assert EventPipeline().process(_make_events(1000)).inserted == 1000
    incidents, dt = _time(
        "correlate 1000",
        lambda: correlate_database(window_seconds=300, min_group_size=2))
    assert isinstance(incidents, list)
    assert dt < 30.0


def test_behavior_over_1000_events():
    assert EventPipeline().process(_make_events(1000)).inserted == 1000
    (out, dt) = _time("behavior 1000", behavior_mod.analyze_database)
    baseline, anomalies = out
    assert len(anomalies) == 1000
    assert dt < 30.0

