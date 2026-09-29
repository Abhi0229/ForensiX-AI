"""Offline unit tests for the Phase-14 runtime layer (Collector Orchestrator).

Everything here runs without Windows, Ollama, or a populated database: the
pipeline is replaced by in-process fakes, the state store is redirected into
``tmp_path``, and the network probe is monkeypatched. These tests exercise the
runtime's own logic -- single-writer serialization, high-water-mark dedup,
exception isolation, backpressure, lifecycle, state persistence, the analysis
worker, the Ollama probe, and the additive status endpoint -- never the
collectors' OS-specific internals (those are covered by the gated live suite).
"""

import queue
import threading
import time
import types
import urllib.error
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.database.models import Event
from backend.processing.normalizer import normalize_event
from backend.processing.pipeline import ProcessingResult
from backend.runtime import manager as rt
from backend.runtime import probe
from backend.runtime.manager import (
    IngestItem,
    RuntimeConfig,
    RuntimeManager,
    _SHUTDOWN,
)
from backend.runtime.state import StateStore


# --- Fakes ------------------------------------------------------------------


class FakePipeline:
    """Records every process() call; reports all events as inserted."""

    def __init__(self):
        self.calls = []

    def process(self, events):
        evs = list(events)
        self.calls.append(evs)
        return ProcessingResult(received=len(evs), inserted=len(evs))


class RaisingPipeline:
    """Always fails -- models a transient writer/DB error."""

    def process(self, events):
        raise RuntimeError("simulated writer failure")


class ConcurrencySpyPipeline:
    """Asserts, over its lifetime, that at most one thread is ever inside
    process() at once -- the single-writer invariant."""

    def __init__(self):
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.calls = 0
        self.total_events = 0

    def process(self, events):
        evs = list(events)
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls += 1
            self.total_events += len(evs)
        time.sleep(0.003)  # widen the window a real second writer would collide in
        with self._lock:
            self.active -= 1
        return ProcessingResult(received=len(evs), inserted=len(evs))


# --- Helpers ----------------------------------------------------------------


def make_event(source="FileSystem", event_type="FILE_CREATED"):
    return Event(timestamp=datetime.now(), source=source,
                 event_type=event_type, description="x")


def make_manager(tmp_path, *, pipeline=None, config=None, collectors=frozenset()):
    cfg = config or RuntimeConfig(enabled=True, collectors=collectors)
    store = StateStore(path=tmp_path / "runtime_state.json")
    m = RuntimeManager(config=cfg, pipeline=pipeline or FakePipeline(), store=store)
    m._store.load()
    return m


def drain(m):
    """Synchronously process every queued poller item (fires on_committed)."""
    items = []
    while True:
        try:
            item = m._queue.get_nowait()
        except queue.Empty:
            break
        m._process_poller_item(item)
        items.append(item)
    return items


def _events_in(items):
    return sum(len(i.events) for i in items)


# --- Raw-event builders (normalize=False shapes) ----------------------------


def win_raw(rn, channel="System", ts="2026-09-20 09:00:00", event_id=7036):
    return {
        "timestamp": ts,
        "event_id": event_id,
        "description": "service state change",
        "severity": "INFO",
        "device": "HOST1",
        "metadata": {"channel": channel, "record_number": rn, "provider": "SCM"},
    }


def def_raw(rn, ts="2026-09-20 10:00:00", event_id=1116):
    # Defender EventRecordID arrives as a STRING when normalize=False.
    return {
        "timestamp": ts,
        "event_id": event_id,
        "description": "threat detected",
        "severity": "HIGH",
        "device": "HOST1",
        "metadata": {"record_number": str(rn)},
    }


def br_raw(url, ts, browser="Chrome", profile="Default"):
    return {
        "timestamp": ts,  # datetime or None (browser collector converts already)
        "source": "Browser",
        "event_type": "BROWSER_VISIT",
        "description": f"{browser} visited a page",
        "severity": "INFO",
        "user": "u",
        "device": "HOST1",
        "file_path": url,
        "metadata": {"browser": browser, "profile": profile, "url": url, "title": "t"},
    }


@pytest.fixture(autouse=True)
def _reset_runtime_singleton():
    """Isolate the module singleton + probe cache between tests."""
    rt.reset_singleton()
    probe.reset_cache()
    yield
    rt.reset_singleton()
    probe.reset_cache()


# --- Single-writer serialization --------------------------------------------


def test_single_writer_serialization(tmp_path):
    """Many producer threads, one consumer -> never two writers at once."""
    spy = ConcurrencySpyPipeline()
    cfg = RuntimeConfig(enabled=True, collectors=frozenset(),
                        queue_maxsize=10000, max_batch=50)
    m = RuntimeManager(config=cfg, pipeline=spy,
                       store=StateStore(path=tmp_path / "s.json"))
    consumer = threading.Thread(target=m._consume_loop, daemon=True)
    consumer.start()

    def produce():
        for _ in range(50):
            m._enqueue_realtime("file", make_event())

    producers = [threading.Thread(target=produce) for _ in range(4)]
    for p in producers:
        p.start()
    for p in producers:
        p.join()

    m._queue.join()          # wait until every item is task_done
    m._stop.set()
    m._queue.put(_SHUTDOWN)  # wake the blocked get()
    consumer.join(timeout=3)

    assert not consumer.is_alive()
    assert spy.max_active == 1          # never two concurrent writers
    assert spy.total_events == 200      # nothing lost (queue never filled)
    assert spy.calls >= 1


# --- Backpressure: non-blocking real-time drop ------------------------------


def test_realtime_drop_on_full_queue(tmp_path):
    cfg = RuntimeConfig(enabled=True, collectors=frozenset(), queue_maxsize=1)
    m = make_manager(tmp_path, config=cfg)
    m._enqueue_realtime("file", make_event())  # fills the single slot
    m._enqueue_realtime("file", make_event())  # no room -> dropped, not raised
    m._enqueue_realtime("file", make_event())  # dropped again

    snap = m._state.snapshot(queue_size=1, queue_maxsize=1, state_file="x")
    file_state = next(c for c in snap["collectors"] if c["name"] == "file")
    assert file_state["dropped_events"] == 2
    assert snap["queue"]["dropped_total"] == 2
    assert m._queue.qsize() == 1  # the observer thread never blocked


# --- Windows RecordNumber high-water-mark -----------------------------------


def test_windows_hwm_dedup_across_cycles(tmp_path):
    m = make_manager(tmp_path)
    raws = [win_raw(10), win_raw(11), win_raw(12)]

    m._ingest_windows(raws, "Windows", normalize_event)
    items = drain(m)
    assert _events_in(items) == 3
    assert m._store.get_windows_hwm("System") == 12

    # Same records next cycle -> HWM blocks every one; nothing enqueued.
    m._ingest_windows(raws, "Windows", normalize_event)
    assert m._queue.empty()

    # A genuinely new record is admitted; HWM advances.
    m._ingest_windows([win_raw(13)], "Windows", normalize_event)
    items = drain(m)
    assert _events_in(items) == 1
    assert m._store.get_windows_hwm("System") == 13

    # State survives a reload (persisted to disk).
    reloaded = StateStore(path=tmp_path / "runtime_state.json")
    reloaded.load()
    assert reloaded.get_windows_hwm("System") == 13


def test_windows_recordnumber_reset_detection(tmp_path):
    m = make_manager(tmp_path)
    m._store.set_windows_hwm("System", 100)
    # Newest read (2) < stored HWM (100) => the log was cleared/wrapped.
    m._ingest_windows([win_raw(1), win_raw(2)], "Windows", normalize_event)
    items = drain(m)
    # After reset the cursor is 0, so the backfill path re-admits the batch.
    assert _events_in(items) == 2
    assert m._store.get_windows_hwm("System") == 2


def test_windows_backfill_zero_primes_without_ingest(tmp_path):
    cfg = RuntimeConfig(enabled=True, collectors=frozenset(), initial_backfill=0)
    m = make_manager(tmp_path, config=cfg)
    m._ingest_windows([win_raw(5), win_raw(6)], "Windows", normalize_event)
    assert m._queue.empty()                       # no historical backfill
    assert m._store.get_windows_hwm("System") == 6  # but cursor is primed


# --- Defender RecordNumber (string ids, timestamp-None handling) ------------


def test_defender_valid_inserts_and_advances(tmp_path):
    m = make_manager(tmp_path)
    m._ingest_defender([def_raw(7)], "Defender", normalize_event)
    items = drain(m)
    assert _events_in(items) == 1
    assert m._store.get_defender_hwm() == 7


def test_defender_timestamp_none_skips_but_advances_hwm(tmp_path):
    m = make_manager(tmp_path)
    # A record with no timestamp: the normalizer refuses to fabricate one, so
    # the event is skipped -- but the HWM must still advance past it so it is
    # never retried forever.
    m._ingest_defender([def_raw(9, ts=None)], "Defender", normalize_event)
    assert m._queue.empty()                 # nothing storable was enqueued
    assert m._store.get_defender_hwm() == 9  # cursor advanced regardless


# --- Browser last_visit_time + boundary-set dedup ---------------------------


def test_browser_dedup_greater_equal_and_boundary(tmp_path):
    m = make_manager(tmp_path)
    t1 = datetime(2026, 9, 20, 9, 0, 0)
    t2 = datetime(2026, 9, 20, 10, 0, 0)
    t3 = datetime(2026, 9, 20, 11, 0, 0)

    # First poll: two distinct visits admitted; HWM = newest timestamp.
    m._ingest_browser([br_raw("http://a", t2), br_raw("http://b", t1)],
                      "Browser", normalize_event)
    assert _events_in(drain(m)) == 2
    hwm_iso, _ = m._store.get_browser_hwm("Chrome::Default")
    assert hwm_iso == t2.isoformat()

    # Re-poll identical records -> boundary set + HWM block everything.
    m._ingest_browser([br_raw("http://a", t2), br_raw("http://b", t1)],
                      "Browser", normalize_event)
    assert m._queue.empty()

    # Equal-timestamp boundary: a NEW url sharing the max ts is admitted once.
    m._ingest_browser([br_raw("http://a", t2), br_raw("http://c", t2)],
                      "Browser", normalize_event)
    assert _events_in(drain(m)) == 1

    # A strictly newer visit (repeat url, greater last_visit_time) is admitted.
    m._ingest_browser([br_raw("http://a", t3)], "Browser", normalize_event)
    assert _events_in(drain(m)) == 1
    hwm_iso, _ = m._store.get_browser_hwm("Chrome::Default")
    assert hwm_iso == t3.isoformat()


# --- Exception isolation + retry semantics ----------------------------------


def test_poller_exception_isolation_no_hwm_advance(tmp_path):
    m = make_manager(tmp_path, pipeline=RaisingPipeline())
    m._ingest_windows([win_raw(10)], "Windows", normalize_event)
    drain(m)  # _process_poller_item catches the writer failure

    # A failed commit must NOT advance the cursor -> the record is retried.
    assert m._store.get_windows_hwm("System") == 0
    snap = m._state.snapshot(queue_size=0, queue_maxsize=0, state_file="x")
    win = next(c for c in snap["collectors"] if c["name"] == "windows")
    assert win["state"] == "error"
    assert win["error_count"] == 1
    # A crash in one collector never taints the others.
    defen = next(c for c in snap["collectors"] if c["name"] == "defender")
    assert defen["error_count"] == 0

    # Once the writer recovers, the very same record commits and advances.
    m._pipeline = FakePipeline()
    m._ingest_windows([win_raw(10)], "Windows", normalize_event)
    assert _events_in(drain(m)) == 1
    assert m._store.get_windows_hwm("System") == 10


# --- State store: corruption tolerance + atomic writes ----------------------


def test_state_store_corrupt_missing_and_atomic(tmp_path):
    p = tmp_path / "runtime_state.json"
    p.write_text("{ this is not valid json", encoding="utf-8")

    s = StateStore(path=p)
    s.load()  # corruption is tolerated -> fresh state, never raises
    assert s.get_defender_hwm() == 0
    assert s.get_windows_hwm("System") == 0

    s.set_defender_hwm(42)
    s.set_windows_hwm("System", 7)
    s.save()
    assert p.exists()
    assert not p.with_suffix(p.suffix + ".tmp").exists()  # temp file replaced in

    s2 = StateStore(path=p)
    s2.load()
    assert s2.get_defender_hwm() == 42
    assert s2.get_windows_hwm("System") == 7

    missing = StateStore(path=tmp_path / "never_written.json")
    missing.load()  # missing file -> fresh start, no crash
    assert missing.get_defender_hwm() == 0


# --- Lifecycle: idempotency, drain, final persist ---------------------------


def test_lifecycle_idempotent_drains_and_persists(tmp_path):
    cfg = RuntimeConfig(enabled=True, collectors=frozenset(), analysis_interval=300)
    m = make_manager(tmp_path, config=cfg)
    m.start()
    m.start()  # second call is a no-op; no duplicate consumer/writer
    assert m._started is True

    committed = {"n": 0}
    m._enqueue("windows", [make_event()],
               on_committed=lambda r: committed.__setitem__("n", committed["n"] + 1))
    m._queue.join()  # the sole-writer consumer drains it

    m.stop()
    m.stop()  # idempotent
    assert m._started is False
    assert committed["n"] == 1                          # committed exactly once
    assert (tmp_path / "runtime_state.json").exists()   # final state persisted


# --- Analysis worker: deterministic, one cycle, no LLM ----------------------


def test_analysis_worker_one_cycle_no_llm(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.database.db.count_events", lambda: 5)
    monkeypatch.setattr("backend.ai.correlator.correlate_database",
                        lambda **k: [object(), object()])
    monkeypatch.setattr("backend.ai.behavior.analyze_database",
                        lambda **k: (object(), [object()]))
    cfg = RuntimeConfig(enabled=True, collectors=frozenset(), analysis_interval=0.05)
    m = make_manager(tmp_path, config=cfg)
    m.start()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        snap = m._state.snapshot(queue_size=0, queue_maxsize=0, state_file="x")
        if snap["analysis"]["runs"] >= 1:
            break
        time.sleep(0.02)
    m.stop()

    snap = m._state.snapshot(queue_size=0, queue_maxsize=0, state_file="x")
    assert snap["analysis"]["runs"] >= 1
    assert snap["analysis"]["candidate_incidents"] == 2
    assert snap["analysis"]["anomalies"] == 1
    assert snap["analysis"]["error_count"] == 0


# --- Ollama probe (monkeypatched urllib; never touches the network) ---------


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _client(model="llama3.1:8b", host="http://127.0.0.1:11434"):
    return types.SimpleNamespace(host=host, model=model)


def test_probe_reachable_and_model_present(monkeypatch):
    body = b'{"models": [{"name": "llama3.1:8b"}, {"name": "mistral:latest"}]}'
    monkeypatch.setattr(probe.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    r = probe.probe_ollama(client=_client(), use_cache=False)
    assert r["reachable"] is True
    assert r["model_present"] is True
    assert r["error"] is None


def test_probe_reachable_model_absent(monkeypatch):
    body = b'{"models": [{"name": "mistral:latest"}]}'
    monkeypatch.setattr(probe.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    r = probe.probe_ollama(client=_client(), use_cache=False)
    assert r["reachable"] is True
    assert r["model_present"] is False


def test_probe_unreachable(monkeypatch):
    def _boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(probe.urllib.request, "urlopen", _boom)
    r = probe.probe_ollama(client=_client(), use_cache=False)
    assert r["reachable"] is False
    assert r["model_present"] is None
    assert r["error"]  # a sanitized type name, never a leaked message


# --- Additive status endpoint (runtime disabled -> no OS deps, no network) --


def test_runtime_status_endpoint_shape(monkeypatch):
    """GET /api/runtime/status returns 200 + the documented envelope.

    Uses a plain (non-context-manager) TestClient so the app lifespan never
    runs and the runtime never auto-starts; the Ollama probe is stubbed so the
    endpoint needs neither Windows nor a live daemon.
    """
    monkeypatch.setattr(
        "backend.runtime.manager.probe_ollama",
        lambda *a, **k: {
            "reachable": False, "model": "llama3.1:8b", "model_present": None,
            "host": "http://127.0.0.1:11434",
            "checked_at": "2026-01-01T00:00:00+00:00", "error": None,
        },
    )
    client = TestClient(app)
    resp = client.get("/api/runtime/status")
    assert resp.status_code == 200

    data = resp.json()
    for key in ("running", "start_time", "uptime_seconds", "collectors",
                "queue", "totals", "analysis", "ollama", "state_file"):
        assert key in data
    assert data["running"] is False               # never auto-started here
    assert data["ollama"]["model"] == "llama3.1:8b"
    assert data["ollama"]["reachable"] is False
    assert {"size", "maxsize", "dropped_total"} <= set(data["queue"])
    assert {"events_ingested", "events_inserted", "batches"} <= set(data["totals"])
    # Every known collector reports a name + state.
    names = {c["name"] for c in data["collectors"]}
    assert {"windows", "defender", "browser", "usb", "file"} <= names

