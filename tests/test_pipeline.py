"""Tests for the integrated event processing pipeline (Phase 8).

The pipeline is the single integration point between collectors and the
database. These tests run entirely against a temporary SQLite database
(patched per test) so the real development database is never touched, and
never depend on Windows or any live OS resource.
"""

import json
from datetime import datetime, timedelta

import pytest

from backend.database import db as _db
from backend.database import schema
from backend.database.db import get_events
from backend.database.models import Event
from backend.processing.pipeline import (
    EventPipeline,
    ProcessingResult,
    process_events,
    drain_collector,
)

# Real collector SOURCE labels, imported so the "all five sources" test is
# tied to the actual collectors rather than hardcoded strings.
from backend.collectors.windows_events import SOURCE as WIN_SOURCE
from backend.collectors.defender import SOURCE as DEF_SOURCE
from backend.collectors.file_activity import SOURCE as FS_SOURCE
from backend.collectors import usb, browser


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Point the DB layer at a throwaway file and create the schema.

    Autouse so no test in this module can ever write to the real dev DB.
    """
    test_db = tmp_path / "test_forensix.db"
    monkeypatch.setattr(_db, "DB_PATH", str(test_db))
    schema.create_tables()
    yield


def _event(**overrides) -> Event:
    base = dict(
        timestamp=datetime(2021, 1, 1, 12, 0, 0),
        source="Windows",
        event_type="TEST_EVENT",
        description="a test event",
    )
    base.update(overrides)
    return Event(**base)


# ---------------------------------------------------------------------------
# 1-2. Processing valid events
# ---------------------------------------------------------------------------

def test_process_single_valid_event():
    result = process_events([_event()])
    assert isinstance(result, ProcessingResult)
    assert result.received == 1
    assert result.normalized == 1
    assert result.inserted == 1
    assert result.skipped == 0
    assert result.errors == 0
    assert len(get_events()) == 1


def test_process_multiple_valid_events():
    events = [_event(description=f"event {i}") for i in range(5)]
    result = process_events(events)
    assert result.received == 5
    assert result.inserted == 5
    assert len(get_events()) == 5


# ---------------------------------------------------------------------------
# 3. Raw dictionary normalization
# ---------------------------------------------------------------------------

def test_process_raw_dictionaries_are_normalized_and_stored():
    raw = {
        "timestamp": datetime(2021, 2, 2, 8, 0, 0),
        "source": "Browser",
        "event_type": "BROWSER_VISIT",
        "description": "visited example.com",
        "file_path": "https://example.com",
        "metadata": {"browser": "Chrome", "visit_count": 2},
    }
    result = process_events([raw])
    assert result.normalized == 1
    assert result.inserted == 1

    rows = get_events()
    assert len(rows) == 1
    assert rows[0]["source"] == "Browser"
    assert rows[0]["file_path"] == "https://example.com"
    assert json.loads(rows[0]["metadata"])["browser"] == "Chrome"


def test_process_mixed_events_and_dicts():
    items = [
        _event(description="an Event object"),
        {"timestamp": datetime(2021, 1, 1), "source": "USB",
         "event_type": "USB_CONNECTED", "description": "a raw dict"},
    ]
    result = process_events(items)
    assert result.inserted == 2


# ---------------------------------------------------------------------------
# 4-5. Invalid / missing-required-field handling
# ---------------------------------------------------------------------------

def test_invalid_input_type_is_counted_as_error_not_crash():
    result = process_events(["not an event", 42, None])
    assert result.received == 3
    assert result.errors == 3
    assert result.inserted == 0
    assert len(get_events()) == 0


def test_dict_missing_source_is_normalization_error():
    # normalize_event requires a source; the pipeline records the failure.
    bad = {"event_type": "X", "description": "no source", "timestamp": datetime.now()}
    result = process_events([bad])
    assert result.errors == 1
    assert result.inserted == 0


def test_event_missing_description_is_skipped_by_validation():
    result = process_events([_event(description="")])
    assert result.normalized == 1
    assert result.skipped == 1
    assert result.inserted == 0
    assert any("description" in note for note in result.error_details)


def test_one_bad_event_does_not_stop_the_batch():
    items = [_event(description="good 1"), "garbage", _event(description="good 2")]
    result = process_events(items)
    assert result.inserted == 2
    assert result.errors == 1
    assert len(get_events()) == 2


# ---------------------------------------------------------------------------
# 6. Optional fields may be empty
# ---------------------------------------------------------------------------

def test_optional_fields_may_be_empty():
    # user, device, file_path, metadata all default to "" and must be accepted.
    event = _event()
    assert event.user == "" and event.device == "" and event.file_path == ""
    result = process_events([event])
    assert result.inserted == 1
    assert result.skipped == 0


# ---------------------------------------------------------------------------
# 7. Database insertion (round-trip)
# ---------------------------------------------------------------------------

def test_database_insertion_round_trip():
    event = _event(source="Defender", event_type="THREAT",
                   description="threat found", severity="WARNING",
                   metadata=json.dumps({"threat": "EICAR"}))
    process_events([event])

    rows = get_events()
    assert len(rows) == 1
    row = rows[0]
    assert row["source"] == "Defender"
    assert row["event_type"] == "THREAT"
    assert row["severity"] == "WARNING"
    assert json.loads(row["metadata"])["threat"] == "EICAR"


# ---------------------------------------------------------------------------
# 8 & 16. Multiple / all five sources
# ---------------------------------------------------------------------------

def test_process_events_from_all_five_sources():
    ts = datetime(2021, 6, 1, 10, 0, 0)
    # Two events use real collector converters; three use their real SOURCE
    # labels via representative raw dicts. All five collector sources covered.
    usb_event = usb.device_to_forensix(
        {"name": "SanDisk", "device_id": r"USB\VID_0781&PID_5581\SER"},
        usb.EVENT_CONNECTED,
    )
    browser_event = browser.record_to_forensix(
        {"url": "https://x.com", "title": "X", "visit_count": 1, "timestamp": ts},
        "Chrome", "Default",
    )
    raw_others = [
        {"timestamp": ts, "source": WIN_SOURCE, "event_type": "INFO",
         "description": "windows log"},
        {"timestamp": ts, "source": DEF_SOURCE, "event_type": "THREAT",
         "description": "defender alert"},
        {"timestamp": ts, "source": FS_SOURCE, "event_type": "FILE_CREATED",
         "description": "file created"},
    ]

    result = process_events([usb_event, browser_event, *raw_others])
    assert result.inserted == 5

    sources = {row["source"] for row in get_events()}
    assert sources == {"USB", "Browser", WIN_SOURCE, DEF_SOURCE, FS_SOURCE}


# ---------------------------------------------------------------------------
# 9 & 14. Chronological ordering; timestamps never modified
# ---------------------------------------------------------------------------

def test_events_stored_in_chronological_order():
    base = datetime(2021, 1, 1, 0, 0, 0)
    # Deliberately out of order on input.
    events = [
        _event(description="third", timestamp=base + timedelta(hours=3)),
        _event(description="first", timestamp=base + timedelta(hours=1)),
        _event(description="second", timestamp=base + timedelta(hours=2)),
    ]
    process_events(events)

    stored = [row["timestamp"] for row in get_events()]
    assert stored == sorted(stored)


def test_pipeline_does_not_modify_event_timestamps():
    ts = datetime(2021, 9, 9, 9, 9, 9)
    event = _event(timestamp=ts)
    process_events([event])
    # The original object is untouched...
    assert event.timestamp == ts
    # ...and the stored value matches exactly.
    assert get_events()[0]["timestamp"] == ts.isoformat()


def test_identical_timestamps_keep_deterministic_order():
    ts = datetime(2021, 1, 1, 0, 0, 0)
    events = [_event(description=f"e{i}", timestamp=ts) for i in range(4)]
    process_events(events)
    # Stable sort preserves original batch order for equal timestamps.
    descriptions = [row["description"] for row in get_events()]
    assert descriptions == ["e0", "e1", "e2", "e3"]


# ---------------------------------------------------------------------------
# 10. Deduplication (opt-in, exact full-field match only)
# ---------------------------------------------------------------------------

def test_dedup_disabled_by_default_keeps_repeats():
    dup = _event()
    result = process_events([dup, _event()])  # two identical events
    assert result.inserted == 2
    assert result.duplicates == 0


def test_dedup_collapses_exact_duplicates_when_enabled():
    dup = _event()
    result = process_events([dup, _event(), _event()], deduplicate=True)
    assert result.inserted == 1
    assert result.duplicates == 2
    assert len(get_events()) == 1


def test_dedup_keeps_events_differing_in_any_field():
    # Same timestamp + type, but different description => NOT duplicates.
    ts = datetime(2021, 1, 1)
    a = _event(timestamp=ts, description="alpha")
    b = _event(timestamp=ts, description="beta")
    # Same everything except source => NOT duplicates (cross-source safety).
    c = _event(timestamp=ts, description="alpha", source="USB")
    result = process_events([a, b, c], deduplicate=True)
    assert result.duplicates == 0
    assert result.inserted == 3


# ---------------------------------------------------------------------------
# 11. Database insertion failure handling
# ---------------------------------------------------------------------------

def test_insertion_failure_is_recorded_not_swallowed():
    def boom(_event):
        raise RuntimeError("disk is on fire")

    result = process_events([_event(), _event()], inserter=boom)
    assert result.normalized == 2
    assert result.inserted == 0
    assert result.errors == 2
    assert any("disk is on fire" in note for note in result.error_details)


def test_insertion_failure_does_not_stop_remaining_events():
    calls = {"n": 0}

    def flaky(_event):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        # subsequent inserts go to the (isolated) real DB layer
        _db.insert_event(_event)

    result = process_events([_event(description="a"), _event(description="b")],
                            inserter=flaky)
    assert result.errors == 1
    assert result.inserted == 1


# ---------------------------------------------------------------------------
# 12. Empty event list
# ---------------------------------------------------------------------------

def test_empty_event_list():
    result = process_events([])
    assert result.received == 0
    assert result.inserted == 0
    assert result.errors == 0
    assert len(get_events()) == 0


# ---------------------------------------------------------------------------
# 13. Processing statistics
# ---------------------------------------------------------------------------

def test_processing_statistics_are_complete():
    items = [
        _event(description="ok 1"),
        _event(description="ok 2"),
        _event(description=""),      # skipped (validation)
        "garbage",                    # error (normalization)
    ]
    result = process_events(items)
    assert result.received == 4
    assert result.normalized == 3
    assert result.inserted == 2
    assert result.skipped == 1
    assert result.errors == 1
    assert result.as_dict() == {
        "received": 4, "normalized": 3, "inserted": 2,
        "skipped": 1, "duplicates": 0, "errors": 1,
    }


# ---------------------------------------------------------------------------
# 15. Collectors remain independent of database insertion
# ---------------------------------------------------------------------------

def _make_chromium_db(path, when):
    import sqlite3
    from datetime import timezone
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    micros = int((when.replace(tzinfo=timezone.utc) - epoch).total_seconds() * 1_000_000)
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, "
                     "title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
        conn.execute("INSERT INTO urls (url, title, visit_count, last_visit_time) "
                     "VALUES (?, ?, ?, ?)", ("https://a.com", "A", 1, micros))
        conn.commit()
    finally:
        conn.close()


def test_collector_does_not_write_db_but_pipeline_does(tmp_path):
    # A real collector run must NOT touch the database on its own.
    user_data = tmp_path / "User Data" / "Default"
    user_data.mkdir(parents=True)
    _make_chromium_db(user_data / "History", datetime(2021, 1, 1, 12, 0, 0))

    before = len(get_events())
    events = browser.collect_chrome(user_data_dir=str(tmp_path / "User Data"))
    assert len(events) == 1
    assert len(get_events()) == before  # collector wrote nothing

    # The pipeline is the component that persists them.
    result = process_events(events)
    assert result.inserted == 1
    assert len(get_events()) == before + 1


# ---------------------------------------------------------------------------
# Orchestration helpers (collect_and_process / drain_collector)
# ---------------------------------------------------------------------------

def test_collect_and_process_empty_and_unknown_sources():
    from backend.processing.pipeline import collect_and_process
    assert collect_and_process(sources=[]).received == 0
    assert collect_and_process(sources=["nonsense"]).received == 0


def test_collect_and_process_wires_a_collector(monkeypatch):
    from backend.processing import pipeline
    two = [_event(description="c1"), _event(description="c2")]
    monkeypatch.setattr(browser, "collect_browser_history", lambda **kw: list(two))

    result = pipeline.collect_and_process(sources=["browser"])
    assert result.inserted == 2
    assert len(get_events()) == 2


def test_collect_and_process_isolates_a_failing_collector(monkeypatch):
    from backend.processing import pipeline
    from backend.collectors import usb as usb_mod

    def boom(*a, **k):
        raise RuntimeError("collector down")

    monkeypatch.setattr(usb_mod, "collect_usb_events", boom)
    monkeypatch.setattr(browser, "collect_browser_history",
                        lambda **kw: [_event(description="ok")])

    result = pipeline.collect_and_process(sources=["usb", "browser"])
    assert result.inserted == 1  # usb failed, browser still processed


def test_drain_collector_processes_buffered_events():
    class FakeWatcher:
        events = [_event(description="live 1"), _event(description="live 2")]

    result = drain_collector(FakeWatcher())
    assert result.inserted == 2
    assert len(get_events()) == 2


def test_drain_collector_handles_no_events():
    class Empty:
        events = []

    assert drain_collector(Empty()).received == 0



