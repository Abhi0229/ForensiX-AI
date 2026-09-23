"""Tests for the browser history collector.

Unit tests build temporary SQLite databases that mimic the real Chromium
('urls') and Firefox ('moz_places') history schemas, so no real browser,
profile, or installed browser is required. A single optional integration test
reads the current user's real browser history only when explicitly enabled on
Windows.

Safety is a first-class concern here: the collector must open browser
databases strictly read-only and must never modify the original file. Dedicated
tests assert both (no rows written to the ForensiX DB, original file bytes
unchanged).
"""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from backend.database.models import Event
from backend.database.db import get_events
from backend.collectors import browser
from backend.collectors.browser import (
    EVENT_TYPE,
    SOURCE,
    _build_raw_event,
    _read_sqlite_history,
    _chromium_row_mapper,
    _firefox_row_mapper,
    chromium_time_to_datetime,
    firefox_time_to_datetime,
    collect_browser_history,
    collect_chrome,
    collect_edge,
    collect_firefox,
    discover_chromium_profiles,
    discover_firefox_profiles,
    record_to_forensix,
    _CHROMIUM_QUERY,
    _FIREFOX_QUERY,
)

_CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers: build temp DBs that look like the real browser schemas
# ---------------------------------------------------------------------------

def _chromium_micros(dt: datetime) -> int:
    """Encode a UTC datetime as Chromium microseconds since 1601-01-01."""
    return int((dt.replace(tzinfo=timezone.utc) - _CHROMIUM_EPOCH).total_seconds() * 1_000_000)


def _firefox_micros(dt: datetime) -> int:
    """Encode a UTC datetime as Firefox microseconds since the Unix epoch."""
    return int((dt.replace(tzinfo=timezone.utc) - _UNIX_EPOCH).total_seconds() * 1_000_000)


def _make_chromium_db(path, rows):
    """rows: list of (url, title, visit_count, last_visit_time)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
            "visit_count INTEGER, last_visit_time INTEGER)"
        )
        conn.executemany(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) "
            "VALUES (?, ?, ?, ?)", rows,
        )
        conn.commit()
    finally:
        conn.close()


def _make_firefox_db(path, rows):
    """rows: list of (url, title, visit_count, last_visit_date)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
            "visit_count INTEGER, last_visit_date INTEGER)"
        )
        conn.executemany(
            "INSERT INTO moz_places (url, title, visit_count, last_visit_date) "
            "VALUES (?, ?, ?, ?)", rows,
        )
        conn.commit()
    finally:
        conn.close()


def _sha256(path) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


# ---------------------------------------------------------------------------
# A. Timestamp conversion (pure)
# ---------------------------------------------------------------------------

def test_chromium_time_to_datetime_valid():
    known = datetime(2021, 6, 15, 12, 30, 45)
    micros = _chromium_micros(known)
    assert chromium_time_to_datetime(micros) == known


def test_chromium_time_to_datetime_zero_returns_none():
    assert chromium_time_to_datetime(0) is None
    assert chromium_time_to_datetime(None) is None


def test_chromium_time_to_datetime_invalid_returns_none():
    assert chromium_time_to_datetime("not-a-number") is None


def test_firefox_time_to_datetime_valid():
    known = datetime(2022, 3, 9, 8, 5, 1)
    micros = _firefox_micros(known)
    assert firefox_time_to_datetime(micros) == known


def test_firefox_time_to_datetime_zero_returns_none():
    assert firefox_time_to_datetime(0) is None
    assert firefox_time_to_datetime(None) is None


def test_firefox_time_to_datetime_invalid_returns_none():
    assert firefox_time_to_datetime("not-a-number") is None


# ---------------------------------------------------------------------------
# B. Raw event building / normalization (pure)
# ---------------------------------------------------------------------------

def _sample_record(**overrides) -> dict:
    record = {
        "url": "https://example.com/page",
        "title": "Example Page",
        "visit_count": 3,
        "timestamp": datetime(2021, 1, 1, 10, 0, 0),
    }
    record.update(overrides)
    return record


def test_build_raw_event_basic_fields():
    raw = _build_raw_event(_sample_record(), "Chrome", "Default",
                           device="DESKTOP-01", user="alice")

    assert raw["source"] == SOURCE
    assert raw["event_type"] == EVENT_TYPE
    assert raw["severity"] == "INFO"
    assert raw["device"] == "DESKTOP-01"
    assert raw["user"] == "alice"
    assert raw["file_path"] == "https://example.com/page"
    assert "Example Page" in raw["description"]
    assert "Chrome" in raw["description"]


def test_build_raw_event_metadata_contains_source_fields():
    raw = _build_raw_event(_sample_record(), "Firefox", "profile-1")
    meta = raw["metadata"]

    assert meta["browser"] == "Firefox"
    assert meta["profile"] == "profile-1"
    assert meta["url"] == "https://example.com/page"
    assert meta["title"] == "Example Page"
    assert meta["visit_count"] == 3


def test_build_raw_event_missing_title_uses_url_label():
    raw = _build_raw_event(_sample_record(title=""), "Edge", "Default")
    assert "https://example.com/page" in raw["description"]
    assert "title" not in raw["metadata"]


def test_build_raw_event_missing_timestamp_is_omitted():
    """An unparseable/missing browser time is left to the normalizer, not faked."""
    raw = _build_raw_event(_sample_record(timestamp=None), "Chrome", "Default")
    assert raw["timestamp"] is None


def test_record_to_forensix_returns_event():
    event = record_to_forensix(_sample_record(), "Chrome", "Default",
                               device="DESKTOP-01", user="alice")
    assert isinstance(event, Event)
    assert event.source == "Browser"
    assert event.event_type == "BROWSER_VISIT"
    assert event.file_path == "https://example.com/page"

    meta = json.loads(event.metadata)
    assert meta["browser"] == "Chrome"
    assert meta["url"] == "https://example.com/page"


def test_record_to_forensix_missing_timestamp_is_rejected_not_fabricated():
    """A visit with no usable time is refused, never stamped with now().

    Forensic rule (see backend/processing/normalizer.py): normalize_event does
    not fabricate an evidence timestamp, so a record whose browser visit time
    could not be decoded raises ValueError instead of defaulting to the current
    time. The batch collectors catch this and skip the record.
    """
    with pytest.raises(ValueError):
        record_to_forensix(_sample_record(timestamp=None), "Chrome", "Default")


# ---------------------------------------------------------------------------
# C. Safe read of temp SQLite databases
# ---------------------------------------------------------------------------

def test_read_chromium_history_from_temp_db(tmp_path):
    db = tmp_path / "History"
    when = datetime(2021, 5, 1, 9, 0, 0)
    _make_chromium_db(db, [
        ("https://a.com", "A", 1, _chromium_micros(when)),
        ("https://b.com", "B", 2, _chromium_micros(when + timedelta(hours=1))),
    ])

    records = _read_sqlite_history(str(db), _CHROMIUM_QUERY, _chromium_row_mapper)
    assert len(records) == 2
    urls = {r["url"] for r in records}
    assert urls == {"https://a.com", "https://b.com"}
    # last_visit_time was decoded into a datetime.
    assert all(isinstance(r["timestamp"], datetime) for r in records)


def test_read_firefox_history_from_temp_db(tmp_path):
    db = tmp_path / "places.sqlite"
    when = datetime(2022, 1, 2, 3, 4, 5)
    _make_firefox_db(db, [
        ("https://c.org", "C", 5, _firefox_micros(when)),
        # A never-visited row (NULL date) must be excluded by the query.
        ("https://never.org", "Never", 0, None),
    ])

    records = _read_sqlite_history(str(db), _FIREFOX_QUERY, _firefox_row_mapper)
    assert len(records) == 1
    assert records[0]["url"] == "https://c.org"


def test_read_respects_max_events_limit(tmp_path):
    db = tmp_path / "History"
    base = datetime(2020, 1, 1)
    rows = [
        (f"https://s{i}.com", f"S{i}", 1, _chromium_micros(base + timedelta(hours=i)))
        for i in range(10)
    ]
    _make_chromium_db(db, rows)

    records = _read_sqlite_history(str(db), _CHROMIUM_QUERY, _chromium_row_mapper,
                                   max_events=3)
    assert len(records) == 3


def test_read_missing_db_raises_filenotfound(tmp_path):
    missing = tmp_path / "does_not_exist" / "History"
    with pytest.raises(FileNotFoundError):
        _read_sqlite_history(str(missing), _CHROMIUM_QUERY, _chromium_row_mapper)


def test_read_corrupted_db_raises_databaseerror(tmp_path):
    db = tmp_path / "History"
    db.write_bytes(b"this is definitely not a sqlite database")
    with pytest.raises(sqlite3.DatabaseError):
        _read_sqlite_history(str(db), _CHROMIUM_QUERY, _chromium_row_mapper)


def test_read_empty_db_returns_empty(tmp_path):
    db = tmp_path / "History"
    _make_chromium_db(db, [])
    records = _read_sqlite_history(str(db), _CHROMIUM_QUERY, _chromium_row_mapper)
    assert records == []


def test_original_db_not_modified(tmp_path):
    """CRITICAL SAFETY: reading history must never alter the source file."""
    db = tmp_path / "History"
    _make_chromium_db(db, [
        ("https://a.com", "A", 1, _chromium_micros(datetime(2021, 1, 1))),
    ])
    before_hash = _sha256(db)
    before_mtime = os.path.getmtime(db)

    _read_sqlite_history(str(db), _CHROMIUM_QUERY, _chromium_row_mapper)

    assert _sha256(db) == before_hash
    assert os.path.getmtime(db) == before_mtime


# ---------------------------------------------------------------------------
# D. Profile discovery (temp layouts, no hardcoded usernames)
# ---------------------------------------------------------------------------

def _make_chromium_layout(root, profiles):
    """Build a fake 'User Data' dir with a History file per named profile."""
    user_data = root / "User Data"
    for name in profiles:
        prof = user_data / name
        prof.mkdir(parents=True)
        _make_chromium_db(prof / "History", [
            ("https://x.com", "X", 1, _chromium_micros(datetime(2021, 1, 1))),
        ])
    # A stray non-profile dir without a History file must be ignored.
    (user_data / "Crashpad").mkdir(parents=True)
    return user_data


def test_discover_chromium_profiles(tmp_path):
    user_data = _make_chromium_layout(tmp_path, ["Default", "Profile 1"])
    profiles = discover_chromium_profiles(str(user_data))
    names = {p["profile"] for p in profiles}
    assert names == {"Default", "Profile 1"}
    assert all(os.path.isfile(p["db_path"]) for p in profiles)


def test_discover_chromium_no_dir_returns_empty(tmp_path):
    assert discover_chromium_profiles(str(tmp_path / "nope")) == []
    assert discover_chromium_profiles("") == []


def test_discover_firefox_profiles(tmp_path):
    profiles_dir = tmp_path / "Profiles"
    (profiles_dir / "abc.default-release").mkdir(parents=True)
    _make_firefox_db(profiles_dir / "abc.default-release" / "places.sqlite", [
        ("https://c.org", "C", 1, _firefox_micros(datetime(2022, 1, 1))),
    ])
    # A profile dir without places.sqlite is skipped.
    (profiles_dir / "empty.profile").mkdir(parents=True)

    profiles = discover_firefox_profiles(str(profiles_dir))
    assert len(profiles) == 1
    assert profiles[0]["profile"] == "abc.default-release"


# ---------------------------------------------------------------------------
# E. Per-browser collectors and the top-level entry point
# ---------------------------------------------------------------------------

def test_collect_chrome_from_temp_user_data(tmp_path):
    user_data = _make_chromium_layout(tmp_path, ["Default"])
    events = collect_chrome(user_data_dir=str(user_data))
    assert len(events) == 1
    assert all(isinstance(e, Event) for e in events)
    assert all(e.source == "Browser" for e in events)
    assert json.loads(events[0].metadata)["browser"] == "Chrome"


def test_collect_edge_from_temp_user_data(tmp_path):
    user_data = _make_chromium_layout(tmp_path, ["Default", "Profile 1"])
    events = collect_edge(user_data_dir=str(user_data))
    assert len(events) == 2
    assert {json.loads(e.metadata)["browser"] for e in events} == {"Edge"}


def test_collect_firefox_from_temp_profiles_dir(tmp_path):
    profiles_dir = tmp_path / "Profiles"
    (profiles_dir / "p1").mkdir(parents=True)
    _make_firefox_db(profiles_dir / "p1" / "places.sqlite", [
        ("https://c.org", "C", 1, _firefox_micros(datetime(2022, 1, 1))),
    ])
    events = collect_firefox(profiles_dir=str(profiles_dir))
    assert len(events) == 1
    assert json.loads(events[0].metadata)["browser"] == "Firefox"


def test_collect_normalize_false_returns_raw_dicts(tmp_path):
    user_data = _make_chromium_layout(tmp_path, ["Default"])
    raws = collect_chrome(user_data_dir=str(user_data), normalize=False)
    assert len(raws) == 1
    assert isinstance(raws[0], dict)
    assert raws[0]["source"] == "Browser"


def test_collect_browser_history_selects_subset(monkeypatch):
    """collect_browser_history dispatches only to the requested browsers."""
    calls = []

    def fake_chrome(max_events, normalize):
        calls.append("chrome")
        return [record_to_forensix(_sample_record(), "Chrome", "Default")]

    def fake_firefox(max_events, normalize):
        calls.append("firefox")
        return [record_to_forensix(_sample_record(), "Firefox", "Default")]

    monkeypatch.setitem(browser._BROWSER_COLLECTORS, "chrome", fake_chrome)
    monkeypatch.setitem(browser._BROWSER_COLLECTORS, "firefox", fake_firefox)

    events = collect_browser_history(browsers=["chrome"])
    assert calls == ["chrome"]
    assert len(events) == 1


def test_one_browser_failure_does_not_stop_others(monkeypatch):
    """A collector raising must not prevent the others from running."""
    def boom(max_events, normalize):
        raise RuntimeError("chrome collector exploded")

    def ok(max_events, normalize):
        return [record_to_forensix(_sample_record(), "Firefox", "Default")]

    monkeypatch.setitem(browser._BROWSER_COLLECTORS, "chrome", boom)
    monkeypatch.setitem(browser._BROWSER_COLLECTORS, "firefox", ok)

    events = collect_browser_history(browsers=["chrome", "firefox"])
    assert len(events) == 1
    assert events[0].source == "Browser"


def test_unknown_browser_name_ignored():
    assert collect_browser_history(browsers=["netscape"]) == []


def test_collector_does_not_write_to_database(tmp_path):
    """Collecting history must not add any rows to the ForensiX database."""
    user_data = _make_chromium_layout(tmp_path, ["Default", "Profile 1"])

    before = len(get_events())
    collect_chrome(user_data_dir=str(user_data))
    after = len(get_events())
    assert before == after


# ---------------------------------------------------------------------------
# F. Optional live integration test (reads the real user's history)
# ---------------------------------------------------------------------------

_WINDOWS_ENABLED = os.name == "nt" and os.environ.get("FORENSIX_RUN_WINDOWS_TESTS") == "1"


@pytest.mark.skipif(
    not _WINDOWS_ENABLED,
    reason="Set FORENSIX_RUN_WINDOWS_TESTS=1 on Windows to run the live browser history test",
)
def test_live_browser_history_smoke():
    """Read whatever real browser history exists; tolerate none present."""
    events = collect_browser_history(max_events=10)
    assert isinstance(events, list)
    for event in events:
        assert isinstance(event, Event)
        assert event.source == "Browser"
        assert event.event_type == "BROWSER_VISIT"
