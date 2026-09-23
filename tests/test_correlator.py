"""Tests for the Phase 10 deterministic event correlation engine.

All tests use isolated, in-memory synthetic events (dicts, real sqlite3.Row
objects, and Event dataclasses). Nothing here touches the real development
database, Windows, or any live OS resource -- the correlator is pure.
"""

import sqlite3
from datetime import datetime, timedelta

import pytest

from backend.ai.correlator import (
    CorrelationEngine,
    CandidateIncident,
    correlate_events,
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    PRIORITY_HIGH,
    PRIORITY_CRITICAL,
    INTEGRITY_LEGACY,
    INTEGRITY_VERIFIED,
    INTEGRITY_TAMPERED,
    SIGNAL_DEVICE,
    SIGNAL_USER,
    SIGNAL_FILE,
    SIGNAL_TEMPORAL,
)
from backend.database.models import Event
from backend.integrity.verifier import IntegrityResult

BASE = datetime(2021, 1, 1, 10, 0, 0)


def _ev(offset=0, source="FileSystem", event_type="FILE_CREATED", *,
        device="DESKTOP-01", user="", file_path="", severity="INFO",
        description="event", metadata=""):
    """Build a raw event dict at BASE + offset seconds."""
    return dict(
        timestamp=BASE + timedelta(seconds=offset),
        source=source, event_type=event_type, description=description,
        severity=severity, user=user, device=device,
        file_path=file_path, metadata=metadata,
    )


def _row(**cols):
    """Produce a real sqlite3.Row (mimics what the DB layer returns)."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    names = list(cols)
    quoted = ", ".join(f'"{n}"' for n in names)
    placeholders = ", ".join("?" for _ in names)
    conn.execute(f"CREATE TABLE t ({quoted})")
    conn.execute(f"INSERT INTO t ({quoted}) VALUES ({placeholders})",
                 tuple(cols.values()))
    row = conn.execute("SELECT * FROM t").fetchone()
    conn.close()
    return row


# ---------------------------------------------------------------------------
# 1-2. Empty / single input
# ---------------------------------------------------------------------------

def test_empty_event_list():
    assert correlate_events([]) == []


def test_single_event():
    # One event is never a candidate incident (min group size is 2).
    assert correlate_events([_ev()]) == []


# ---------------------------------------------------------------------------
# 3-4. Temporal correlation + configurable window
# ---------------------------------------------------------------------------

def test_temporal_correlation():
    events = [_ev(0), _ev(60, event_type="FILE_MODIFIED")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert len(incidents[0].events) == 2


def test_configurable_correlation_window():
    events = [_ev(0), _ev(200, event_type="FILE_MODIFIED")]
    # 200s apart: linked with a 300s window, not with a 100s window.
    assert len(correlate_events(events, window_seconds=300)) == 1
    assert len(correlate_events(events, window_seconds=100)) == 0


# ---------------------------------------------------------------------------
# 5-7. Same device / same user / file path signals (each isolated)
# ---------------------------------------------------------------------------

def test_same_device_correlation():
    # Two unrelated-category events linked purely by a shared device.
    events = [_ev(0, source="AppLog", event_type="A", device="HOST-1"),
              _ev(30, source="AppLog", event_type="B", device="HOST-1")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert SIGNAL_DEVICE in incidents[0].confidence_signals
    assert any("same device" in r for r in incidents[0].correlation_reasons)


def test_same_user_correlation():
    # Empty devices (no device signal / no veto); linked purely by shared user.
    events = [_ev(0, source="AppLog", event_type="A", device="", user="alice"),
              _ev(30, source="AppLog", event_type="B", device="", user="alice")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert SIGNAL_USER in incidents[0].confidence_signals
    assert any("same user: alice" in r for r in incidents[0].correlation_reasons)


def test_file_path_relationship():
    events = [_ev(0, source="AppLog", event_type="A", device="",
                  file_path="C:/data/report.docx"),
              _ev(30, source="AppLog", event_type="B", device="",
                  file_path="C:/data/report.docx")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert SIGNAL_FILE in incidents[0].confidence_signals
    assert any("same file path" in r for r in incidents[0].correlation_reasons)


# ---------------------------------------------------------------------------
# 8-11. Known event-type relationships (the documented scenarios)
# ---------------------------------------------------------------------------

def test_usb_file_activity_sequence():
    # Scenario 1: USB connect -> file create/modify -> USB disconnect.
    events = [
        _ev(0, source="USB", event_type="USB_CONNECTED"),
        _ev(120, source="FileSystem", event_type="FILE_CREATED"),
        _ev(300, source="FileSystem", event_type="FILE_MODIFIED"),
        _ev(420, source="USB", event_type="USB_DISCONNECTED"),
    ]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    inc = incidents[0]
    assert len(inc.events) == 4                       # transitively one group
    assert inc.priority == PRIORITY_MEDIUM            # USB + file, not auto-HIGH
    assert any("usb" in r and "file" in r for r in inc.correlation_reasons)


def test_browser_file_activity_relationship():
    # Scenario 2: a browser visit followed by a file write.
    events = [_ev(0, source="Browser", event_type="BROWSER_VISIT",
                  file_path="http://example.test/download"),
              _ev(60, source="FileSystem", event_type="FILE_CREATED",
                  file_path="C:/Downloads/setup.exe")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert any("browser" in r and "file" in r
               for r in incidents[0].correlation_reasons)
    assert incidents[0].priority == PRIORITY_LOW      # ordinary activity


def test_defender_file_activity_relationship():
    # Scenario 3: file activity next to a Defender detection.
    events = [_ev(0, source="FileSystem", event_type="FILE_MODIFIED",
                  file_path="C:/tmp/x.exe"),
              _ev(60, source="Defender", event_type="1116", severity="INFO")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert incidents[0].priority == PRIORITY_HIGH     # Defender detection present
    assert any("defender" in r and "file" in r
               for r in incidents[0].correlation_reasons)


def test_windows_event_related_activity():
    events = [_ev(0, source="Windows", event_type="4624", severity="AUDIT_FAILURE"),
              _ev(45, source="FileSystem", event_type="FILE_CREATED")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert any("windows" in r and "file" in r
               for r in incidents[0].correlation_reasons)


# ---------------------------------------------------------------------------
# 12-13. Temporal boundaries
# ---------------------------------------------------------------------------

def test_events_outside_window_not_correlated():
    # Scenario 4: several hours apart with no non-temporal rule to bridge them.
    events = [_ev(0, source="USB", event_type="USB_CONNECTED"),
              _ev(7200, source="FileSystem", event_type="FILE_CREATED")]
    assert correlate_events(events, window_seconds=300) == []


def test_same_timestamp_does_not_imply_correlation():
    # Scenario 5: identical timestamps, unrelated sources, no shared identity.
    events = [_ev(0, source="AppLog", event_type="A", device="", user="alice"),
              _ev(0, source="SysLog", event_type="B", device="", user="bob")]
    assert correlate_events(events, window_seconds=300) == []


# ---------------------------------------------------------------------------
# 14-17. Grouping: independence, overlap merge, dedup, determinism
# ---------------------------------------------------------------------------

def test_multiple_independent_incidents():
    events = [
        _ev(0, event_type="FILE_CREATED"), _ev(30, event_type="FILE_MODIFIED"),
        _ev(10000, event_type="FILE_CREATED"), _ev(10030, event_type="FILE_MODIFIED"),
    ]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 2
    assert all(len(i.events) == 2 for i in incidents)
    # First incident (by start_time) is the earlier cluster.
    assert incidents[0].start_time < incidents[1].start_time


def test_overlapping_event_groups_merge_deterministically():
    # A-B within window and B-C within window, but A-C is not: they must all
    # collapse into ONE incident (transitive connected component).
    events = [_ev(0, event_type="FILE_CREATED"),
              _ev(200, event_type="FILE_MODIFIED"),
              _ev(400, event_type="FILE_DELETED")]
    incidents = correlate_events(events, window_seconds=300)
    assert len(incidents) == 1
    assert len(incidents[0].events) == 3


def test_duplicate_incident_prevention():
    events = [_ev(0), _ev(60, event_type="FILE_MODIFIED"),
              _ev(120, event_type="FILE_DELETED")]
    incidents = correlate_events(events, window_seconds=300)
    ids = [i.incident_id for i in incidents]
    assert len(ids) == len(set(ids))                  # unique incident ids
    # No event appears in more than one incident (disjoint groups).
    seen = []
    for inc in incidents:
        seen.extend(id(e) for e in inc.events)
    assert len(seen) == len(set(seen))


def test_deterministic_output():
    events = [_ev(0, source="USB", event_type="USB_CONNECTED"),
              _ev(60, event_type="FILE_CREATED"),
              _ev(120, source="Defender", event_type="1116")]
    first = correlate_events(events, window_seconds=300)
    second = correlate_events(events, window_seconds=300)
    assert [i.incident_id for i in first] == [i.incident_id for i in second]
    assert [i.as_dict() for i in first] == [i.as_dict() for i in second]


# ---------------------------------------------------------------------------
# 18-19. Explainability + severity
# ---------------------------------------------------------------------------

def test_explainable_correlation_reasons():
    events = [_ev(0), _ev(60, event_type="FILE_MODIFIED")]
    inc = correlate_events(events, window_seconds=300)[0]
    assert inc.correlation_reasons
    assert all(isinstance(r, str) for r in inc.correlation_reasons)
    assert any("temporal proximity" in r for r in inc.correlation_reasons)
    # Confidence is an explainability count, never presented as a probability.
    assert isinstance(inc.confidence_score, int)
    assert 2 <= inc.confidence_score <= 5
    assert SIGNAL_TEMPORAL in inc.confidence_signals


def test_severity_priority_rules():
    def prio(events):
        return correlate_events(events, window_seconds=300)[0].priority

    # Defender detection + file activity, Defender severity CRITICAL -> CRITICAL.
    assert prio([_ev(0, event_type="FILE_MODIFIED", file_path="C:/x.exe"),
                 _ev(30, source="Defender", event_type="1116",
                     severity="CRITICAL")]) == PRIORITY_CRITICAL
    # Two Defender detections (same device) -> HIGH.
    assert prio([_ev(0, source="Defender", event_type="1116"),
                 _ev(30, source="Defender", event_type="1117")]) == PRIORITY_HIGH
    # USB + file activity -> MEDIUM.
    assert prio([_ev(0, source="USB", event_type="USB_CONNECTED"),
                 _ev(30, event_type="FILE_CREATED")]) == PRIORITY_MEDIUM
    # Ordinary browser + file activity -> LOW (not auto-escalated).
    assert prio([_ev(0, source="Browser", event_type="BROWSER_VISIT"),
                 _ev(30, event_type="FILE_CREATED")]) == PRIORITY_LOW


# ---------------------------------------------------------------------------
# 20-23. Evidence preservation (ids, immutability, hashes, legacy)
# ---------------------------------------------------------------------------

def test_event_ids_preserved():
    r1 = _row(id=1, timestamp="2021-01-01T10:00:00", source="FileSystem",
              event_type="FILE_CREATED", description="a", severity="INFO",
              user="", device="HOST", file_path="", metadata="",
              event_hash=None, previous_hash=None)
    r2 = _row(id=2, timestamp="2021-01-01T10:01:00", source="FileSystem",
              event_type="FILE_MODIFIED", description="b", severity="INFO",
              user="", device="HOST", file_path="", metadata="",
              event_hash=None, previous_hash=None)
    inc = correlate_events([r1, r2], window_seconds=300)[0]
    assert inc.event_ids == [1, 2]


def test_original_event_objects_not_modified():
    import dataclasses
    e1 = Event(timestamp=BASE, source="FileSystem", event_type="FILE_CREATED",
               description="a", device="HOST")
    e2 = Event(timestamp=BASE + timedelta(seconds=60), source="FileSystem",
               event_type="FILE_MODIFIED", description="b", device="HOST")
    before = [dataclasses.asdict(e1), dataclasses.asdict(e2)]
    correlate_events([e1, e2], window_seconds=300)
    assert [dataclasses.asdict(e1), dataclasses.asdict(e2)] == before


def test_hash_fields_remain_unchanged():
    import copy
    d1 = _ev(0); d1.update(id=1, event_hash="a" * 64, previous_hash="")
    d2 = _ev(60, event_type="FILE_MODIFIED")
    d2.update(id=2, event_hash="b" * 64, previous_hash="a" * 64)
    before = copy.deepcopy([d1, d2])
    inc = correlate_events([d1, d2], window_seconds=300)[0]
    assert [d1, d2] == before                              # inputs untouched
    assert {e.event_hash for e in inc.events} == {"a" * 64, "b" * 64}


def test_legacy_unhashed_events_handled_without_fabrication():
    inc = correlate_events([_ev(0), _ev(60, event_type="FILE_MODIFIED")],
                           window_seconds=300)[0]
    assert inc.integrity_summary.get(INTEGRITY_LEGACY) == 2
    assert INTEGRITY_VERIFIED not in inc.integrity_summary
    assert all(e.event_hash is None for e in inc.events)   # not fabricated


# ---------------------------------------------------------------------------
# 24-26. Robustness: missing fields, unknown types, invalid input
# ---------------------------------------------------------------------------

def test_missing_optional_fields():
    # Only the required fields present; optionals default to empty, no crash.
    e1 = {"timestamp": BASE, "source": "USB",
          "event_type": "USB_CONNECTED", "description": "c"}
    e2 = {"timestamp": BASE + timedelta(seconds=60), "source": "FileSystem",
          "event_type": "FILE_CREATED", "description": "f"}
    incidents = correlate_events([e1, e2], window_seconds=300)
    assert len(incidents) == 1        # linked by the USB<->file relationship


def test_unknown_event_types_do_not_crash():
    events = [_ev(0, source="Mystery", event_type="WEIRD_THING", device="H"),
              _ev(30, source="Mystery", event_type="ALSO_WEIRD", device="H")]
    incidents = correlate_events(events, window_seconds=300)
    assert isinstance(incidents, list)
    assert len(incidents) == 1         # still linked by shared device


def test_invalid_input_handling():
    with pytest.raises(TypeError):
        correlate_events(None)
    with pytest.raises(TypeError):
        correlate_events(42)
    # Unusable items are skipped rather than crashing the run.
    assert correlate_events([42, "junk", None]) == []


# ---------------------------------------------------------------------------
# 27-28. Do not merge across devices / users
# ---------------------------------------------------------------------------

def test_different_devices_not_merged():
    events = [_ev(0, device="HOST-A", file_path="C:/f.txt"),
              _ev(0, event_type="FILE_MODIFIED", device="HOST-B",
                  file_path="C:/f.txt")]
    assert correlate_events(events, window_seconds=300) == []


def test_different_users_not_treated_as_same():
    events = [_ev(0, source="AppLog", event_type="A", device="", user="alice"),
              _ev(30, source="AppLog", event_type="B", device="", user="bob")]
    assert correlate_events(events, window_seconds=300) == []


# ---------------------------------------------------------------------------
# 29-30. Incident shape: time range + sources
# ---------------------------------------------------------------------------

def test_incident_contains_start_and_end_time():
    events = [_ev(0), _ev(120, event_type="FILE_MODIFIED"),
              _ev(60, event_type="FILE_DELETED")]
    inc = correlate_events(events, window_seconds=300)[0]
    assert inc.start_time == BASE
    assert inc.end_time == BASE + timedelta(seconds=120)
    assert isinstance(inc.start_time, datetime)
    assert isinstance(inc.end_time, datetime)


def test_incident_contains_source_information():
    events = [_ev(0, source="USB", event_type="USB_CONNECTED"),
              _ev(60, source="FileSystem", event_type="FILE_CREATED")]
    inc = correlate_events(events, window_seconds=300)[0]
    assert set(inc.sources) == {"USB", "FileSystem"}


# ---------------------------------------------------------------------------
# Integrity annotation (Phase 9 aware; correlation does not itself verify)
# ---------------------------------------------------------------------------

def test_integrity_annotation_uses_supplied_result():
    common = dict(source="FileSystem", severity="INFO", user="",
                  device="HOST", file_path="", metadata="")
    r1 = _row(id=1, timestamp="2021-01-01T10:00:00", event_type="FILE_CREATED",
              description="a", event_hash="h1", previous_hash="", **common)
    r2 = _row(id=2, timestamp="2021-01-01T10:01:00", event_type="FILE_MODIFIED",
              description="b", event_hash="h2", previous_hash="h1", **common)
    # The verifier (run separately) flagged event id=2.
    result = IntegrityResult(
        invalid_events=[{"id": 2, "reasons": ["event_hash does not match"]}])
    inc = correlate_events([r1, r2], window_seconds=300,
                           integrity_result=result)[0]
    labels = {e.event_id: e.integrity for e in inc.events}
    assert labels[1] == INTEGRITY_VERIFIED
    assert labels[2] == INTEGRITY_TAMPERED


def test_result_is_candidate_incident_type():
    inc = correlate_events([_ev(0), _ev(60, event_type="FILE_MODIFIED")],
                           window_seconds=300)[0]
    assert isinstance(inc, CandidateIncident)
    assert isinstance(inc.as_dict(), dict)
