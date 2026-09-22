"""Tests for the Windows Event Log collector.

Unit tests use lightweight sample records and do not depend on the machine's
actual Event Viewer contents or administrator rights. A single optional
integration test runs only when explicitly enabled on Windows.
"""

import json
import os
from datetime import datetime
from types import SimpleNamespace

import pytest

from backend.database.models import Event
from backend.collectors import windows_events
from backend.collectors.windows_events import (
    _parse_event_record,
    collect_windows_events,
)


def _sample_record(**overrides):
    """Build a stand-in for a pywin32 event record using SimpleNamespace."""
    defaults = dict(
        TimeGenerated=datetime(2026, 9, 20, 18, 30, 0),
        SourceName="Service Control Manager",
        EventID=7036,
        EventType=4,  # INFORMATION
        EventCategory=0,
        RecordNumber=12345,
        ComputerName="DESKTOP-01",
        Sid=None,
        StringInserts=("The service entered the running state",),
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# A. Unit tests (no pywin32 / no Event Viewer required)
# ---------------------------------------------------------------------------

def test_parse_extracts_core_fields():
    raw = _parse_event_record(_sample_record(), "System", message="running state")

    assert raw["event_id"] == 7036
    assert raw["description"] == "running state"
    assert raw["severity"] == "INFO"
    assert raw["device"] == "DESKTOP-01"
    assert isinstance(raw["timestamp"], datetime)


def test_parse_masks_event_id_high_bits():
    """The high word of EventID is stripped to the friendly identifier."""
    record = _sample_record(EventID=(4 << 30) | 4624)
    raw = _parse_event_record(record, "Security", message="logon")

    assert raw["event_id"] == 4624


def test_severity_mapping_from_event_type():
    error = _parse_event_record(_sample_record(EventType=1), "System", message="x")
    warning = _parse_event_record(_sample_record(EventType=2), "System", message="x")
    audit_fail = _parse_event_record(_sample_record(EventType=16), "Security", message="x")
    unknown = _parse_event_record(_sample_record(EventType=999), "System", message="x")

    assert error["severity"] == "ERROR"
    assert warning["severity"] == "WARNING"
    assert audit_fail["severity"] == "AUDIT_FAILURE"
    assert unknown["severity"] == "INFO"  # safe default


def test_conversion_through_normalizer_produces_event():
    raw = _parse_event_record(_sample_record(), "System", message="hello")
    event = windows_events.normalize_event(raw, source=windows_events.SOURCE)

    assert isinstance(event, Event)
    assert event.source == "Windows"
    # event_id is mapped onto event_type by the normalizer.
    assert event.event_type == "7036"
    assert event.description == "hello"


def test_missing_optional_fields():
    """No Sid -> empty user; no message -> StringInserts fallback."""
    record = _sample_record(Sid=None, StringInserts=("fallback text", "more"))
    raw = _parse_event_record(record, "System", message=None)

    assert raw["user"] == ""                       # no SID available
    assert raw["description"] == "fallback text more"

    event = windows_events.normalize_event(raw, source=windows_events.SOURCE)
    assert event.user == ""


def test_metadata_preserves_provider_and_ids():
    raw = _parse_event_record(_sample_record(), "Application", message="msg")
    event = windows_events.normalize_event(raw, source=windows_events.SOURCE)
    metadata = json.loads(event.metadata)

    assert metadata["provider"] == "Service Control Manager"
    assert metadata["event_id"] == 7036
    assert metadata["channel"] == "Application"
    assert metadata["record_number"] == 12345


def test_collect_normalizes_via_monkeypatched_reader(monkeypatch):
    """collect_windows_events routes raw dicts through the normalizer."""
    sample_raw = _parse_event_record(_sample_record(), "System", message="msg")

    def fake_reader(channel, max_events=None, since=None):
        yield sample_raw

    monkeypatch.setattr(windows_events, "read_windows_event_logs", fake_reader)

    events = collect_windows_events(channels=["System"])
    assert len(events) == 1
    assert isinstance(events[0], Event)
    assert events[0].source == "Windows"


def test_collect_returns_raw_when_normalize_false(monkeypatch):
    sample_raw = _parse_event_record(_sample_record(), "System", message="msg")

    def fake_reader(channel, max_events=None, since=None):
        yield sample_raw

    monkeypatch.setattr(windows_events, "read_windows_event_logs", fake_reader)

    raws = collect_windows_events(channels=["System"], normalize=False)
    assert len(raws) == 1
    assert isinstance(raws[0], dict)
    assert raws[0]["event_id"] == 7036


def test_inaccessible_channel_is_skipped(monkeypatch):
    """A channel that raises (e.g. Security w/o admin) must not abort others."""
    good_raw = _parse_event_record(_sample_record(), "System", message="ok")

    def fake_reader(channel, max_events=None, since=None):
        if channel == "Security":
            raise PermissionError("access denied")
        yield good_raw

    monkeypatch.setattr(windows_events, "read_windows_event_logs", fake_reader)

    events = collect_windows_events(channels=["Security", "System"])
    # Security skipped, System still collected.
    assert len(events) == 1
    assert events[0].source == "Windows"


def test_malformed_record_does_not_crash_parse():
    """Parsing tolerates missing attributes via safe getattr defaults."""
    record = SimpleNamespace()  # nothing set
    raw = _parse_event_record(record, "System", message="")

    # It should still produce a dict; description falls back to "".
    assert isinstance(raw, dict)
    assert raw["description"] == ""


# ---------------------------------------------------------------------------
# B. Optional Windows integration test
# ---------------------------------------------------------------------------

_WINDOWS_ENABLED = os.name == "nt" and os.environ.get("FORENSIX_RUN_WINDOWS_TESTS") == "1"


@pytest.mark.skipif(
    not _WINDOWS_ENABLED,
    reason="Set FORENSIX_RUN_WINDOWS_TESTS=1 on Windows to run the live collector test",
)
def test_live_collection_smoke():
    """Read a few real System events; tolerate permission-limited channels."""
    events = collect_windows_events(channels=["System"], max_events=5)

    # System does not require admin; we expect it to return Event objects.
    assert isinstance(events, list)
    for event in events:
        assert isinstance(event, Event)
        assert event.source == "Windows"
        assert isinstance(event.timestamp, datetime)
