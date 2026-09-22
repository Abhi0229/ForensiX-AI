"""Tests for the Windows Defender collector.

Unit tests use sample rendered-event XML and do not require a real Defender
installation, its logs, or administrator rights. A single optional integration
test runs only when explicitly enabled on Windows.
"""

import json
import os
from datetime import datetime

import pytest

from backend.database.models import Event
from backend.collectors import defender
from backend.collectors.defender import (
    _parse_event_xml,
    collect_defender_events,
)


# A realistic threat-detection event (EventID 1116) with full EventData.
DEFENDER_THREAT_XML = r"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/>
    <EventID>1116</EventID>
    <Version>0</Version>
    <Level>3</Level>
    <TimeCreated SystemTime='2026-09-22T14:30:00.7225856Z'/>
    <EventRecordID>4521</EventRecordID>
    <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
    <Computer>DESKTOP-01</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='Product Name'>Microsoft Defender Antivirus</Data>
    <Data Name='Threat Name'>Trojan:Win32/Testfile.A</Data>
    <Data Name='Threat ID'>2147519003</Data>
    <Data Name='Severity Name'>Severe</Data>
    <Data Name='Category Name'>Trojan</Data>
    <Data Name='Path'>file:_C:\Users\Abhi\Downloads\bad.exe</Data>
    <Data Name='Process Name'>C:\Windows\explorer.exe</Data>
    <Data Name='Action Name'>Quarantine</Data>
    <Data Name='Detection ID'>{3F2A1B4C-0000-1111-2222-333344445555}</Data>
  </EventData>
</Event>"""

# A non-threat configuration/info event (no EventData severity, Level 4).
DEFENDER_CONFIG_XML = r"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Windows Defender'/>
    <EventID>5007</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime='2026-09-22T09:00:00Z'/>
    <EventRecordID>1200</EventRecordID>
    <Computer>DESKTOP-01</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='Old Value'>0x0</Data>
    <Data Name='New Value'>0x1</Data>
  </EventData>
</Event>"""

# A minimal event: only System, no EventData, no Security node.
DEFENDER_MINIMAL_XML = r"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>1000</EventID>
    <TimeCreated SystemTime='2026-09-22T08:00:00Z'/>
  </System>
</Event>"""


# ---------------------------------------------------------------------------
# A. Unit tests (no pywin32 / no Defender required)
# ---------------------------------------------------------------------------

def test_valid_event_parsing():
    raw = _parse_event_xml(DEFENDER_THREAT_XML)

    assert raw["event_id"] == 1116
    assert raw["device"] == "DESKTOP-01"
    assert "Trojan:Win32/Testfile.A" in raw["description"]
    assert raw["user"] == "S-1-5-18"  # SID string (pure parser does not resolve)


def test_timestamp_extraction_handles_100ns_fraction():
    """7-digit fractional seconds + trailing Z parse to a datetime."""
    raw = _parse_event_xml(DEFENDER_THREAT_XML)

    assert isinstance(raw["timestamp"], datetime)
    assert raw["timestamp"] == datetime(2026, 9, 22, 14, 30, 0, 722585)


def test_event_id_extraction():
    assert _parse_event_xml(DEFENDER_THREAT_XML)["event_id"] == 1116
    assert _parse_event_xml(DEFENDER_CONFIG_XML)["event_id"] == 5007


def test_severity_mapping():
    # Defender's own severity name is preferred when present.
    assert _parse_event_xml(DEFENDER_THREAT_XML)["severity"] == "Severe"
    # Otherwise fall back to the Level code mapping (Level 4 -> INFO).
    assert _parse_event_xml(DEFENDER_CONFIG_XML)["severity"] == "INFO"


def test_threat_information_extraction():
    raw = _parse_event_xml(DEFENDER_THREAT_XML)

    assert raw["metadata"]["threat_name"] == "Trojan:Win32/Testfile.A"
    assert raw["metadata"]["threat_id"] == "2147519003"
    assert raw["metadata"]["action_name"] == "Quarantine"
    assert raw["metadata"]["detection_id"] == "{3F2A1B4C-0000-1111-2222-333344445555}"
    assert raw["file_path"] == r"file:_C:\Users\Abhi\Downloads\bad.exe"


def test_metadata_preserves_full_event_data():
    raw = _parse_event_xml(DEFENDER_THREAT_XML)
    event_data = raw["metadata"]["event_data"]

    assert event_data["Product Name"] == "Microsoft Defender Antivirus"
    assert event_data["Category Name"] == "Trojan"
    assert event_data["Process Name"] == r"C:\Windows\explorer.exe"
    assert raw["metadata"]["provider"] == "Microsoft-Windows-Windows Defender"
    assert raw["metadata"]["record_number"] == "4521"


def test_missing_optional_fields():
    """A minimal event (no EventData, no Security) parses safely."""
    raw = _parse_event_xml(DEFENDER_MINIMAL_XML)

    assert raw["event_id"] == 1000
    assert raw["user"] == ""            # no Security node
    assert raw["file_path"] == ""       # no Path field
    assert raw["severity"] == "INFO"    # no Level, no Severity Name -> default
    assert raw["description"] == "Windows Defender event 1000"


def test_malformed_event_handling():
    with pytest.raises(ValueError):
        _parse_event_xml("<Event><System><EventID>1</EventID>")  # truncated


def test_normalization_into_event_model():
    raw = _parse_event_xml(DEFENDER_THREAT_XML)
    event = defender.normalize_event(raw, source=defender.SOURCE)

    assert isinstance(event, Event)
    assert event.source == "Defender"
    assert event.event_type == "1116"          # event_id mapped to event_type
    assert event.severity == "Severe"
    assert event.device == "DESKTOP-01"
    metadata = json.loads(event.metadata)
    assert metadata["threat_name"] == "Trojan:Win32/Testfile.A"


def test_collect_normalizes_via_monkeypatched_reader(monkeypatch):
    raw = _parse_event_xml(DEFENDER_THREAT_XML)

    def fake_reader(channel=defender.CHANNEL, max_events=None, since=None):
        yield raw

    monkeypatch.setattr(defender, "read_defender_events", fake_reader)

    events = collect_defender_events()
    assert len(events) == 1
    assert isinstance(events[0], Event)
    assert events[0].source == "Defender"


def test_collect_returns_raw_when_normalize_false(monkeypatch):
    raw = _parse_event_xml(DEFENDER_CONFIG_XML)

    def fake_reader(channel=defender.CHANNEL, max_events=None, since=None):
        yield raw

    monkeypatch.setattr(defender, "read_defender_events", fake_reader)

    raws = collect_defender_events(normalize=False)
    assert len(raws) == 1
    assert isinstance(raws[0], dict)
    assert raws[0]["event_id"] == 5007


def test_empty_event_result(monkeypatch):
    """A channel with no events yields an empty list, not an error."""
    def empty_reader(channel=defender.CHANNEL, max_events=None, since=None):
        return iter(())

    monkeypatch.setattr(defender, "read_defender_events", empty_reader)

    assert collect_defender_events() == []


def test_permission_or_missing_channel_handled(monkeypatch):
    """A reader that raises (missing log / access denied) yields []."""
    def failing_reader(channel=defender.CHANNEL, max_events=None, since=None):
        raise PermissionError("access denied")
        yield  # pragma: no cover - makes this a generator

    monkeypatch.setattr(defender, "read_defender_events", failing_reader)

    assert collect_defender_events() == []


# ---------------------------------------------------------------------------
# B. Optional Windows integration test
# ---------------------------------------------------------------------------

_WINDOWS_ENABLED = os.name == "nt" and os.environ.get("FORENSIX_RUN_WINDOWS_TESTS") == "1"


@pytest.mark.skipif(
    not _WINDOWS_ENABLED,
    reason="Set FORENSIX_RUN_WINDOWS_TESTS=1 on Windows to run the live Defender test",
)
def test_live_defender_collection_smoke():
    """Read a few real Defender events; tolerate an empty/absent log."""
    events = collect_defender_events(max_events=5)

    assert isinstance(events, list)
    for event in events:
        assert isinstance(event, Event)
        assert event.source == "Defender"
        assert isinstance(event.timestamp, datetime)
