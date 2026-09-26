"""Integration: collector -> normalizer -> pipeline -> SQLite database.

Each collector is driven with MOCKED data (no live Windows/USB/browser state)
and its events are pushed through the real Phase 8 pipeline into a temporary
database, proving the collect -> normalize -> validate -> store path holds for
every source and that no field is lost in transit.
"""

import json
from datetime import datetime
from types import SimpleNamespace

from backend.collectors import browser as browser_mod
from backend.collectors import defender as def_mod
from backend.collectors import file_activity as file_mod
from backend.collectors import usb as usb_mod
from backend.collectors import windows_events as win_mod
from backend.database import db as _db
from backend.database.models import Event
from backend.processing.pipeline import EventPipeline


def _store(events):
    return EventPipeline().process(events)


def _rows():
    return list(_db.get_events())


def test_usb_event_reaches_database():
    device_info = dict(
        name="SanDisk Ultra USB Device",
        device_id=r"USB\VID_0781&PID_5581\4C530001120830108564",
        pnp_device_id=r"USB\VID_0781&PID_5581\4C530001120830108564",
        manufacturer="SanDisk", description="USB Mass Storage Device",
        status="OK")
    ev = usb_mod.device_to_forensix(device_info)
    assert isinstance(ev, Event) and ev.source == "USB"
    assert _store([ev]).inserted == 1
    row = _rows()[0]
    assert row["source"] == "USB"
    assert row["event_type"] == usb_mod.EVENT_CONNECTED


def test_file_activity_event_reaches_database():
    ns = SimpleNamespace(event_type="created",
                         src_path=r"C:\tmp\evidence.txt", is_directory=False)
    ev = file_mod.event_to_forensix(ns)
    assert isinstance(ev, Event) and ev.source == "FileSystem"
    assert ev.event_type == "FILE_CREATED"
    assert _store([ev]).inserted == 1
    row = _rows()[0]
    assert row["source"] == "FileSystem"
    assert row["event_type"] == "FILE_CREATED"
    assert row["file_path"] and "evidence.txt" in row["file_path"]


def test_browser_event_reaches_database():
    record = dict(url="http://example.test/download", title="Example Download",
                  visit_count=3, timestamp=datetime(2026, 9, 24, 14, 30, 0))
    ev = browser_mod.record_to_forensix(record, browser="chrome",
                                        profile="Default")
    assert isinstance(ev, Event) and ev.source == "Browser"
    assert ev.event_type == "BROWSER_VISIT"
    assert _store([ev]).inserted == 1
    row = _rows()[0]
    assert row["source"] == "Browser"
    assert row["event_type"] == "BROWSER_VISIT"
    blob = (row["file_path"] or "") + (row["metadata"] or "")
    assert "example.test" in blob


def test_windows_event_reaches_database(monkeypatch):
    raw = dict(timestamp=datetime(2026, 9, 24, 9, 0, 0), event_type="4624",
               description="An account was successfully logged on",
               user="alice", device="HOST1", record_number=101)

    def fake_reader(channel, max_events=None, since=None):
        yield raw

    monkeypatch.setattr(win_mod, "read_windows_event_logs", fake_reader)
    events = win_mod.collect_windows_events(channels=("System",))
    assert events and all(isinstance(e, Event) for e in events)
    assert all(e.source == "Windows" for e in events)
    assert _store(events).inserted == len(events)
    row = _rows()[0]
    assert row["source"] == "Windows"
    assert row["event_type"] == "4624"
    assert row["user"] == "alice"


def test_defender_event_reaches_database(monkeypatch):
    raw = dict(timestamp=datetime(2026, 9, 24, 3, 0, 0), event_type="1116",
               description="Windows Defender detected malware",
               severity="HIGH", device="HOST1", threat_name="EICAR_Test_File")

    def fake_reader(channel=def_mod.CHANNEL, max_events=None, since=None):
        yield raw

    monkeypatch.setattr(def_mod, "read_defender_events", fake_reader)
    events = def_mod.collect_defender_events()
    assert events and all(e.source == "Defender" for e in events)
    assert _store(events).inserted == len(events)
    row = _rows()[0]
    assert row["source"] == "Defender"
    assert row["event_type"] == "1116"
    assert row["severity"] == "HIGH"


def test_pipeline_preserves_all_fields_end_to_end():
    """No field is lost between a raw collector dict and the stored row;
    unmapped extras are retained in metadata rather than silently dropped."""
    ts = datetime(2026, 9, 24, 3, 15, 0)
    raw = dict(timestamp=ts, source="Defender", event_type="THREAT_DETECTED",
               description="threat found", severity="HIGH", user="alice",
               device="HOST1", file_path="C:/evil.exe", threat_id=9001)
    assert _store([raw]).inserted == 1          # pipeline normalizes the dict
    row = _rows()[0]
    assert row["timestamp"] == ts.isoformat()
    assert row["source"] == "Defender"
    assert row["event_type"] == "THREAT_DETECTED"
    assert row["severity"] == "HIGH"
    assert row["user"] == "alice" and row["device"] == "HOST1"
    assert row["file_path"] == "C:/evil.exe"
    meta = json.loads(row["metadata"])
    assert meta["threat_id"] == 9001


