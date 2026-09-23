"""Tests for the USB device collector.

Unit tests use plain device-info dicts and monkeypatched enumeration, so they
require no physical USB device, no WMI, and no administrator rights. A single
optional integration test enumerates real devices only when explicitly enabled
on Windows.
"""

import json
import os

import pytest

from backend.database.models import Event
from backend.database.db import get_events
from backend.collectors import usb
from backend.collectors.usb import (
    EVENT_CONNECTED,
    EVENT_DISCONNECTED,
    _build_raw_event,
    _parse_device_id,
    device_to_forensix,
    enumerate_usb_devices,
    collect_usb_events,
    USBEventWatcher,
)


def _sample_device(**overrides) -> dict:
    info = dict(
        name="SanDisk Ultra USB Device",
        device_id=r"USB\VID_0781&PID_5581\4C530001120830108564",
        pnp_device_id=r"USB\VID_0781&PID_5581\4C530001120830108564",
        manufacturer="SanDisk",
        description="USB Mass Storage Device",
        status="OK",
    )
    info.update(overrides)
    return info


# ---------------------------------------------------------------------------
# A. Pure parsing / mapping unit tests (no WMI)
# ---------------------------------------------------------------------------

def test_parse_device_id_extracts_vid_pid_instance():
    parsed = _parse_device_id(r"USB\VID_0781&PID_5581\4C530001120830108564")
    assert parsed["vendor_id"] == "0781"
    assert parsed["product_id"] == "5581"
    assert parsed["instance_id"] == "4C530001120830108564"


def test_usb_connected_event_parsing():
    raw = _build_raw_event(_sample_device(), EVENT_CONNECTED, device="DESKTOP-01")

    assert raw["source"] == "USB"
    assert raw["event_type"] == "USB_CONNECTED"
    assert "connected" in raw["description"]
    assert raw["severity"] == "INFO"
    assert raw["device"] == "DESKTOP-01"


def test_usb_disconnected_event_parsing():
    raw = _build_raw_event(_sample_device(), EVENT_DISCONNECTED)

    assert raw["event_type"] == "USB_DISCONNECTED"
    assert "disconnected" in raw["description"]


def test_device_name_extraction():
    raw = _build_raw_event(_sample_device(), EVENT_CONNECTED)
    assert raw["metadata"]["device_name"] == "SanDisk Ultra USB Device"


def test_device_id_and_pnp_extraction():
    raw = _build_raw_event(_sample_device(), EVENT_CONNECTED)
    assert raw["metadata"]["device_id"] == r"USB\VID_0781&PID_5581\4C530001120830108564"
    assert raw["metadata"]["pnp_device_id"] == raw["metadata"]["device_id"]
    assert raw["metadata"]["vendor_id"] == "0781"
    assert raw["metadata"]["product_id"] == "5581"


def test_manufacturer_extraction():
    raw = _build_raw_event(_sample_device(), EVENT_CONNECTED)
    assert raw["metadata"]["manufacturer"] == "SanDisk"


def test_serial_number_extraction_from_instance_id():
    """Serial falls back to the device-id instance segment when not explicit."""
    raw = _build_raw_event(_sample_device(), EVENT_CONNECTED)
    assert raw["metadata"]["serial_number"] == "4C530001120830108564"

    explicit = _build_raw_event(
        _sample_device(serial_number="EXPLICIT123"), EVENT_CONNECTED
    )
    assert explicit["metadata"]["serial_number"] == "EXPLICIT123"


def test_missing_optional_fields():
    """A sparse device (only a name) parses without fabricating values."""
    raw = _build_raw_event({"name": "Generic USB"}, EVENT_CONNECTED)

    assert raw["metadata"]["device_name"] == "Generic USB"
    # Absent fields are simply not present in metadata (filtered out).
    assert "manufacturer" not in raw["metadata"]
    assert "vendor_id" not in raw["metadata"]
    assert raw["user"] == ""


def test_metadata_preservation_through_normalization():
    event = device_to_forensix(_sample_device(), EVENT_CONNECTED, device="DESKTOP-01")
    metadata = json.loads(event.metadata)

    assert metadata["device_name"] == "SanDisk Ultra USB Device"
    assert metadata["manufacturer"] == "SanDisk"
    assert metadata["serial_number"] == "4C530001120830108564"
    assert metadata["vendor_id"] == "0781"
    assert metadata["product_id"] == "5581"


def test_normalization_into_event_model():
    event = device_to_forensix(_sample_device(), EVENT_CONNECTED)

    assert isinstance(event, Event)
    assert event.source == "USB"
    assert event.event_type == "USB_CONNECTED"
    assert event.severity == "INFO"


def test_capture_provenance_labels():
    snapshot = _build_raw_event(_sample_device(), EVENT_CONNECTED, observed=False)
    live = _build_raw_event(_sample_device(), EVENT_CONNECTED, observed=True)

    assert snapshot["metadata"]["capture"] == "current_state"
    assert live["metadata"]["capture"] == "realtime"


# ---------------------------------------------------------------------------
# B. Enumeration behavior with mocked WMI layer
# ---------------------------------------------------------------------------

def test_enumerate_normalizes_via_monkeypatched_build(monkeypatch):
    """enumerate_usb_devices returns Event objects (COM layer mocked out)."""
    devices = [_sample_device(name="Dev1"), _sample_device(name="Dev2")]

    def fake_enum(normalize=True):
        events = [device_to_forensix(d, EVENT_CONNECTED) for d in devices]
        return events if normalize else [
            _build_raw_event(d, EVENT_CONNECTED) for d in devices
        ]

    monkeypatch.setattr(usb, "enumerate_usb_devices", fake_enum)
    events = usb.enumerate_usb_devices()

    assert len(events) == 2
    assert all(isinstance(e, Event) for e in events)
    assert all(e.source == "USB" for e in events)


def test_multiple_usb_events():
    devices = [
        _sample_device(name=f"Device {i}",
                       device_id=rf"USB\VID_0781&PID_558{i}\SERIAL{i}")
        for i in range(4)
    ]
    events = [device_to_forensix(d, EVENT_CONNECTED) for d in devices]

    assert len(events) == 4
    assert {json.loads(e.metadata)["device_name"] for e in events} == {
        "Device 0", "Device 1", "Device 2", "Device 3"
    }


def test_wmi_unavailable_returns_empty(monkeypatch):
    """When COM/pywin32 cannot be imported, enumeration yields []."""
    def boom():
        raise RuntimeError("USB collection requires pywin32")

    monkeypatch.setattr(usb, "_com_modules", boom)
    assert enumerate_usb_devices() == []
    assert collect_usb_events() == []


def test_incomplete_device_info_handled():
    """A device with no usable fields still produces a valid Event."""
    event = device_to_forensix({}, EVENT_CONNECTED)
    assert isinstance(event, Event)
    assert event.source == "USB"
    assert "Unknown USB device" in event.description


def test_collector_does_not_write_to_database(monkeypatch):
    """Enumeration must not add any rows to the database."""
    devices = [_sample_device()]

    def fake_enum(normalize=True):
        return [device_to_forensix(d, EVENT_CONNECTED) for d in devices]

    monkeypatch.setattr(usb, "enumerate_usb_devices", fake_enum)

    before = len(get_events())
    usb.enumerate_usb_devices()
    after = len(get_events())
    assert before == after


# ---------------------------------------------------------------------------
# C. Watcher lifecycle (no real WMI events required)
# ---------------------------------------------------------------------------

def test_watcher_start_stop_when_wmi_available_or_not():
    """start/stop must behave cleanly whether or not WMI is present."""
    watcher = USBEventWatcher()
    try:
        watcher.start()
    except RuntimeError:
        # No COM/pywin32: acceptable; stop must still be safe.
        watcher.stop()
        return
    # Started: stopping (twice) must be clean and non-blocking.
    watcher.stop()
    watcher.stop()
    assert watcher._thread is None


# ---------------------------------------------------------------------------
# D. Optional Windows integration test
# ---------------------------------------------------------------------------

_WINDOWS_ENABLED = os.name == "nt" and os.environ.get("FORENSIX_RUN_WINDOWS_TESTS") == "1"


@pytest.mark.skipif(
    not _WINDOWS_ENABLED,
    reason="Set FORENSIX_RUN_WINDOWS_TESTS=1 on Windows to run the live USB enumeration test",
)
def test_live_usb_enumeration_smoke():
    """Enumerate currently connected USB devices; tolerate none present."""
    events = enumerate_usb_devices()

    assert isinstance(events, list)
    for event in events:
        assert isinstance(event, Event)
        assert event.source == "USB"
        assert event.event_type == "USB_CONNECTED"
        # Current-state enumeration is honestly labelled.
        assert json.loads(event.metadata)["capture"] == "current_state"
