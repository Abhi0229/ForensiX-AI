import json
from datetime import datetime

from backend.database.models import Event
from backend.processing.normalizer import normalize_event


def test_normalize_complete_event():
    """A fully populated raw event maps onto every Event field."""
    raw = {
        "timestamp": "2026-09-20T18:30:00",
        "source": "USB",
        "event_type": "USB_CONNECTED",
        "description": "SanDisk USB device connected",
        "severity": "INFO",
        "user": "Abhi",
        "device": "SanDisk Ultra",
        "file_path": "",
    }

    event = normalize_event(raw)

    assert event.source == "USB"
    assert event.event_type == "USB_CONNECTED"
    assert event.description == "SanDisk USB device connected"
    assert event.severity == "INFO"
    assert event.user == "Abhi"
    assert event.device == "SanDisk Ultra"
    assert event.timestamp == datetime(2026, 9, 20, 18, 30, 0)


def test_normalize_missing_optional_fields_uses_defaults():
    """Missing optional fields fall back to the Event dataclass defaults."""
    raw = {
        "timestamp": "2026-09-20 18:30:00",
        "source": "FILE",
        "event_type": "FILE_CREATE",
        "description": "File created",
    }

    event = normalize_event(raw)

    # Defaults come straight from the existing Event model.
    assert event.severity == "INFO"
    assert event.user == ""
    assert event.device == ""
    assert event.file_path == ""
    assert event.metadata == ""


def test_source_and_event_type_preserved():
    """Source and event type survive normalization unchanged."""
    raw = {
        "timestamp": "2026-09-20T10:00:00",
        "source": "Defender",
        "event_type": "THREAT_DETECTED",
        "description": "Threat quarantined",
    }

    event = normalize_event(raw)

    assert event.source == "Defender"
    assert event.event_type == "THREAT_DETECTED"


def test_timestamp_converted_to_datetime():
    """String and epoch timestamps are converted to datetime objects."""
    string_event = normalize_event({
        "timestamp": "2026-09-20 18:30:00",
        "source": "Windows",
        "event_type": "LOGIN",
        "description": "User logged in",
    })
    assert isinstance(string_event.timestamp, datetime)
    assert string_event.timestamp == datetime(2026, 9, 20, 18, 30, 0)

    epoch = datetime(2026, 9, 20, 18, 30, 0).timestamp()
    epoch_event = normalize_event({
        "timestamp": epoch,
        "source": "Windows",
        "event_type": "LOGIN",
        "description": "User logged in",
    })
    assert isinstance(epoch_event.timestamp, datetime)
    assert epoch_event.timestamp == datetime(2026, 9, 20, 18, 30, 0)


def test_returns_event_instance():
    """The normalizer returns the existing Event dataclass, not a new type."""
    event = normalize_event({
        "timestamp": "2026-09-20T18:30:00",
        "source": "USB",
        "event_type": "USB_CONNECTED",
        "description": "USB connected",
    })

    assert isinstance(event, Event)


def test_source_specific_metadata_preserved():
    """Unmapped source-specific keys are preserved inside metadata."""
    raw = {
        "timestamp": "2026-09-20T18:30:00",
        "source": "USB",
        "event_type": "USB_CONNECTED",
        "description": "USB connected",
        # Source-specific fields with no Event column of their own:
        "vendor": "SanDisk",
        "serial_number": "AA123456",
        "product_id": "0x5581",
    }

    event = normalize_event(raw)
    metadata = json.loads(event.metadata)

    assert metadata["vendor"] == "SanDisk"
    assert metadata["serial_number"] == "AA123456"
    assert metadata["product_id"] == "0x5581"


def test_explicit_overrides_win():
    """Explicit source/event_type override values found in the raw dict."""
    raw = {
        "timestamp": "2026-09-20T18:30:00",
        "source": "ignored",
        "event_type": "ignored",
        "description": "Browser visit",
        "url": "https://example.com",
    }

    event = normalize_event(raw, source="Browser", event_type="WEBSITE_VISIT")

    assert event.source == "Browser"
    assert event.event_type == "WEBSITE_VISIT"
    # 'url' alias maps to file_path (path_or_url in the roadmap schema).
    assert event.file_path == "https://example.com"


def test_alias_mapping():
    """Common source-specific aliases map onto canonical Event fields."""
    raw = {
        "time": "2026-09-20T18:30:00",
        "log_source": "Windows",
        "EventID": 4624,
        "message": "An account was successfully logged on",
        "account": "SYSTEM",
        "computer": "DESKTOP-01",
    }

    event = normalize_event(raw)

    assert event.source == "Windows"
    assert event.event_type == "4624"
    assert event.description == "An account was successfully logged on"
    assert event.user == "SYSTEM"
    assert event.device == "DESKTOP-01"
    assert event.timestamp == datetime(2026, 9, 20, 18, 30, 0)


def test_non_dict_raises_type_error():
    """A non-dict raw event is rejected."""
    try:
        normalize_event("not a dict")
        assert False, "Expected TypeError"
    except TypeError:
        pass


def test_missing_required_fields_raises():
    """Source and event_type are required."""
    try:
        normalize_event({"description": "no source or type"})
        assert False, "Expected ValueError"
    except ValueError:
        pass
