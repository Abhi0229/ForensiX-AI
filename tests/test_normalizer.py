import json
from datetime import datetime

import pytest

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


# ---------------------------------------------------------------------------
# Forensic timestamp handling: a timestamp is NEVER fabricated.
#
# A digital-forensics record must not invent an evidence time. When the source
# event carries no usable timestamp, normalize_event() raises ValueError so the
# pipeline can reject the event, rather than silently stamping it with the
# current system time. Valid timestamps keep working exactly as before.
# ---------------------------------------------------------------------------

def _valid_raw(**overrides):
    """A raw event with every required field except (optionally) timestamp."""
    raw = {
        "timestamp": "2026-09-20T18:30:00",
        "source": "Windows",
        "event_type": "LOGIN",
        "description": "User logged in",
    }
    raw.update(overrides)
    return raw


def test_missing_timestamp_key_raises():
    """A raw event with no timestamp field is rejected, not back-filled."""
    raw = _valid_raw()
    del raw["timestamp"]
    with pytest.raises(ValueError):
        normalize_event(raw)


def test_none_timestamp_raises():
    """An explicit None timestamp is rejected rather than replaced with now()."""
    with pytest.raises(ValueError):
        normalize_event(_valid_raw(timestamp=None))


def test_empty_timestamp_string_treated_as_missing_and_raises():
    """An empty timestamp string counts as 'no timestamp' and is rejected."""
    with pytest.raises(ValueError):
        normalize_event(_valid_raw(timestamp=""))


def test_invalid_timestamp_string_raises():
    """An unparseable timestamp string is rejected, never fabricated."""
    with pytest.raises(ValueError):
        normalize_event(_valid_raw(timestamp="definitely-not-a-date"))


def test_valid_datetime_passthrough_unchanged():
    """A datetime input is preserved exactly (not replaced by 'now')."""
    exact = datetime(2021, 3, 4, 5, 6, 7)
    event = normalize_event(_valid_raw(timestamp=exact))
    assert event.timestamp == exact


def test_valid_iso_timestamp_parsed_exactly():
    """An ISO-8601 timestamp string is parsed to the exact datetime."""
    event = normalize_event(_valid_raw(timestamp="2021-03-04T05:06:07"))
    assert event.timestamp == datetime(2021, 3, 4, 5, 6, 7)


def test_valid_epoch_timestamp_parsed_exactly():
    """A numeric epoch timestamp is parsed to the exact datetime."""
    exact = datetime(2021, 3, 4, 5, 6, 7)
    event = normalize_event(_valid_raw(timestamp=exact.timestamp()))
    assert event.timestamp == exact


def test_now_is_never_used_as_timestamp_fallback(monkeypatch):
    """Prove datetime.now() is never called to back-fill a missing timestamp.

    The normalizer's datetime is swapped for a guard whose now() blows up. A
    missing timestamp must raise ValueError from the explicit refusal, never
    reach (and never fabricate from) now().
    """
    import backend.processing.normalizer as normalizer

    class _NoNow(datetime):
        @classmethod
        def now(cls, *args, **kwargs):
            raise AssertionError(
                "normalize_event must never fall back to datetime.now()"
            )

    monkeypatch.setattr(normalizer, "datetime", _NoNow)

    raw = _valid_raw()
    del raw["timestamp"]
    with pytest.raises(ValueError):
        normalize_event(raw)
    with pytest.raises(ValueError):
        normalize_event(_valid_raw(timestamp=None))


