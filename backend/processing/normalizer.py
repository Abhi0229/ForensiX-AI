"""Event normalization layer for ForensiX AI.

Converts raw, source-specific events (Windows Event Logs, browser history,
file activity, USB events, Defender alerts, ...) into the common
``Event`` structure defined in ``backend.database.models``.

    Raw source-specific event  ->  normalize_event()  ->  common Event

The normalizer is responsible for mapping and cleaning only. It never
touches the database; persisting a normalized Event is the caller's job.
"""

import json
from datetime import datetime

from backend.database.models import Event


# Aliases let each collector hand us its own key names without the
# normalizer needing to know about every source in advance. Add new
# source-specific keys here as collectors are built.
FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "ts", "event_time", "datetime",
                  "date", "TimeGenerated", "visit_time"),
    "source": ("source", "log_source"),
    "event_type": ("event_type", "type", "event_id", "EventID",
                   "category", "action"),
    "description": ("description", "message", "Message", "desc",
                    "summary", "title"),
    "severity": ("severity", "level", "Level", "priority"),
    "user": ("user", "user_name", "username", "account", "User"),
    "device": ("device", "device_name", "machine", "computer",
               "host", "hostname"),
    "file_path": ("file_path", "path", "path_or_url", "file",
                  "target_path", "url"),
}

# Every raw key we consume into a first-class Event field. Anything left
# over is preserved in metadata so no source information is lost.
_MAPPED_KEYS = {key for aliases in FIELD_ALIASES.values() for key in aliases}
_MAPPED_KEYS.add("metadata")

# Timestamp formats tried, in order, before giving up. datetime.fromisoformat
# is tried first and covers most ISO / SQLite-style strings.
_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d",
)


def _first_present(raw, aliases):
    """Return the value of the first alias found in ``raw``, else None."""
    for key in aliases:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


def _to_datetime(value):
    """Coerce a raw timestamp value into a ``datetime`` object.

    Accepts an existing datetime, an epoch number, or a string in a range
    of common formats. Falls back to ``datetime.now()`` when no timestamp
    was supplied.
    """
    if value is None:
        return datetime.now()
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass
        for fmt in _TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        raise ValueError(f"Unrecognized timestamp format: {value!r}")
    raise TypeError(f"Unsupported timestamp type: {type(value).__name__}")


def _build_metadata(raw):
    """Collect source-specific extras into a JSON string.

    Includes any explicit ``metadata`` the caller passed plus every raw key
    that did not map onto a first-class Event field, so nothing is silently
    dropped. Returns ``""`` when there is nothing to preserve.
    """
    extras = {}

    explicit = raw.get("metadata")
    if isinstance(explicit, dict):
        extras.update(explicit)
    elif explicit not in (None, ""):
        extras["metadata"] = explicit

    for key, value in raw.items():
        if key not in _MAPPED_KEYS and value not in (None, ""):
            extras[key] = value

    if not extras:
        return ""
    return json.dumps(extras, default=str, sort_keys=True)


def normalize_event(raw_event, *, source=None, event_type=None):
    """Convert a raw source-specific event into a common ``Event``.

    Args:
        raw_event: A dict of raw event data using either the canonical Event
            field names or any of the aliases in ``FIELD_ALIASES``.
        source: Optional explicit source (e.g. "USB", "Browser"). Overrides
            any source found in ``raw_event``. Collectors typically pass this.
        event_type: Optional explicit event type. Overrides any event type
            found in ``raw_event``.

    Returns:
        An ``Event`` instance. Optional fields fall back to the Event
        dataclass defaults; unmapped raw keys are preserved in ``metadata``.

    Raises:
        TypeError: If ``raw_event`` is not a dict.
        ValueError: If a supplied timestamp cannot be parsed, or if neither
            source nor event_type can be determined.
    """
    if not isinstance(raw_event, dict):
        raise TypeError(
            f"raw_event must be a dict, got {type(raw_event).__name__}"
        )

    resolved_source = source or _first_present(raw_event, FIELD_ALIASES["source"])
    resolved_type = event_type or _first_present(raw_event, FIELD_ALIASES["event_type"])

    if resolved_source is None:
        raise ValueError("Cannot normalize event: 'source' is required")
    if resolved_type is None:
        raise ValueError("Cannot normalize event: 'event_type' is required")

    timestamp = _to_datetime(_first_present(raw_event, FIELD_ALIASES["timestamp"]))
    description = _first_present(raw_event, FIELD_ALIASES["description"]) or ""

    # Optional fields: pull the value if present, otherwise leave to the
    # Event dataclass defaults by only overriding when we have something.
    optional = {}
    severity = _first_present(raw_event, FIELD_ALIASES["severity"])
    if severity is not None:
        optional["severity"] = str(severity)
    for field in ("user", "device", "file_path"):
        value = _first_present(raw_event, FIELD_ALIASES[field])
        if value is not None:
            optional[field] = str(value)

    metadata = _build_metadata(raw_event)
    if metadata:
        optional["metadata"] = metadata

    return Event(
        timestamp=timestamp,
        source=str(resolved_source),
        event_type=str(resolved_type),
        description=str(description),
        **optional,
    )
