"""Windows Event Log collector for ForensiX AI.

Reads records from the Windows Event Log and turns them into the common
ForensiX ``Event`` structure by routing raw data through the shared
normalizer. It never writes to the database.

    Windows Event Logs
            |
    read_windows_event_logs()   ->  raw event dicts   (Windows-only)
            |
    _parse_event_record()        ->  raw event dict    (pure, testable)
            |
    normalize_event()            ->  common Event object
            |
    (caller stores it)

The parsing/mapping logic is a pure function so it can be unit tested with
sample data on any platform. Only the reader touches pywin32, and it is
imported lazily so importing this module never fails off-Windows.
"""

from datetime import datetime

from backend.processing.normalizer import normalize_event

# ForensiX source label for every record this collector emits. The original
# Windows provider name is preserved in metadata (see _parse_event_record).
SOURCE = "Windows"

# Default channels. "Security" typically requires administrator rights and is
# handled gracefully if inaccessible.
DEFAULT_CHANNELS = ("System", "Application", "Security")

# Sensible default so we never pull an unbounded amount of history.
DEFAULT_MAX_EVENTS = 100

# Windows EventType codes -> human-readable severity labels. Kept in Windows
# terms (not the roadmap's Low/Medium/High scale, which is defined later) so
# the mapping stays faithful to the source record.
EVENT_TYPE_LABELS = {
    1: "ERROR",           # EVENTLOG_ERROR_TYPE
    2: "WARNING",         # EVENTLOG_WARNING_TYPE
    4: "INFO",            # EVENTLOG_INFORMATION_TYPE
    8: "AUDIT_SUCCESS",   # EVENTLOG_AUDIT_SUCCESS
    16: "AUDIT_FAILURE",  # EVENTLOG_AUDIT_FAILURE
}


def _windows_modules():
    """Import pywin32 event modules lazily.

    Returns the modules tuple, or raises RuntimeError with a clear message
    when pywin32 is unavailable (e.g. running off-Windows). Importing this
    collector module itself never triggers this.
    """
    try:
        import win32evtlog
        import win32evtlogutil
        import win32security
        return win32evtlog, win32evtlogutil, win32security
    except ImportError as exc:  # pragma: no cover - platform dependent
        raise RuntimeError(
            "Windows Event Log collection requires pywin32 on Windows"
        ) from exc


def _to_datetime(time_generated):
    """Normalize a record's TimeGenerated into a datetime.

    pywin32 may hand back a datetime subclass (pywintypes.datetime) or an
    epoch-like integer depending on version; both are handled. Anything else
    is left for the normalizer to interpret.
    """
    if isinstance(time_generated, datetime):
        # Drop any tzinfo to stay consistent with the naive datetimes used
        # elsewhere in the project.
        return time_generated.replace(tzinfo=None)
    if isinstance(time_generated, (int, float)):
        return datetime.fromtimestamp(time_generated)
    return time_generated


def _resolve_user(record, win32security=None):
    """Best-effort resolve the record's SID to a DOMAIN\\user string.

    Returns "" when there is no SID. Falls back to the raw SID string if the
    account cannot be looked up (deleted account, no permission, etc.). Never
    raises — user information is optional.
    """
    sid = getattr(record, "Sid", None)
    if not sid:
        return ""
    if win32security is not None:
        try:
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}" if domain else name
        except Exception:
            pass
    try:
        return str(sid)
    except Exception:
        return ""


def _parse_event_record(record, channel, message=None):
    """Map a single Windows event record onto a raw ForensiX event dict.

    Pure and side-effect free: it reads attributes off ``record`` with safe
    getattr defaults, so a lightweight stand-in object works in tests without
    pywin32. ``message`` is the pre-rendered description supplied by the
    reader; when absent, StringInserts are joined as a fallback.

    Returns a dict suitable for ``normalize_event(..., source=SOURCE)``.
    """
    # EventID carries severity/customer bits in its high word; mask to the
    # friendly identifier admins actually recognize.
    raw_event_id = getattr(record, "EventID", None)
    event_id = (raw_event_id & 0xFFFF) if isinstance(raw_event_id, int) else raw_event_id

    type_code = getattr(record, "EventType", None)
    severity = EVENT_TYPE_LABELS.get(type_code, "INFO")

    if message is None:
        inserts = getattr(record, "StringInserts", None) or ()
        message = " ".join(str(part) for part in inserts if part)

    provider = getattr(record, "SourceName", None) or ""
    computer = getattr(record, "ComputerName", None) or ""

    # Preserve source-specific identifiers that have no dedicated Event column
    # so nothing is lost and events remain traceable to the original record.
    metadata = {
        "provider": provider,
        "event_id": event_id,
        "channel": channel,
        "event_category": getattr(record, "EventCategory", None),
        "event_type_code": type_code,
        "record_number": getattr(record, "RecordNumber", None),
    }
    metadata = {key: value for key, value in metadata.items() if value not in (None, "")}

    return {
        "timestamp": _to_datetime(getattr(record, "TimeGenerated", None)),
        "event_id": event_id,          # normalizer maps this to event_type
        "description": message,
        "severity": severity,
        "user": _resolve_user(record),
        "device": computer,
        "metadata": metadata,
    }


def read_windows_event_logs(channel, max_events=DEFAULT_MAX_EVENTS, since=None):
    """Yield raw event dicts from a single Windows Event Log channel.

    Reads newest-first and stops once ``max_events`` are yielded or a record
    older than ``since`` is reached. Windows-only; raises RuntimeError if
    pywin32 is unavailable. Individual records that fail to parse are skipped
    rather than aborting the whole read.

    Args:
        channel: Channel name, e.g. "System", "Application", "Security".
        max_events: Maximum records to yield (None for no cap).
        since: Optional datetime; only records at or after this time are
            yielded, and reading stops at the first older record.
    """
    win32evtlog, win32evtlogutil, win32security = _windows_modules()

    handle = win32evtlog.OpenEventLog(None, channel)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    yielded = 0
    try:
        while max_events is None or yielded < max_events:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            for record in records:
                if max_events is not None and yielded >= max_events:
                    return

                when = _to_datetime(getattr(record, "TimeGenerated", None))
                if since is not None and isinstance(when, datetime) and when < since:
                    # Backwards read is newest-first, so everything past here
                    # is older too.
                    return

                try:
                    message = win32evtlogutil.SafeFormatMessage(record, channel)
                except Exception:
                    message = None

                try:
                    raw = _parse_event_record(record, channel, message=message)
                    # Resolve user with the real module now that we have it.
                    raw["user"] = _resolve_user(record, win32security)
                except Exception:
                    # One malformed record must not stop the collector.
                    continue

                yielded += 1
                yield raw
    finally:
        win32evtlog.CloseEventLog(handle)


def collect_windows_events(channels=None, max_events=DEFAULT_MAX_EVENTS,
                           since=None, normalize=True):
    """Collect recent Windows events as normalized ForensiX Events.

    Reads each requested channel, converts records through the shared
    normalizer, and returns the results. A channel that cannot be opened
    (missing permissions, unknown name) is skipped without failing the others.

    Args:
        channels: Iterable of channel names. Defaults to DEFAULT_CHANNELS.
        max_events: Maximum records per channel.
        since: Optional datetime lower bound.
        normalize: When True (default) return Event objects; when False return
            the raw event dicts (useful for debugging/inspection).

    Returns:
        A list of Event objects (or raw dicts when normalize=False).
    """
    if channels is None:
        channels = DEFAULT_CHANNELS

    collected = []
    for channel in channels:
        try:
            for raw in read_windows_event_logs(channel, max_events=max_events, since=since):
                if normalize:
                    try:
                        collected.append(normalize_event(raw, source=SOURCE))
                    except Exception:
                        # Skip a record the normalizer rejects rather than
                        # aborting the whole collection.
                        continue
                else:
                    collected.append(raw)
        except Exception:
            # Inaccessible channel (e.g. Security without admin) or a read
            # failure: skip this channel, keep collecting the rest.
            continue

    return collected
