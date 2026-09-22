"""Windows Defender collector for ForensiX AI.

Reads Microsoft Defender Antivirus security/threat events from the modern
Windows event channel and turns them into the common ForensiX ``Event``
structure via the shared normalizer. It never writes to the database.

    Windows Defender (Operational channel)
            |
    read_defender_events()   ->  raw event dicts        (Windows-only, pywin32)
            |
    _parse_event_xml()        ->  raw event dict         (pure, testable)
            |
    normalize_event()         ->  common Event object
            |
    (caller stores it)

Unlike the classic System/Application/Security logs (Phase 3), Defender logs
to a modern channel, so this collector uses the Windows Eventing 6 API
(EvtQuery/EvtNext/EvtRender) and parses the rendered event XML. The XML parser
is a pure function so it can be unit tested with sample data on any platform.
pywin32 is imported lazily; importing this module never fails off-Windows.

All event content is treated strictly as data. Nothing found inside an event
message, path, or field is ever executed.
"""

from datetime import datetime
from xml.etree import ElementTree as ET

from backend.processing.normalizer import normalize_event

# ForensiX source label for every record this collector emits.
SOURCE = "Defender"

# Modern Defender operational channel. Provider name appears inside the XML.
CHANNEL = "Microsoft-Windows-Windows Defender/Operational"

# Bound how much history we pull by default.
DEFAULT_MAX_EVENTS = 100

# Windows Eventing Level codes -> readable labels (fallback when a Defender
# "Severity Name" field is not present on the event).
LEVEL_LABELS = {
    1: "CRITICAL",
    2: "ERROR",
    3: "WARNING",
    4: "INFO",
    5: "VERBOSE",
}

# EventData field names that are useful enough to lift to top-level metadata
# keys for convenient querying later. The full EventData is always preserved
# under metadata["event_data"], so nothing is lost either way.
_LIFTED_FIELDS = {
    "Threat Name": "threat_name",
    "Threat ID": "threat_id",
    "Severity Name": "severity_name",
    "Category Name": "category_name",
    "Action Name": "action_name",
    "Action ID": "action_id",
    "Detection ID": "detection_id",
    "Process Name": "process_name",
    "Path": "path",
    "Detection User": "detection_user",
    "Origin Name": "origin_name",
    "Error Description": "error_description",
}


def _windows_modules():
    """Import pywin32 event modules lazily.

    Returns (win32evtlog, win32security, pywintypes) or raises RuntimeError
    with a clear message when pywin32 is unavailable (e.g. off-Windows).
    """
    try:
        import win32evtlog
        import win32security
        import pywintypes
        return win32evtlog, win32security, pywintypes
    except ImportError as exc:  # pragma: no cover - platform dependent
        raise RuntimeError(
            "Windows Defender collection requires pywin32 on Windows"
        ) from exc


def _parse_defender_time(text):
    """Parse a Defender SystemTime string into a naive datetime.

    Handles the trailing 'Z' and the 100-ns (7-digit) fractional seconds
    Windows emits, which stdlib parsers reject. Returns None when the value
    is missing or unparseable (the normalizer then defaults to now()).
    """
    if not text:
        return None
    value = text.strip()
    if value.endswith("Z"):
        value = value[:-1]
    # Truncate fractional seconds to 6 digits (microseconds).
    if "." in value:
        head, frac = value.split(".", 1)
        frac = "".join(ch for ch in frac if ch.isdigit())[:6]
        value = f"{head}.{frac}" if frac else head
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return None


def _text(element):
    """Return stripped text of an element, or None."""
    if element is None or element.text is None:
        return None
    text = element.text.strip()
    return text or None


def _parse_event_xml(xml_string):
    """Map a single rendered Defender event (XML string) to a raw event dict.

    Pure and side-effect free. Uses namespace-agnostic lookups so the event's
    default namespace does not need special handling. Returns a dict suitable
    for ``normalize_event(..., source=SOURCE)``.

    Raises:
        ValueError: If the XML cannot be parsed.
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed Defender event XML: {exc}") from exc

    system = root.find("{*}System")
    system = system if system is not None else ET.Element("empty")

    provider_el = system.find("{*}Provider")
    provider = provider_el.get("Name") if provider_el is not None else None

    event_id_text = _text(system.find("{*}EventID"))
    event_id = int(event_id_text) if event_id_text and event_id_text.isdigit() else event_id_text

    level_text = _text(system.find("{*}Level"))
    level = int(level_text) if level_text and level_text.isdigit() else None

    time_el = system.find("{*}TimeCreated")
    timestamp = _parse_defender_time(time_el.get("SystemTime") if time_el is not None else None)

    record_number = _text(system.find("{*}EventRecordID"))
    computer = _text(system.find("{*}Computer")) or ""

    security_el = system.find("{*}Security")
    user = security_el.get("UserID") if security_el is not None else None

    # Collect every EventData/Data field. Named fields keyed by their Name;
    # unnamed positional fields keyed as data_0, data_1, ...
    event_data = {}
    data_parent = root.find("{*}EventData")
    if data_parent is not None:
        for index, data_el in enumerate(data_parent.findall("{*}Data")):
            name = data_el.get("Name") or f"data_{index}"
            value = data_el.text.strip() if data_el.text else ""
            event_data[name] = value

    # Severity: prefer Defender's own severity label, else map from Level.
    severity = event_data.get("Severity Name") or LEVEL_LABELS.get(level, "INFO")

    # Build a description from real fields (never fabricated).
    threat = event_data.get("Threat Name")
    action = event_data.get("Action Name")
    path = event_data.get("Path")
    if threat:
        description = f"Windows Defender detected threat: {threat}"
        if action:
            description += f" (action: {action})"
        if path:
            description += f" [path: {path}]"
    else:
        description = f"Windows Defender event {event_id}"

    # Metadata: key identifiers, lifted convenience fields, and the full
    # EventData so no Defender-specific information is lost.
    metadata = {
        "provider": provider,
        "event_id": event_id,
        "channel": CHANNEL,
        "level": level,
        "record_number": record_number,
        "event_data": event_data,
    }
    for source_name, meta_key in _LIFTED_FIELDS.items():
        if event_data.get(source_name):
            metadata[meta_key] = event_data[source_name]
    metadata = {key: value for key, value in metadata.items() if value not in (None, "")}

    return {
        "timestamp": timestamp,
        "event_id": event_id,          # normalizer maps this to event_type
        "description": description,
        "severity": severity,
        "user": user or "",
        "device": computer,
        "file_path": path or "",       # Defender file path when present
        "metadata": metadata,
    }


def _resolve_sid(sid_string, win32security):
    """Best-effort upgrade of a SID string to DOMAIN\\user. Never raises."""
    if not sid_string or win32security is None:
        return sid_string or ""
    try:
        import pywintypes
        sid = pywintypes.SID(win32security.ConvertStringSidToSid(sid_string))
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{name}" if domain else name
    except Exception:
        return sid_string


def read_defender_events(channel=CHANNEL, max_events=DEFAULT_MAX_EVENTS, since=None):
    """Yield raw Defender event dicts from the operational channel.

    Reads newest-first and stops once ``max_events`` are yielded or a record
    older than ``since`` is reached. Windows-only; raises RuntimeError if
    pywin32 is unavailable and propagates a query error if the channel cannot
    be opened (callers handle that). Individual malformed events are skipped.
    """
    win32evtlog, win32security, pywintypes = _windows_modules()

    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    query_handle = win32evtlog.EvtQuery(channel, flags, "*")
    yielded = 0
    try:
        while max_events is None or yielded < max_events:
            try:
                event_handles = win32evtlog.EvtNext(query_handle, 10)
            except pywintypes.error as exc:
                # ERROR_NO_MORE_ITEMS (259): normal end of the log.
                if exc.winerror == 259:
                    break
                raise
            if not event_handles:
                break

            for event_handle in event_handles:
                if max_events is not None and yielded >= max_events:
                    return
                try:
                    xml_string = win32evtlog.EvtRender(
                        event_handle, win32evtlog.EvtRenderEventXml
                    )
                    raw = _parse_event_xml(xml_string)
                except Exception:
                    # One malformed/unreadable event must not stop the read.
                    continue
                finally:
                    try:
                        win32evtlog.EvtClose(event_handle)
                    except Exception:
                        pass

                when = raw.get("timestamp")
                if since is not None and isinstance(when, datetime) and when < since:
                    # Reverse direction is newest-first; everything older follows.
                    return

                raw["user"] = _resolve_sid(raw.get("user"), win32security)
                yielded += 1
                yield raw
    finally:
        try:
            win32evtlog.EvtClose(query_handle)
        except Exception:
            pass


def collect_defender_events(channel=CHANNEL, max_events=DEFAULT_MAX_EVENTS,
                            since=None, normalize=True):
    """Collect recent Windows Defender events as normalized ForensiX Events.

    Gracefully returns an empty list if the Defender channel is missing,
    inaccessible (permissions), or the service is unavailable. Records the
    normalizer rejects are skipped rather than aborting the whole collection.

    Args:
        channel: Defender channel name. Defaults to CHANNEL.
        max_events: Maximum records to read.
        since: Optional datetime lower bound.
        normalize: When True (default) return Event objects; when False return
            the raw event dicts (useful for debugging/inspection).

    Returns:
        A list of Event objects (or raw dicts when normalize=False).
    """
    collected = []
    try:
        for raw in read_defender_events(channel, max_events=max_events, since=since):
            if normalize:
                try:
                    collected.append(normalize_event(raw, source=SOURCE))
                except Exception:
                    continue
            else:
                collected.append(raw)
    except Exception:
        # Missing/inaccessible channel, unavailable service, pywin32 absent:
        # return whatever was collected so far (typically nothing).
        return collected

    return collected
