"""USB device collector for ForensiX AI.

Provides two distinct, clearly-labelled capabilities on Windows:

1. **Current device enumeration** (point-in-time) via WMI ``Win32_PnPEntity``:
   which USB devices are connected *right now*. This is NOT a history of past
   connections -- WMI does not expose that -- so it is represented honestly as
   the current state, emitted as ``USB_CONNECTED`` snapshot events.

2. **Real-time monitoring** via WMI instance-creation/deletion event queries
   (``__InstanceCreationEvent`` / ``__InstanceDeletionEvent`` over
   ``Win32_PnPEntity``): genuine ``USB_CONNECTED`` / ``USB_DISCONNECTED``
   events observed live while the watcher runs.

    Windows USB subsystem (WMI)
            |
    enumerate_usb_devices() / USBEventWatcher
            |
    _build_raw_event()      ->  raw event dict     (pure, testable)
            |
    normalize_event()        ->  common Event object
            |
    (caller stores it)

WMI is reached through ``win32com.client`` (part of pywin32, already a
dependency), so no extra package is required. COM is imported lazily; importing
this module never fails off-Windows. The mapping logic is a pure function,
unit-testable without WMI.

This collector is strictly passive: it never mounts devices, opens/copies/
executes/deletes files, or modifies device contents. USB data is treated only
as data.
"""

import re
import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional

from backend.processing.normalizer import normalize_event

# ForensiX source label for every record this collector emits.
SOURCE = "USB"

# Normalized event types.
EVENT_CONNECTED = "USB_CONNECTED"
EVENT_DISCONNECTED = "USB_DISCONNECTED"

# A normal insertion/removal is routine, not a security incident.
DEFAULT_SEVERITY = "INFO"

# WMI query selecting only USB-attached PnP entities.
_USB_PNP_QUERY = "SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%'"

# Extract Vendor ID / Product ID / serial-or-instance from a USB device id
# such as: USB\VID_048D&PID_C966\5&5DD469C&0&8
_VID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})")
_PID_RE = re.compile(r"PID_([0-9A-Fa-f]{4})")


def _parse_device_id(device_id: str) -> Dict[str, str]:
    """Pull vendor id, product id and the trailing instance/serial segment.

    Returns a dict with whatever could be parsed; missing pieces are simply
    absent rather than fabricated. The final ``\\``-separated segment of a USB
    device id is the device instance id, which for many storage devices is the
    hardware serial number (best-effort; not guaranteed).
    """
    parsed: Dict[str, str] = {}
    if not device_id:
        return parsed

    vid = _VID_RE.search(device_id)
    if vid:
        parsed["vendor_id"] = vid.group(1).upper()
    pid = _PID_RE.search(device_id)
    if pid:
        parsed["product_id"] = pid.group(1).upper()

    parts = device_id.split("\\")
    if len(parts) >= 3 and parts[-1]:
        parsed["instance_id"] = parts[-1]

    return parsed


def _clean(value) -> str:
    """Coerce a possibly-None WMI property to a stripped string."""
    if value is None:
        return ""
    return str(value).strip()


def _build_raw_event(device_info: dict, event_type: str = EVENT_CONNECTED,
                     device: Optional[str] = None,
                     observed: bool = False) -> dict:
    """Map a USB device-info dict to a raw ForensiX event dict.

    Pure and side-effect free. ``device_info`` uses plain string keys
    (name, device_id, manufacturer, description, status, ...), so tests can
    build one directly without WMI. Missing fields become empty strings, never
    invented values.

    Args:
        device_info: Extracted device properties.
        event_type: EVENT_CONNECTED or EVENT_DISCONNECTED.
        device: Computer/host name.
        observed: True for a live watcher event, False for a current-state
            enumeration snapshot. Recorded in metadata as ``capture``.

    Returns:
        A dict suitable for ``normalize_event(..., source=SOURCE)``.
    """
    name = _clean(device_info.get("name"))
    device_id = _clean(device_info.get("device_id") or device_info.get("pnp_device_id"))
    manufacturer = _clean(device_info.get("manufacturer"))
    description = _clean(device_info.get("description"))
    status = _clean(device_info.get("status"))

    ids = _parse_device_id(device_id)
    serial = _clean(device_info.get("serial_number")) or ids.get("instance_id", "")

    verb = "connected" if event_type == EVENT_CONNECTED else "disconnected"
    label = name or description or device_id or "Unknown USB device"
    event_description = f"USB device {verb}: {label}"

    metadata = {
        "device_name": name,
        "device_id": device_id,
        "pnp_device_id": device_id,
        "manufacturer": manufacturer,
        "description": description,
        "status": status,
        "serial_number": serial,
        "vendor_id": ids.get("vendor_id", ""),
        "product_id": ids.get("product_id", ""),
        # Honest provenance: a live-observed event vs a current-state snapshot.
        "capture": "realtime" if observed else "current_state",
    }
    metadata = {key: value for key, value in metadata.items() if value not in (None, "")}

    return {
        "timestamp": datetime.now(),
        "source": SOURCE,
        "event_type": event_type,
        "description": event_description,
        "severity": DEFAULT_SEVERITY,
        # WMI PnP entities do not carry an acting user; leave empty.
        "user": "",
        "device": device or "",
        # No file path for a device event.
        "file_path": "",
        "metadata": metadata,
    }


def device_to_forensix(device_info: dict, event_type: str = EVENT_CONNECTED,
                       device: Optional[str] = None, observed: bool = False):
    """Convert a device-info dict to a normalized ForensiX Event."""
    raw = _build_raw_event(device_info, event_type=event_type,
                           device=device, observed=observed)
    return normalize_event(raw, source=SOURCE)


def _com_modules():
    """Import pywin32 COM modules lazily.

    Returns (win32com.client, pythoncom) or raises RuntimeError with a clear
    message when unavailable. Importing this collector module never triggers
    this.
    """
    try:
        import win32com.client
        import pythoncom
        return win32com.client, pythoncom
    except ImportError as exc:  # pragma: no cover - platform dependent
        raise RuntimeError(
            "USB collection requires pywin32 (WMI via win32com) on Windows"
        ) from exc


def _extract_device_info(wmi_object) -> dict:
    """Read the properties we care about off a WMI Win32_PnPEntity object.

    Never raises for a missing property; a device that disappears mid-read
    simply yields empty values for whatever could not be fetched.
    """
    def prop(name):
        try:
            return getattr(wmi_object, name, None)
        except Exception:
            return None

    return {
        "name": prop("Name"),
        "device_id": prop("DeviceID"),
        "pnp_device_id": prop("PNPDeviceID"),
        "manufacturer": prop("Manufacturer"),
        "description": prop("Description"),
        "status": prop("Status"),
    }


def _hostname() -> str:
    import socket
    try:
        return socket.gethostname()
    except Exception:
        return ""


def enumerate_usb_devices(normalize: bool = True) -> list:
    """Enumerate USB devices currently connected (point-in-time snapshot).

    IMPORTANT: this reflects *current* device state, not a history of past
    connections -- WMI does not expose connection history. Each device is
    emitted as a ``USB_CONNECTED`` event tagged ``capture=current_state``.

    Gracefully returns an empty list if WMI is unavailable or the query fails.

    Args:
        normalize: When True (default) return Event objects; when False return
            the raw event dicts.

    Returns:
        A list of Event objects (or raw dicts when normalize=False).
    """
    try:
        win32com_client, pythoncom = _com_modules()
    except RuntimeError:
        return []

    host = _hostname()
    collected = []
    pythoncom.CoInitialize()
    try:
        wmi = win32com_client.GetObject("winmgmts:root\\cimv2")
        for wmi_object in wmi.ExecQuery(_USB_PNP_QUERY):
            try:
                info = _extract_device_info(wmi_object)
                raw = _build_raw_event(info, EVENT_CONNECTED, device=host, observed=False)
            except Exception:
                # A device disappearing mid-enumeration must not abort the rest.
                continue
            if normalize:
                try:
                    collected.append(normalize_event(raw, source=SOURCE))
                except Exception:
                    continue
            else:
                collected.append(raw)
    except Exception:
        # WMI unavailable / access denied / malformed results: return what we have.
        return collected
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass

    return collected


# Backwards-friendly alias matching the requested public API shape.
def collect_usb_events(normalize: bool = True) -> list:
    """Collect current USB device state as ForensiX Events.

    Thin wrapper over :func:`enumerate_usb_devices`. See its docstring for the
    important current-state (not historical) caveat.
    """
    return enumerate_usb_devices(normalize=normalize)


class USBEventWatcher:
    """Real-time USB connect/disconnect watcher using WMI event queries.

    Runs a background thread that polls WMI ``__InstanceCreationEvent`` /
    ``__InstanceDeletionEvent`` notifications for ``Win32_PnPEntity`` and pushes
    normalized ForensiX Events into a thread-safe buffer (and an optional
    callback). Events produced here are genuine live observations
    (``capture=realtime``), distinct from the current-state snapshot above.

    The watcher can be started and stopped cleanly; ``stop()`` is idempotent.
    If WMI/COM is unavailable, ``start()`` raises RuntimeError.
    """

    def __init__(self, on_event: Optional[Callable] = None,
                 poll_timeout_ms: int = 500):
        self._user_callback = on_event
        self._poll_timeout_ms = poll_timeout_ms
        self._device = _hostname()

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._events: List = []
        self._condition = threading.Condition()

    def _handle(self, event) -> None:
        with self._condition:
            self._events.append(event)
            self._condition.notify_all()
        if self._user_callback is not None:
            try:
                self._user_callback(event)
            except Exception:
                pass

    def _run(self) -> None:  # pragma: no cover - requires live WMI + hardware
        win32com_client, pythoncom = _com_modules()
        pythoncom.CoInitialize()
        try:
            wmi = win32com_client.GetObject("winmgmts:root\\cimv2")
            creation = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 "
                "WHERE TargetInstance ISA 'Win32_PnPEntity'"
            )
            deletion = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceDeletionEvent WITHIN 1 "
                "WHERE TargetInstance ISA 'Win32_PnPEntity'"
            )
            while not self._stop.is_set():
                for watcher, event_type in (
                    (creation, EVENT_CONNECTED),
                    (deletion, EVENT_DISCONNECTED),
                ):
                    try:
                        wmi_event = watcher.NextEvent(self._poll_timeout_ms)
                    except Exception:
                        # Timeout (no event within the window) or transient error.
                        continue
                    try:
                        target = wmi_event.TargetInstance
                        device_id = _clean(getattr(target, "PNPDeviceID", ""))
                        if not device_id.upper().startswith("USB"):
                            continue  # only USB PnP entities
                        info = _extract_device_info(target)
                        event = device_to_forensix(
                            info, event_type=event_type,
                            device=self._device, observed=True,
                        )
                    except Exception:
                        continue
                    self._handle(event)
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def start(self) -> "USBEventWatcher":
        """Start the background watcher thread. Raises if WMI is unavailable."""
        # Fail fast and clearly if COM/pywin32 is missing.
        _com_modules()
        if self._thread is not None:
            return self
        self._stop.clear()
        thread = threading.Thread(target=self._run, name="USBEventWatcher", daemon=True)
        thread.start()
        self._thread = thread
        return self

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the watcher to stop and join its thread. Safe to call twice."""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
        self._thread = None

    @property
    def events(self) -> list:
        """A snapshot copy of the events observed so far."""
        with self._condition:
            return list(self._events)

    def wait_for_count(self, count: int, timeout: float = 5.0) -> bool:
        """Block until at least ``count`` events are observed or timeout."""
        import time
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self._events) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def __enter__(self) -> "USBEventWatcher":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
