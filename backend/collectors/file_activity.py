"""File-system activity collector for ForensiX AI.

Observes create / modify / delete / rename activity under a directory using
the Watchdog library and converts each event into the common ForensiX
``Event`` structure via the shared normalizer. It never writes to the
database.

    Windows File System
            |
    Watchdog Observer + handler
            |
    _build_raw_event()      ->  raw event dict          (pure, testable)
            |
    normalize_event()        ->  common Event object
            |
    (delivered via callback / collected list; caller stores it)

Unlike the Windows Event Log / Defender collectors (batch reads of historical
records), file activity is a live stream, so this collector is built around a
start/stop observer with a thread-safe collected-events buffer. The mapping
logic is a pure function, unit-testable without an actual observer.

This is a strictly passive forensic monitor: it only observes. It never opens,
executes, modifies, moves, deletes, or quarantines any monitored file, and it
treats every path and filename purely as data.
"""

import os
import socket
import threading
import time
from datetime import datetime
from typing import Callable, List, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from backend.database.models import Event
from backend.processing.normalizer import normalize_event

# ForensiX source label for every record this collector emits.
SOURCE = "FileSystem"

# Watchdog event_type -> ForensiX event_type. Types not listed (e.g. the
# "opened"/"closed" events some platforms emit) are ignored.
EVENT_TYPE_MAP = {
    "created": "FILE_CREATED",
    "modified": "FILE_MODIFIED",
    "deleted": "FILE_DELETED",
    "moved": "FILE_RENAMED",
}


def _device_name() -> str:
    """Return the local hostname as the device/computer identifier."""
    try:
        return socket.gethostname()
    except Exception:
        return ""


def _build_raw_event(event, device: Optional[str] = None) -> Optional[dict]:
    """Map a single watchdog event to a raw ForensiX event dict.

    Pure and side-effect free: reads attributes off ``event`` with safe
    getattr defaults, so a lightweight stand-in works in tests without an
    observer. Returns None for watchdog event types ForensiX does not track.

    Args:
        event: A watchdog filesystem event (has event_type, src_path,
            optionally dest_path, is_directory).
        device: Device/computer name; defaults to the local hostname.

    Returns:
        A dict suitable for ``normalize_event(..., source=SOURCE)``, or None.
    """
    event_type = EVENT_TYPE_MAP.get(getattr(event, "event_type", None))
    if event_type is None:
        return None

    if device is None:
        device = _device_name()

    src_path = getattr(event, "src_path", "") or ""
    dest_path = getattr(event, "dest_path", "") or ""
    is_directory = bool(getattr(event, "is_directory", False))
    kind = "Directory" if is_directory else "File"

    metadata = {
        "src_path": src_path,
        "is_directory": is_directory,
    }

    if event_type == "FILE_RENAMED":
        # Renames/moves: file_path is the new location; both ends preserved.
        file_path = dest_path or src_path
        metadata["old_path"] = src_path
        metadata["new_path"] = dest_path
        description = f"{kind} renamed from {src_path} to {dest_path}"
    else:
        file_path = src_path
        verb = {
            "FILE_CREATED": "created",
            "FILE_MODIFIED": "modified",
            "FILE_DELETED": "deleted",
        }[event_type]
        description = f"{kind} {verb}: {src_path}"

    return {
        "timestamp": datetime.now(),
        "source": SOURCE,
        "event_type": event_type,
        "description": description,
        # Watchdog exposes no user; leave empty rather than guessing.
        "user": "",
        "device": device,
        "file_path": file_path,
        "metadata": metadata,
    }


def event_to_forensix(event, device: Optional[str] = None) -> Optional[Event]:
    """Convert a watchdog event into a normalized ForensiX Event, or None."""
    raw = _build_raw_event(event, device=device)
    if raw is None:
        return None
    return normalize_event(raw, source=SOURCE)


class _ForensiXFileEventHandler(FileSystemEventHandler):
    """Watchdog handler that normalizes events and hands them to the collector."""

    def __init__(self, on_event: Callable[[Event], None], device: str):
        super().__init__()
        self._on_event = on_event
        self._device = device

    def on_any_event(self, event) -> None:  # noqa: D401 - watchdog hook
        # A single malformed event must never crash the observer thread.
        try:
            forensix_event = event_to_forensix(event, device=self._device)
        except Exception:
            return
        if forensix_event is not None:
            self._on_event(forensix_event)


class FileActivityCollector:
    """Start/stop file-activity monitor for a single directory tree.

    Collected events are buffered in a thread-safe list and, optionally,
    pushed to an ``on_event`` callback as they arrive. The collector never
    persists anything; storing events is the caller's responsibility.
    """

    def __init__(self, path: str, recursive: bool = True,
                 on_event: Optional[Callable[[Event], None]] = None):
        self.path = path
        self.recursive = recursive
        self._user_callback = on_event
        self._device = _device_name()

        self._observer: Optional[Observer] = None
        self._events: List[Event] = []
        self._condition = threading.Condition()

    def _handle(self, event: Event) -> None:
        with self._condition:
            self._events.append(event)
            self._condition.notify_all()
        if self._user_callback is not None:
            try:
                self._user_callback(event)
            except Exception:
                # A failing user callback must not break monitoring.
                pass

    def start(self) -> "FileActivityCollector":
        """Begin monitoring. Raises ValueError for a missing/invalid path."""
        if not self.path or not os.path.isdir(self.path):
            raise ValueError(f"Monitored path does not exist: {self.path!r}")

        handler = _ForensiXFileEventHandler(self._handle, self._device)
        observer = Observer()
        try:
            observer.schedule(handler, self.path, recursive=self.recursive)
            observer.start()
        except Exception as exc:  # startup failure: clean up, re-raise clearly
            try:
                observer.stop()
            except Exception:
                pass
            raise RuntimeError(f"Failed to start file monitor: {exc}") from exc

        self._observer = observer
        return self

    def stop(self, timeout: float = 5.0) -> None:
        """Stop monitoring and join the observer thread. Safe to call twice."""
        observer = self._observer
        if observer is None:
            return
        try:
            observer.stop()
            observer.join(timeout)
        except Exception:
            pass
        finally:
            self._observer = None

    @property
    def events(self) -> List[Event]:
        """A snapshot copy of the events collected so far."""
        with self._condition:
            return list(self._events)

    def wait_for(self, predicate: Callable[[Event], bool],
                 timeout: float = 5.0) -> Optional[Event]:
        """Block until a collected event matches ``predicate`` or timeout.

        Returns the matching Event, or None if the timeout elapses. Uses a
        condition variable rather than fixed sleeps so tests stay fast and
        deterministic.
        """
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                for event in self._events:
                    if predicate(event):
                        return event
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)

    def wait_for_count(self, count: int, timeout: float = 5.0) -> bool:
        """Block until at least ``count`` events are collected or timeout."""
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self._events) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def __enter__(self) -> "FileActivityCollector":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


def collect_file_activity(path: str, duration: float = 2.0,
                          recursive: bool = True) -> List[Event]:
    """Monitor ``path`` for a bounded ``duration`` and return collected Events.

    Convenience wrapper around FileActivityCollector for one-shot collection.
    For long-running/application use, drive the collector directly with
    start()/stop() and an on_event callback instead.

    Args:
        path: Directory to monitor.
        duration: Seconds to observe before stopping (bounded so it never
            blocks indefinitely).
        recursive: Monitor subdirectories too.

    Returns:
        The list of normalized Event objects observed during the window.
    """
    collector = FileActivityCollector(path, recursive=recursive)
    collector.start()
    try:
        time.sleep(max(0.0, duration))
    finally:
        collector.stop()
    return collector.events
