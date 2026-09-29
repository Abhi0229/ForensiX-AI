"""Runtime state + persisted high-water-mark store for the ForensiX AI runtime.

Two concerns live here, deliberately separate:

* ``RuntimeState`` -- live, in-memory counters describing what the runtime is
  doing *right now* (per-collector health, queue depth, totals, last analysis).
  It is mutated from several threads, so every read/update takes one lock and
  ``snapshot()`` returns a plain dict the API can serialize. Nothing here is
  persisted; it resets on restart, which is correct for "current status".

* ``StateStore`` -- the small, durable high-water-mark cursors that let the
  pollers resume without re-inserting everything after a restart. This is the
  only runtime state written to disk. It is a JSON file (NOT a DB table and NOT
  a second database -- the event schema is deliberately untouched), written
  atomically (temp file + ``os.replace``) under a lock. A missing or corrupt
  file yields a fresh store rather than crashing the runtime.

Privacy: the store never records URLs, paths, users, or descriptions. Browser
cursors keep only a timestamp plus short ``sha256(url)[:16]`` prefixes to
disambiguate visits sharing the exact same last_visit_time.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from backend.database import db

logger = logging.getLogger("forensix.runtime")

STATE_VERSION = 1
STATE_PATH_ENV = "FORENSIX_RUNTIME_STATE_PATH"

# Cap the per-timestamp browser boundary set so the state file can't grow
# without bound when many visits share one last_visit_time.
MAX_BOUNDARY_KEYS = 256


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# Collector health states surfaced verbatim in the status payload.
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"
STATE_DISABLED = "disabled"
STATE_UNAVAILABLE = "unavailable"


@dataclass
class CollectorState:
    """Live health of a single collector. Counters only -- no event content."""

    name: str
    state: str = STATE_STOPPED
    last_collection_time: Optional[str] = None
    last_event_time: Optional[str] = None
    events_processed: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    dropped_events: int = 0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self.state,
            "last_collection_time": self.last_collection_time,
            "last_event_time": self.last_event_time,
            "events_processed": self.events_processed,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "dropped_events": self.dropped_events,
        }


class RuntimeState:
    """Thread-safe container for live runtime status.

    All mutation goes through methods that take ``self._lock`` so concurrent
    collector threads never corrupt a counter or read a half-updated dict.
    """

    def __init__(self, collector_names: List[str]):
        self._lock = threading.Lock()
        self._running = False
        self._start_time: Optional[datetime] = None
        self._collectors: Dict[str, CollectorState] = {
            name: CollectorState(name=name) for name in collector_names
        }
        self._events_ingested = 0
        self._events_inserted = 0
        self._batches = 0
        self._queue_dropped_total = 0
        self._analysis = {
            "last_run_time": None,
            "last_duration_seconds": None,
            "candidate_incidents": None,
            "anomalies": None,
            "runs": 0,
            "error_count": 0,
            "last_error": None,
        }

    # ---- lifecycle -----------------------------------------------------
    def mark_started(self) -> None:
        with self._lock:
            self._running = True
            self._start_time = datetime.now(timezone.utc)

    def mark_stopped(self) -> None:
        with self._lock:
            self._running = False

    # ---- collector helpers --------------------------------------------
    def set_collector_state(self, name: str, state: str, *,
                            error: Optional[str] = None) -> None:
        """Set a collector's health state. ``error`` sets last_error WITHOUT
        bumping error_count (that is reserved for record_collector_error)."""
        with self._lock:
            cs = self._collectors.get(name)
            if cs is None:
                return
            cs.state = state
            if error is not None:
                cs.last_error = error


    def record_collection(self, name: str, *, events: int = 0,
                          last_event_time: Optional[str] = None) -> None:
        with self._lock:
            cs = self._collectors.get(name)
            if cs is None:
                return
            cs.last_collection_time = _utcnow_iso()
            cs.events_processed += events
            if last_event_time is not None:
                cs.last_event_time = last_event_time

    def record_collector_error(self, name: str, message: str) -> None:
        with self._lock:
            cs = self._collectors.get(name)
            if cs is None:
                return
            cs.state = STATE_ERROR
            cs.error_count += 1
            cs.last_error = message

    def record_dropped(self, name: str, count: int = 1) -> None:
        with self._lock:
            cs = self._collectors.get(name)
            if cs is not None:
                cs.dropped_events += count
            self._queue_dropped_total += count

    # ---- totals --------------------------------------------------------
    def record_batch(self, *, ingested: int = 0, inserted: int = 0) -> None:
        with self._lock:
            self._events_ingested += ingested
            self._events_inserted += inserted
            self._batches += 1

    # ---- analysis ------------------------------------------------------
    def record_analysis(self, *, duration: float, candidate_incidents: int,
                        anomalies: int) -> None:
        with self._lock:
            self._analysis["last_run_time"] = _utcnow_iso()
            self._analysis["last_duration_seconds"] = duration
            self._analysis["candidate_incidents"] = candidate_incidents
            self._analysis["anomalies"] = anomalies
            self._analysis["runs"] += 1

    def record_analysis_error(self, message: str) -> None:
        with self._lock:
            self._analysis["error_count"] += 1
            self._analysis["last_error"] = message


    # ---- snapshot ------------------------------------------------------
    def snapshot(self, *, queue_size: int, queue_maxsize: int,
                 state_file) -> dict:
        with self._lock:
            uptime = 0.0
            start_iso = None
            if self._start_time is not None:
                start_iso = self._start_time.replace(microsecond=0).isoformat()
                uptime = (datetime.now(timezone.utc)
                          - self._start_time).total_seconds()
            return {
                "running": self._running,
                "start_time": start_iso,
                "uptime_seconds": round(uptime, 3),
                "collectors": [cs.as_dict() for cs in self._collectors.values()],
                "queue": {
                    "size": queue_size,
                    "maxsize": queue_maxsize,
                    "dropped_total": self._queue_dropped_total,
                },
                "totals": {
                    "events_ingested": self._events_ingested,
                    "events_inserted": self._events_inserted,
                    "batches": self._batches,
                },
                "analysis": dict(self._analysis),
                "state_file": str(state_file),
            }


def _default_state_path() -> Path:
    """Resolve the state-file path.

    Deriving from ``db.DB_PATH`` (rather than a fixed location) means a test
    that monkeypatches ``DB_PATH`` into a ``tmp_path`` automatically carries the
    state file with it, so tests never touch real runtime state.
    """
    override = os.environ.get(STATE_PATH_ENV)
    if override:
        return Path(override)
    return Path(db.DB_PATH).with_name("runtime_state.json")


def _empty_state() -> dict:
    return {
        "version": STATE_VERSION,
        "updated_at": None,
        "windows": {"channels": {}},
        "defender": {"record_number": 0},
        "browser": {},
    }


class StateStore:
    """Durable JSON high-water-mark cursors. Atomic writes, corrupt-safe load.

    Only the pollers (Windows/Defender/Browser) use this; each collector owns
    its own keys, so there is no cross-thread contention on the same value. The
    lock guards the dict during the JSON serialization inside ``save()``.
    """

    def __init__(self, path: Optional[Path] = None):
        self._path = Path(path) if path is not None else _default_state_path()
        self._lock = threading.Lock()
        self._data = _empty_state()

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> None:
        with self._lock:
            try:
                text = self._path.read_text(encoding="utf-8")
                data = json.loads(text)
                if not isinstance(data, dict):
                    raise ValueError("state root is not an object")
                self._data = self._migrate(data)
            except FileNotFoundError:
                self._data = _empty_state()
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning(
                    "[ForensiX Runtime] state file unreadable (%s); starting fresh",
                    type(exc).__name__,
                )
                self._data = _empty_state()

    @staticmethod
    def _migrate(data: dict) -> dict:
        base = _empty_state()
        for key in base:
            if key in data:
                base[key] = data[key]
        if not isinstance(base.get("windows"), dict):
            base["windows"] = {"channels": {}}
        if not isinstance(base["windows"].get("channels"), dict):
            base["windows"]["channels"] = {}
        if not isinstance(base.get("defender"), dict):
            base["defender"] = {"record_number": 0}
        base["defender"].setdefault("record_number", 0)
        if not isinstance(base.get("browser"), dict):
            base["browser"] = {}
        return base


    def save(self) -> None:
        """Persist atomically: write a temp file then ``os.replace`` it in."""
        with self._lock:
            self._data["updated_at"] = _utcnow_iso()
            self._data["version"] = STATE_VERSION
            payload = json.dumps(self._data, indent=2, sort_keys=True)
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self._path.with_suffix(self._path.suffix + ".tmp")
                tmp.write_text(payload, encoding="utf-8")
                os.replace(tmp, self._path)
            except OSError as exc:
                logger.warning(
                    "[ForensiX Runtime] could not persist state (%s)",
                    type(exc).__name__,
                )

    # ---- windows (per-channel RecordNumber) ---------------------------
    def get_windows_hwm(self, channel: str) -> int:
        with self._lock:
            return int(self._data["windows"]["channels"].get(channel, 0))

    def set_windows_hwm(self, channel: str, value: int) -> None:
        with self._lock:
            self._data["windows"]["channels"][channel] = int(value)

    # ---- defender (single-channel EventRecordID) ----------------------
    def get_defender_hwm(self) -> int:
        with self._lock:
            return int(self._data["defender"].get("record_number", 0))

    def set_defender_hwm(self, value: int) -> None:
        with self._lock:
            self._data["defender"]["record_number"] = int(value)

    # ---- browser (per browser::profile last_visit_time + boundary) ----
    def get_browser_hwm(self, key: str):
        """Return ``(last_visit_time_iso_or_None, set_of_url_key_prefixes)``."""
        with self._lock:
            entry = self._data["browser"].get(key) or {}
            keys = entry.get("boundary_keys", [])
            return entry.get("last_visit_time"), set(keys)

    def set_browser_hwm(self, key: str, last_visit_time: Optional[str],
                        boundary_keys) -> None:
        with self._lock:
            trimmed = list(boundary_keys)[:MAX_BOUNDARY_KEYS]
            self._data["browser"][key] = {
                "last_visit_time": last_visit_time,
                "boundary_keys": trimmed,
            }

    def as_dict(self) -> dict:
        """A copy of the persisted cursor data (for tests/inspection)."""
        with self._lock:
            return json.loads(json.dumps(self._data))

