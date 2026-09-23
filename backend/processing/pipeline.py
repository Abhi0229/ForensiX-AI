"""Integrated event processing pipeline for ForensiX AI.

This is the single integration point that connects the independent collectors
to the database. The collectors themselves stay database-free; the pipeline
receives their events, ensures they are normalized, validates them, optionally
removes exact duplicates, orders them chronologically, and stores them via the
existing ``backend.database.db`` layer.

    Collectors (Windows / Defender / FileSystem / USB / Browser)
            |
    raw dicts or Event objects
            |
    EventPipeline.process()
            |
        normalize (backend.processing.normalizer)
            |
        validate required fields
            |
        optional exact-duplicate removal (opt-in)
            |
        deterministic chronological ordering
            |
        insert_event (backend.database.db)
            |
        SQLite database

Design rules honored here:
* Collection logic lives in the collectors; normalization lives in
  ``normalizer.py``; database access lives in ``db.py``. This module only
  orchestrates -- it never re-implements any of them.
* Importing this module has no side effects: it never starts a real-time
  watcher and never touches the database on import.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable, List, Optional, Union

from backend.database import db as _db
from backend.database.models import Event
from backend.processing.normalizer import normalize_event

# The fields every event must carry to be storable. Optional Event fields
# (user, device, file_path, metadata) may legitimately be empty and are never
# required here.
REQUIRED_FIELDS = ("timestamp", "source", "event_type", "description")

# An input item is either an already-built Event or a raw source dict.
RawOrEvent = Union[Event, dict]


@dataclass
class ProcessingResult:
    """Statistics describing one ``process()`` run.

    * ``received``   -- input items seen
    * ``normalized`` -- items successfully turned into (or already were) Events
    * ``inserted``   -- events written to the database
    * ``skipped``    -- events dropped by validation (missing required field)
    * ``duplicates`` -- events dropped by exact-duplicate removal
    * ``errors``     -- normalization or insertion failures
    * ``error_details`` -- human-readable notes for each error/skip

    Invariant: ``received == normalized + <normalization errors>`` and
    ``normalized == inserted + skipped + duplicates + <insertion errors>``.
    """

    received: int = 0
    normalized: int = 0
    inserted: int = 0
    skipped: int = 0
    duplicates: int = 0
    errors: int = 0
    error_details: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "received": self.received,
            "normalized": self.normalized,
            "inserted": self.inserted,
            "skipped": self.skipped,
            "duplicates": self.duplicates,
            "errors": self.errors,
        }


class EventPipeline:
    """Orchestrates normalize -> validate -> dedup -> order -> store.

    Args:
        deduplicate: When True, drop events whose full fingerprint (every
            Event field) exactly matches an earlier event in the same batch.
            Defaults to False -- see the module/dedup docs for why exact match
            only, and why it is opt-in.
        inserter: Optional callable used to persist one Event. Defaults to the
            existing ``backend.database.db.insert_event``. Injectable so tests
            can exercise insertion-failure handling without a real database.
    """

    def __init__(self, *, deduplicate: bool = False,
                 inserter: Optional[Callable[[Event], None]] = None):
        self.deduplicate = deduplicate
        self._inserter = inserter

    # -- helpers -----------------------------------------------------------

    def _insert(self, event: Event) -> None:
        """Persist one event via the injected inserter or the real DB layer.

        Resolved at call time so monkeypatching ``db.insert_event`` (or the
        module's ``DB_PATH``) in tests is always honored.
        """
        if self._inserter is not None:
            self._inserter(event)
        else:
            _db.insert_event(event)

    @staticmethod
    def _coerce(item: RawOrEvent) -> Event:
        """Return an Event, normalizing a raw dict through the normalizer.

        Raises TypeError/ValueError for unusable input; the caller counts it
        as an error rather than crashing the batch.
        """
        if isinstance(item, Event):
            return item
        if isinstance(item, dict):
            return normalize_event(item)
        raise TypeError(
            f"pipeline input must be Event or dict, got {type(item).__name__}"
        )

    @staticmethod
    def _validation_error(event: Event) -> Optional[str]:
        """Return a reason string if the event is invalid, else None."""
        if not isinstance(event.timestamp, datetime):
            return "timestamp is missing or not a datetime"
        for field_name in ("source", "event_type", "description"):
            value = getattr(event, field_name, None)
            if not isinstance(value, str) or not value.strip():
                return f"{field_name} is required but empty"
        return None

    @staticmethod
    def _fingerprint(event: Event) -> tuple:
        """Deterministic identity across *every* Event field.

        Two events collapse only when they are identical in timestamp, source,
        event_type, description, user, device, file_path AND metadata -- so a
        shared timestamp or shared description alone never counts as a
        duplicate.
        """
        return (
            event.timestamp.isoformat(),
            event.source,
            event.event_type,
            event.description,
            event.user,
            event.device,
            event.file_path,
            event.metadata,
        )

    # -- main entry point --------------------------------------------------

    def process(self, events: Iterable[RawOrEvent]) -> ProcessingResult:
        """Normalize, validate, (optionally) dedup, order, and store events.

        A single malformed item never aborts the batch: it is recorded and
        processing continues. Event timestamps are never modified.
        """
        result = ProcessingResult()
        valid: List[Event] = []

        for item in events:
            result.received += 1
            try:
                event = self._coerce(item)
            except Exception as exc:  # normalization / type failure
                result.errors += 1
                result.error_details.append(f"normalize: {exc}")
                continue
            result.normalized += 1

            reason = self._validation_error(event)
            if reason is not None:
                result.skipped += 1
                result.error_details.append(f"validation: {reason}")
                continue
            valid.append(event)

        if self.deduplicate:
            seen = set()
            deduped: List[Event] = []
            for event in valid:
                fingerprint = self._fingerprint(event)
                if fingerprint in seen:
                    result.duplicates += 1
                    continue
                seen.add(fingerprint)
                deduped.append(event)
            valid = deduped

        # Stable sort: chronological, ties keep original batch order. This
        # orders storage deterministically without ever altering a timestamp.
        valid.sort(key=lambda e: e.timestamp)

        for event in valid:
            try:
                self._insert(event)
            except Exception as exc:  # DB failure -- surfaced, not swallowed
                result.errors += 1
                result.error_details.append(f"insert: {exc}")
                continue
            result.inserted += 1

        return result


def process_events(events: Iterable[RawOrEvent], *, deduplicate: bool = False,
                   inserter: Optional[Callable[[Event], None]] = None) -> ProcessingResult:
    """Convenience one-shot wrapper around :class:`EventPipeline`."""
    return EventPipeline(deduplicate=deduplicate, inserter=inserter).process(events)


# --- Collector orchestration -----------------------------------------------
# Batch collectors only. Live watchers (FileActivityCollector, USBEventWatcher)
# are NOT auto-started here -- that is left under explicit caller control; use
# ``drain_collector`` to feed their buffered events into a pipeline.

def collect_and_process(sources: Optional[Iterable[str]] = None, *,
                        max_events: int = 100, deduplicate: bool = False,
                        pipeline: Optional[EventPipeline] = None) -> ProcessingResult:
    """Run the bounded batch collectors and store their events.

    Collectors are imported lazily so importing this module never pulls in
    Windows-only dependencies. Each collector is isolated: one failing (or
    returning nothing off-Windows) never stops the others.

    Args:
        sources: subset of {"windows", "defender", "usb", "browser"}.
            Defaults to all of them. File Activity is live, not batch, and is
            intentionally excluded -- integrate it via ``drain_collector``.
    """
    from backend.collectors.windows_events import collect_windows_events
    from backend.collectors.defender import collect_defender_events
    from backend.collectors.usb import collect_usb_events
    from backend.collectors.browser import collect_browser_history

    batch = {
        "windows": lambda: collect_windows_events(max_events=max_events),
        "defender": lambda: collect_defender_events(max_events=max_events),
        "usb": lambda: collect_usb_events(),
        "browser": lambda: collect_browser_history(max_events=max_events),
    }
    if sources is None:
        sources = tuple(batch)

    pipeline = pipeline or EventPipeline(deduplicate=deduplicate)

    events: List[Event] = []
    for name in sources:
        collector = batch.get(str(name).lower())
        if collector is None:
            continue
        try:
            events.extend(collector())
        except Exception:
            # A collector failing must never stop the pipeline run.
            continue
    return pipeline.process(events)


def drain_collector(collector, *, pipeline: Optional[EventPipeline] = None,
                    deduplicate: bool = False) -> ProcessingResult:
    """Process the events currently buffered by a live collector.

    Works with any object exposing an ``events`` snapshot property (e.g.
    ``FileActivityCollector`` or ``USBEventWatcher``). The caller owns the
    watcher's start/stop lifecycle; this only reads and stores what has been
    observed so far, so it can never hang waiting for new events.
    """
    pipeline = pipeline or EventPipeline(deduplicate=deduplicate)
    return pipeline.process(list(getattr(collector, "events", []) or []))
