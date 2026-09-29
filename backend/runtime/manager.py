"""Runtime Manager / Collector Orchestrator for ForensiX AI.

Turns the existing one-shot collectors into a continuously running endpoint
agent. The whole design rests on one invariant: **there is exactly one writer**.

    File / USB (real-time, on_event)  --.
    Windows / Defender / Browser       >-- queue.Queue --> consumer --> pipeline.process() --> DB
    (pollers, incremental)            --'   (buffer)      (SOLE WRITER)   (existing)     (hash chain)

Only ``_consume_loop`` ever calls ``pipeline.process()``. That guarantees a
single, linear SHA-256 hash chain (``process()`` seeds ``previous_hash`` from
the chain tip once per call), eliminates SQLite lock contention, never blocks
the OS observer threads (real-time enqueues are ``put_nowait``), and coalesces
bursts into one ``process()`` call.

Duplicate prevention is the runtime's own concern (the pipeline only dedups
within a single call). Pollers keep restart-surviving high-water marks in a
JSON state file (see ``state.StateStore``): Windows/Defender by RecordNumber,
Browser by last_visit_time + a bounded hashed-URL boundary set. Real-time
collectors need no cursor -- ``on_event`` delivers each OS event exactly once.

Nothing here rewrites a collector, the pipeline, the DB, or the schema; it only
composes their existing public APIs. No data is ever deleted, executed, or sent
anywhere; the only network call is the additive local Ollama status probe.
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, List, Optional

from backend.database import db
from backend.processing.pipeline import EventPipeline, ProcessingResult
from backend.runtime.probe import probe_ollama
from backend.runtime.state import (
    RuntimeState,
    StateStore,
    STATE_DISABLED,
    STATE_ERROR,
    STATE_RUNNING,
    STATE_STOPPED,
    STATE_UNAVAILABLE,
)

logger = logging.getLogger("forensix.runtime")

# Poller reads use ``since = last_poll - OVERLAP`` only to cap read volume; the
# record-number / timestamp high-water mark is the authoritative dedup key.
OVERLAP_SECONDS = 5.0

# Collector names used both as status keys and IngestItem.source labels.
COLLECTOR_NAMES = ("windows", "defender", "browser", "usb", "file")

# Sentinel enqueued by stop() to wake the consumer for a clean drain + exit.
_SHUTDOWN = object()

def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_csv(name: str, default: tuple) -> tuple:
    val = os.environ.get(name)
    if val is None:
        return default
    parts = tuple(p.strip() for p in val.split(",") if p.strip())
    return parts or default


def _url_key(url: str) -> str:
    """Short, privacy-preserving fingerprint of a URL (never the URL itself)."""
    return hashlib.sha256((url or "").encode("utf-8", "replace")).hexdigest()[:16]


def _parse_iso(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None


def _err(exc: BaseException) -> str:
    """Sanitized error label: exception type ONLY.

    Exception messages can embed file paths, URLs or user names; the status
    payload and logs must never leak those (Section 17), so we surface the type
    and nothing else.
    """
    return type(exc).__name__


@dataclass
class IngestItem:
    """One unit of work handed to the sole-writer consumer.

    ``events`` are already-normalized ``Event`` objects (the pollers normalize
    with the correct source before enqueuing; the real-time collectors deliver
    Event objects via ``on_event``). ``on_committed`` -- present only for poller
    items -- runs after a successful ``process()`` to advance + persist that
    collector's high-water mark. It is deliberately NOT called on failure, so a
    failed batch is simply re-read next poll (at-least-once).
    """

    source: str
    events: list
    on_committed: Optional[Callable[[ProcessingResult], None]] = None


@dataclass
class RuntimeConfig:
    """All runtime knobs, every one overridable via a ``FORENSIX_*`` env var."""

    enabled: bool = True
    collectors: frozenset = field(
        default_factory=lambda: frozenset(COLLECTOR_NAMES))
    file_paths: tuple = ()
    file_recursive: bool = True
    windows_interval: float = 60.0
    defender_interval: float = 60.0
    browser_interval: float = 300.0
    analysis_interval: float = 300.0
    windows_channels: tuple = ("System", "Application", "Security")
    browsers: tuple = ("chrome", "edge", "firefox")
    max_batch: int = 200
    queue_maxsize: int = 10000
    initial_backfill: int = 100
    analysis_limit: int = 5000

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        collectors = _env_csv("FORENSIX_RUNTIME_COLLECTORS", COLLECTOR_NAMES)
        return cls(
            enabled=_env_bool("FORENSIX_RUNTIME_ENABLED", True),
            collectors=frozenset(c.lower() for c in collectors),
            file_paths=_env_csv("FORENSIX_RUNTIME_FILE_PATH", ()),
            file_recursive=_env_bool("FORENSIX_RUNTIME_FILE_RECURSIVE", True),
            windows_interval=_env_float("FORENSIX_RUNTIME_WINDOWS_INTERVAL", 60.0),
            defender_interval=_env_float("FORENSIX_RUNTIME_DEFENDER_INTERVAL", 60.0),
            browser_interval=_env_float("FORENSIX_RUNTIME_BROWSER_INTERVAL", 300.0),
            analysis_interval=_env_float("FORENSIX_RUNTIME_ANALYSIS_INTERVAL", 300.0),
            windows_channels=_env_csv("FORENSIX_RUNTIME_WINDOWS_CHANNELS",
                                      ("System", "Application", "Security")),
            browsers=_env_csv("FORENSIX_RUNTIME_BROWSERS",
                              ("chrome", "edge", "firefox")),
            max_batch=_env_int("FORENSIX_RUNTIME_MAX_BATCH", 200),
            queue_maxsize=_env_int("FORENSIX_RUNTIME_QUEUE_MAXSIZE", 10000),
            initial_backfill=_env_int("FORENSIX_RUNTIME_INITIAL_BACKFILL", 100),
            analysis_limit=_env_int("FORENSIX_RUNTIME_ANALYSIS_LIMIT", 5000),
        )


class RuntimeManager:
    """Starts and supervises the collectors; owns the single writer thread.

    All collaborators are injectable so tests can drive the manager with fakes
    (a spy pipeline, a tmp-path state store) without any OS collector or DB.
    """

    def __init__(self, *, config: Optional[RuntimeConfig] = None,
                 pipeline: Optional[EventPipeline] = None,
                 state: Optional[RuntimeState] = None,
                 store: Optional[StateStore] = None):
        self.config = config or RuntimeConfig.from_env()
        self._pipeline = pipeline
        self._store = store or StateStore()
        self._state = state or RuntimeState(list(COLLECTOR_NAMES))
        self._queue: "queue.Queue" = queue.Queue(maxsize=self.config.queue_maxsize)
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._file_collectors: list = []
        self._usb_watcher = None
        self._started = False
        self._lifecycle_lock = threading.Lock()
        self._last_drop_warn = 0.0

    # ---- lifecycle -----------------------------------------------------
    def start(self) -> "RuntimeManager":
        """Idempotent start: spawn the consumer, pollers, analysis + collectors."""
        with self._lifecycle_lock:
            if self._started:
                return self
            self._stop.clear()
            self._store.load()
            if self._pipeline is None:
                # Defaults: no in-batch dedup (real activity may legitimately
                # repeat) and the hash chain ON. Reuses the existing pipeline.
                self._pipeline = EventPipeline()
            self._state.mark_started()

            # The sole writer is always running.
            self._spawn(self._consume_loop, "fx-consumer")

            enabled = self.config.collectors
            self._start_poller("windows", self._windows_poll_loop, "fx-windows")
            self._start_poller("defender", self._defender_poll_loop, "fx-defender")
            self._start_poller("browser", self._browser_poll_loop, "fx-browser")

            # Deterministic periodic analysis worker (no per-event LLM).
            self._spawn(self._analysis_loop, "fx-analysis")

            if "usb" in enabled:
                self._start_usb()
            else:
                self._state.set_collector_state("usb", STATE_DISABLED)
            if "file" in enabled:
                self._start_file()
            else:
                self._state.set_collector_state("file", STATE_DISABLED)

            self._started = True
            logger.info("[ForensiX Runtime] started (collectors=%s)",
                        sorted(enabled))
            return self

    def _spawn(self, target: Callable, name: str) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _start_poller(self, name: str, loop: Callable, thread_name: str) -> None:
        if name in self.config.collectors:
            self._spawn(loop, thread_name)
        else:
            self._state.set_collector_state(name, STATE_DISABLED)


    def _start_file(self) -> None:
        from backend.collectors.file_activity import FileActivityCollector
        paths = self.config.file_paths
        if not paths:
            # Opt-in: without a configured path we do not monitor the whole
            # filesystem. This is a deliberate default, reported as disabled.
            self._state.set_collector_state("file", STATE_DISABLED)
            logger.info("[Collector:file] disabled (set FORENSIX_RUNTIME_FILE_PATH "
                        "to enable)")
            return
        started_any = False
        for path in paths:
            try:
                collector = FileActivityCollector(
                    path, recursive=self.config.file_recursive,
                    on_event=self._file_callback,
                )
                collector.start()
                self._file_collectors.append(collector)
                started_any = True
            except Exception as exc:
                # ValueError message would contain the path -> type only.
                self._state.record_collector_error("file", _err(exc))
                logger.error("[Collector:file] failed to start on a path: %s",
                             _err(exc))
        if started_any:
            self._state.set_collector_state("file", STATE_RUNNING)

    def _start_usb(self) -> None:
        from backend.collectors.usb import USBEventWatcher
        try:
            watcher = USBEventWatcher(on_event=self._usb_callback)
            watcher.start()
            self._usb_watcher = watcher
            self._state.set_collector_state("usb", STATE_RUNNING)
        except RuntimeError as exc:
            # pywin32 / WMI unavailable (non-Windows or missing dependency).
            self._state.set_collector_state(
                "usb", STATE_UNAVAILABLE, error="WMI/pywin32 unavailable")
            logger.warning("[Collector:usb] unavailable: %s", _err(exc))
        except Exception as exc:
            self._state.record_collector_error("usb", _err(exc))
            logger.error("[Collector:usb] failed to start: %s", _err(exc))

    # ---- enqueue (producers) ------------------------------------------
    def _file_callback(self, event) -> None:
        self._enqueue_realtime("file", event)

    def _usb_callback(self, event) -> None:
        self._enqueue_realtime("usb", event)

    def _enqueue_realtime(self, source: str, event) -> None:
        """Non-blocking enqueue for real-time collectors.

        Runs on the Watchdog/WMI OS threads, so it must never block: on a full
        queue we drop + count (dropping beats stalling the OS observer) rather
        than applying backpressure to the operating system.
        """
        item = IngestItem(source=source, events=[event], on_committed=None)
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            self._state.record_dropped(source, 1)
            self._warn_drop(source)

    def _warn_drop(self, source: str) -> None:
        now = time.monotonic()
        if now - self._last_drop_warn >= 5.0:
            self._last_drop_warn = now
            logger.warning("[ForensiX Runtime] queue full; dropping real-time "
                           "events (source=%s)", source)

    def _enqueue(self, source: str, events: list,
                 on_committed: Optional[Callable] = None) -> None:
        """Blocking enqueue for pollers (their source is durable, so applying
        backpressure is safe -- an un-enqueued record is re-read next cycle)."""
        if not events:
            return
        item = IngestItem(source=source, events=events, on_committed=on_committed)
        while not self._stop.is_set():
            try:
                self._queue.put(item, timeout=0.5)
                return
            except queue.Full:
                continue


    # ---- consumer (SOLE WRITER) ---------------------------------------
    def _consume_loop(self) -> None:
        """Drain the queue and call ``process()`` -- the only DB writer.

        Real-time (callback-free) items are coalesced up to ``max_batch`` into
        one ``process()`` call so bursts share a single chain-tip seed. Poller
        items each carry an ``on_committed`` hook and are processed one at a
        time so their high-water mark advances only for their own batch.
        """
        while not (self._stop.is_set() and self._queue.empty()):
            try:
                first = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            gets = 1
            if first is _SHUTDOWN:
                self._queue.task_done()
                break
            realtime_batch: List[IngestItem] = []
            poller_items: List[IngestItem] = []
            stop_after = False
            if first.on_committed is None:
                realtime_batch.append(first)
                while len(realtime_batch) < self.config.max_batch:
                    try:
                        nxt = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    gets += 1
                    if nxt is _SHUTDOWN:
                        stop_after = True
                        break
                    if nxt.on_committed is None:
                        realtime_batch.append(nxt)
                    else:
                        poller_items.append(nxt)
                        break
            else:
                poller_items.append(first)

            try:
                if realtime_batch:
                    self._process_realtime_batch(realtime_batch)
                for pitem in poller_items:
                    self._process_poller_item(pitem)
            finally:
                for _ in range(gets):
                    self._queue.task_done()
            if stop_after:
                break

    def _process_realtime_batch(self, items: List[IngestItem]) -> None:
        events: list = []
        per_source: dict = {}
        latest_ts: dict = {}
        for item in items:
            per_source[item.source] = per_source.get(item.source, 0) + len(item.events)
            for event in item.events:
                events.append(event)
                ts = getattr(event, "timestamp", None)
                if ts is not None and (latest_ts.get(item.source) is None
                                       or ts > latest_ts[item.source]):
                    latest_ts[item.source] = ts
        if not events:
            return
        try:
            result = self._pipeline.process(events)
        except Exception as exc:
            # Real-time events are at-most-once; a writer failure loses this
            # burst but must not kill the consumer. Log type only.
            logger.error("[ForensiX Runtime] writer error on real-time batch: %s",
                         _err(exc))
            return
        self._state.record_batch(ingested=len(events), inserted=result.inserted)
        for source, count in per_source.items():
            lt = latest_ts.get(source)
            self._state.record_collection(
                source, events=count,
                last_event_time=lt.isoformat() if lt else None,
            )


    def _process_poller_item(self, item: IngestItem) -> None:
        if not item.events:
            return
        try:
            result = self._pipeline.process(item.events)
        except Exception as exc:
            # Do NOT advance the HWM: the batch is re-read next cycle.
            self._state.record_collector_error(item.source, _err(exc))
            logger.error("[Collector:%s] writer error: %s", item.source, _err(exc))
            return
        self._state.record_batch(ingested=len(item.events), inserted=result.inserted)
        latest = None
        for event in item.events:
            ts = getattr(event, "timestamp", None)
            if ts is not None and (latest is None or ts > latest):
                latest = ts
        self._state.record_collection(
            item.source, events=len(item.events),
            last_event_time=latest.isoformat() if latest else None,
        )
        if item.on_committed is not None:
            try:
                item.on_committed(result)
            except Exception as exc:
                logger.error("[Collector:%s] commit hook error: %s",
                             item.source, _err(exc))

    # ---- Windows poller -----------------------------------------------
    def _windows_poll_loop(self) -> None:
        from backend.collectors.windows_events import (
            collect_windows_events, SOURCE as WIN_SOURCE)
        from backend.processing.normalizer import normalize_event
        self._state.set_collector_state("windows", STATE_RUNNING)
        last_poll: Optional[datetime] = None
        while not self._stop.is_set():
            try:
                since = (last_poll - timedelta(seconds=OVERLAP_SECONDS)
                         if last_poll else None)
                raws = collect_windows_events(
                    channels=self.config.windows_channels,
                    max_events=self.config.max_batch, since=since,
                    normalize=False,
                )
                last_poll = datetime.now()
                self._ingest_windows(raws, WIN_SOURCE, normalize_event)
            except Exception as exc:
                self._state.record_collector_error("windows", _err(exc))
                logger.error("[Collector:windows] poll error: %s", _err(exc))
            self._stop.wait(self.config.windows_interval)
        self._state.set_collector_state("windows", STATE_STOPPED)

    def _ingest_windows(self, raws, source, normalize_event) -> None:
        by_channel: dict = {}
        for raw in raws:
            md = raw.get("metadata") or {}
            channel = md.get("channel")
            rn = md.get("record_number")
            if channel is None or rn is None:
                continue
            try:
                rn = int(rn)
            except (TypeError, ValueError):
                continue
            by_channel.setdefault(channel, []).append((rn, raw))
        if not by_channel:
            self._state.record_collection("windows", events=0)
            return
        for channel, entries in by_channel.items():
            self._ingest_rn_channel("windows", source, normalize_event,
                                    entries, channel=channel)


    def _ingest_rn_channel(self, collector, source, normalize_event, entries,
                           *, channel=None) -> None:
        """Shared RecordNumber high-water-mark ingest for Windows/Defender.

        ``entries`` is a list of ``(record_number:int, raw_dict)``. Admits only
        records above the stored HWM (or, on a fresh cursor, the newest
        ``initial_backfill``), advancing the HWM to the max RecordNumber READ so
        a permanently-unstorable record can never be retried forever.
        """
        if collector == "windows":
            get_hwm = lambda: self._store.get_windows_hwm(channel)
            set_hwm = lambda v: self._store.set_windows_hwm(channel, v)
        else:
            get_hwm = self._store.get_defender_hwm
            set_hwm = self._store.set_defender_hwm

        max_read = max(rn for rn, _ in entries)
        cur = get_hwm()
        if max_read < cur:
            logger.warning("[Collector:%s] record numbers rolled back; log "
                           "likely cleared/wrapped -- resetting cursor", collector)
            cur = 0

        if cur == 0 and self.config.initial_backfill == 0:
            admitted = []
        elif cur == 0:
            newest = sorted(entries, key=lambda t: t[0], reverse=True)
            admitted = [raw for _, raw in newest[:self.config.initial_backfill]]
        else:
            admitted = [raw for rn, raw in entries if rn > cur]

        events = []
        for raw in admitted:
            try:
                events.append(normalize_event(raw, source=source))
            except (ValueError, TypeError):
                # e.g. Defender records with no timestamp: skip the event but
                # still let the HWM advance past it (never crash, never retry).
                continue

        def _commit(_result, set_hwm=set_hwm, new_hwm=max_read):
            set_hwm(new_hwm)
            self._store.save()

        if events:
            self._enqueue(source=collector, events=events, on_committed=_commit)
        else:
            if max_read > get_hwm():
                set_hwm(max_read)
                self._store.save()
            self._state.record_collection(collector, events=0)

    # ---- Defender poller ----------------------------------------------
    def _defender_poll_loop(self) -> None:
        from backend.collectors.defender import (
            collect_defender_events, SOURCE as DEF_SOURCE)
        from backend.processing.normalizer import normalize_event
        self._state.set_collector_state("defender", STATE_RUNNING)
        last_poll: Optional[datetime] = None
        while not self._stop.is_set():
            try:
                since = (last_poll - timedelta(seconds=OVERLAP_SECONDS)
                         if last_poll else None)
                raws = collect_defender_events(
                    max_events=self.config.max_batch, since=since,
                    normalize=False)
                last_poll = datetime.now()
                self._ingest_defender(raws, DEF_SOURCE, normalize_event)
            except Exception as exc:
                self._state.record_collector_error("defender", _err(exc))
                logger.error("[Collector:defender] poll error: %s", _err(exc))
            self._stop.wait(self.config.defender_interval)
        self._state.set_collector_state("defender", STATE_STOPPED)

    def _ingest_defender(self, raws, source, normalize_event) -> None:
        entries = []
        for raw in raws:
            md = raw.get("metadata") or {}
            rn = md.get("record_number")  # EventRecordID -- a STRING here
            if rn is None:
                continue
            try:
                rn = int(rn)
            except (TypeError, ValueError):
                continue
            entries.append((rn, raw))
        if not entries:
            self._state.record_collection("defender", events=0)
            return
        self._ingest_rn_channel("defender", source, normalize_event, entries)


    # ---- Browser poller -----------------------------------------------
    def _browser_poll_loop(self) -> None:
        from backend.collectors.browser import (
            collect_browser_history, SOURCE as BR_SOURCE)
        from backend.processing.normalizer import normalize_event
        self._state.set_collector_state("browser", STATE_RUNNING)
        while not self._stop.is_set():
            try:
                raws = collect_browser_history(
                    browsers=self.config.browsers,
                    max_events=self.config.max_batch, normalize=False)
                self._ingest_browser(raws, BR_SOURCE, normalize_event)
            except Exception as exc:
                self._state.record_collector_error("browser", _err(exc))
                logger.error("[Collector:browser] poll error: %s", _err(exc))
            self._stop.wait(self.config.browser_interval)
        self._state.set_collector_state("browser", STATE_STOPPED)

    def _ingest_browser(self, raws, source, normalize_event) -> None:
        groups: dict = {}
        for raw in raws:
            md = raw.get("metadata") or {}
            browser = md.get("browser") or "?"
            profile = md.get("profile") or "?"
            groups.setdefault(f"{browser}::{profile}", []).append(raw)
        if not groups:
            self._state.record_collection("browser", events=0)
            return
        for key, records in groups.items():
            self._ingest_browser_group(source, normalize_event, key, records)


    def _ingest_browser_group(self, source, normalize_event, key, records) -> None:
        """Dedup one browser::profile group by last_visit_time + boundary set.

        Admit a record when its timestamp is strictly newer than the stored
        HWM, OR equal to it but with a URL fingerprint not already seen at that
        exact timestamp. This keeps legitimate repeat visits (a new visit gets a
        greater last_visit_time) while preventing re-inserts across polls. Only
        hashed URL prefixes are persisted -- never the URL itself.
        """
        hwm_iso, boundary = self._store.get_browser_hwm(key)
        hwm_dt = _parse_iso(hwm_iso)
        admitted = []
        read_max_dt = None
        for raw in records:
            ts = raw.get("timestamp")  # datetime or None (already converted)
            if ts is None:
                continue
            if read_max_dt is None or ts > read_max_dt:
                read_max_dt = ts
            url = (raw.get("metadata") or {}).get("url") or raw.get("file_path") or ""
            fp = _url_key(url)
            if hwm_dt is None:
                admit = True
            elif ts > hwm_dt:
                admit = True
            elif ts == hwm_dt and fp not in boundary:
                admit = True
            else:
                admit = False
            if admit:
                admitted.append(raw)

        if read_max_dt is None:
            self._state.record_collection("browser", events=0)
            return

        # Fresh-cursor backfill policy mirrors the RecordNumber pollers.
        if hwm_dt is None:
            if self.config.initial_backfill == 0:
                admitted = []
            else:
                admitted = sorted(
                    admitted, key=lambda r: r.get("timestamp"),
                    reverse=True)[:self.config.initial_backfill]

        new_max_dt = read_max_dt if (hwm_dt is None or read_max_dt > hwm_dt) else hwm_dt
        new_boundary = set(boundary) if (hwm_dt is not None
                                         and new_max_dt == hwm_dt) else set()
        for raw in records:
            ts = raw.get("timestamp")
            if ts is not None and ts == new_max_dt:
                url = (raw.get("metadata") or {}).get("url") or raw.get("file_path") or ""
                new_boundary.add(_url_key(url))

        events = []
        for raw in admitted:
            try:
                events.append(normalize_event(raw, source=source))
            except (ValueError, TypeError):
                continue

        def _commit(_result, key=key, ndt=new_max_dt, nb=sorted(new_boundary)):
            self._store.set_browser_hwm(key, ndt.isoformat(), nb)
            self._store.save()

        if events:
            self._enqueue(source="browser", events=events, on_committed=_commit)
        else:
            self._store.set_browser_hwm(key, new_max_dt.isoformat(),
                                        sorted(new_boundary))
            self._store.save()
            self._state.record_collection("browser", events=0)


    # ---- Analysis worker (deterministic, no per-event LLM) ------------
    def _analysis_loop(self) -> None:
        from backend.ai.behavior import analyze_database
        from backend.ai.correlator import correlate_database
        last_count = -1
        while not self._stop.is_set():
            self._stop.wait(self.config.analysis_interval)
            if self._stop.is_set():
                break
            try:
                count = db.count_events()
                if count == 0 or count == last_count:
                    continue  # nothing new since last run -> skip the O(n) work
                started = time.monotonic()
                limit = self.config.analysis_limit or None
                incidents = correlate_database(limit=limit)
                _baseline, anomalies = analyze_database(limit=limit)
                duration = round(time.monotonic() - started, 3)
                self._state.record_analysis(
                    duration=duration,
                    candidate_incidents=len(incidents),
                    anomalies=len(anomalies),
                )
                last_count = count
                logger.info("[ForensiX Runtime] analysis: %d incidents, %d "
                            "anomalies over %d events (%.2fs)",
                            len(incidents), len(anomalies), count, duration)
            except Exception as exc:
                self._state.record_analysis_error(_err(exc))
                logger.error("[ForensiX Runtime] analysis error: %s", _err(exc))

    # ---- status -------------------------------------------------------
    def status(self) -> dict:
        """A live, never-fabricated snapshot + a cached local Ollama probe."""
        snapshot = self._state.snapshot(
            queue_size=self._queue.qsize(),
            queue_maxsize=self.config.queue_maxsize,
            state_file=self._store.path,
        )
        snapshot["ollama"] = probe_ollama()
        return snapshot

    # ---- shutdown -----------------------------------------------------
    def stop(self, timeout: float = 10.0) -> None:
        """Graceful, idempotent shutdown.

        Order: signal stop -> stop real-time collectors (no new enqueues) ->
        wake the consumer to drain the queue -> join every thread (bounded) ->
        persist the final cursor state.
        """
        with self._lifecycle_lock:
            if not self._started:
                return
            logger.info("[ForensiX Runtime] stopping...")
            self._stop.set()

            for collector in self._file_collectors:
                try:
                    collector.stop()
                except Exception:
                    pass
            self._file_collectors = []
            if self._usb_watcher is not None:
                try:
                    self._usb_watcher.stop()
                except Exception:
                    pass
                self._usb_watcher = None

            try:
                self._queue.put_nowait(_SHUTDOWN)
            except queue.Full:
                pass

            deadline = time.monotonic() + timeout
            for thread in self._threads:
                remaining = max(0.0, deadline - time.monotonic())
                thread.join(remaining)
                if thread.is_alive():
                    logger.warning("[ForensiX Runtime] thread %s did not stop "
                                   "within timeout", thread.name)
            self._threads = []

            try:
                self._store.save()
            except Exception:
                pass
            self._state.mark_stopped()
            self._started = False
            logger.info("[ForensiX Runtime] stopped")


# --- Module singleton + lifecycle helpers ----------------------------------
# One manager per process. The idempotent start() + this singleton are what make
# uvicorn's lifespan safe to call; running with --reload or multiple workers
# would spawn multiple writers and fork the chain, so real collection uses a
# single worker with no reload (see the run docs).

_manager: Optional[RuntimeManager] = None
_manager_lock = threading.Lock()


def _under_pytest() -> bool:
    return "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules


def get_runtime() -> RuntimeManager:
    """Return the process-wide manager, constructing it on first use."""
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = RuntimeManager()
        return _manager


def start_if_enabled() -> Optional[RuntimeManager]:
    """Start the runtime unless disabled by env or running under pytest.

    Auto-disabling under pytest is a safety net: the suite never uses
    ``with TestClient(app)`` so lifespan does not fire, but this guarantees the
    runtime can never spin up collectors during tests even if that changes.
    """
    if _under_pytest():
        logger.info("[ForensiX Runtime] not starting (pytest detected)")
        return None
    config = RuntimeConfig.from_env()
    if not config.enabled:
        logger.info("[ForensiX Runtime] disabled (FORENSIX_RUNTIME_ENABLED=0)")
        return None
    manager = get_runtime()
    manager.start()
    return manager


def stop() -> None:
    """Stop the singleton manager if one exists. Safe to call unconditionally."""
    with _manager_lock:
        manager = _manager
    if manager is not None:
        manager.stop()


def reset_singleton() -> None:
    """Test helper: drop the module singleton so the next call builds fresh."""
    global _manager
    with _manager_lock:
        _manager = None

