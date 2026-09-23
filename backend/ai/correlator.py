"""Deterministic, rule-based event correlation engine for ForensiX AI (Phase 10).

This engine reads normalized events (as stored by the pipeline / returned by the
database layer) and groups events that are *logically or temporally related*
into **candidate incidents**. It is the deterministic, explainable foundation
that later AI phases will build on.

    Stored events  ->  CorrelationEngine.correlate()  ->  candidate incidents

What this is / is NOT
---------------------
* This is a **deterministic, rule-based** correlator. It is NOT machine
  learning, NOT an LLM, and uses no embeddings, models, or anomaly detection.
* It identifies "related events" and "candidate incidents" -- it does NOT
  declare confirmed attacks and never fabricates attacker identity, intent,
  malware family, exfiltration, or compromise. Language is evidence-based.
* Temporal proximity alone is treated as necessary-but-insufficient: two events
  are linked only when they fall inside the configured time window AND share a
  substantive signal (same device / same user / related file path / a known
  event-type relationship). Same timestamp alone never merges unrelated events.

Read-only over evidence
-----------------------
Correlation is a pure analysis operation. It never writes to the database,
never mutates the Event objects/rows it is given, and never touches the Phase 9
``event_hash`` / ``previous_hash`` fields. It can *annotate* each event with an
integrity label (see ``integrity_result``) but it does not itself verify the
chain -- pass an ``IntegrityResult`` from ``backend.integrity.verifier`` for
that. Correlation does not prove the real-world truth of an event.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional, Sequence, Set, Tuple

# --- Configuration defaults -------------------------------------------------

DEFAULT_WINDOW_SECONDS = 300  # 5 minutes; caller-configurable, never hardcoded.
DEFAULT_MIN_GROUP_SIZE = 2    # a candidate incident needs >= 2 related events.

# --- Collector source labels (must match backend/collectors/*) --------------

SOURCE_USB = "USB"
SOURCE_FILE = "FileSystem"
SOURCE_BROWSER = "Browser"
SOURCE_DEFENDER = "Defender"
SOURCE_WINDOWS = "Windows"

# event_type values emitted by the USB / File / Browser collectors. Defender
# and Windows events carry a numeric event id as their event_type, so those two
# are recognised by source instead of event_type.
USB_EVENT_TYPES = {"USB_CONNECTED", "USB_DISCONNECTED"}
FILE_EVENT_TYPES = {"FILE_CREATED", "FILE_MODIFIED", "FILE_DELETED", "FILE_RENAMED"}
BROWSER_EVENT_TYPES = {"BROWSER_VISIT"}

# --- Event categories used by the relationship rules ------------------------

CAT_USB = "usb"
CAT_FILE = "file"
CAT_BROWSER = "browser"
CAT_DEFENDER = "defender"
CAT_WINDOWS = "windows"
CAT_OTHER = "other"

# Forensically-meaningful category adjacencies (unordered). A pair of events
# whose categories form one of these sets is treated as a "known event-type
# relationship" -- an explicit, documented signal, not an inference of intent.
KNOWN_RELATIONSHIPS = {
    frozenset({CAT_USB}),                    # USB connect/disconnect sequence
    frozenset({CAT_FILE}),                   # successive file operations
    frozenset({CAT_USB, CAT_FILE}),          # removable-media data movement
    frozenset({CAT_BROWSER, CAT_FILE}),      # download-then-write pattern
    frozenset({CAT_FILE, CAT_DEFENDER}),     # file activity near a detection
    frozenset({CAT_USB, CAT_DEFENDER}),      # removable media near a detection
    frozenset({CAT_WINDOWS, CAT_FILE}),
    frozenset({CAT_WINDOWS, CAT_USB}),
    frozenset({CAT_WINDOWS, CAT_DEFENDER}),
    frozenset({CAT_WINDOWS, CAT_BROWSER}),
}

# --- Integrity annotation labels (Phase 9 aware, but never claims to verify) -

INTEGRITY_LEGACY = "LEGACY"                    # pre-Phase-9 row, no hash
INTEGRITY_HASHED_UNVERIFIED = "HASHED_UNVERIFIED"  # hashed, no verification run
INTEGRITY_VERIFIED = "VERIFIED"                # hashed + IntegrityResult confirms
INTEGRITY_TAMPERED = "TAMPERED"                # hashed + flagged by IntegrityResult

# --- Priority levels --------------------------------------------------------

PRIORITY_LOW = "LOW"
PRIORITY_MEDIUM = "MEDIUM"
PRIORITY_HIGH = "HIGH"
PRIORITY_CRITICAL = "CRITICAL"
_PRIORITY_RANK = {PRIORITY_LOW: 0, PRIORITY_MEDIUM: 1,
                  PRIORITY_HIGH: 2, PRIORITY_CRITICAL: 3}

# Map stored severity strings (from any collector) to a comparable rank. Unknown
# values rank 0 so a surprise string never silently escalates an incident.
_SEVERITY_RANK = {
    "": 0, "INFO": 0, "LOW": 0, "AUDIT_SUCCESS": 0,
    "WARNING": 1, "MEDIUM": 1, "AUDIT_FAILURE": 1,
    "ERROR": 2, "HIGH": 2,
    "CRITICAL": 3,
}

# The distinct correlation signals; the confidence score counts how many are
# present (0-5). This is an explainability count, NOT a probability.
SIGNAL_TEMPORAL = "temporal"
SIGNAL_DEVICE = "device"
SIGNAL_USER = "user"
SIGNAL_FILE = "file"
SIGNAL_TYPE = "type_relationship"

# --- Domain objects ---------------------------------------------------------


@dataclass(frozen=True)
class CorrelatedEvent:
    """A read-only snapshot of one input event used by the correlator.

    This is a *copy* of the relevant fields; the original Event/row/dict handed
    to :meth:`CorrelationEngine.correlate` is never mutated. ``event_id`` is the
    database ``id`` when present (rows) and ``None`` otherwise (bare Event
    objects or dicts without an id).
    """

    event_id: Optional[int]
    timestamp: Optional[datetime]
    source: str
    event_type: str
    description: str
    severity: str
    user: str
    device: str
    file_path: str
    metadata: str
    event_hash: Optional[str]
    previous_hash: Optional[str]
    integrity: str
    index: int  # stable position in the input, for deterministic tie-breaks

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "user": self.user,
            "device": self.device,
            "file_path": self.file_path,
            "integrity": self.integrity,
        }


@dataclass
class CandidateIncident:
    """A group of related events and the explicit evidence that links them.

    Deliberately named a *candidate* incident: the correlator asserts that these
    events are related by the documented rules, not that they constitute a
    confirmed attack.
    """

    incident_id: str
    start_time: datetime
    end_time: datetime
    events: List[CorrelatedEvent]
    event_ids: List[Optional[int]]
    sources: List[str]
    event_types: List[str]
    correlation_reasons: List[str]
    priority: str
    confidence_score: int
    confidence_signals: List[str]
    integrity_summary: dict

    def as_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "event_ids": list(self.event_ids),
            "sources": list(self.sources),
            "event_types": list(self.event_types),
            "correlation_reasons": list(self.correlation_reasons),
            "priority": self.priority,
            "confidence_score": self.confidence_score,
            "confidence_signals": list(self.confidence_signals),
            "integrity_summary": dict(self.integrity_summary),
            "events": [e.as_dict() for e in self.events],
        }


# --- Field access / coercion (works for sqlite3.Row, dict, or Event) --------


def _field(obj, name, default=None):
    """Read ``name`` from a sqlite3.Row, dict, or object, else ``default``.

    ``None`` values are normalised to ``default`` so callers get consistent
    empties. Never raises for a missing field.
    """
    try:
        keys = obj.keys()  # sqlite3.Row and dict both expose keys()
    except AttributeError:
        value = getattr(obj, name, default)
        return default if value is None else value
    if name in keys:
        value = obj[name]
        return default if value is None else value
    return default


def _coerce_timestamp(value) -> Optional[datetime]:
    """Coerce a stored timestamp into a datetime, or None if unusable.

    Accepts a datetime, an epoch number, or an ISO/SQLite-style string. Unlike
    the normalizer, a missing/invalid timestamp yields ``None`` (the event is
    simply left uncorrelated) rather than defaulting to "now" -- correlation
    must never invent a time.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                        "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(text, fmt)
                except ValueError:
                    continue
        return None
    return None


def _category(event: CorrelatedEvent) -> str:
    """Classify an event into a coarse category for the relationship rules."""
    src = event.source
    etype = (event.event_type or "").upper()
    if src == SOURCE_USB or etype in USB_EVENT_TYPES or etype.startswith("USB_"):
        return CAT_USB
    if src == SOURCE_FILE or etype in FILE_EVENT_TYPES or etype.startswith("FILE_"):
        return CAT_FILE
    if src == SOURCE_BROWSER or etype in BROWSER_EVENT_TYPES:
        return CAT_BROWSER
    if src == SOURCE_DEFENDER:
        return CAT_DEFENDER
    if src == SOURCE_WINDOWS:
        return CAT_WINDOWS
    return CAT_OTHER


def _norm_path(path: str) -> str:
    """Normalise a filesystem path for comparison (Windows is case-insensitive).

    URLs (browser events store the URL in file_path) simply won't match real
    paths, which is the intended behaviour -- no false file links.
    """
    return path.replace("\\", "/").rstrip("/").lower()


def _parent_dir(norm_path: str) -> str:
    """Return the parent directory of an already-normalised path, or ""."""
    return norm_path.rsplit("/", 1)[0] if "/" in norm_path else ""


def _classify_integrity(event_id, event_hash, invalid_ids,
                        integrity_supplied) -> str:
    """Label an event's integrity without claiming to have verified the chain.

    * no hash                          -> LEGACY (pre-Phase-9; not fabricated)
    * hashed, no IntegrityResult given -> HASHED_UNVERIFIED
    * hashed + flagged by result       -> TAMPERED
    * hashed + not flagged by result   -> VERIFIED
    """
    if event_hash in (None, ""):
        return INTEGRITY_LEGACY
    if not integrity_supplied:
        return INTEGRITY_HASHED_UNVERIFIED
    if invalid_ids is not None and event_id in invalid_ids:
        return INTEGRITY_TAMPERED
    return INTEGRITY_VERIFIED


class _UnionFind:
    """Minimal union-find for deterministic connected-component grouping."""

    def __init__(self, n: int):
        self._parent = list(range(n))
        self._rank = [0] * n

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1


def _pair_signals(a: CorrelatedEvent, b: CorrelatedEvent,
                  window_seconds: float) -> Optional[Tuple[List[str], Set[str]]]:
    """Return (reasons, signals) if a and b are related, else None.

    Gating rules:
      * temporal: both timestamps present and within ``window_seconds``;
      * device veto: if both events name a device and the names differ, they
        are from different machines and are never linked.
    A link additionally requires at least one substantive signal (same device,
    same user, related file path, or a known event-type relationship) so that
    temporal proximity alone can never merge unrelated events.
    """
    if a.timestamp is None or b.timestamp is None:
        return None
    delta = abs((a.timestamp - b.timestamp).total_seconds())
    if delta > window_seconds:
        return None
    if a.device and b.device and a.device != b.device:
        return None  # different devices: not the same endpoint

    reasons: List[str] = []
    signals: Set[str] = set()

    if a.device and b.device and a.device == b.device:
        reasons.append(f"same device: {a.device}")
        signals.add(SIGNAL_DEVICE)
    if a.user and b.user and a.user == b.user:
        reasons.append(f"same user: {a.user}")
        signals.add(SIGNAL_USER)
    if a.file_path and b.file_path:
        na, nb = _norm_path(a.file_path), _norm_path(b.file_path)
        if na == nb:
            reasons.append(f"same file path: {a.file_path}")
            signals.add(SIGNAL_FILE)
        else:
            da, db = _parent_dir(na), _parent_dir(nb)
            if da and da == db:
                reasons.append(f"related file path (same directory): {da}")
                signals.add(SIGNAL_FILE)
    ca, cb = _category(a), _category(b)
    if frozenset({ca, cb}) in KNOWN_RELATIONSHIPS:
        if ca == cb:
            reasons.append(f"related {ca} events")
        else:
            lo, hi = sorted((ca, cb))
            reasons.append(f"known event-type relationship ({lo} + {hi})")
        signals.add(SIGNAL_TYPE)

    if not signals:  # only temporal proximity -> not enough to link
        return None
    reasons.insert(0, f"temporal proximity (within {int(window_seconds)}s window)")
    signals.add(SIGNAL_TEMPORAL)
    return reasons, signals


def _priority(members: Sequence[CorrelatedEvent]) -> str:
    """Assign a priority using explicit, documented rules (not ML).

    Rules (first match wins), then a critical floor:
      1. Defender detection + file activity  -> CRITICAL if the Defender event's
         own stored severity is HIGH/CRITICAL, else HIGH.
      2. Defender detection present          -> HIGH.
      3. USB activity + file create/modify   -> MEDIUM.
      4. A notable Windows event (severity >= WARNING) present -> MEDIUM.
      5. Otherwise                           -> LOW.
    Critical floor: if any member's own stored severity is CRITICAL and the
    rules above produced less than HIGH, raise to HIGH. We never invent CRITICAL
    for ordinary activity -- only a Defender detection can reach CRITICAL.
    """
    cats = {_category(m) for m in members}
    has_defender = CAT_DEFENDER in cats
    has_file = CAT_FILE in cats
    has_usb = CAT_USB in cats
    has_notable_windows = any(
        _category(m) == CAT_WINDOWS
        and _SEVERITY_RANK.get((m.severity or "").upper(), 0) >= 1
        for m in members
    )

    if has_defender and has_file:
        defender_sev = max(
            (_SEVERITY_RANK.get((m.severity or "").upper(), 0)
             for m in members if _category(m) == CAT_DEFENDER),
            default=0,
        )
        priority = PRIORITY_CRITICAL if defender_sev >= 2 else PRIORITY_HIGH
    elif has_defender:
        priority = PRIORITY_HIGH
    elif has_usb and has_file:
        priority = PRIORITY_MEDIUM
    elif has_notable_windows:
        priority = PRIORITY_MEDIUM
    else:
        priority = PRIORITY_LOW

    max_member = max((_SEVERITY_RANK.get((m.severity or "").upper(), 0)
                      for m in members), default=0)
    if max_member >= 3 and _PRIORITY_RANK[priority] < _PRIORITY_RANK[PRIORITY_HIGH]:
        priority = PRIORITY_HIGH
    return priority


class CorrelationEngine:
    """Groups related events into candidate incidents (deterministic, rule-based).

    Args:
        window_seconds: temporal proximity window; two events can only link when
            their timestamps are within this many seconds. Configurable per call.
        min_group_size: minimum number of related events for a candidate
            incident (default 2 -- a lone event is not an incident).
        integrity_result: optional ``IntegrityResult`` from
            ``backend.integrity.verifier``. When supplied, each event is
            annotated VERIFIED / TAMPERED accordingly. Correlation itself does
            not verify the chain; without this argument hashed events are simply
            labelled HASHED_UNVERIFIED.

    Complexity: events are sorted once (O(n log n)); edges are found with a
    sliding window over the sorted stream, which is O(n * w) where w is the
    number of events per window -- near-linear for normal workloads and O(n^2)
    only in the worst case where every event falls inside one window.
    """

    def __init__(self, *, window_seconds: float = DEFAULT_WINDOW_SECONDS,
                 min_group_size: int = DEFAULT_MIN_GROUP_SIZE,
                 integrity_result=None):
        if window_seconds < 0:
            raise ValueError("window_seconds must be non-negative")
        self.window_seconds = window_seconds
        self.min_group_size = max(1, int(min_group_size))
        self._integrity_result = integrity_result

    def correlate(self, events: Iterable) -> List[CandidateIncident]:
        """Return the candidate incidents found among ``events``.

        ``events`` may be sqlite3.Row objects, dicts, or Event dataclasses (or a
        mix). Items that cannot be interpreted (no timestamp / source /
        event_type) are skipped rather than crashing the run.
        """
        if events is None:
            raise TypeError("events must be an iterable, got None")
        try:
            raw_items = list(events)
        except TypeError as exc:
            raise TypeError(f"events must be iterable: {exc}") from exc

        invalid_ids = (set(self._integrity_result.invalid_ids)
                       if self._integrity_result is not None else None)
        supplied = self._integrity_result is not None

        coerced: List[CorrelatedEvent] = []
        for index, item in enumerate(raw_items):
            coerced.append(self._coerce(item, index, invalid_ids, supplied))

        # Only events with a usable timestamp + source + event_type participate.
        usable = [e for e in coerced
                  if e.timestamp is not None and e.source and e.event_type]
        usable.sort(key=lambda e: (e.timestamp, e.index))

        return self._build_incidents(usable)

    # -- internals ---------------------------------------------------------

    def _coerce(self, item, index, invalid_ids, supplied) -> CorrelatedEvent:
        event_id = _field(item, "id", None)
        if isinstance(event_id, bool):  # guard against odd inputs
            event_id = None
        event_hash = _field(item, "event_hash", None)
        return CorrelatedEvent(
            event_id=event_id,
            timestamp=_coerce_timestamp(_field(item, "timestamp", None)),
            source=str(_field(item, "source", "") or ""),
            event_type=str(_field(item, "event_type", "") or ""),
            description=str(_field(item, "description", "") or ""),
            severity=str(_field(item, "severity", "") or ""),
            user=str(_field(item, "user", "") or ""),
            device=str(_field(item, "device", "") or ""),
            file_path=str(_field(item, "file_path", "") or ""),
            metadata=str(_field(item, "metadata", "") or ""),
            event_hash=event_hash,
            previous_hash=_field(item, "previous_hash", None),
            integrity=_classify_integrity(event_id, event_hash,
                                          invalid_ids, supplied),
            index=index,
        )

    def _build_incidents(self, usable: List[CorrelatedEvent]) -> List[CandidateIncident]:
        n = len(usable)
        uf = _UnionFind(n)
        edges: List[Tuple[int, int, List[str], Set[str]]] = []

        for i in range(n):
            ti = usable[i].timestamp
            for j in range(i + 1, n):
                # Sorted by time: once past the window, no later j can qualify.
                if (usable[j].timestamp - ti).total_seconds() > self.window_seconds:
                    break
                result = _pair_signals(usable[i], usable[j], self.window_seconds)
                if result is None:
                    continue
                reasons, signals = result
                uf.union(i, j)
                edges.append((i, j, reasons, signals))

        components: dict = defaultdict(list)
        for idx in range(n):
            components[uf.find(idx)].append(idx)
        comp_reasons: dict = defaultdict(list)
        comp_signals: dict = defaultdict(set)
        for i, _j, reasons, signals in edges:
            root = uf.find(i)
            comp_reasons[root].extend(reasons)
            comp_signals[root] |= signals

        incidents: List[CandidateIncident] = []
        for root, idxs in components.items():
            if len(idxs) < self.min_group_size:
                continue
            members = [usable[k] for k in idxs]
            members.sort(key=lambda e: (e.timestamp, e.index))
            incidents.append(self._make_incident(members,
                                                  comp_reasons[root],
                                                  comp_signals[root]))

        incidents.sort(key=lambda inc: (inc.start_time, inc.incident_id))
        return incidents

    @staticmethod
    def _make_incident(members, reasons, signals) -> CandidateIncident:
        keys = [str(m.event_id) if m.event_id is not None else f"idx{m.index}"
                for m in members]
        digest = hashlib.sha256("|".join(sorted(keys)).encode("utf-8")).hexdigest()
        integrity_summary: dict = defaultdict(int)
        for m in members:
            integrity_summary[m.integrity] += 1
        return CandidateIncident(
            incident_id=f"INC-{digest[:12]}",
            start_time=min(m.timestamp for m in members),
            end_time=max(m.timestamp for m in members),
            events=members,
            event_ids=[m.event_id for m in members],
            sources=sorted({m.source for m in members}),
            event_types=sorted({m.event_type for m in members}),
            correlation_reasons=sorted(set(reasons)),
            priority=_priority(members),
            confidence_score=len(signals),
            confidence_signals=sorted(signals),
            integrity_summary=dict(integrity_summary),
        )


def correlate_events(events: Iterable, *,
                     window_seconds: float = DEFAULT_WINDOW_SECONDS,
                     min_group_size: int = DEFAULT_MIN_GROUP_SIZE,
                     integrity_result=None) -> List[CandidateIncident]:
    """Convenience one-shot wrapper around :class:`CorrelationEngine`."""
    return CorrelationEngine(window_seconds=window_seconds,
                             min_group_size=min_group_size,
                             integrity_result=integrity_result).correlate(events)


def correlate_database(*, window_seconds: float = DEFAULT_WINDOW_SECONDS,
                       min_group_size: int = DEFAULT_MIN_GROUP_SIZE,
                       limit: Optional[int] = None,
                       verify_integrity: bool = False) -> List[CandidateIncident]:
    """Correlate the events currently stored in the database.

    The database layer is imported lazily so importing this module has no side
    effects and never touches the DB. When ``verify_integrity`` is True the
    hash chain is verified first (read-only) and the result is used purely to
    annotate events -- correlation still runs regardless of the outcome.
    """
    from backend.database.db import get_events

    integrity_result = None
    if verify_integrity:
        from backend.integrity.verifier import verify_chain
        integrity_result = verify_chain()

    return correlate_events(get_events(limit=limit),
                            window_seconds=window_seconds,
                            min_group_size=min_group_size,
                            integrity_result=integrity_result)
