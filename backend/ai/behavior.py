"""Deterministic behavioral baseline & anomaly detection for ForensiX AI (Phase 11).

This engine learns what "normal" activity looks like for the endpoint from the
events already collected (as stored by the pipeline / returned by the database
layer) and scores new events by how far they deviate from that baseline.

    Stored events  ->  BehavioralBaselineEngine.build_baseline()  ->  BehavioralBaseline
    new event + baseline  ->  .evaluate()  ->  BehaviorAnomaly

What this is / is NOT
---------------------
* This is a **deterministic, statistical** baseline. It is NOT machine learning,
  NOT deep learning, NOT an LLM, and uses no embeddings or trained models. Every
  score is the sum of documented, explainable signal weights -- given the same
  events and configuration it always produces the same result.
* It reports whether activity is *unusual compared with historical behaviour*
  ("SUSPICIOUS"/"ANOMALOUS"). It never declares a confirmed attack and never
  fabricates attacker identity, intent, or malware family. An anomaly is a
  deviation worth a human's attention, not proof of wrongdoing.
* The 0-100 ``anomaly_score`` is an explainability score, **NOT a probability**.

Relationship to the correlator (Phase 10)
------------------------------------------
Correlation answers "what events are related?"; this engine answers "is this
activity unusual compared with historical behaviour?". They are independent,
sibling analysis components; this module does not import or change the correlator.

Read-only over evidence
-----------------------
The engine is a pure analysis component. It never writes to the database, never
creates anomaly tables, never mutates the Event objects/rows it is given, and
never touches the Phase 9 ``event_hash`` / ``previous_hash`` fields. Missing or
invalid timestamps are skipped for time-based analysis -- a timestamp is never
fabricated.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple


# --- Configuration defaults (all caller-configurable, never hardcoded) ------

DEFAULT_MIN_BASELINE_EVENTS = 20  # cold-start: fewer than this => insufficient_history
DEFAULT_MIN_SUBJECT_EVENTS = 5    # min events for a per-user/per-device sub-baseline
DEFAULT_RARE_THRESHOLD = 0.05     # relative frequency below this counts as "rare"
DEFAULT_Z_THRESHOLD = 2.0         # |z| >= this is a statistically unusual frequency
DEFAULT_SUSPICIOUS_SCORE = 30     # anomaly_score >= this => SUSPICIOUS
DEFAULT_ANOMALOUS_SCORE = 60      # anomaly_score >= this => ANOMALOUS

# --- Classification labels --------------------------------------------------

STATUS_NORMAL = "NORMAL"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_ANOMALOUS = "ANOMALOUS"
STATUS_INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"

# Baseline readiness (reported by BehavioralBaseline.status).
BASELINE_READY = "ready"
BASELINE_INSUFFICIENT = "insufficient_history"

# Human-facing severity derived from the classification (for dashboards/API).
_CLASSIFICATION_SEVERITY = {
    STATUS_NORMAL: "INFO",
    STATUS_SUSPICIOUS: "WARNING",
    STATUS_ANOMALOUS: "HIGH",
    STATUS_INSUFFICIENT_HISTORY: "INFO",
}

# --- Signal names (which behavioural dimension deviated) --------------------

SIGNAL_SOURCE = "unusual_source"
SIGNAL_CATEGORY = "unusual_category"
SIGNAL_EVENT_TYPE = "unusual_event_type"
SIGNAL_USER = "unusual_user"
SIGNAL_DEVICE = "unusual_device"
SIGNAL_SEVERITY = "unusual_severity"
SIGNAL_HOUR = "unusual_hour"
SIGNAL_FREQUENCY = "unusual_frequency"
SIGNAL_DAY = "unusual_day"

# --- Signal weights (documented; the score is their bounded sum) ------------
# Each categorical signal contributes its "unseen" weight when the event's value
# was never seen in the baseline, or its "rare" weight when it was seen but at a
# relative frequency below the rare threshold. Weights are chosen so that a
# single strong deviation reaches SUSPICIOUS and two independent strong
# deviations reach ANOMALOUS.
_W_UNSEEN_SOURCE, _W_RARE_SOURCE = 40.0, 15.0
_W_UNSEEN_CATEGORY, _W_RARE_CATEGORY = 35.0, 12.0
_W_UNSEEN_EVENT_TYPE, _W_RARE_EVENT_TYPE = 30.0, 12.0
_W_UNSEEN_USER, _W_RARE_USER = 30.0, 12.0
_W_UNSEEN_DEVICE, _W_RARE_DEVICE = 30.0, 10.0
_W_UNSEEN_SEVERITY, _W_RARE_SEVERITY = 25.0, 10.0
_W_UNSEEN_HOUR = 30.0        # activity in an hour the subject is never active
_W_FREQUENCY_HOUR = 20.0     # activity in an hour far below the subject's norm
_W_UNSEEN_DAY = 10.0         # activity on a weekday with no baseline activity

SCORE_MIN, SCORE_MAX = 0.0, 100.0

# --- Collector source labels (must match backend/collectors/*) --------------

SOURCE_USB = "USB"
SOURCE_FILE = "FileSystem"
SOURCE_BROWSER = "Browser"
SOURCE_DEFENDER = "Defender"
SOURCE_WINDOWS = "Windows"

USB_EVENT_TYPES = {"USB_CONNECTED", "USB_DISCONNECTED"}
FILE_EVENT_TYPES = {"FILE_CREATED", "FILE_MODIFIED", "FILE_DELETED", "FILE_RENAMED"}
BROWSER_EVENT_TYPES = {"BROWSER_VISIT"}

CAT_USB = "usb"
CAT_FILE = "file"
CAT_BROWSER = "browser"
CAT_DEFENDER = "defender"
CAT_WINDOWS = "windows"
CAT_OTHER = "other"

# Friendly nouns for explainable category reasons.
_CATEGORY_NOUN = {
    CAT_USB: "USB activity",
    CAT_FILE: "File activity",
    CAT_BROWSER: "Browser activity",
    CAT_DEFENDER: "Defender activity",
    CAT_WINDOWS: "Windows event activity",
    CAT_OTHER: "Activity",
}

_WEEKDAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday",
                  "Friday", "Saturday", "Sunday")


# --- Field access / coercion (works for sqlite3.Row, dict, or Event) --------
# These mirror the safe-access helpers used by the correlator so the engine
# accepts the same event representations, but are kept local so this module is
# independently testable and does not depend on the correlator.


def _field(obj, name, default=None):
    """Read ``name`` from a sqlite3.Row, dict, or object, else ``default``.

    ``None`` values are normalised to ``default``. Never raises for a missing
    field, so events with missing optional fields do not crash the engine.
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

    Accepts a datetime, an epoch number, or an ISO/SQLite-style string. A
    missing/invalid timestamp yields ``None`` (the event is skipped for
    time-based analysis) -- the engine never fabricates a time.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, bool):
        return None
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


def _category(source: str, event_type: str) -> str:
    """Classify an event into a coarse behavioural category."""
    etype = (event_type or "").upper()
    if source == SOURCE_USB or etype in USB_EVENT_TYPES or etype.startswith("USB_"):
        return CAT_USB
    if source == SOURCE_FILE or etype in FILE_EVENT_TYPES or etype.startswith("FILE_"):
        return CAT_FILE
    if source == SOURCE_BROWSER or etype in BROWSER_EVENT_TYPES:
        return CAT_BROWSER
    if source == SOURCE_DEFENDER:
        return CAT_DEFENDER
    if source == SOURCE_WINDOWS:
        return CAT_WINDOWS
    return CAT_OTHER


# --- Small, NaN/Infinity-safe statistics ------------------------------------


def _mean(values) -> float:
    return sum(values) / len(values) if values else 0.0


def _pstd(values) -> float:
    """Population standard deviation; 0.0 for empty or constant input."""
    n = len(values)
    if n == 0:
        return 0.0
    m = _mean(values)
    var = sum((v - m) ** 2 for v in values) / n
    return math.sqrt(var) if var > 0 else 0.0


def _zscore(value: float, mean: float, std: float) -> float:
    """Z-score, or 0.0 when std is 0 (constant baseline) or non-finite."""
    if std <= 0:
        return 0.0
    z = (value - mean) / std
    return z if math.isfinite(z) else 0.0


def _rarity(count: int, total: int, unseen_weight: float,
            rare_weight: float, rare_threshold: float) -> Tuple[float, Optional[str]]:
    """Return (weight, kind) for a categorical value's rarity in the baseline.

    kind is "unseen" (never observed), "rare" (below the rare threshold), or
    None (common enough to be normal). ``total <= 0`` yields no contribution,
    avoiding division by zero.
    """
    if total <= 0:
        return 0.0, None
    if count <= 0:
        return unseen_weight, "unseen"
    if (count / total) < rare_threshold:
        return rare_weight, "rare"
    return 0.0, None


def _pct(count: int, total: int) -> str:
    """Format a relative frequency as a percentage string (safe for total 0)."""
    return f"{(100.0 * count / total):.1f}%" if total > 0 else "0.0%"


# --- Domain objects ---------------------------------------------------------


@dataclass(frozen=True)
class BehaviorEvent:
    """A read-only snapshot of one input event and its extracted features.

    This is a *copy*; the original Event/row/dict is never mutated. ``hour`` and
    ``weekday`` are None when the event had no usable timestamp (never invented).
    """

    index: int
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
    category: str
    hour: Optional[int]
    weekday: Optional[int]

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "user": self.user,
            "device": self.device,
            "file_path": self.file_path,
            "category": self.category,
            "hour": self.hour,
            "weekday": self.weekday,
        }


@dataclass
class BehavioralBaseline:
    """Learned statistics describing "normal" activity for the endpoint.

    Counts are plain histograms so every downstream decision is inspectable.
    ``status`` is ``ready`` once at least ``min_baseline_events`` events have
    been observed, otherwise ``insufficient_history`` (cold start).
    """

    total_events: int
    timestamped_events: int
    status: str
    min_baseline_events: int
    source_counts: Dict[str, int]
    event_type_counts: Dict[str, int]
    category_counts: Dict[str, int]
    severity_counts: Dict[str, int]
    user_counts: Dict[str, int]
    device_counts: Dict[str, int]
    hour_counts: Dict[int, int]
    day_counts: Dict[int, int]
    user_hour_counts: Dict[str, Dict[int, int]]
    device_hour_counts: Dict[str, Dict[int, int]]
    hourly_mean: float
    hourly_std: float

    @property
    def insufficient_history(self) -> bool:
        return self.status != BASELINE_READY

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "total_events": self.total_events,
            "timestamped_events": self.timestamped_events,
            "min_baseline_events": self.min_baseline_events,
            "source_counts": dict(self.source_counts),
            "event_type_counts": dict(self.event_type_counts),
            "category_counts": dict(self.category_counts),
            "severity_counts": dict(self.severity_counts),
            "user_counts": dict(self.user_counts),
            "device_counts": dict(self.device_counts),
            "hour_counts": {str(h): c for h, c in sorted(self.hour_counts.items())},
            "day_counts": {str(d): c for d, c in sorted(self.day_counts.items())},
            "hourly_mean": round(self.hourly_mean, 4),
            "hourly_std": round(self.hourly_std, 4),
        }


@dataclass
class BehaviorAnomaly:
    """The result of scoring one event against a baseline.

    ``anomaly_score`` is a bounded 0-100 explainability score, **not** a
    probability. ``classification`` is one of NORMAL / SUSPICIOUS / ANOMALOUS /
    INSUFFICIENT_HISTORY. ``reasons`` explain, deterministically, why the event
    was flagged; ``signals`` name the behavioural dimensions that deviated.
    """

    event: BehaviorEvent
    anomaly_score: float
    classification: str
    severity: str
    reasons: List[str]
    signals: List[str]
    baseline_status: str

    def as_dict(self) -> dict:
        return {
            "anomaly_score": self.anomaly_score,
            "classification": self.classification,
            "severity": self.severity,
            "reasons": list(self.reasons),
            "signals": list(self.signals),
            "baseline_status": self.baseline_status,
            "event": self.event.as_dict(),
        }


# --- Engine -----------------------------------------------------------------


class BehavioralBaselineEngine:
    """Learns a statistical baseline and scores events against it.

    All thresholds are constructor arguments so behaviour is configurable and
    never hardcoded. The engine holds no per-call mutable state, so the same
    inputs and configuration always yield identical baselines and anomalies.

    Complexity: building the baseline is O(n) over the events; evaluating one
    event is O(1) amortised (dictionary look-ups plus a fixed 24-slot hour scan).
    """

    def __init__(self, *,
                 min_baseline_events: int = DEFAULT_MIN_BASELINE_EVENTS,
                 min_subject_events: int = DEFAULT_MIN_SUBJECT_EVENTS,
                 rare_threshold: float = DEFAULT_RARE_THRESHOLD,
                 z_threshold: float = DEFAULT_Z_THRESHOLD,
                 suspicious_score: float = DEFAULT_SUSPICIOUS_SCORE,
                 anomalous_score: float = DEFAULT_ANOMALOUS_SCORE):
        if min_baseline_events < 1:
            raise ValueError("min_baseline_events must be >= 1")
        if min_subject_events < 1:
            raise ValueError("min_subject_events must be >= 1")
        if not (0.0 <= rare_threshold <= 1.0):
            raise ValueError("rare_threshold must be between 0 and 1")
        if z_threshold < 0:
            raise ValueError("z_threshold must be non-negative")
        if not (0 <= suspicious_score <= anomalous_score <= SCORE_MAX):
            raise ValueError("require 0 <= suspicious_score <= anomalous_score <= 100")
        self.min_baseline_events = int(min_baseline_events)
        self.min_subject_events = int(min_subject_events)
        self.rare_threshold = float(rare_threshold)
        self.z_threshold = float(z_threshold)
        self.suspicious_score = float(suspicious_score)
        self.anomalous_score = float(anomalous_score)

    # -- extraction --------------------------------------------------------

    def _extract(self, item, index: int) -> BehaviorEvent:
        ts = _coerce_timestamp(_field(item, "timestamp", None))
        source = str(_field(item, "source", "") or "")
        event_type = str(_field(item, "event_type", "") or "")
        event_id = _field(item, "id", None)
        if isinstance(event_id, bool):
            event_id = None
        return BehaviorEvent(
            index=index,
            event_id=event_id,
            timestamp=ts,
            source=source,
            event_type=event_type,
            description=str(_field(item, "description", "") or ""),
            severity=str(_field(item, "severity", "") or ""),
            user=str(_field(item, "user", "") or ""),
            device=str(_field(item, "device", "") or ""),
            file_path=str(_field(item, "file_path", "") or ""),
            metadata=str(_field(item, "metadata", "") or ""),
            event_hash=_field(item, "event_hash", None),
            previous_hash=_field(item, "previous_hash", None),
            category=_category(source, event_type),
            hour=ts.hour if ts is not None else None,
            weekday=ts.weekday() if ts is not None else None,
        )

    # -- baseline ----------------------------------------------------------

    def build_baseline(self, events: Iterable) -> BehavioralBaseline:
        """Learn a :class:`BehavioralBaseline` from historical events.

        Accepts Event objects, sqlite3.Row objects, dicts, or a mix. Events with
        no usable timestamp still count toward the categorical baseline but are
        excluded from the hour/day distributions (their time is never invented).
        """
        if events is None:
            raise TypeError("events must be an iterable, got None")
        try:
            extracted = [self._extract(item, i) for i, item in enumerate(events)]
        except TypeError as exc:
            raise TypeError(f"events must be iterable: {exc}") from exc

        source_counts: Dict[str, int] = defaultdict(int)
        event_type_counts: Dict[str, int] = defaultdict(int)
        category_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        user_counts: Dict[str, int] = defaultdict(int)
        device_counts: Dict[str, int] = defaultdict(int)
        hour_counts: Dict[int, int] = defaultdict(int)
        day_counts: Dict[int, int] = defaultdict(int)
        user_hour_counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        device_hour_counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

        timestamped = 0
        for ev in extracted:
            if ev.source:
                source_counts[ev.source] += 1
            if ev.event_type:
                event_type_counts[ev.event_type] += 1
            category_counts[ev.category] += 1
            if ev.severity:
                severity_counts[ev.severity] += 1
            if ev.user:
                user_counts[ev.user] += 1
            if ev.device:
                device_counts[ev.device] += 1
            if ev.hour is not None:
                timestamped += 1
                hour_counts[ev.hour] += 1
                day_counts[ev.weekday] += 1
                if ev.user:
                    user_hour_counts[ev.user][ev.hour] += 1
                if ev.device:
                    device_hour_counts[ev.device][ev.hour] += 1

        total = len(extracted)
        status = BASELINE_READY if total >= self.min_baseline_events else BASELINE_INSUFFICIENT
        hour_vector = [hour_counts.get(h, 0) for h in range(24)]

        return BehavioralBaseline(
            total_events=total,
            timestamped_events=timestamped,
            status=status,
            min_baseline_events=self.min_baseline_events,
            source_counts=dict(source_counts),
            event_type_counts=dict(event_type_counts),
            category_counts=dict(category_counts),
            severity_counts=dict(severity_counts),
            user_counts=dict(user_counts),
            device_counts=dict(device_counts),
            hour_counts=dict(hour_counts),
            day_counts=dict(day_counts),
            user_hour_counts={u: dict(h) for u, h in user_hour_counts.items()},
            device_hour_counts={d: dict(h) for d, h in device_hour_counts.items()},
            hourly_mean=_mean(hour_vector),
            hourly_std=_pstd(hour_vector),
        )

    # -- evaluation --------------------------------------------------------

    def _add_rarity(self, out: List[Tuple[str, float, str]], signal: str,
                    count: int, total: int, unseen_weight: float,
                    rare_weight: float, unseen_reason: str, rare_reason: str) -> None:
        """Append a categorical rarity signal to ``out`` if the value is rare."""
        weight, kind = _rarity(count, total, unseen_weight, rare_weight,
                               self.rare_threshold)
        if kind == "unseen":
            out.append((signal, weight, unseen_reason))
        elif kind == "rare":
            out.append((signal, weight, rare_reason))

    def evaluate(self, event, baseline: BehavioralBaseline) -> BehaviorAnomaly:
        """Score one event against ``baseline``; returns a :class:`BehaviorAnomaly`.

        ``event`` may be an Event, sqlite3.Row, dict, or a pre-extracted
        BehaviorEvent. The input is never mutated. When the baseline is a cold
        start the result is INSUFFICIENT_HISTORY (never a false anomaly).
        """
        ev = event if isinstance(event, BehaviorEvent) else self._extract(event, 0)
        if baseline.status != BASELINE_READY:
            return self._insufficient(ev, baseline)

        total = baseline.total_events
        out: List[Tuple[str, float, str]] = []

        # Activity type: assessed via category for known sources, or the raw
        # source label for unknown ("other") sources -- never both, so the two
        # do not double-count the same information.
        if ev.category != CAT_OTHER:
            noun = _CATEGORY_NOUN[ev.category]
            c = baseline.category_counts.get(ev.category, 0)
            self._add_rarity(
                out, SIGNAL_CATEGORY, c, total, _W_UNSEEN_CATEGORY, _W_RARE_CATEGORY,
                f"{noun} has not appeared in the baseline.",
                f"{noun} is unusual compared with historical behaviour ({_pct(c, total)} of events).")
        elif ev.source:
            c = baseline.source_counts.get(ev.source, 0)
            self._add_rarity(
                out, SIGNAL_SOURCE, c, total, _W_UNSEEN_SOURCE, _W_RARE_SOURCE,
                f"Source '{ev.source}' has not appeared in the baseline.",
                f"Source '{ev.source}' is rare in the baseline ({_pct(c, total)}).")

        if ev.event_type:
            c = baseline.event_type_counts.get(ev.event_type, 0)
            self._add_rarity(
                out, SIGNAL_EVENT_TYPE, c, total, _W_UNSEEN_EVENT_TYPE, _W_RARE_EVENT_TYPE,
                f"Event type '{ev.event_type}' has not appeared in the baseline.",
                f"Event type '{ev.event_type}' is rare in the baseline ({_pct(c, total)}).")

        if ev.user:
            c = baseline.user_counts.get(ev.user, 0)
            self._add_rarity(
                out, SIGNAL_USER, c, total, _W_UNSEEN_USER, _W_RARE_USER,
                f"User '{ev.user}' has not appeared in the baseline.",
                f"User '{ev.user}' is rare in the baseline ({_pct(c, total)}).")

        if ev.device:
            c = baseline.device_counts.get(ev.device, 0)
            self._add_rarity(
                out, SIGNAL_DEVICE, c, total, _W_UNSEEN_DEVICE, _W_RARE_DEVICE,
                f"Device '{ev.device}' has not appeared in the baseline.",
                f"Device '{ev.device}' is rare in the baseline ({_pct(c, total)}).")

        if ev.severity:
            c = baseline.severity_counts.get(ev.severity, 0)
            self._add_rarity(
                out, SIGNAL_SEVERITY, c, total, _W_UNSEEN_SEVERITY, _W_RARE_SEVERITY,
                f"Severity '{ev.severity}' has not appeared in the baseline.",
                f"Severity '{ev.severity}' is rare in the baseline ({_pct(c, total)}).")

        out.extend(self._time_signals(ev, baseline))
        return self._finalize(ev, baseline, out)

    def _select_hour_dist(self, ev: BehaviorEvent,
                          baseline: BehavioralBaseline) -> Tuple[Dict[int, int], str]:
        """Pick the most specific trustworthy hour distribution for ``ev``.

        Prefers the event's own user, then its device, then the whole endpoint,
        falling back whenever a subject has fewer than ``min_subject_events``
        timestamped events. Returns (hour->count dist, human scope label).
        """
        if ev.user:
            uh = baseline.user_hour_counts.get(ev.user, {})
            if sum(uh.values()) >= self.min_subject_events:
                return uh, f"user '{ev.user}'"
        if ev.device:
            dh = baseline.device_hour_counts.get(ev.device, {})
            if sum(dh.values()) >= self.min_subject_events:
                return dh, f"device '{ev.device}'"
        return baseline.hour_counts, "the endpoint"

    def _time_signals(self, ev: BehaviorEvent,
                      baseline: BehavioralBaseline) -> List[Tuple[str, float, str]]:
        """Time-of-day / day-of-week signals; empty when no usable timestamp."""
        out: List[Tuple[str, float, str]] = []
        if ev.hour is None:
            return out  # no timestamp -> skipped, never fabricated

        dist, scope = self._select_hour_dist(ev, baseline)
        if sum(dist.values()) > 0:
            hc = dist.get(ev.hour, 0)
            if hc == 0:
                out.append((SIGNAL_HOUR, _W_UNSEEN_HOUR,
                            f"Activity occurred at {ev.hour:02d}:00, outside the "
                            f"normal active hours for {scope}."))
            else:
                vec = [dist.get(h, 0) for h in range(24)]
                z = _zscore(hc, _mean(vec), _pstd(vec))
                if z <= -self.z_threshold:
                    out.append((SIGNAL_FREQUENCY, _W_FREQUENCY_HOUR,
                                f"Activity at {ev.hour:02d}:00 is significantly below "
                                f"the normal level for {scope} (z-score {z:.2f})."))

        if ev.weekday is not None and baseline.timestamped_events > 0:
            if baseline.day_counts.get(ev.weekday, 0) == 0:
                out.append((SIGNAL_DAY, _W_UNSEEN_DAY,
                            f"Activity occurred on {_WEEKDAY_NAMES[ev.weekday]}, a "
                            f"day with no baseline activity."))
        return out

    def _classify(self, score: float) -> str:
        if score >= self.anomalous_score:
            return STATUS_ANOMALOUS
        if score >= self.suspicious_score:
            return STATUS_SUSPICIOUS
        return STATUS_NORMAL

    def _finalize(self, ev: BehaviorEvent, baseline: BehavioralBaseline,
                  contributions: List[Tuple[str, float, str]]) -> BehaviorAnomaly:
        raw = sum(weight for _s, weight, _r in contributions)
        score = round(max(SCORE_MIN, min(SCORE_MAX, raw)), 4)
        classification = self._classify(score)
        signals = sorted({s for s, _w, _r in contributions})
        reasons = sorted({r for _s, _w, r in contributions})
        if not reasons:
            reasons = ["Activity is consistent with the established baseline."]
        return BehaviorAnomaly(
            event=ev,
            anomaly_score=score,
            classification=classification,
            severity=_CLASSIFICATION_SEVERITY[classification],
            reasons=reasons,
            signals=signals,
            baseline_status=baseline.status,
        )

    def _insufficient(self, ev: BehaviorEvent,
                      baseline: BehavioralBaseline) -> BehaviorAnomaly:
        reason = (f"Insufficient baseline history: {baseline.total_events} event(s) "
                  f"observed, {baseline.min_baseline_events} required; activity "
                  f"cannot be assessed as anomalous yet.")
        return BehaviorAnomaly(
            event=ev,
            anomaly_score=0.0,
            classification=STATUS_INSUFFICIENT_HISTORY,
            severity=_CLASSIFICATION_SEVERITY[STATUS_INSUFFICIENT_HISTORY],
            reasons=[reason],
            signals=[],
            baseline_status=baseline.status,
        )

    def evaluate_all(self, events: Iterable,
                     baseline: Optional[BehavioralBaseline] = None) -> List[BehaviorAnomaly]:
        """Evaluate every event against ``baseline`` (built from ``events`` if None).

        Building the baseline from the same events is a reasonable default for a
        one-shot review of a batch; pass an explicit baseline to score new events
        against previously-learned history.
        """
        if events is None:
            raise TypeError("events must be an iterable, got None")
        items = list(events)
        if baseline is None:
            baseline = self.build_baseline(items)
        return [self.evaluate(item, baseline) for item in items]


# --- Module-level convenience wrappers --------------------------------------


def build_baseline(events: Iterable, **engine_kwargs) -> BehavioralBaseline:
    """Build a baseline with a one-off :class:`BehavioralBaselineEngine`."""
    return BehavioralBaselineEngine(**engine_kwargs).build_baseline(events)


def detect_anomalies(events: Iterable, *,
                     baseline: Optional[BehavioralBaseline] = None,
                     **engine_kwargs) -> List[BehaviorAnomaly]:
    """One-shot: build a baseline (if not supplied) and score every event."""
    engine = BehavioralBaselineEngine(**engine_kwargs)
    return engine.evaluate_all(events, baseline=baseline)


def analyze_database(*, limit: Optional[int] = None,
                     **engine_kwargs) -> Tuple[BehavioralBaseline, List[BehaviorAnomaly]]:
    """Read stored events and analyse them (read-only convenience method).

    The database layer is imported lazily so importing this module has no side
    effects and never touches the DB. This reads events only; it never writes
    anomalies back, creates tables, or modifies any stored event or its hashes.
    Returns ``(baseline, anomalies)``.
    """
    from backend.database.db import get_events

    rows = get_events(limit=limit)
    engine = BehavioralBaselineEngine(**engine_kwargs)
    baseline = engine.build_baseline(rows)
    return baseline, engine.evaluate_all(rows, baseline)
