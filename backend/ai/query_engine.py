"""Natural-Language Investigation Engine for ForensiX AI (Phase 12).

Lets an investigator ask a plain-English question ("Show USB activity between
2 PM and 3 PM", "Were there any suspicious file deletions?") and get back a
grounded, evidence-based answer drawn ONLY from the events ForensiX has already
collected.

    question -> deterministic parse -> InvestigationRequest (validated filters)
             -> parameterized, read-only DB retrieval -> events
             -> optional Phase 10 correlation / Phase 11 behavior / Phase 9 integrity
             -> InvestigationContext (the evidence) -> local LLM (Ollama) -> answer

What this is / is NOT
---------------------
* The natural-language layer is an *interface*, never the source of truth. The
  facts come from deterministic retrieval and the existing analysis engines; the
  LLM only phrases them. If the LLM is unavailable the engine still returns the
  full structured result.
* **Security: the natural-language input NEVER becomes SQL.** We do not ask the
  model to write SQL and we never execute model output. The question is parsed
  into a validated ``InvestigationRequest`` and retrieval uses fixed,
  parameterized queries (column names are constants, user text is only ever a
  bound ``?`` parameter). No arbitrary SQL, no code execution.
* The LLM is instructed to answer only from the supplied evidence, to never
  invent events/timestamps/users/devices/files/event-ids, to distinguish facts
  from analysis and correlation from causation, and to treat an anomaly as a
  deviation worth review -- not a confirmed attack.

Read-only over evidence
-----------------------
Every database access is a ``SELECT``. The engine never inserts, updates,
deletes, creates tables, or touches the Phase 9 ``event_hash`` /
``previous_hash`` fields. It imports the existing correlator, behavioral engine
and integrity verifier and calls them without modifying or duplicating them.
"""

from __future__ import annotations

import json
import os
import re
import socket
import sqlite3
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Sequence, Tuple

# Existing analysis engines are imported and *called*, never modified or
# duplicated. None of these touch the database at import time (the DB layer is
# only reached when a query actually runs), so importing here has no side effect.
from backend.ai.behavior import (
    BASELINE_INSUFFICIENT,
    STATUS_ANOMALOUS,
    STATUS_SUSPICIOUS,
    BehavioralBaselineEngine,
)
from backend.ai.correlator import CorrelationEngine
from backend.integrity.verifier import verify_chain


# --- Configuration defaults (all caller-configurable, never hardcoded) ------

DEFAULT_LIMIT = 100            # events returned when the query gives no explicit cap
MAX_LIMIT = 1000               # hard ceiling; protects the DB and the LLM context
DEFAULT_OLLAMA_MODEL = "llama3"        # overridable via OLLAMA_MODEL env var
DEFAULT_OLLAMA_HOST = "http://localhost:11434"  # overridable via OLLAMA_HOST
DEFAULT_OLLAMA_TIMEOUT = 60.0          # seconds; overridable via OLLAMA_TIMEOUT

# --- Intents (what the investigator is trying to do) ------------------------

INTENT_SEARCH = "search"           # plain lookup/filter of events
INTENT_TIMELINE = "timeline"       # ordered "what happened" view
INTENT_CORRELATION = "correlation"  # related events / incidents
INTENT_BEHAVIOR = "behavior"       # unusual / suspicious activity
INTENT_EXPLAIN = "explain"         # "why / explain this"
_VALID_INTENTS = {INTENT_SEARCH, INTENT_TIMELINE, INTENT_CORRELATION,
                  INTENT_BEHAVIOR, INTENT_EXPLAIN}

# --- Collector source labels (must match backend/collectors/*) --------------

SOURCE_USB = "USB"
SOURCE_FILE = "FileSystem"
SOURCE_BROWSER = "Browser"
SOURCE_DEFENDER = "Defender"
SOURCE_WINDOWS = "Windows"

# Severities that may legitimately appear on a stored event. An explicit
# severity filter outside this set is rejected as an invalid filter.
KNOWN_SEVERITIES = {"INFO", "LOW", "WARNING", "MEDIUM", "ERROR", "HIGH",
                    "CRITICAL", "AUDIT_SUCCESS", "AUDIT_FAILURE"}

# Integrity annotation labels (mirror the correlator's, Phase 9 aware). We never
# claim to have verified the chain unless the verifier was actually run.
INTEGRITY_LEGACY = "LEGACY"
INTEGRITY_HASHED_UNVERIFIED = "HASHED_UNVERIFIED"
INTEGRITY_VERIFIED = "VERIFIED"
INTEGRITY_TAMPERED = "TAMPERED"

# The only columns retrieval will ever reference. Fixed constants -- never built
# from user input -- so the query shape can never be influenced by the question.
_EVENT_COLUMNS = ("id", "timestamp", "source", "event_type", "description",
                  "severity", "user", "device", "file_path", "metadata",
                  "event_hash", "previous_hash")

# Fixed user-facing messages (deterministic, no fabrication).
NO_EVIDENCE_MESSAGE = "No matching evidence was found in the collected ForensiX data."
INSUFFICIENT_EVIDENCE_MESSAGE = "The available evidence is insufficient to determine this."
LLM_UNAVAILABLE_MESSAGE = ("Natural-language explanation unavailable because the "
                           "local LLM is unavailable.")
LLM_EMPTY_MESSAGE = ("Natural-language explanation unavailable because the local "
                     "LLM returned an empty response.")

# Answer provenance, so callers can tell where the text came from.
ANSWER_SOURCE_LLM = "llm"
ANSWER_SOURCE_NO_EVIDENCE = "no_evidence"
ANSWER_SOURCE_FALLBACK = "deterministic_fallback"

# --- Exceptions -------------------------------------------------------------


class LLMError(Exception):
    """Base class for local-LLM failures. Never raised to callers of
    ``investigate`` -- the engine catches these and degrades gracefully."""


class LLMUnavailableError(LLMError):
    """Ollama could not be reached (not installed/running, timeout, HTTP error)."""


class LLMResponseError(LLMError):
    """Ollama replied but the response was malformed or unusable."""


# --- Deterministic natural-language keyword maps ----------------------------
# Order matters only where noted; matching is case-insensitive and uses word
# boundaries so "profile" never triggers the "file" source, etc.

# (regex, source label). Checked in order; all matches are collected.
_SOURCE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\busb\b|\bremovable\b|\bthumb ?drive\b|\bflash ?drive\b", SOURCE_USB),
    (r"\bfile ?system\b|\bfiles?\b|\bfolder\b|\bdirector(?:y|ies)\b", SOURCE_FILE),
    (r"\bbrowser\b|\bbrowsing\b|\bweb\b|\bwebsite\b|\burl\b|\bvisited?\b", SOURCE_BROWSER),
    (r"\bdefender\b|\bantiviru?s\b|\banti-viru?s\b|\bmalware\b|\bthreat\b|\bvirus\b", SOURCE_DEFENDER),
    (r"\bwindows event\b|\bevent log\b|\blog[- ]?on\b|\blog[- ]?in\b|\bsign[- ]?in\b", SOURCE_WINDOWS),
)

# (regex, event_type). Collected in order.
_EVENT_TYPE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bdelet(?:e|ed|ion|ions)\b|\bremoved file\b", "FILE_DELETED"),
    (r"\bcreat(?:e|ed|ion|ions)\b|\bnew file\b", "FILE_CREATED"),
    (r"\bmodif(?:y|ied|ication|ications)\b|\bchanged? file\b|\bedited?\b", "FILE_MODIFIED"),
    (r"\brenamed?\b|\brenaming\b", "FILE_RENAMED"),
    (r"\b(?:connect(?:ed|ion)?|plugged ?in|inserted?|mounted)\b", "USB_CONNECTED"),
    (r"\b(?:disconnect(?:ed|ion)?|unplugged|ejected|removed drive)\b", "USB_DISCONNECTED"),
    (r"\bvisit(?:ed|s)?\b|\bbrowsed?\b", "BROWSER_VISIT"),
)

# (regex, severity). Longest/most-specific first so "high severity" wins.
_SEVERITY_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bcritical\b", "CRITICAL"),
    (r"\bhigh[- ]?(?:severity|risk|priority)?\b|\bsevere\b", "HIGH"),
    (r"\bmedium[- ]?severity\b|\bmoderate\b", "MEDIUM"),
    (r"\bwarnings?\b", "WARNING"),
    (r"\blow[- ]?severity\b", "LOW"),
    (r"\binformational\b|\binfo\b", "INFO"),
)

# Behavioral / correlation / explanation intent triggers.
_BEHAVIOR_WORDS = re.compile(
    r"\b(suspicious|unusual|anomal(?:y|ous|ies)|abnormal|weird|strange|"
    r"out of the ordinary|off[- ]hours|unexpected)\b", re.IGNORECASE)
_CORRELATION_WORDS = re.compile(
    r"\b(related|connected|correlat(?:e|ed|ion)|incidents?|linked|together|"
    r"what else|around (?:this|that|the))\b", re.IGNORECASE)
_EXPLAIN_WORDS = re.compile(
    r"\b(why|explain|how did|what does this mean|what happened here)\b",
    re.IGNORECASE)
_TIMELINE_WORDS = re.compile(
    r"\b(timeline|sequence|chronolog|what happened)\b", re.IGNORECASE)
_INTEGRITY_WORDS = re.compile(
    r"\b(tamper(?:ed|ing)?|integrity|altered|modified evidence|verif(?:y|ied)|"
    r"chain of custody)\b", re.IGNORECASE)

# A filename-like token (has an extension) or an explicit path.
_FILENAME_RE = re.compile(r"[A-Za-z0-9_\-][A-Za-z0-9_\-.]*\.[A-Za-z0-9]{1,8}")
_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\|/)[^\s\"']+")
_USER_RE = re.compile(r"\buser\s+(?:named\s+|account\s+)?['\"]?([A-Za-z0-9._\-\\]+)",
                      re.IGNORECASE)
_DEVICE_RE = re.compile(
    r"\b(?:device|host|hostname|machine|computer|endpoint)\s+['\"]?([A-Za-z0-9._\-]+)",
    re.IGNORECASE)

# --- Field access / coercion (works for sqlite3.Row, dict, or Event) --------
# Kept local (mirrors the correlator / behavior helpers) so this module is
# independently testable and never fabricates values.


def _field(obj, name, default=None):
    """Read ``name`` from a sqlite3.Row, dict, or object, else ``default``.

    ``None`` is normalised to ``default``. Never raises for a missing field.
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

    Accepts a datetime, epoch number, or ISO/SQLite-style string. A
    missing/invalid timestamp yields ``None`` -- the engine never invents time.
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


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards so user text is matched literally (ESCAPE '\\').

    This is defence-in-depth for pattern semantics; injection is already
    impossible because the value is a bound parameter, never SQL text.
    """
    return (value.replace("\\", "\\\\")
                 .replace("%", "\\%")
                 .replace("_", "\\_"))


_CLOCK_RE = re.compile(
    r"\b(\d{1,2})(?::(\d{2}))?\s*(a\.?m\.?|p\.?m\.?)?\b", re.IGNORECASE)


def _parse_clock_hour(text: str) -> Optional[int]:
    """Parse a clock time ("3 PM", "15:00", "2 p.m.") into an hour 0-23, or None."""
    match = _CLOCK_RE.search(text)
    if not match:
        return None
    hour = int(match.group(1))
    meridiem = (match.group(3) or "").replace(".", "").lower()
    if meridiem == "pm":
        if hour < 12:
            hour += 12
    elif meridiem == "am":
        if hour == 12:
            hour = 0
    if 0 <= hour <= 23:
        return hour
    return None


# --- Structured, validated investigation request ---------------------------


@dataclass
class InvestigationRequest:
    """A validated, deterministic description of what to retrieve and analyse.

    Produced by parsing a natural-language question (or built directly by a
    caller). Every field is a plain filter; the natural-language text has been
    reduced to these safe values before any database access. Constructing the
    request validates it -- an out-of-range or unsupported filter raises
    ``ValueError`` rather than silently returning wrong evidence.
    """

    original_question: str = ""
    intent: str = INTENT_SEARCH
    sources: Tuple[str, ...] = ()
    event_types: Tuple[str, ...] = ()
    keywords: Tuple[str, ...] = ()
    user: Optional[str] = None
    device: Optional[str] = None
    file_path: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    hour_start: Optional[int] = None
    hour_end: Optional[int] = None
    limit: int = DEFAULT_LIMIT
    include_correlations: bool = False
    include_behavior: bool = False
    verify_integrity: bool = False
    warnings: Tuple[str, ...] = ()

    def __post_init__(self):
        notes: List[str] = list(self.warnings)

        self.sources = tuple(dict.fromkeys(self.sources))          # de-dup, keep order
        self.event_types = tuple(dict.fromkeys(self.event_types))
        self.keywords = tuple(dict.fromkeys(self.keywords))
        if self.intent not in _VALID_INTENTS:
            self.intent = INTENT_SEARCH

        for name in ("user", "device", "file_path"):
            value = getattr(self, name)
            if value is not None:
                value = str(value).strip()
                setattr(self, name, value or None)

        if self.severity is not None:
            self.severity = str(self.severity).strip().upper()
            if self.severity not in KNOWN_SEVERITIES:
                raise ValueError(f"unsupported severity filter: {self.severity!r}")

        # Hour-of-day window (0-23): both bounds together, ordered.
        for name in ("hour_start", "hour_end"):
            value = getattr(self, name)
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(f"{name} must be an integer hour 0-23")
                if not (0 <= value <= 23):
                    raise ValueError(f"{name} must be between 0 and 23")
        if (self.hour_start is None) != (self.hour_end is None):
            raise ValueError("hour_start and hour_end must be provided together")
        if (self.hour_start is not None and self.hour_end is not None
                and self.hour_start > self.hour_end):
            raise ValueError("hour_start must not be after hour_end")

        # Absolute time window.
        if self.start_time is not None and not isinstance(self.start_time, datetime):
            raise ValueError("start_time must be a datetime")
        if self.end_time is not None and not isinstance(self.end_time, datetime):
            raise ValueError("end_time must be a datetime")
        if (self.start_time is not None and self.end_time is not None
                and self.start_time > self.end_time):
            raise ValueError("start_time must not be after end_time")

        # Result limit: positive, capped at MAX_LIMIT (protects DB and LLM).
        if isinstance(self.limit, bool) or not isinstance(self.limit, int):
            raise ValueError("limit must be a positive integer")
        if self.limit <= 0:
            raise ValueError("limit must be a positive integer")
        if self.limit > MAX_LIMIT:
            notes.append(f"requested limit {self.limit} capped at {MAX_LIMIT}")
            self.limit = MAX_LIMIT

        # __POSTINIT__
        self.warnings = tuple(notes)

    def as_dict(self) -> dict:
        return {
            "original_question": self.original_question,
            "intent": self.intent,
            "sources": list(self.sources),
            "event_types": list(self.event_types),
            "keywords": list(self.keywords),
            "user": self.user,
            "device": self.device,
            "file_path": self.file_path,
            "severity": self.severity,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "hour_start": self.hour_start,
            "hour_end": self.hour_end,
            "limit": self.limit,
            "include_correlations": self.include_correlations,
            "include_behavior": self.include_behavior,
            "verify_integrity": self.verify_integrity,
            "warnings": list(self.warnings),
        }


# --- Deterministic natural-language parser ----------------------------------


def parse_question(question: Optional[str], *,
                   default_limit: int = DEFAULT_LIMIT,
                   **overrides) -> InvestigationRequest:
    """Turn a natural-language question into a validated ``InvestigationRequest``.

    Purely deterministic: the same text and overrides always yield the same
    request. Nothing here touches the database or the LLM. Explicit ``overrides``
    (e.g. ``severity="HIGH"``, ``limit=25``, ``start_time=...``) take precedence
    over anything parsed from the text, giving callers a safe programmatic path.
    """
    text = question or ""
    low = text.lower()

    sources = [label for pat, label in _SOURCE_PATTERNS if re.search(pat, low)]
    event_types = [et for pat, et in _EVENT_TYPE_PATTERNS if re.search(pat, low)]

    severity = None
    for pat, sev in _SEVERITY_PATTERNS:
        if re.search(pat, low):
            severity = sev
            break

    # Keywords / file references (kept as literal bound parameters downstream).
    keywords: List[str] = []
    file_path: Optional[str] = None
    path_match = _PATH_RE.search(text)
    if path_match:
        file_path = path_match.group(0)
    for token in _FILENAME_RE.findall(text):
        token = token.strip()
        if token and token not in keywords:
            keywords.append(token)
    for quoted in re.findall(r"['\"]([^'\"]{2,})['\"]", text):
        quoted = quoted.strip()
        if quoted and quoted not in keywords:
            keywords.append(quoted)

    user_match = _USER_RE.search(text)
    user = user_match.group(1) if user_match else None
    device_match = _DEVICE_RE.search(text)
    device = device_match.group(1) if device_match else None

    hour_start, hour_end = _parse_time_window(low)
    intent, flags = _parse_intent(text)

    fields = dict(
        original_question=text,
        intent=intent,
        sources=tuple(sources),
        event_types=tuple(event_types),
        keywords=tuple(keywords),
        user=user,
        device=device,
        file_path=file_path,
        severity=severity,
        hour_start=hour_start,
        hour_end=hour_end,
        limit=default_limit,
        **flags,
    )
    fields.update(overrides)  # explicit caller overrides win
    return InvestigationRequest(**fields)


def _parse_time_window(low: str) -> Tuple[Optional[int], Optional[int]]:
    """Parse an hour-of-day window from lowercased text (hour-of-day, 0-23).

    "between 2 pm and 3 pm" -> (14, 15); "around 3 pm"/"at 15:00" -> (15, 15);
    "after 5 pm" -> (17, 23); "before 9 am" -> (0, 9). Returns (None, None)
    when no clock time is present. Interpreted as hour-of-day across the data,
    inclusive of both named hours -- a triage aid, not sub-hour precision.
    """
    between = re.search(r"\bbetween\b\s+(.+?)\s+\band\b\s+(.+)", low)
    if between:
        h1 = _parse_clock_hour(between.group(1))
        h2 = _parse_clock_hour(between.group(2))
        if h1 is not None and h2 is not None:
            return (h1, h2) if h1 <= h2 else (h2, h1)
    after = re.search(r"\bafter\b\s+(.+)", low)
    if after:
        h = _parse_clock_hour(after.group(1))
        if h is not None:
            return h, 23
    before = re.search(r"\bbefore\b\s+(.+)", low)
    if before:
        h = _parse_clock_hour(before.group(1))
        if h is not None:
            return 0, h
    around = re.search(r"\b(?:around|about|near|at)\b\s+(.+)", low)
    if around:
        h = _parse_clock_hour(around.group(1))
        if h is not None:
            return h, h
    return None, None


def _parse_intent(text: str) -> Tuple[str, dict]:
    """Infer intent + which analyses to run from the question wording."""
    intent = INTENT_SEARCH
    flags = {"include_correlations": False, "include_behavior": False,
             "verify_integrity": False}
    if _TIMELINE_WORDS.search(text):
        intent = INTENT_TIMELINE
    if _CORRELATION_WORDS.search(text):
        intent, flags["include_correlations"] = INTENT_CORRELATION, True
    if _BEHAVIOR_WORDS.search(text):
        intent, flags["include_behavior"] = INTENT_BEHAVIOR, True
    if _EXPLAIN_WORDS.search(text):
        intent = INTENT_EXPLAIN
        flags["include_correlations"] = flags["include_behavior"] = True
    if _INTEGRITY_WORDS.search(text):
        flags["verify_integrity"] = True
    return intent, flags


# --- Evidence + context + result objects ------------------------------------


@dataclass(frozen=True)
class EvidenceRecord:
    """A read-only snapshot of one retrieved event (the identifiable evidence).

    ``event_id`` is the database ``id`` when the event came from a stored row and
    ``None`` otherwise; ``db_backed`` makes that explicit so a caller never
    mistakes an ad-hoc Event for a persisted, id-addressable record. The original
    row/Event is copied, never mutated, and the raw hashes are not exposed here
    (only the derived ``integrity`` label is).
    """

    event_id: Optional[int]
    db_backed: bool
    timestamp: Optional[datetime]
    source: str
    event_type: str
    description: str
    severity: str
    user: str
    device: str
    file_path: str
    metadata: str
    integrity: str

    @classmethod
    def from_item(cls, item, integrity_label: str) -> "EvidenceRecord":
        event_id = _field(item, "id", None)
        if isinstance(event_id, bool):
            event_id = None
        return cls(
            event_id=event_id,
            db_backed=event_id is not None,
            timestamp=_coerce_timestamp(_field(item, "timestamp", None)),
            source=str(_field(item, "source", "") or ""),
            event_type=str(_field(item, "event_type", "") or ""),
            description=str(_field(item, "description", "") or ""),
            severity=str(_field(item, "severity", "") or ""),
            user=str(_field(item, "user", "") or ""),
            device=str(_field(item, "device", "") or ""),
            file_path=str(_field(item, "file_path", "") or ""),
            metadata=str(_field(item, "metadata", "") or ""),
            integrity=integrity_label,
        )

    def reference(self) -> str:
        """A human/LLM-facing identifier that never invents an id."""
        if self.db_backed:
            return f"event {self.event_id}"
        return "an event with no database id"

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "db_backed": self.db_backed,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "user": self.user,
            "device": self.device,
            "file_path": self.file_path,
            "metadata": self.metadata,
            "integrity": self.integrity,
        }


@dataclass
class InvestigationContext:
    """The complete, serialisable evidence package assembled for a question.

    This is exactly the material handed to the LLM (nothing else is): the parsed
    request, the retrieved events, any correlation/behavioral/integrity analysis,
    warnings, and retrieval metadata. It is produced deterministically and does
    not depend on the LLM in any way.
    """

    original_question: str
    request: InvestigationRequest
    retrieved_events: List[EvidenceRecord] = field(default_factory=list)
    candidate_incidents: List[dict] = field(default_factory=list)
    behavioral_anomalies: List[dict] = field(default_factory=list)
    behavioral_baseline_status: Optional[str] = None
    integrity: Optional[dict] = None
    warnings: List[str] = field(default_factory=list)
    retrieval_metadata: dict = field(default_factory=dict)

    @property
    def evidence_count(self) -> int:
        return len(self.retrieved_events)

    @property
    def evidence_ids(self) -> List[int]:
        return [e.event_id for e in self.retrieved_events if e.db_backed]

    def as_dict(self) -> dict:
        return {
            "original_question": self.original_question,
            "request": self.request.as_dict(),
            "evidence_count": self.evidence_count,
            "evidence_ids": self.evidence_ids,
            "retrieved_events": [e.as_dict() for e in self.retrieved_events],
            "candidate_incidents": list(self.candidate_incidents),
            "behavioral_anomalies": list(self.behavioral_anomalies),
            "behavioral_baseline_status": self.behavioral_baseline_status,
            "integrity": self.integrity,
            "warnings": list(self.warnings),
            "retrieval_metadata": dict(self.retrieval_metadata),
        }


@dataclass
class InvestigationResult:
    """The full outcome of an investigation: deterministic context + LLM answer.

    ``answer`` is the natural-language explanation when the LLM produced one, or
    the fixed no-evidence message, or ``None`` when the LLM was unavailable. In
    every case ``context`` (the deterministic evidence) and
    ``deterministic_summary`` are populated, so the result is useful even with no
    LLM. ``message`` carries the reason when no LLM answer is available.
    """

    context: InvestigationContext
    answer: Optional[str] = None
    answer_source: str = ANSWER_SOURCE_FALLBACK
    message: Optional[str] = None
    llm_available: bool = False
    llm_error: Optional[str] = None
    llm_model: Optional[str] = None
    deterministic_summary: str = ""

    def as_dict(self) -> dict:
        return {
            "answer": self.answer,
            "answer_source": self.answer_source,
            "message": self.message,
            "llm_available": self.llm_available,
            "llm_error": self.llm_error,
            "llm_model": self.llm_model,
            "deterministic_summary": self.deterministic_summary,
            "context": self.context.as_dict(),
        }


# --- Safe, parameterized retrieval ------------------------------------------


def build_retrieval_query(request: InvestigationRequest) -> Tuple[str, list]:
    """Build a fully parameterized ``SELECT`` for a request.

    The SQL *shape* is built only from fixed constants (column names, operators).
    Every value derived from the user's question is a bound ``?`` parameter and
    never appears in the SQL text -- so the natural-language input can never
    become SQL. Returns ``(sql, params)``.
    """
    clauses: List[str] = []
    params: list = []

    if request.sources:
        placeholders = ",".join("?" for _ in request.sources)
        clauses.append(f"source IN ({placeholders})")
        params.extend(request.sources)
    if request.event_types:
        placeholders = ",".join("?" for _ in request.event_types)
        clauses.append(f"event_type IN ({placeholders})")
        params.extend(request.event_types)
    if request.severity:
        clauses.append("severity = ?")
        params.append(request.severity)
    if request.user:
        clauses.append("user = ?")
        params.append(request.user)
    if request.device:
        clauses.append("device = ?")
        params.append(request.device)
    if request.file_path:
        clauses.append("file_path LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(request.file_path)}%")
    for keyword in request.keywords:
        like = f"%{_escape_like(keyword)}%"
        clauses.append("(description LIKE ? ESCAPE '\\' "
                       "OR file_path LIKE ? ESCAPE '\\' "
                       "OR metadata LIKE ? ESCAPE '\\')")
        params.extend([like, like, like])
    if request.start_time is not None:
        clauses.append("timestamp >= ?")
        params.append(request.start_time.isoformat())
    if request.end_time is not None:
        clauses.append("timestamp <= ?")
        params.append(request.end_time.isoformat())
    if request.hour_start is not None and request.hour_end is not None:
        clauses.append("CAST(strftime('%H', REPLACE(timestamp, 'T', ' ')) "
                       "AS INTEGER) BETWEEN ? AND ?")
        params.extend([request.hour_start, request.hour_end])

    columns = ", ".join(_EVENT_COLUMNS)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (f"SELECT {columns} FROM events{where} "
           f"ORDER BY timestamp ASC, id ASC LIMIT ?")
    params.append(request.limit)
    return sql, params


# --- Local LLM (Ollama) client ----------------------------------------------


class OllamaClient:
    """Minimal client for a *local* Ollama server (privacy-preserving).

    Uses only the standard library (``urllib``) so no new dependency is needed.
    The model, host, and timeout are configurable via constructor arguments or
    the ``OLLAMA_MODEL`` / ``OLLAMA_HOST`` / ``OLLAMA_TIMEOUT`` environment
    variables -- no single model is hardcoded. Evidence is only ever sent to
    this local endpoint, never to a cloud API.

    ``generate`` raises :class:`LLMUnavailableError` when the server cannot be
    reached and :class:`LLMResponseError` for a malformed reply; the engine
    turns both into a graceful, evidence-only result.
    """

    def __init__(self, *, model: Optional[str] = None, host: Optional[str] = None,
                 timeout: Optional[float] = None):
        self.model = model or os.environ.get("OLLAMA_MODEL") or DEFAULT_OLLAMA_MODEL
        self.host = (host or os.environ.get("OLLAMA_HOST")
                     or DEFAULT_OLLAMA_HOST).rstrip("/")
        env_timeout = os.environ.get("OLLAMA_TIMEOUT")
        if timeout is not None:
            self.timeout = float(timeout)
        elif env_timeout:
            try:
                self.timeout = float(env_timeout)
            except ValueError:
                self.timeout = DEFAULT_OLLAMA_TIMEOUT
        else:
            self.timeout = DEFAULT_OLLAMA_TIMEOUT

    def generate(self, prompt: str, *, system: Optional[str] = None) -> str:
        """Send a non-streaming generation request; return the response text."""
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        if system:
            payload["system"] = system
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/generate", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            raise LLMUnavailableError(f"could not reach Ollama at {self.host}: {exc}") from exc
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            raise LLMResponseError(f"malformed response from Ollama: {exc}") from exc
        if not isinstance(parsed, dict) or "response" not in parsed:
            raise LLMResponseError("Ollama response missing the 'response' field")
        return str(parsed.get("response") or "")


# --- Grounded prompt construction -------------------------------------------

GROUNDING_SYSTEM_PROMPT = (
    "You are a forensic analysis assistant for ForensiX AI. Answer the "
    "investigator's question using ONLY the evidence in the EVIDENCE section "
    "below. Follow these rules strictly:\n"
    "1. Do NOT invent, assume, or fabricate any events, timestamps, users, "
    "devices, files, paths, IP addresses, or event IDs. Use only what the "
    "evidence contains.\n"
    "2. If the evidence does not support an answer, say the evidence is "
    "insufficient rather than guessing.\n"
    "3. Clearly distinguish observed facts (what the evidence shows) from "
    "analysis or interpretation (what it might indicate).\n"
    "4. Never claim an attack, breach, malware infection, data theft, or "
    "attacker occurred unless the evidence explicitly shows it. Describe what "
    "the evidence contains, not what you imagine happened.\n"
    "5. Correlation and temporal proximity are NOT proof of causation. Say "
    "events are 'related' or 'occurred close in time', never that one 'caused' "
    "another, unless the evidence states it.\n"
    "6. A behavioral anomaly is a deviation from normal patterns that warrants "
    "review -- it is NOT confirmed malicious activity. Present it as such.\n"
    "7. When you refer to an event, cite its event ID (for example, 'event 42') "
    "when one is provided in the evidence.\n"
    "8. Do not strengthen, exaggerate, or extrapolate beyond what the "
    "deterministic evidence and analysis already state.\n"
    "9. Be concise, factual, and neutral. If the question cannot be answered "
    "from the evidence, say so plainly."
)

_PROMPT_EVENT_CAP = 200          # never dump unlimited history into the LLM
_PROMPT_FIELD_CAP = 400          # trim over-long description/metadata fields


def _trim(text: str, cap: int = _PROMPT_FIELD_CAP) -> str:
    text = text or ""
    return text if len(text) <= cap else text[:cap] + "..."


def _format_evidence_block(context: InvestigationContext) -> str:
    """Render the retrieved evidence as compact, factual text for the LLM."""
    lines: List[str] = []
    events = context.retrieved_events[:_PROMPT_EVENT_CAP]
    lines.append(f"Events retrieved: {context.evidence_count} "
                 f"(showing {len(events)}).")
    for ev in events:
        ident = ev.reference()
        ts = ev.timestamp.isoformat() if ev.timestamp else "unknown-time"
        detail = _trim(ev.description)
        extra = []
        if ev.user:
            extra.append(f"user={ev.user}")
        if ev.device:
            extra.append(f"device={ev.device}")
        if ev.file_path:
            extra.append(f"path={_trim(ev.file_path, 200)}")
        extra.append(f"integrity={ev.integrity}")
        lines.append(f"- [{ident}] {ts} {ev.source}/{ev.event_type} "
                     f"({ev.severity}): {detail} [{', '.join(extra)}]")
    return "\n".join(lines)


def build_prompt(context: InvestigationContext) -> Tuple[str, str]:
    """Return ``(prompt, system)`` grounding the LLM in the retrieved evidence."""
    parts: List[str] = [f"QUESTION: {context.original_question}", "", "EVIDENCE:"]
    parts.append(_format_evidence_block(context))

    if context.candidate_incidents:
        parts.append("")
        parts.append("CORRELATION (candidate incidents -- related events, not "
                     "proof of an attack):")
        for inc in context.candidate_incidents:
            parts.append(
                f"- {inc.get('incident_id')}: events {inc.get('event_ids')}, "
                f"priority {inc.get('priority')}, "
                f"confidence {inc.get('confidence_score')} "
                f"({', '.join(inc.get('correlation_reasons', []))})")

    if context.behavioral_anomalies:
        parts.append("")
        parts.append("BEHAVIORAL ANALYSIS (deviations from baseline -- NOT "
                     "confirmed malicious activity):")
        for anomaly in context.behavioral_anomalies:
            parts.append(
                f"- {anomaly.get('classification')} "
                f"(score {anomaly.get('anomaly_score')}): "
                f"{'; '.join(anomaly.get('reasons', []))}")
    elif context.behavioral_baseline_status == BASELINE_INSUFFICIENT:
        parts.append("")
        parts.append("BEHAVIORAL ANALYSIS: insufficient baseline history to "
                     "assess anomalies.")

    if context.integrity is not None:
        parts.append("")
        parts.append(
            f"INTEGRITY: chain valid={context.integrity.get('valid')}, "
            f"hashed={context.integrity.get('hashed_events')}, "
            f"legacy={context.integrity.get('legacy_events')}, "
            f"invalid/tampered ids={[e['id'] for e in context.integrity.get('invalid_events', [])]}.")

    return "\n".join(parts), GROUNDING_SYSTEM_PROMPT


# --- Deterministic (LLM-free) summary ---------------------------------------


def build_deterministic_summary(context: InvestigationContext) -> str:
    """A concise, factual summary built without the LLM.

    Always available, so an investigation is useful even when the local LLM is
    not. States only what the deterministic layers established -- no narrative,
    no speculation.
    """
    if context.evidence_count == 0:
        return NO_EVIDENCE_MESSAGE

    source_counts: dict = {}
    for ev in context.retrieved_events:
        source_counts[ev.source] = source_counts.get(ev.source, 0) + 1
    breakdown = ", ".join(f"{src}={count}"
                          for src, count in sorted(source_counts.items()))
    parts = [f"Retrieved {context.evidence_count} matching event(s) [{breakdown}]."]

    times = [ev.timestamp for ev in context.retrieved_events if ev.timestamp]
    if times:
        parts.append(f"Time range: {min(times).isoformat()} to "
                     f"{max(times).isoformat()}.")

    if context.candidate_incidents:
        parts.append(f"{len(context.candidate_incidents)} candidate incident(s) "
                     "of related events (correlation, not proof of an attack).")
    if context.behavioral_anomalies:
        parts.append(f"{len(context.behavioral_anomalies)} event(s) deviate from "
                     "the behavioral baseline (review-worthy, not confirmed "
                     "malicious).")
    elif context.behavioral_baseline_status == BASELINE_INSUFFICIENT:
        parts.append("Behavioral baseline has insufficient history to assess "
                     "anomalies.")
    if context.integrity is not None:
        if context.integrity.get("valid"):
            parts.append("Integrity: hash chain intact for the checked events.")
        else:
            parts.append("Integrity: chain verification found issues "
                         f"(ids {[e['id'] for e in context.integrity.get('invalid_events', [])]}).")
    return " ".join(parts)


_DEFAULT_LLM = object()  # sentinel: build a default OllamaClient lazily


# --- The investigation engine -----------------------------------------------


class InvestigationQueryEngine:
    """Orchestrates parse -> retrieve -> analyse -> ground into an answer.

    Args:
        llm: object exposing ``generate(prompt, system=...) -> str``. Defaults to
            a lazily-created :class:`OllamaClient` (local). Pass ``None`` to run
            with no LLM (deterministic-only), or a stub in tests.
        connection_factory: zero-arg callable returning a DB connection. Defaults
            to the project's ``get_connection``. Injected in tests to point at an
            isolated database. Retrieval is always read-only (``SELECT`` only).
        default_limit: result cap applied when a query specifies none.
        correlation_kwargs / behavior_kwargs: forwarded to the Phase 10 / Phase 11
            engines so their thresholds stay configurable.
    """

    def __init__(self, *, llm=_DEFAULT_LLM, connection_factory=None,
                 default_limit: int = DEFAULT_LIMIT,
                 correlation_kwargs: Optional[dict] = None,
                 behavior_kwargs: Optional[dict] = None):
        self._llm_arg = llm
        self._connection_factory = connection_factory
        self.default_limit = int(default_limit)
        self._correlation_kwargs = dict(correlation_kwargs or {})
        self._correlation_kwargs.pop("integrity_result", None)  # set by the engine
        self._behavior_kwargs = dict(behavior_kwargs or {})

    # -- parsing -----------------------------------------------------------

    def parse(self, question, **overrides) -> InvestigationRequest:
        """Parse a question (or apply overrides) into a validated request."""
        return parse_question(question, default_limit=self.default_limit,
                              **overrides)

    # -- database access (read-only) --------------------------------------

    def _connect(self):
        if self._connection_factory is not None:
            conn = self._connection_factory()
        else:
            from backend.database.db import get_connection
            conn = get_connection()
        conn.row_factory = sqlite3.Row
        return conn

    def _retrieve_from_db(self, request: InvestigationRequest):
        """Run the parameterized filter query + (when needed) fetch full history.

        Returns ``(filtered_rows, history_rows_or_None, warnings)``. ``history``
        is the whole event table in chain (id) order, fetched only when behavior
        or integrity analysis needs it -- and kept separate from the investigated
        subset so a baseline is never built from just the events being examined.
        """
        warnings: List[str] = []
        need_history = request.include_behavior or request.verify_integrity
        conn = self._connect()
        try:
            sql, params = build_retrieval_query(request)
            try:
                filtered = conn.execute(sql, params).fetchall()
                history = (conn.execute(
                    f"SELECT {', '.join(_EVENT_COLUMNS)} FROM events "
                    "ORDER BY id ASC").fetchall() if need_history else None)
            except sqlite3.OperationalError as exc:
                warnings.append(f"retrieval skipped: {exc}")
                return [], (None if not need_history else []), warnings
        finally:
            conn.close()
        return list(filtered), (list(history) if history is not None else None), warnings

    @staticmethod
    def _integrity_label(item, verified: bool, invalid_ids) -> str:
        """Label one event's integrity without claiming to verify unless run."""
        event_hash = _field(item, "event_hash", None)
        if event_hash in (None, ""):
            return INTEGRITY_LEGACY
        if not verified:
            return INTEGRITY_HASHED_UNVERIFIED
        event_id = _field(item, "id", None)
        if invalid_ids and event_id in invalid_ids:
            return INTEGRITY_TAMPERED
        return INTEGRITY_VERIFIED

    # -- analysis integrations (imported engines, never modified) ----------

    def _run_integrity(self, chain_rows):
        """Verify the hash chain (Phase 9) over ``chain_rows``; read-only.

        The verifier needs database-backed rows in chain order. When only bare
        Event objects are available it is skipped with a warning rather than
        fabricating a result.
        """
        warnings: List[str] = []
        if chain_rows is None:
            warnings.append("integrity verification requires database-backed "
                            "events; skipped.")
            return None, warnings
        try:
            result = verify_chain(rows=list(chain_rows))
        except Exception as exc:  # non-row inputs / unexpected shapes
            warnings.append(f"integrity verification skipped: {exc}")
            return None, warnings
        return result, warnings

    def _run_behavior(self, filtered, history):
        """Score the retrieved events against a baseline (Phase 11).

        The baseline is built from historical events kept separate from the
        events under investigation; only when no historical data exists does it
        fall back to the retrieved set (and says so). An insufficient-history
        baseline is preserved, not forced into a false anomaly.
        """
        warnings: List[str] = []
        engine = BehavioralBaselineEngine(**self._behavior_kwargs)
        if history is not None:
            baseline_source = history
        else:
            baseline_source = filtered
            warnings.append("behavioral baseline built from the investigated "
                            "events (no separate historical data available).")
        baseline = engine.build_baseline(baseline_source)
        anomalies: List[dict] = []
        for row in filtered:
            anomaly = engine.evaluate(row, baseline)
            if anomaly.classification in (STATUS_SUSPICIOUS, STATUS_ANOMALOUS):
                anomalies.append(anomaly.as_dict())
        if baseline.status == BASELINE_INSUFFICIENT:
            warnings.append(
                f"behavioral baseline insufficient: {baseline.total_events} "
                f"event(s), {baseline.min_baseline_events} required.")
        return anomalies, baseline.status, warnings

    # -- context assembly --------------------------------------------------

    def build_context(self, question_or_request, *, events=None,
                      baseline_events=None, **overrides) -> InvestigationContext:
        """Assemble the deterministic evidence package for a question.

        ``question_or_request`` may be a string (parsed here) or a pre-built
        :class:`InvestigationRequest`. When ``events`` is given the engine
        analyses that caller-supplied set instead of querying the database
        (useful for ad-hoc analysis and tests); ``baseline_events`` supplies the
        separate historical baseline in that case. No LLM is involved.
        """
        request = (question_or_request
                   if isinstance(question_or_request, InvestigationRequest)
                   else self.parse(question_or_request, **overrides))
        warnings: List[str] = list(request.warnings)
        metadata: dict = {"limit": request.limit}

        if events is not None:
            filtered = list(events)
            history = list(baseline_events) if baseline_events is not None else None
            metadata["retrieval_source"] = "provided_events"
        else:
            filtered, history, retr_warnings = self._retrieve_from_db(request)
            warnings.extend(retr_warnings)
            metadata["retrieval_source"] = "database"
        metadata["returned"] = len(filtered)
        metadata["truncated"] = len(filtered) >= request.limit

        integrity_result = None
        integrity_dict = None
        if request.verify_integrity:
            chain_rows = history if history is not None else filtered
            integrity_result, integ_warnings = self._run_integrity(chain_rows)
            warnings.extend(integ_warnings)
            if integrity_result is not None:
                integrity_dict = integrity_result.as_dict()
        verified = integrity_result is not None
        invalid_ids = set(integrity_result.invalid_ids) if integrity_result else set()

        evidence = [
            EvidenceRecord.from_item(
                row, self._integrity_label(row, verified, invalid_ids))
            for row in filtered
        ]

        incidents: List[dict] = []
        if request.include_correlations:
            engine = CorrelationEngine(integrity_result=integrity_result,
                                       **self._correlation_kwargs)
            incidents = [inc.as_dict() for inc in engine.correlate(filtered)]

        anomalies: List[dict] = []
        baseline_status = None
        if request.include_behavior:
            anomalies, baseline_status, beh_warnings = self._run_behavior(
                filtered, history)
            warnings.extend(beh_warnings)

        return InvestigationContext(
            original_question=request.original_question,
            request=request,
            retrieved_events=evidence,
            candidate_incidents=incidents,
            behavioral_anomalies=anomalies,
            behavioral_baseline_status=baseline_status,
            integrity=integrity_dict,
            warnings=warnings,
            retrieval_metadata=metadata,
        )

    # -- grounded answer generation ---------------------------------------

    def _resolve_llm(self):
        """Return the configured LLM, lazily constructing the default client."""
        if self._llm_arg is _DEFAULT_LLM:
            return OllamaClient()
        return self._llm_arg

    def _generate_answer(self, context: InvestigationContext):
        """Ask the LLM to explain the evidence; degrade gracefully on failure.

        Returns ``(answer, llm_available, error, model, message, answer_source)``.
        The LLM only ever sees the grounded prompt built from ``context``.
        """
        llm = self._resolve_llm()
        model = getattr(llm, "model", None)
        if llm is None:
            return (None, False, "no LLM configured", model,
                    LLM_UNAVAILABLE_MESSAGE, ANSWER_SOURCE_FALLBACK)

        prompt, system = build_prompt(context)
        try:
            raw = llm.generate(prompt, system=system)
        except LLMError as exc:
            return (None, False, str(exc), model, LLM_UNAVAILABLE_MESSAGE,
                    ANSWER_SOURCE_FALLBACK)
        except Exception as exc:  # the LLM layer must never crash the read-only run
            return (None, False, f"unexpected LLM error: {exc}", model,
                    LLM_UNAVAILABLE_MESSAGE, ANSWER_SOURCE_FALLBACK)

        text = (raw or "").strip()
        if not text:
            return (None, True, "empty response", model, LLM_EMPTY_MESSAGE,
                    ANSWER_SOURCE_FALLBACK)
        return (text, True, None, model, None, ANSWER_SOURCE_LLM)

    # -- top-level entry point --------------------------------------------

    def investigate(self, question, *, generate_answer: bool = True,
                    events=None, baseline_events=None,
                    **overrides) -> InvestigationResult:
        """Run a full investigation and return a :class:`InvestigationResult`.

        The deterministic context and summary are always produced. The LLM answer
        is added when ``generate_answer`` is true and evidence exists; otherwise a
        fixed no-evidence message or an LLM-unavailable fallback is returned.
        """
        context = self.build_context(question, events=events,
                                     baseline_events=baseline_events, **overrides)
        result = InvestigationResult(
            context=context,
            deterministic_summary=build_deterministic_summary(context))

        if not generate_answer:
            result.message = "Natural-language answer not requested."
            return result

        if context.evidence_count == 0:
            result.answer = NO_EVIDENCE_MESSAGE
            result.answer_source = ANSWER_SOURCE_NO_EVIDENCE
            return result

        (result.answer, result.llm_available, result.llm_error, result.llm_model,
         result.message, result.answer_source) = self._generate_answer(context)
        return result


# --- Module-level convenience -----------------------------------------------


def investigate(question, *, llm=_DEFAULT_LLM, connection_factory=None,
                default_limit: int = DEFAULT_LIMIT,
                correlation_kwargs: Optional[dict] = None,
                behavior_kwargs: Optional[dict] = None,
                generate_answer: bool = True, events=None,
                baseline_events=None, **overrides) -> InvestigationResult:
    """One-shot investigation with a fresh :class:`InvestigationQueryEngine`."""
    engine = InvestigationQueryEngine(
        llm=llm, connection_factory=connection_factory,
        default_limit=default_limit, correlation_kwargs=correlation_kwargs,
        behavior_kwargs=behavior_kwargs)
    return engine.investigate(question, generate_answer=generate_answer,
                              events=events, baseline_events=baseline_events,
                              **overrides)
















