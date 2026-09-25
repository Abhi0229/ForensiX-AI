"""Pydantic v2 response/request models for the ForensiX AI API.

These models define the stable, predictable JSON contract the future React
dashboard consumes. The top-level envelopes are strongly typed; deeply nested
payloads that come straight from an existing engine's ``as_dict()`` (an
incident's member events, an anomaly's event detail, integrity findings) are
typed as ``Dict``/``List`` so the API never diverges from -- or duplicates --
the deterministic structures those modules already own.

Request models use ``extra="forbid"`` so unknown fields are rejected with a
422; response models ignore extras by default.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.ai.query_engine import KNOWN_SEVERITIES


# --- Health / errors --------------------------------------------------------


class HealthResponse(BaseModel):
    """Liveness probe payload. Never depends on a populated database."""

    status: str = "ok"
    service: str = "ForensiX AI"


class ErrorResponse(BaseModel):
    """Uniform error envelope. Only a safe, human-readable message is exposed."""

    detail: str


# --- Events -----------------------------------------------------------------


class EventResponse(BaseModel):
    """A single stored forensic event.

    Internal hash-chain columns (``event_hash``/``previous_hash``) are
    intentionally omitted -- they are an implementation detail surfaced only via
    the dedicated integrity endpoint.
    """

    id: Optional[int] = None
    timestamp: Optional[str] = None
    source: str = ""
    event_type: str = ""
    description: str = ""
    severity: str = ""
    user: str = ""
    device: str = ""
    file_path: str = ""
    metadata: str = ""


class EventListResponse(BaseModel):
    """A page of events plus the pagination envelope for the event explorer."""

    events: List[EventResponse]
    total: int
    limit: int
    offset: int


class TimelineResponse(BaseModel):
    """Chronologically ordered events for the timeline view."""

    events: List[EventResponse]
    total: int
    limit: int
    offset: int


# --- Investigation ----------------------------------------------------------


class InvestigationRequest(BaseModel):
    """Body for ``POST /api/investigate``.

    ``question`` is the natural-language query; the optional structured fields
    are passed to the Phase 12 engine as explicit overrides on top of whatever
    it parses from the question. The natural-language text never becomes SQL --
    the engine binds every value as a parameter.
    """

    model_config = ConfigDict(extra="forbid")

    question: str = Field(..., min_length=1, max_length=2000)
    severity: Optional[str] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    user: Optional[str] = None
    device: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: Optional[int] = Field(default=None, ge=1, le=1000)
    include_correlations: bool = True
    include_behavior: bool = True
    verify_integrity: bool = True
    generate_answer: bool = True

    @field_validator("question")
    @classmethod
    def _question_not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("question must not be empty")
        return stripped

    @field_validator("severity")
    @classmethod
    def _severity_known(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().upper()
        if normalized not in KNOWN_SEVERITIES:
            raise ValueError(f"unknown severity: {value!r}")
        return normalized


class InvestigationResponse(BaseModel):
    """Result of an investigation, shaped for a React investigation panel.

    Mirrors the Phase 12 ``InvestigationResult``/``InvestigationContext`` but
    lifts the evidence and analysis lists to the top level for easy rendering.
    """

    question: str
    answer: Optional[str] = None
    answer_source: Optional[str] = None
    message: Optional[str] = None
    llm_available: bool = False
    llm_model: Optional[str] = None
    deterministic_summary: str = ""
    context: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_count: int = 0
    candidate_incidents: List[Dict[str, Any]] = Field(default_factory=list)
    behavioral_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    behavioral_baseline_status: Optional[str] = None
    integrity: Optional[Dict[str, Any]] = None
    warnings: List[str] = Field(default_factory=list)


# --- Incidents (Phase 10 correlation) ---------------------------------------


class IncidentResponse(BaseModel):
    """A single candidate incident (a deterministic grouping of related events).

    Named a *candidate* incident deliberately: the correlator asserts the events
    are related by documented rules, not that they form a confirmed attack.
    """

    incident_id: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    event_ids: List[Optional[int]] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    event_types: List[str] = Field(default_factory=list)
    correlation_reasons: List[str] = Field(default_factory=list)
    priority: str = ""
    confidence_score: int = 0
    confidence_signals: List[str] = Field(default_factory=list)
    integrity_summary: Dict[str, Any] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)

class IncidentListResponse(BaseModel):
    """Collection of candidate incidents with terminology preserved explicitly."""

    candidate_incidents: List[IncidentResponse]
    total: int
    terminology: str = "candidate incident"
    note: str = (
        "Candidate incidents are deterministic groupings of related events, "
        "not confirmed security incidents."
    )


# --- Behavioral anomalies (Phase 11) ----------------------------------------


class BehaviorAnomalyResponse(BaseModel):
    """One event scored against the behavioral baseline.

    ``anomaly_score`` is a bounded 0-100 explainability score, not a
    probability, and ``classification`` is NORMAL / SUSPICIOUS / ANOMALOUS /
    INSUFFICIENT_HISTORY. A flag means statistical deviation, not malice.
    """

    anomaly_score: float = 0.0
    classification: str = ""
    severity: str = ""
    reasons: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    baseline_status: Optional[str] = None
    event: Dict[str, Any] = Field(default_factory=dict)


class BehaviorResponse(BaseModel):
    """Behavioral analysis over the available events for the anomaly viewer."""

    baseline_status: str
    counts: Dict[str, int]
    total_evaluated: int
    anomalies: List[BehaviorAnomalyResponse]
    disclaimer: str = (
        "Anomalies indicate statistical deviation from the learned baseline, "
        "not confirmed malicious activity."
    )


# --- Integrity (Phase 9) ----------------------------------------------------


class IntegrityResponse(BaseModel):
    """Hash-chain verification result. Reports internal consistency only."""

    valid: bool
    status: str
    total_events: int
    checked_events: int
    hashed_events: int
    legacy_events: int
    invalid_events: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

# --- Reports (Phase 13) -----------------------------------------------------


class ReportRequest(BaseModel):
    """Body for ``POST /api/reports/investigation`` and its text variant.

    Same structured overrides as an investigation. Correlation, behavior and
    integrity default to enabled so the generated report is complete; the LLM
    narrative is opt-in and off by default (deterministic report always built).
    """

    model_config = ConfigDict(extra="forbid")

    question: str = Field(..., min_length=1, max_length=2000)
    include_llm_narrative: bool = False
    severity: Optional[str] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    user: Optional[str] = None
    device: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: Optional[int] = Field(default=None, ge=1, le=1000)
    include_correlations: bool = True
    include_behavior: bool = True
    verify_integrity: bool = True

    @field_validator("question")
    @classmethod
    def _question_not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("question must not be empty")
        return stripped

    @field_validator("severity")
    @classmethod
    def _severity_known(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().upper()
        if normalized not in KNOWN_SEVERITIES:
            raise ValueError(f"unknown severity: {value!r}")
        return normalized


class InvestigationReportResponse(BaseModel):
    """Structured forensic report for the report viewer.

    Fields mirror the Phase 13 ``InvestigationReport.as_dict()``. Nested
    sections keep the generator's own shapes verbatim.
    """

    report_id: str
    generated_at: Optional[str] = None
    original_question: str = ""
    executive_summary: str = ""
    incident_summary: Dict[str, Any] = Field(default_factory=dict)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    correlation_findings: List[Dict[str, Any]] = Field(default_factory=list)
    behavioral_findings: List[Dict[str, Any]] = Field(default_factory=list)
    integrity_status: Any = None
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    conclusion: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    llm_narrative: Optional[str] = None
    llm_available: bool = False
    llm_error: Optional[str] = None


class ReportTextResponse(BaseModel):
    """Plain-text rendering produced by ``generate_text_report()``."""

    report_id: str
    text: str

# --- Dashboard --------------------------------------------------------------


class DashboardCapabilities(BaseModel):
    """Which analysis capabilities the API can serve (for feature toggling)."""

    investigation_available: bool = True
    report_available: bool = True
    correlation_available: bool = True
    behavior_available: bool = True
    integrity_available: bool = True


class DashboardSummaryResponse(BaseModel):
    """Deterministic high-level snapshot for the dashboard landing view.

    Every value is computed from stored data or existing engines; nothing here
    is invented or estimated.
    """

    total_events: int
    events_by_source: Dict[str, int] = Field(default_factory=dict)
    events_by_severity: Dict[str, int] = Field(default_factory=dict)
    recent_events: List[EventResponse] = Field(default_factory=list)
    candidate_incident_count: int = 0
    behavioral_anomaly_count: int = 0
    integrity: IntegrityResponse
    latest_event_timestamp: Optional[str] = None
    capabilities: DashboardCapabilities = Field(default_factory=DashboardCapabilities)
