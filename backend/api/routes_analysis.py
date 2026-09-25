"""Correlation, behavior, and dashboard endpoints (Phases 10, 11 + aggregation).

Each analysis endpoint delegates to its existing engine convenience function:
``correlator.correlate_database`` (candidate incidents) and
``behavior.analyze_database`` (anomalies). The dashboard summary composes those
read-only engines with simple parameterized aggregate counts. Nothing here
re-implements an algorithm or writes to the database.
"""

from typing import Optional

from fastapi import APIRouter, Query

from backend.ai import behavior as behavior_mod
from backend.ai import correlator as correlator_mod
from backend.database import db
from backend.integrity.verifier import verify_chain
from backend.api.routes_events import row_to_event_dict
from backend.api.schemas import (
    BehaviorResponse,
    DashboardSummaryResponse,
    IncidentListResponse,
    IntegrityResponse,
)

router = APIRouter(prefix="/api", tags=["analysis"])

# Classifications that count as an actual anomaly for headline metrics.
_ANOMALY_CLASSES = (behavior_mod.STATUS_SUSPICIOUS, behavior_mod.STATUS_ANOMALOUS)


def _integrity_response() -> IntegrityResponse:
    """Verify the chain and shape it into the shared IntegrityResponse."""
    result = verify_chain().as_dict()
    checked = result["checked_events"]
    if checked == 0:
        status = "NO_EVENTS"
    else:
        status = "VALID" if result["valid"] else "INVALID"
    return IntegrityResponse(
        valid=result["valid"],
        status=status,
        total_events=checked,
        checked_events=checked,
        hashed_events=result["hashed_events"],
        legacy_events=result["legacy_events"],
        invalid_events=result["invalid_events"],
        errors=result["errors"],
    )


@router.get("/incidents", response_model=IncidentListResponse)
def list_incidents(
    window_seconds: float = Query(correlator_mod.DEFAULT_WINDOW_SECONDS, gt=0, le=86400),
    min_group_size: int = Query(correlator_mod.DEFAULT_MIN_GROUP_SIZE, ge=2, le=1000),
    limit: Optional[int] = Query(None, ge=1, le=100000),
    verify_integrity: bool = Query(False),
) -> IncidentListResponse:
    """Return candidate incidents from the Phase 10 correlator (read-only).

    These are deterministic groupings of related events, not confirmed attacks;
    the terminology is preserved in the response.
    """
    incidents = correlator_mod.correlate_database(
        window_seconds=window_seconds,
        min_group_size=min_group_size,
        limit=limit,
        verify_integrity=verify_integrity,
    )
    payload = [inc.as_dict() for inc in incidents]
    return IncidentListResponse(candidate_incidents=payload, total=len(payload))


@router.get("/behavior/anomalies", response_model=BehaviorResponse)
def list_behavior_anomalies(
    limit: Optional[int] = Query(None, ge=1, le=100000),
) -> BehaviorResponse:
    """Return behavioral evaluations from the Phase 11 engine (read-only).

    Every evaluated event is returned with its classification so the frontend
    can distinguish NORMAL / SUSPICIOUS / ANOMALOUS / INSUFFICIENT_HISTORY. A
    non-NORMAL result signals deviation from baseline, not confirmed malice.
    """
    baseline, anomalies = behavior_mod.analyze_database(limit=limit)
    counts = {
        behavior_mod.STATUS_NORMAL: 0,
        behavior_mod.STATUS_SUSPICIOUS: 0,
        behavior_mod.STATUS_ANOMALOUS: 0,
        behavior_mod.STATUS_INSUFFICIENT_HISTORY: 0,
    }
    payload = []
    for anomaly in anomalies:
        data = anomaly.as_dict()
        counts[data["classification"]] = counts.get(data["classification"], 0) + 1
        payload.append(data)
    return BehaviorResponse(
        baseline_status=baseline.status,
        counts=counts,
        total_evaluated=len(payload),
        anomalies=payload,
    )


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
def dashboard_summary() -> DashboardSummaryResponse:
    """Deterministic high-level snapshot for the dashboard landing view.

    Composes stored-data counts with the correlation, behavior and integrity
    engines. Every number is derived from real data -- nothing is invented.
    """
    total_events = db.count_events()
    events_by_source = db.count_events_by("source")
    events_by_severity = db.count_events_by("severity")
    recent_rows = db.query_events(limit=10, offset=0, order="DESC")
    recent_events = [row_to_event_dict(row) for row in recent_rows]
    latest_timestamp = recent_events[0]["timestamp"] if recent_events else None

    incidents = correlator_mod.correlate_database()
    _, anomalies = behavior_mod.analyze_database()
    anomaly_count = sum(
        1 for a in anomalies if a.classification in _ANOMALY_CLASSES
    )

    return DashboardSummaryResponse(
        total_events=total_events,
        events_by_source=events_by_source,
        events_by_severity=events_by_severity,
        recent_events=recent_events,
        candidate_incident_count=len(incidents),
        behavioral_anomaly_count=anomaly_count,
        integrity=_integrity_response(),
        latest_event_timestamp=latest_timestamp,
    )
