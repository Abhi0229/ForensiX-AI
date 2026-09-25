"""Event + timeline read endpoints.

Thin transport layer over ``backend.database.db``: every query uses the
parameterized ``query_events``/``count_events`` helpers (fixed column allowlist,
values bound as ``?``), so no user input can influence the SQL shape. All
handlers are read-only; none writes to the database.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Path, Query

from backend.ai.query_engine import KNOWN_SEVERITIES
from backend.database import db
from backend.api.schemas import (
    EventListResponse,
    EventResponse,
    TimelineResponse,
)

router = APIRouter(prefix="/api", tags=["events"])

# Columns we expose. Hash-chain columns are deliberately excluded from the API
# surface (see the integrity endpoint for chain verification).
_EVENT_FIELDS = ("id", "timestamp", "source", "event_type", "description",
                 "severity", "user", "device", "file_path", "metadata")


def row_to_event_dict(row) -> dict:
    """Project a ``sqlite3.Row`` into the public event shape.

    Missing/NULL text columns become empty strings so the JSON contract is
    stable for the frontend; ``id``/``timestamp`` may legitimately be absent.
    """
    data = dict(row)
    result = {"id": data.get("id"), "timestamp": data.get("timestamp")}
    for field in ("source", "event_type", "description", "severity",
                  "user", "device", "file_path", "metadata"):
        value = data.get(field)
        result[field] = "" if value is None else value
    return result


def _normalize_severity(severity: Optional[str]) -> Optional[str]:
    """Validate an optional severity filter against the known set.

    Returns the upper-cased value, or raises 400 for an unknown severity so the
    client gets a clear message instead of a silent empty result.
    """
    if severity is None:
        return None
    normalized = severity.strip().upper()
    if normalized not in KNOWN_SEVERITIES:
        raise HTTPException(status_code=400,
                            detail=f"Unknown severity: {severity}")
    return normalized


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Stored timestamps are ISO text, so compare against ISO strings."""
    return value.isoformat() if value is not None else None


def _list_events(limit, offset, source, event_type, severity, user, device,
                 start_time, end_time, order):
    """Shared retrieval used by both /events and /timeline (read-only)."""
    severity = _normalize_severity(severity)
    filters = dict(source=source, event_type=event_type, severity=severity,
                   user=user, device=device,
                   start_time=_iso(start_time), end_time=_iso(end_time))
    rows = db.query_events(limit=limit, offset=offset, order=order, **filters)
    total = db.count_events(**filters)
    events = [row_to_event_dict(row) for row in rows]
    return events, total


@router.get("/events", response_model=EventListResponse)
def list_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: Optional[str] = Query(None, max_length=200),
    event_type: Optional[str] = Query(None, max_length=200),
    severity: Optional[str] = Query(None, max_length=50),
    user: Optional[str] = Query(None, max_length=200),
    device: Optional[str] = Query(None, max_length=200),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
) -> EventListResponse:
    """Return a filtered, paginated page of stored events (newest-first)."""
    events, total = _list_events(limit, offset, source, event_type, severity,
                                 user, device, start_time, end_time, "DESC")
    return EventListResponse(events=events, total=total,
                             limit=limit, offset=offset)


@router.get("/events/{event_id}", response_model=EventResponse)
def get_event(event_id: int = Path(..., ge=1)) -> EventResponse:
    """Return a single event by id, or 404 if it does not exist."""
    row = db.get_event_by_id(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventResponse(**row_to_event_dict(row))


@router.get("/timeline", response_model=TimelineResponse)
def get_timeline(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: Optional[str] = Query(None, max_length=200),
    event_type: Optional[str] = Query(None, max_length=200),
    severity: Optional[str] = Query(None, max_length=50),
    user: Optional[str] = Query(None, max_length=200),
    device: Optional[str] = Query(None, max_length=200),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
) -> TimelineResponse:
    """Return events in chronological order (oldest-first) for the timeline."""
    events, total = _list_events(limit, offset, source, event_type, severity,
                                 user, device, start_time, end_time, "ASC")
    return TimelineResponse(events=events, total=total,
                            limit=limit, offset=offset)
