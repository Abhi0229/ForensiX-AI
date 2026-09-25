"""Tests for the ForensiX AI REST API layer (Phase 14).

These tests exercise the FastAPI app end-to-end via ``TestClient`` while staying
completely offline and hermetic:

* The database layer is pointed at a throwaway SQLite file (autouse fixture
  monkeypatching ``backend.database.db.DB_PATH``) so the real dev DB is never
  touched and no test needs a production database.
* The LLM dependency is overridden with an in-process stub, so no test touches
  Ollama or the network.
* No Windows event logs, browser databases or USB hardware are involved --
  events are seeded directly through the existing Phase 8 pipeline.

The suite also asserts the security properties the API promises: parameterized
queries (SQL-injection attempts are inert), bounded pagination, no internal
detail leakage on errors, and that the API never mutates stored evidence.
"""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.api.deps import get_llm, get_query_engine
from backend.database import db as _db
from backend.database import schema
from backend.database.models import Event
from backend.processing.pipeline import EventPipeline
from backend.ai.query_engine import (
    ANSWER_SOURCE_FALLBACK,
    ANSWER_SOURCE_LLM,
    ANSWER_SOURCE_NO_EVIDENCE,
    LLMUnavailableError,
)


class FakeLLM:
    """Offline stand-in for OllamaClient that always returns a canned answer."""

    model = "fake-model"

    def generate(self, prompt, *, system=None):
        return "Deterministic grounded answer based only on the evidence."


class UnavailableLLM:
    """Stub whose generate() fails, to exercise graceful LLM degradation."""

    model = "unavailable-model"

    def generate(self, prompt, *, system=None):
        raise LLMUnavailableError("ollama not running")


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Point the DB layer at a throwaway file and create the schema.

    Autouse so no test can ever read from or write to the real dev database.
    """
    test_db = tmp_path / "test_api.db"
    monkeypatch.setattr(_db, "DB_PATH", str(test_db))
    schema.create_tables()
    yield


def _baseline_events():
    """20 routine business-hours logons -- enough for a 'ready' baseline."""
    base = datetime(2026, 9, 20, 9, 0, 0)
    return [
        Event(timestamp=base + timedelta(minutes=i), source="Windows",
              event_type="LOGON", description=f"User logon {i}",
              severity="INFO", user="alice", device="HOST1")
        for i in range(20)
    ]


def _cluster_events():
    """A tight, off-hours cluster on one device that correlates across sources."""
    t = datetime(2026, 9, 21, 3, 0, 0)
    return [
        Event(timestamp=t, source="USB", event_type="USB_CONNECTED",
              description="USB device connected", severity="INFO",
              user="", device="HOST1"),
        Event(timestamp=t + timedelta(seconds=30), source="FileSystem",
              event_type="FILE_CREATED", description="File created",
              severity="INFO", user="", device="HOST1",
              file_path="C:/secret.docx"),
        Event(timestamp=t + timedelta(seconds=60), source="Defender",
              event_type="THREAT_DETECTED", description="Threat found",
              severity="HIGH", user="", device="HOST1",
              file_path="C:/secret.docx"),
        Event(timestamp=t + timedelta(seconds=90), source="Browser",
              event_type="BROWSER_VISIT", description="Visited a site",
              severity="INFO", user="alice", device="HOST1",
              file_path="http://malware.test/download"),
        Event(timestamp=t + timedelta(seconds=120), source="Windows",
              event_type="LOGON", description="Off-hours logon",
              severity="WARNING", user="alice", device="HOST1"),
    ]


SEED_COUNT = 25


@pytest.fixture
def seeded(temp_db):
    """Seed the temp DB with a hashed event chain via the real pipeline."""
    events = _baseline_events() + _cluster_events()
    result = EventPipeline().process(events)
    assert result.inserted == SEED_COUNT
    return SEED_COUNT


@pytest.fixture
def client():
    """TestClient with the LLM dependency replaced by an offline stub."""
    app.dependency_overrides[get_llm] = lambda: FakeLLM()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


# --- Health & docs ----------------------------------------------------------


def test_health_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "ForensiX AI"}


def test_health_does_not_require_populated_db(client):
    # No `seeded` fixture: the DB is empty, health must still succeed.
    assert client.get("/api/health").status_code == 200


def test_openapi_docs_available(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


# --- Events -----------------------------------------------------------------


def test_events_list(client, seeded):
    resp = client.get("/api/events")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"events", "total", "limit", "offset"}
    assert body["total"] == seeded
    assert len(body["events"]) == seeded
    # Internal hash-chain columns must never be exposed.
    sample = body["events"][0]
    assert "event_hash" not in sample and "previous_hash" not in sample
    assert set(sample) >= {"id", "timestamp", "source", "event_type"}


def test_events_filter_by_source(client, seeded):
    body = client.get("/api/events", params={"source": "USB"}).json()
    assert body["total"] == 1
    assert all(e["source"] == "USB" for e in body["events"])


def test_events_filter_by_severity(client, seeded):
    body = client.get("/api/events", params={"severity": "HIGH"}).json()
    assert body["total"] == 1
    assert all(e["severity"] == "HIGH" for e in body["events"])


def test_events_pagination(client, seeded):
    page = client.get("/api/events", params={"limit": 5, "offset": 0}).json()
    assert page["limit"] == 5 and page["offset"] == 0
    assert len(page["events"]) == 5
    assert page["total"] == seeded
    nxt = client.get("/api/events", params={"limit": 5, "offset": 5}).json()
    assert len(nxt["events"]) == 5
    first_ids = {e["id"] for e in page["events"]}
    next_ids = {e["id"] for e in nxt["events"]}
    assert first_ids.isdisjoint(next_ids)


def test_event_detail(client, seeded):
    listed = client.get("/api/events", params={"limit": 1}).json()["events"][0]
    resp = client.get(f"/api/events/{listed['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == listed["id"]


def test_event_not_found(client, seeded):
    resp = client.get("/api/events/999999")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Event not found"}


def test_event_invalid_id_rejected(client, seeded):
    # Non-integer / non-positive ids are rejected by validation, not a 500.
    assert client.get("/api/events/abc").status_code == 422
    assert client.get("/api/events/0").status_code == 422


def test_invalid_pagination_params(client, seeded):
    assert client.get("/api/events", params={"limit": 0}).status_code == 422
    assert client.get("/api/events", params={"limit": 5000}).status_code == 422
    assert client.get("/api/events", params={"offset": -1}).status_code == 422


def test_events_unknown_severity_rejected(client, seeded):
    resp = client.get("/api/events", params={"severity": "BOGUS"})
    assert resp.status_code == 400
    assert "severity" in resp.json()["detail"].lower()


# --- Timeline ---------------------------------------------------------------


def test_timeline_chronological(client, seeded):
    resp = client.get("/api/timeline")
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert resp.json()["total"] == seeded
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)  # ascending = chronological


def test_timeline_filters(client, seeded):
    body = client.get("/api/timeline", params={"source": "Defender"}).json()
    assert body["total"] == 1
    assert all(e["source"] == "Defender" for e in body["events"])


# --- Investigation ----------------------------------------------------------


def test_investigate_basic(client, seeded):
    resp = client.post("/api/investigate", json={"question": "What happened?"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["question"] == "What happened?"
    assert body["evidence_count"] > 0
    assert len(body["evidence"]) == body["evidence_count"]
    # Fake LLM is available, so the answer comes from the LLM wording layer.
    assert body["llm_available"] is True
    assert body["answer_source"] == ANSWER_SOURCE_LLM
    assert body["answer"]
    assert "context" in body and "candidate_incidents" in body


def test_investigate_empty_question_rejected(client, seeded):
    assert client.post("/api/investigate", json={"question": ""}).status_code == 422
    assert client.post("/api/investigate",
                       json={"question": "   "}).status_code == 422


def test_investigate_unknown_severity_rejected(client, seeded):
    resp = client.post("/api/investigate",
                       json={"question": "x", "severity": "BOGUS"})
    assert resp.status_code == 422


def test_investigate_malformed_body_rejected(client, seeded):
    # Missing required "question" and an unexpected extra field.
    assert client.post("/api/investigate", json={}).status_code == 422
    assert client.post("/api/investigate",
                       json={"question": "x", "bogus": 1}).status_code == 422


def test_investigate_empty_database(client):
    # No seeding: engine short-circuits to the no-evidence path, no LLM call.
    body = client.post("/api/investigate",
                       json={"question": "What happened?"}).json()
    assert body["evidence_count"] == 0
    assert body["answer_source"] == ANSWER_SOURCE_NO_EVIDENCE


def test_investigate_llm_unavailable(seeded):
    # Override the LLM with a failing stub -> graceful deterministic fallback.
    app.dependency_overrides[get_llm] = lambda: UnavailableLLM()
    try:
        c = TestClient(app)
        body = c.post("/api/investigate",
                      json={"question": "What happened?"}).json()
    finally:
        app.dependency_overrides.clear()
    assert body["llm_available"] is False
    assert body["answer_source"] == ANSWER_SOURCE_FALLBACK
    assert body["message"]  # a reason is provided
    assert body["evidence_count"] > 0  # deterministic evidence still returned


# --- Reports ----------------------------------------------------------------


def test_report_investigation(client, seeded):
    resp = client.post("/api/reports/investigation",
                       json={"question": "What happened overnight?"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["report_id"].startswith("RPT-")
    for key in ("executive_summary", "timeline", "evidence",
                "correlation_findings", "behavioral_findings",
                "integrity_status", "conclusion", "limitations"):
        assert key in body
    # Narrative is opt-in and off by default.
    assert body["llm_narrative"] is None


def test_report_investigation_with_llm_narrative(client, seeded):
    resp = client.post("/api/reports/investigation",
                       json={"question": "What happened?",
                             "include_llm_narrative": True})
    body = resp.json()
    assert body["llm_available"] is True
    assert body["llm_narrative"]


def test_report_text(client, seeded):
    resp = client.post("/api/reports/investigation/text",
                       json={"question": "What happened?"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["report_id"].startswith("RPT-")
    assert isinstance(body["text"], str) and body["text"].strip()


# --- Integrity --------------------------------------------------------------


def test_integrity_valid_chain(client, seeded):
    resp = client.get("/api/integrity")
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["status"] == "VALID"
    assert body["total_events"] == seeded
    assert body["hashed_events"] == seeded
    assert body["invalid_events"] == []


def test_integrity_empty_db(client):
    body = client.get("/api/integrity").json()
    assert body["status"] == "NO_EVENTS"
    assert body["total_events"] == 0


# --- Incidents (correlation) ------------------------------------------------


def test_incidents(client, seeded):
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert len(body["candidate_incidents"]) == body["total"]
    for inc in body["candidate_incidents"]:
        assert inc["incident_id"].startswith("INC-")
        assert "confidence_score" in inc and "priority" in inc


def test_incidents_terminology_preserved(client, seeded):
    body = client.get("/api/incidents").json()
    # The API must keep the conservative "candidate incident" terminology.
    assert body["terminology"] == "candidate incident"
    assert "not confirmed" in body["note"].lower()


# --- Behavior ---------------------------------------------------------------


def test_behavior_anomalies(client, seeded):
    resp = client.get("/api/behavior/anomalies")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["counts"]) == {
        "NORMAL", "SUSPICIOUS", "ANOMALOUS", "INSUFFICIENT_HISTORY"
    }
    assert body["total_evaluated"] == seeded
    assert sum(body["counts"].values()) == seeded
    valid = {"NORMAL", "SUSPICIOUS", "ANOMALOUS", "INSUFFICIENT_HISTORY"}
    assert all(a["classification"] in valid for a in body["anomalies"])
    # Must not claim anomalies are malicious.
    assert "not confirmed malicious" in body["disclaimer"].lower()


# --- Dashboard --------------------------------------------------------------


def test_dashboard_summary(client, seeded):
    resp = client.get("/api/dashboard/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_events"] == seeded
    assert body["events_by_source"]["Windows"] == 21
    assert body["events_by_source"]["USB"] == 1
    assert len(body["recent_events"]) <= 10
    assert body["candidate_incident_count"] >= 1
    assert body["integrity"]["status"] == "VALID"
    assert body["latest_event_timestamp"] is not None
    assert body["capabilities"]["investigation_available"] is True


# --- Security ---------------------------------------------------------------


def test_sql_injection_in_filter_is_inert(client, seeded):
    payload = "'; DROP TABLE events; --"
    resp = client.get("/api/events", params={"source": payload})
    assert resp.status_code == 200
    assert resp.json()["total"] == 0  # bound as a value, matches nothing
    # The events table is untouched: an unfiltered query still sees everything.
    assert client.get("/api/events").json()["total"] == seeded


def test_sql_injection_in_investigation_is_inert(client, seeded):
    resp = client.post("/api/investigate",
                       json={"question": "'; DROP TABLE events; --"})
    assert resp.status_code == 200
    # Table survived: the NL text never became SQL.
    assert client.get("/api/events").json()["total"] == seeded


def test_cors_allows_dev_origins(client):
    for origin in ("http://localhost:3000", "http://localhost:5173"):
        resp = client.get("/api/health", headers={"Origin": origin})
        assert resp.headers.get("access-control-allow-origin") == origin


def test_cors_rejects_unknown_origin(client):
    resp = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert resp.headers.get("access-control-allow-origin") != "http://evil.example"


def test_internal_error_is_not_leaked(seeded):
    def _boom():
        raise RuntimeError("boom leaking C:/secret/internal/path and token")

    app.dependency_overrides[get_llm] = lambda: FakeLLM()
    app.dependency_overrides[get_query_engine] = _boom
    try:
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post("/api/investigate", json={"question": "What happened?"})
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert "boom" not in resp.text and "secret" not in resp.text


def test_api_does_not_modify_evidence(client, seeded):
    before = client.get("/api/integrity").json()
    before_count = client.get("/api/events").json()["total"]

    # Exercise every read/analysis endpoint, including the POST analyses.
    client.get("/api/timeline")
    client.get("/api/incidents")
    client.get("/api/behavior/anomalies")
    client.get("/api/dashboard/summary")
    client.post("/api/investigate", json={"question": "What happened?"})
    client.post("/api/reports/investigation", json={"question": "What happened?"})
    client.post("/api/reports/investigation/text",
                json={"question": "What happened?"})

    after = client.get("/api/integrity").json()
    after_count = client.get("/api/events").json()["total"]
    assert after_count == before_count == seeded
    assert after["valid"] is True
    assert after["hashed_events"] == before["hashed_events"]
    assert after["checked_events"] == before["checked_events"]
