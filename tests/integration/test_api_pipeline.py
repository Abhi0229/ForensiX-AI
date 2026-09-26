"""Integration: the full stack served over HTTP by the FastAPI app.

Drives the real ASGI app with TestClient against a seeded temporary database
and asserts that stored evidence and every analysis layer reach the HTTP
surface consistently, that bad input is rejected without a crash, and that no
internal detail leaks on error. The LLM is a stub; the DB is throwaway. This
complements (does not duplicate) the per-endpoint unit tests in test_api.py by
asserting cross-endpoint consistency and end-to-end data provenance.
"""

from .conftest import FakeLLM

READ_ENDPOINTS = ("/api/health", "/api/events", "/api/timeline",
                  "/api/integrity", "/api/incidents",
                  "/api/behavior/anomalies", "/api/dashboard/summary")


def test_all_read_endpoints_ok(client, seeded):
    for path in READ_ENDPOINTS:
        resp = client.get(path)
        assert resp.status_code == 200, (path, resp.status_code)


def test_cross_endpoint_counts_are_consistent(client, seeded):
    events = client.get("/api/events").json()
    timeline = client.get("/api/timeline").json()
    integrity = client.get("/api/integrity").json()
    dashboard = client.get("/api/dashboard/summary").json()
    assert events["total"] == seeded
    assert timeline["total"] == seeded
    assert integrity["total_events"] == seeded
    assert dashboard["total_events"] == seeded


def test_event_detail_reachable_from_list(client, seeded):
    first = client.get("/api/events", params={"limit": 1}).json()["events"][0]
    detail = client.get(f"/api/events/{first['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == first["id"]
    # Internal hash-chain columns never surface at the API.
    assert "event_hash" not in detail.json()
    assert "previous_hash" not in detail.json()


def test_analysis_results_reach_api(client, seeded):
    incidents = client.get("/api/incidents").json()
    assert incidents["total"] >= 1
    assert incidents["candidate_incidents"]
    # Conservative terminology is preserved end-to-end.
    assert incidents["terminology"] == "candidate incident"
    behavior = client.get("/api/behavior/anomalies").json()
    assert behavior["total_evaluated"] == seeded
    assert sum(behavior["counts"].values()) == seeded


def test_investigate_and_reports_flow(client, seeded):
    q = {"question": "what happened overnight"}
    inv = client.post("/api/investigate", json=q)
    assert inv.status_code == 200
    body = inv.json()
    assert body["evidence_count"] > 0
    assert len(body["evidence"]) == body["evidence_count"]

    rep = client.post("/api/reports/investigation", json=q)
    assert rep.status_code == 200
    assert rep.json()["report_id"].startswith("RPT-")

    txt = client.post("/api/reports/investigation/text", json=q)
    assert txt.status_code == 200
    assert txt.json()["text"].strip()


def test_malformed_requests_do_not_crash(client, seeded):
    assert client.post("/api/investigate", json={}).status_code == 422
    assert client.get("/api/events/abc").status_code == 422
    assert client.get("/api/events", params={"limit": 999999}).status_code == 422
    assert client.get("/api/events",
                      params={"severity": "BOGUS"}).status_code == 400


def test_internal_error_is_not_leaked(seeded):
    from fastapi.testclient import TestClient
    from backend.app import app
    from backend.api.deps import get_llm, get_query_engine

    def _boom():
        raise RuntimeError("boom leaking C:/secret/internal/path and token")

    app.dependency_overrides[get_llm] = lambda: FakeLLM()
    app.dependency_overrides[get_query_engine] = _boom
    try:
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post("/api/investigate", json={"question": "what happened"})
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert "boom" not in resp.text and "secret" not in resp.text


def test_api_never_mutates_evidence(client, seeded):
    before = client.get("/api/integrity").json()
    for path in READ_ENDPOINTS:
        client.get(path)
    client.post("/api/investigate", json={"question": "what happened"})
    client.post("/api/reports/investigation", json={"question": "what happened"})
    client.post("/api/reports/investigation/text",
                json={"question": "what happened"})
    after = client.get("/api/integrity").json()
    assert after["valid"] is True
    assert after["total_events"] == before["total_events"] == seeded
    assert after["hashed_events"] == before["hashed_events"]


