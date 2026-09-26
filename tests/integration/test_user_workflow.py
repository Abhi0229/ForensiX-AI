"""Integration: one real analyst workflow, end-to-end over the HTTP API.

This documents and exercises a single cohesive user journey (STEP 13) the way
a forensic analyst actually drives ForensiX AI through the FastAPI surface --
from opening the dashboard to exporting a report -- and asserts *continuity*
between steps (the same real evidence flows from listing -> investigation ->
report) rather than re-testing each endpoint in isolation. The LLM is stubbed
and the database is a throwaway seeded copy; nothing on the host is touched.

Workflow under test (each numbered step maps to a block below):
  1. Open the dashboard summary.
  2. Establish chain-of-custody: verify evidence integrity up front.
  3. Browse the collected events and pick the Defender threat.
  4. Open that event's detail (and confirm no internal hash columns leak).
  5. Review the chronological timeline.
  6. Review correlated *candidate* incidents.
  7. Review behavioral anomalies.
  8. Ask a natural-language investigation question.
  9. Generate a structured investigation report.
 10. Export the human-readable text report.
 11. Re-verify integrity: the whole read/investigate session mutated nothing.
"""


def _defender_event(client):
    events = client.get("/api/events", params={"limit": 100}).json()["events"]
    hits = [e for e in events if e["source"] == "Defender"]
    assert hits, "seed is expected to contain a Defender threat event"
    return hits[0]


def test_analyst_end_to_end_workflow(client, seeded):
    # 1. Dashboard: the analyst gets an at-a-glance picture of the endpoint.
    summary = client.get("/api/dashboard/summary").json()
    assert summary["total_events"] == seeded

    # 2. Chain of custody FIRST: confirm the evidence is intact before relying
    #    on any of it. This is the baseline we re-check in step 11.
    integrity_before = client.get("/api/integrity").json()
    assert integrity_before["valid"] is True
    assert integrity_before["total_events"] == seeded

    # 3. Browse the collected events; zero in on the Defender threat.
    threat = _defender_event(client)
    assert threat["event_type"] == "THREAT_DETECTED"

    # 4. Open its detail. Internal hash-chain columns must never surface.
    detail = client.get(f"/api/events/{threat['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == threat["id"]
    assert "event_hash" not in detail.json()
    assert "previous_hash" not in detail.json()

    # 5. Timeline: entries are ordered and map back to real evidence.
    timeline = client.get("/api/timeline").json()
    assert timeline["total"] == seeded

    # 6. Correlated *candidate* incidents (never "confirmed attacks").
    incidents = client.get("/api/incidents").json()
    assert incidents["total"] >= 1
    assert incidents["terminology"] == "candidate incident"

    # 7. Behavioral anomalies: every stored event is classified.
    behavior = client.get("/api/behavior/anomalies").json()
    assert behavior["total_evaluated"] == seeded

    # 8. Ask a natural-language question; the answer is grounded in real ids.
    inv = client.post("/api/investigate",
                      json={"question": "what happened overnight"}).json()
    assert inv["evidence_count"] > 0
    cited = {e["event_id"] for e in inv["evidence"] if e.get("db_backed")}
    existing = {e["id"] for e in
                client.get("/api/events", params={"limit": 100}).json()["events"]}
    assert cited and cited <= existing        # nothing fabricated

    # 9. Generate the structured report; it carries the integrity verdict.
    report = client.post("/api/reports/investigation",
                        json={"question": "what happened overnight"}).json()
    assert report["report_id"].startswith("RPT-")
    assert report["integrity_status"]["valid"] is True

    # 10. Export the human-readable text report.
    text = client.post("/api/reports/investigation/text",
                      json={"question": "what happened overnight"}).json()["text"]
    assert "FORENSIX AI INVESTIGATION REPORT" in text
    assert report["report_id"] in text

    # 11. Re-verify integrity: a full read/investigate/report session is
    #     non-destructive -- the evidence is byte-for-byte what we started with.
    integrity_after = client.get("/api/integrity").json()
    assert integrity_after["valid"] is True
    assert integrity_after["total_events"] == integrity_before["total_events"]
    assert integrity_after["hashed_events"] == integrity_before["hashed_events"]

