"""Integration: database events -> CorrelationEngine / BehavioralBaselineEngine.

Correlation groups related multi-source activity into *candidate* incidents
(never "confirmed attacks"); behavioral analysis classifies deviation from a
learned baseline without ever labelling an event confirmed-malicious. Both are
exercised over controlled event lists and over a seeded temporary database.
"""

from datetime import datetime, timedelta

from backend.database.models import Event
from backend.ai.correlator import correlate_database, correlate_events
from backend.ai import behavior as behavior_mod
from backend.ai.behavior import (
    BASELINE_READY,
    STATUS_ANOMALOUS,
    STATUS_INSUFFICIENT_HISTORY,
    STATUS_NORMAL,
    STATUS_SUSPICIOUS,
    build_baseline,
    detect_anomalies,
)

from .conftest import baseline_events, cluster_events, seed_events

_VALID_CLASSES = {STATUS_NORMAL, STATUS_SUSPICIOUS, STATUS_ANOMALOUS,
                  STATUS_INSUFFICIENT_HISTORY}


def _incident_sequence(device="HOST-A"):
    """FILE_MODIFIED -> PROCESS -> DEFENDER ALERT -> FILE_CREATED, one device."""
    t = datetime(2026, 9, 22, 2, 0, 0)
    return [
        Event(timestamp=t, source="FileSystem", event_type="FILE_MODIFIED",
              description="report.docx modified", device=device,
              file_path="C:/report.docx"),
        Event(timestamp=t + timedelta(seconds=20), source="Windows",
              event_type="PROCESS_CREATED", description="process started",
              device=device),
        Event(timestamp=t + timedelta(seconds=40), source="Defender",
              event_type="THREAT_DETECTED", description="threat detected",
              severity="HIGH", device=device, file_path="C:/report.docx"),
        Event(timestamp=t + timedelta(seconds=60), source="FileSystem",
              event_type="FILE_CREATED", description="dropper created",
              device=device),
    ]


def _unusual_event():
    """An event unlike the all-daytime-alice-logon baseline on every axis."""
    return Event(timestamp=datetime(2026, 9, 25, 3, 0, 0), source="USB",
                 event_type="USB_CONNECTED", description="off-hours USB insert",
                 severity="HIGH", user="attacker", device="HOST-X")


# --- Correlation ------------------------------------------------------------

def test_correlation_groups_related_sequence():
    incidents = correlate_events(_incident_sequence(), window_seconds=300,
                                 min_group_size=2)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.incident_id.startswith("INC-")
    assert len(inc.events) == 4
    assert set(inc.sources) >= {"FileSystem", "Windows", "Defender"}
    assert "FILE_MODIFIED" in inc.event_types
    assert "THREAT_DETECTED" in inc.event_types
    assert isinstance(inc.confidence_score, int)
    assert inc.confidence_signals            # findings are explainable
    assert inc.priority in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_correlation_respects_device_boundary():
    t = datetime(2026, 9, 22, 2, 0, 0)
    a = Event(timestamp=t, source="FileSystem", event_type="FILE_CREATED",
              description="x", device="HOST-A")
    b = Event(timestamp=t + timedelta(seconds=10), source="Defender",
              event_type="THREAT_DETECTED", description="y", device="HOST-B")
    # Different devices are never merged, even within the temporal window.
    assert correlate_events([a, b], window_seconds=300, min_group_size=2) == []


def test_correlation_respects_temporal_window():
    t = datetime(2026, 9, 22, 2, 0, 0)
    a = Event(timestamp=t, source="FileSystem", event_type="FILE_CREATED",
              description="x", device="HOST-A")
    b = Event(timestamp=t + timedelta(minutes=10), source="Defender",
              event_type="THREAT_DETECTED", description="y", device="HOST-A")
    # 10 min apart: outside a 300s window -> not grouped.
    assert correlate_events([a, b], window_seconds=300, min_group_size=2) == []
    # Widen the window and the same pair now correlates.
    grouped = correlate_events([a, b], window_seconds=1200, min_group_size=2)
    assert len(grouped) == 1
    assert len(grouped[0].events) == 2


def test_correlation_over_database_uses_real_ids():
    assert seed_events(cluster_events()).inserted == 5
    incidents = correlate_database(window_seconds=300, min_group_size=2)
    assert incidents
    inc = max(incidents, key=lambda i: len(i.events))
    # Events read from the DB carry real integer ids.
    assert inc.event_ids and all(eid is not None for eid in inc.event_ids)
    assert set(inc.sources) >= {"USB", "FileSystem", "Defender"}


# --- Behavioral baseline ----------------------------------------------------

def test_baseline_ready_with_enough_history():
    baseline = build_baseline(baseline_events())
    assert baseline.status == BASELINE_READY
    assert baseline.total_events == 20


def test_cold_start_reports_insufficient_history():
    baseline = build_baseline(baseline_events()[:5])   # only 5 < 20 required
    assert baseline.status != BASELINE_READY
    anomalies = detect_anomalies([_unusual_event()], baseline=baseline)
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.classification == STATUS_INSUFFICIENT_HISTORY
    assert a.anomaly_score == 0.0


def test_unusual_event_flagged_and_explained():
    baseline = build_baseline(baseline_events())
    a = detect_anomalies([_unusual_event()], baseline=baseline)[0]
    assert a.classification in {STATUS_SUSPICIOUS, STATUS_ANOMALOUS}
    assert a.reasons and a.signals              # deviation is explained
    # An anomaly is never described as confirmed malicious activity.
    assert "malicious" not in " ".join(a.reasons).lower()


def test_anomaly_score_is_deterministic():
    baseline = build_baseline(baseline_events())
    ev = _unusual_event()
    first = detect_anomalies([ev], baseline=baseline)[0]
    second = detect_anomalies([ev], baseline=baseline)[0]
    assert first.anomaly_score == second.anomaly_score
    assert first.classification == second.classification


def test_analyze_database_evaluates_every_event(seeded):
    baseline, anomalies = behavior_mod.analyze_database()
    assert baseline.status == BASELINE_READY        # 25 seeded events
    assert len(anomalies) == seeded                 # every event evaluated
    assert all(a.classification in _VALID_CLASSES for a in anomalies)


