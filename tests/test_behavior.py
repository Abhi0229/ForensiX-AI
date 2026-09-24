"""Tests for the Phase 11 behavioral baseline & anomaly detection engine.

These tests use only synthetic events -- plain dicts, Event dataclass instances,
and real in-memory sqlite3.Row objects -- so no real database, OS resource, or
collected history is required. They assert the engine is deterministic,
explainable, read-only (never mutates inputs or their hash fields), handles cold
starts without false anomalies, and keeps its 0-100 score bounded and finite.
"""

import copy
import json
import math
import sqlite3
from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

from backend.database.models import Event
from backend.ai.behavior import (
    BehavioralBaselineEngine,
    BehavioralBaseline,
    BehaviorAnomaly,
    BehaviorEvent,
    build_baseline,
    detect_anomalies,
    analyze_database,
    STATUS_NORMAL, STATUS_SUSPICIOUS, STATUS_ANOMALOUS, STATUS_INSUFFICIENT_HISTORY,
    BASELINE_READY, BASELINE_INSUFFICIENT,
    SIGNAL_SOURCE, SIGNAL_CATEGORY, SIGNAL_EVENT_TYPE, SIGNAL_USER, SIGNAL_DEVICE,
    SIGNAL_SEVERITY, SIGNAL_HOUR, SIGNAL_FREQUENCY, SIGNAL_DAY,
    _mean, _pstd, _zscore, _rarity, _category, _coerce_timestamp,
    CAT_USB, CAT_FILE, CAT_BROWSER, CAT_DEFENDER, CAT_WINDOWS, CAT_OTHER,
)

MONDAY = datetime(2021, 1, 4)      # a Monday; weekday() == 0
SATURDAY = datetime(2021, 1, 9)    # weekday() == 5


# ---------------------------------------------------------------------------
# Helpers: build synthetic events as dicts, Event objects, and sqlite3.Row
# ---------------------------------------------------------------------------

def make_event(source="FileSystem", event_type="FILE_CREATED", *,
               timestamp=None, description="activity", severity="INFO",
               user="", device="DESKTOP-01", file_path="", metadata="",
               include_timestamp=True, **extra):
    """Return a raw event dict. ``include_timestamp=False`` omits the key entirely."""
    d = {
        "source": source,
        "event_type": event_type,
        "description": description,
        "severity": severity,
        "user": user,
        "device": device,
        "file_path": file_path,
        "metadata": metadata,
    }
    if include_timestamp:
        d["timestamp"] = timestamp
    d.update(extra)
    return d


def make_engine(**kw):
    kw.setdefault("min_baseline_events", 10)
    return BehavioralBaselineEngine(**kw)


def repeat(n, **kw):
    return [make_event(**kw) for _ in range(n)]


def at(dt, hour, **kw):
    return make_event(timestamp=dt.replace(hour=hour), **kw)


def hourly_events(counts, day=MONDAY, **kw):
    evs = []
    for hour, n in counts.items():
        for _ in range(n):
            evs.append(at(day, hour, **kw))
    return evs


def make_row(**fields):
    """A genuine sqlite3.Row built from an in-memory table (survives conn close)."""
    conn = sqlite3.connect(":memory:")
    try:
        conn.row_factory = sqlite3.Row
        cols = list(fields)
        conn.execute("CREATE TABLE t (%s)" % ",".join(cols))
        conn.execute(
            "INSERT INTO t (%s) VALUES (%s)" % (",".join(cols), ",".join(["?"] * len(cols))),
            [fields[c] for c in cols],
        )
        return conn.execute("SELECT * FROM t").fetchone()
    finally:
        conn.close()


def _event_obj(**kw):
    base = dict(timestamp=MONDAY.replace(hour=10), source="FileSystem",
                event_type="FILE_CREATED", description="a", severity="INFO",
                user="", device="DESKTOP-01", file_path="", metadata="")
    base.update(kw)
    return Event(**base)


def normal_baseline(engine=None, n=12):
    engine = engine or make_engine(min_baseline_events=10)
    return engine, engine.build_baseline(repeat(n))


# ---------------------------------------------------------------------------
# A. Pure helpers: statistics, timestamp coercion, categorisation
# ---------------------------------------------------------------------------

def test_mean_and_pstd_basic():
    assert _mean([]) == 0.0
    assert _mean([2, 4, 6]) == 4.0
    assert _pstd([]) == 0.0


def test_pstd_constant_values_is_zero():
    """Constant input has zero standard deviation (no divide/NaN issues)."""
    assert _pstd([5, 5, 5, 5]) == 0.0
    assert _pstd([0, 0, 0]) == 0.0


def test_zscore_zero_std_returns_zero():
    """A zero (or negative) std yields a 0.0 z-score rather than NaN/inf."""
    assert _zscore(10.0, 5.0, 0.0) == 0.0
    assert _zscore(10.0, 10.0, 0.0) == 0.0


def test_zscore_is_finite_and_correct():
    z = _zscore(10.0, 4.0, 2.0)
    assert z == 3.0
    assert math.isfinite(z)


def test_rarity_unseen_rare_and_common():
    assert _rarity(0, 0, 40.0, 15.0, 0.05) == (0.0, None)      # total 0 -> no divide
    assert _rarity(0, 100, 40.0, 15.0, 0.05) == (40.0, "unseen")
    assert _rarity(2, 100, 40.0, 15.0, 0.05) == (15.0, "rare")
    assert _rarity(50, 100, 40.0, 15.0, 0.05) == (0.0, None)


def test_category_classification():
    assert _category("USB", "USB_CONNECTED") == CAT_USB
    assert _category("FileSystem", "FILE_CREATED") == CAT_FILE
    assert _category("Browser", "BROWSER_VISIT") == CAT_BROWSER
    assert _category("Defender", "1116") == CAT_DEFENDER
    assert _category("Windows", "4624") == CAT_WINDOWS
    assert _category("SomeAgent", "PING") == CAT_OTHER
    assert _category("", "USB_INSERTED") == CAT_USB     # event-type prefix classifies
    assert _category("", "FILE_MOVED") == CAT_FILE


def test_coerce_timestamp_variants():
    dt = datetime(2021, 1, 4, 10, 0, 0)
    assert _coerce_timestamp(dt) == dt
    assert _coerce_timestamp("2021-01-04T10:00:00") == dt
    assert _coerce_timestamp("2021-01-04 10:00:00") == dt
    assert _coerce_timestamp(dt.timestamp()) == dt
    assert _coerce_timestamp(None) is None              # never fabricated
    assert _coerce_timestamp("") is None
    assert _coerce_timestamp("not-a-date") is None
    assert _coerce_timestamp(True) is None
    assert _coerce_timestamp(object()) is None


# ---------------------------------------------------------------------------
# B. Baseline construction, cold start, category/severity/user/device counts
# ---------------------------------------------------------------------------

def test_empty_input_builds_empty_baseline():
    b = make_engine().build_baseline([])
    assert b.total_events == 0
    assert b.timestamped_events == 0
    assert b.status == BASELINE_INSUFFICIENT
    assert b.insufficient_history is True
    assert b.source_counts == {}
    assert b.hour_counts == {}


def test_insufficient_history_baseline():
    b = make_engine(min_baseline_events=10).build_baseline(repeat(3))
    assert b.total_events == 3
    assert b.status == BASELINE_INSUFFICIENT
    assert b.insufficient_history is True


def test_sufficient_baseline_is_ready():
    b = make_engine(min_baseline_events=10).build_baseline(repeat(12))
    assert b.total_events == 12
    assert b.status == BASELINE_READY
    assert b.insufficient_history is False


def test_default_min_baseline_events_is_20():
    eng = BehavioralBaselineEngine()
    assert eng.min_baseline_events == 20
    assert eng.build_baseline(repeat(19)).status == BASELINE_INSUFFICIENT
    assert eng.build_baseline(repeat(20)).status == BASELINE_READY


def test_baseline_counts_categories_and_severity():
    events = repeat(10, severity="INFO") + repeat(2, event_type="FILE_DELETED", severity="WARNING")
    b = make_engine(min_baseline_events=5).build_baseline(events)
    assert b.total_events == 12
    assert b.source_counts["FileSystem"] == 12
    assert b.category_counts[CAT_FILE] == 12
    assert b.event_type_counts["FILE_CREATED"] == 10
    assert b.event_type_counts["FILE_DELETED"] == 2
    assert b.severity_counts == {"INFO": 10, "WARNING": 2}


def test_baseline_multiple_users_counted_separately():
    events = repeat(6, user="alice") + repeat(4, user="bob")
    b = make_engine(min_baseline_events=5).build_baseline(events)
    assert b.user_counts == {"alice": 6, "bob": 4}


def test_baseline_multiple_devices_counted_separately():
    events = repeat(5, device="LAPTOP-A") + repeat(5, device="SERVER-B")
    b = make_engine(min_baseline_events=5).build_baseline(events)
    assert b.device_counts == {"LAPTOP-A": 5, "SERVER-B": 5}


def test_baseline_timestamped_vs_untimed():
    timed = hourly_events({9: 3, 10: 3})       # 6 timestamped, all Monday
    untimed = repeat(6)                        # timestamp None
    b = make_engine(min_baseline_events=5).build_baseline(timed + untimed)
    assert b.total_events == 12
    assert b.timestamped_events == 6
    assert b.hour_counts == {9: 3, 10: 3}
    assert b.day_counts == {0: 6}


def test_build_baseline_none_raises_type_error():
    with pytest.raises(TypeError):
        make_engine().build_baseline(None)


# ---------------------------------------------------------------------------
# C. Evaluation: normal, unusual categorical dimensions, scoring
# ---------------------------------------------------------------------------

def test_normal_event_is_not_flagged():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(), base)
    assert result.classification == STATUS_NORMAL
    assert result.anomaly_score == 0.0
    assert result.signals == []
    assert result.reasons == ["Activity is consistent with the established baseline."]
    assert result.severity == "INFO"


def test_unusual_event_type_is_suspicious():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(event_type="FILE_DELETED"), base)
    assert result.classification == STATUS_SUSPICIOUS
    assert result.anomaly_score == 30.0
    assert result.signals == [SIGNAL_EVENT_TYPE]
    assert any("FILE_DELETED" in r for r in result.reasons)


def test_unseen_source_only_signal():
    eng = make_engine(min_baseline_events=10)
    base = eng.build_baseline(repeat(12, source="AppLog", event_type="INFO_MSG"))
    result = eng.evaluate(make_event(source="EvilAgent", event_type="INFO_MSG"), base)
    assert result.signals == [SIGNAL_SOURCE]
    assert result.anomaly_score == 40.0
    assert result.classification == STATUS_SUSPICIOUS


def test_unseen_category_flagged():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(source="USB", event_type="USB_CONNECTED"), base)
    assert SIGNAL_CATEGORY in result.signals
    assert result.classification == STATUS_ANOMALOUS
    assert any("USB activity" in r for r in result.reasons)


def test_known_category_suppresses_source_signal():
    """Category and source never double-count: a known category is assessed by
    category, so an unusual source label on a known category is not re-counted."""
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(source="WeirdFS", event_type="FILE_CREATED"), base)
    assert SIGNAL_SOURCE not in result.signals
    assert result.classification == STATUS_NORMAL


def test_rare_event_type_signal():
    eng = make_engine(min_baseline_events=10)
    events = (repeat(24, source="AppLog", event_type="LOGIN")
              + repeat(1, source="AppLog", event_type="RARE_OP"))
    base = eng.build_baseline(events)
    result = eng.evaluate(make_event(source="AppLog", event_type="RARE_OP"), base)
    assert result.signals == [SIGNAL_EVENT_TYPE]
    assert result.anomaly_score == 12.0
    assert any("rare" in r.lower() for r in result.reasons)


def test_unseen_severity_signal():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(severity="CRITICAL"), base)
    assert SIGNAL_SEVERITY in result.signals
    assert result.anomaly_score == 25.0
    assert any("CRITICAL" in r for r in result.reasons)


def test_empty_baseline_category_treats_new_user_as_unseen():
    """A dimension never observed in the baseline (no users) does not crash and
    an incoming value for it is treated as unseen."""
    eng = make_engine(min_baseline_events=10)
    base = eng.build_baseline(repeat(12, user=""))   # user_counts stays empty
    assert base.user_counts == {}
    result = eng.evaluate(make_event(user="alice"), base)
    assert SIGNAL_USER in result.signals


# ---------------------------------------------------------------------------
# D. Time-of-day / day-of-week behaviour
# ---------------------------------------------------------------------------

def test_unusual_hour_is_flagged():
    eng = make_engine(min_baseline_events=10)
    base = eng.build_baseline(hourly_events({h: 4 for h in range(9, 18)}))  # 09-17
    result = eng.evaluate(at(MONDAY, 3), base)  # 03:00 -- outside active hours
    assert result.signals == [SIGNAL_HOUR]
    assert result.anomaly_score == 30.0
    assert result.classification == STATUS_SUSPICIOUS
    assert any("03:00" in r for r in result.reasons)


def test_normal_hour_not_flagged():
    eng = make_engine(min_baseline_events=10)
    base = eng.build_baseline(hourly_events({h: 4 for h in range(9, 18)}))
    result = eng.evaluate(at(MONDAY, 10), base)
    assert SIGNAL_HOUR not in result.signals
    assert SIGNAL_FREQUENCY not in result.signals


def test_unusual_frequency_hour_signal():
    """An hour that is active but far below the norm yields a frequency signal."""
    eng = make_engine(min_baseline_events=10)
    counts = {h: 3 for h in range(24) if h != 3}
    counts[3] = 1  # hour 3 is heavily under-represented but not unseen
    base = eng.build_baseline(hourly_events(counts))
    result = eng.evaluate(at(MONDAY, 3), base)
    assert SIGNAL_FREQUENCY in result.signals
    assert result.anomaly_score == 20.0
    assert any("z-score" in r for r in result.reasons)


def test_unseen_weekday_signal():
    eng = make_engine(min_baseline_events=10)
    base = eng.build_baseline(hourly_events({h: 3 for h in range(9, 18)}, day=MONDAY))
    result = eng.evaluate(at(SATURDAY, 10), base)  # active hour, brand new weekday
    assert SIGNAL_DAY in result.signals
    assert any("Saturday" in r for r in result.reasons)


def test_missing_timestamp_skips_time_signals():
    eng, base = normal_baseline()
    ev = make_event(include_timestamp=False)  # no timestamp key at all
    result = eng.evaluate(ev, base)
    assert result.event.hour is None
    assert result.event.weekday is None
    assert SIGNAL_HOUR not in result.signals
    assert SIGNAL_DAY not in result.signals


def test_invalid_timestamp_is_not_fabricated():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(timestamp="definitely-not-a-date"), base)
    assert result.event.hour is None
    assert SIGNAL_HOUR not in result.signals


# ---------------------------------------------------------------------------
# E. User-specific and device-specific baselines (with graceful fallback)
# ---------------------------------------------------------------------------

def test_user_specific_hour_baseline():
    """alice works 09-17, bob works 00-05. 02:00 is normal for bob but unusual
    for alice -- proving the per-user hour distribution is used, not the global."""
    eng = make_engine(min_baseline_events=10)
    events = (hourly_events({h: 3 for h in range(9, 18)}, user="alice")
              + hourly_events({h: 3 for h in range(0, 6)}, user="bob"))
    base = eng.build_baseline(events)

    alice_night = eng.evaluate(at(MONDAY, 2, user="alice"), base)
    assert SIGNAL_HOUR in alice_night.signals
    assert any("alice" in r for r in alice_night.reasons)

    bob_night = eng.evaluate(at(MONDAY, 2, user="bob"), base)
    assert SIGNAL_HOUR not in bob_night.signals


def test_device_specific_hour_baseline():
    eng = make_engine(min_baseline_events=10)
    events = (hourly_events({h: 3 for h in range(8, 17)}, device="LAPTOP-A")
              + hourly_events({h: 3 for h in range(20, 24)}, device="SERVER-B"))
    base = eng.build_baseline(events)
    result = eng.evaluate(at(MONDAY, 22, device="LAPTOP-A"), base)
    assert SIGNAL_HOUR in result.signals
    assert any("LAPTOP-A" in r for r in result.reasons)


def test_missing_user_produces_no_user_signal():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(user=""), base)
    assert SIGNAL_USER not in result.signals


def test_missing_device_produces_no_device_signal_and_no_crash():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(device=""), base)
    assert SIGNAL_DEVICE not in result.signals
    assert isinstance(result, BehaviorAnomaly)


# ---------------------------------------------------------------------------
# F. Input compatibility: Event, dict, sqlite3.Row, mixed
# ---------------------------------------------------------------------------

def test_event_dataclass_input():
    eng = make_engine(min_baseline_events=5)
    base = eng.build_baseline([_event_obj() for _ in range(6)])
    result = eng.evaluate(_event_obj(event_type="FILE_DELETED"), base)
    assert result.classification == STATUS_SUSPICIOUS
    assert result.event.source == "FileSystem"


def test_dict_input():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(), base)
    assert isinstance(result, BehaviorAnomaly)


def test_sqlite_row_input():
    eng = make_engine(min_baseline_events=5)
    rows = [make_row(id=i + 1, timestamp="2021-01-04T10:00:00", source="FileSystem",
                     event_type="FILE_CREATED", description="a", severity="INFO",
                     user="", device="DESKTOP-01", file_path="", metadata="",
                     event_hash="h", previous_hash="p") for i in range(6)]
    base = eng.build_baseline(rows)
    assert base.status == BASELINE_READY
    weird = make_row(id=99, timestamp="2021-01-04T03:00:00", source="USB",
                     event_type="USB_CONNECTED", description="x", severity="INFO",
                     user="", device="DESKTOP-01", file_path="", metadata="",
                     event_hash="h2", previous_hash="p2")
    result = eng.evaluate(weird, base)
    assert result.classification == STATUS_ANOMALOUS
    assert result.event.event_id == 99


def test_mixed_input_types():
    eng = make_engine(min_baseline_events=5)
    mixed = [
        make_event(),
        _event_obj(),
        make_row(timestamp="2021-01-04T10:00:00", source="FileSystem",
                 event_type="FILE_CREATED", description="a", severity="INFO",
                 user="", device="DESKTOP-01", file_path="", metadata=""),
    ] * 2
    base = eng.build_baseline(mixed)
    assert base.total_events == 6
    assert base.source_counts["FileSystem"] == 6
    results = [eng.evaluate(item, base) for item in mixed]
    assert all(isinstance(r, BehaviorAnomaly) for r in results)


# ---------------------------------------------------------------------------
# G. Immutability: inputs and their Phase 9 hash fields are never modified
# ---------------------------------------------------------------------------

def test_dict_input_not_mutated():
    eng, base = normal_baseline()
    ev = make_event(source="USB", event_type="USB_CONNECTED", user="alice",
                    timestamp=MONDAY.replace(hour=3))
    snapshot = copy.deepcopy(ev)
    eng.evaluate(ev, base)
    assert ev == snapshot


def test_event_dataclass_not_mutated():
    eng = make_engine(min_baseline_events=5)
    base = eng.build_baseline([_event_obj() for _ in range(6)])
    ev = _event_obj(event_type="FILE_DELETED", user="bob")
    before = (ev.timestamp, ev.source, ev.event_type, ev.description, ev.severity,
              ev.user, ev.device, ev.file_path, ev.metadata)
    eng.evaluate(ev, base)
    after = (ev.timestamp, ev.source, ev.event_type, ev.description, ev.severity,
             ev.user, ev.device, ev.file_path, ev.metadata)
    assert before == after


def test_hash_fields_not_modified():
    """Phase 9 event_hash / previous_hash are read-only to this engine."""
    eng = make_engine(min_baseline_events=5)
    rows_src = [dict(timestamp="2021-01-04T10:00:00", source="FileSystem",
                     event_type="FILE_CREATED", description="a", severity="INFO",
                     user="", device="DESKTOP-01", file_path="", metadata="",
                     event_hash="hash-%d" % i, previous_hash="hash-%d" % (i - 1))
                for i in range(6)]
    snapshot = copy.deepcopy(rows_src)
    base = eng.build_baseline(rows_src)
    for r in rows_src:
        eng.evaluate(r, base)
    assert rows_src == snapshot
    result = eng.evaluate(rows_src[0], base)
    assert result.event.event_hash == "hash-0"
    assert result.event.previous_hash == "hash--1"


def test_baseline_build_does_not_mutate_inputs():
    events = [make_event() for _ in range(12)]
    snapshot = copy.deepcopy(events)
    make_engine(min_baseline_events=5).build_baseline(events)
    assert events == snapshot


# ---------------------------------------------------------------------------
# H. Determinism, score bounds, finiteness, result typing
# ---------------------------------------------------------------------------

def test_deterministic_scores_and_reasons():
    eng1 = make_engine(min_baseline_events=10)
    eng2 = make_engine(min_baseline_events=10)
    events = repeat(12)
    ev = make_event(source="USB", event_type="USB_CONNECTED",
                    timestamp=MONDAY.replace(hour=3), user="eve")
    r1 = eng1.evaluate(ev, eng1.build_baseline(events))
    r2 = eng2.evaluate(ev, eng2.build_baseline(events))
    assert r1.as_dict() == r2.as_dict()
    assert r1.anomaly_score == r2.anomaly_score
    assert r1.reasons == r2.reasons
    assert r1.signals == r2.signals


def test_reasons_are_sorted_deduplicated_nonempty():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(source="X", event_type="Y", user="eve",
                                     device="Z", severity="CRITICAL",
                                     timestamp=SATURDAY.replace(hour=3)), base)
    assert result.reasons == sorted(result.reasons)
    assert len(result.reasons) == len(set(result.reasons))
    assert all(r and isinstance(r, str) for r in result.reasons)
    assert result.signals == sorted(result.signals)


def test_score_is_bounded_and_finite():
    eng = make_engine(min_baseline_events=10)
    base = eng.build_baseline(hourly_events({h: 2 for h in range(9, 18)},
                                            user="alice", device="DESKTOP-01"))
    wild = make_event(source="Nmap", event_type="SCAN", user="eve",
                      device="ROGUE", severity="CRITICAL",
                      timestamp=SATURDAY.replace(hour=3))
    result = eng.evaluate(wild, base)
    assert result.anomaly_score == 100.0          # clamped, never exceeds the max
    assert 0.0 <= result.anomaly_score <= 100.0
    assert math.isfinite(result.anomaly_score)
    assert result.classification == STATUS_ANOMALOUS


def test_score_never_nan_or_inf_across_inputs():
    eng, base = normal_baseline()
    samples = [
        make_event(),
        make_event(event_type="FILE_DELETED"),
        make_event(source="USB", event_type="USB_CONNECTED"),
        make_event(timestamp="bad"),
        make_event(include_timestamp=False),
        make_event(user="x", device="y", severity="Z"),
    ]
    for ev in samples:
        score = eng.evaluate(ev, base).anomaly_score
        assert math.isfinite(score)
        assert 0.0 <= score <= 100.0


def test_insufficient_history_never_false_anomaly():
    """Even a wildly unusual event on a cold-start baseline is reported as
    INSUFFICIENT_HISTORY, never SUSPICIOUS/ANOMALOUS."""
    eng = make_engine(min_baseline_events=20)
    base = eng.build_baseline(repeat(3))          # cold start
    wild = make_event(source="Nmap", event_type="SCAN", user="eve",
                      severity="CRITICAL", timestamp=SATURDAY.replace(hour=3))
    result = eng.evaluate(wild, base)
    assert result.classification == STATUS_INSUFFICIENT_HISTORY
    assert result.anomaly_score == 0.0
    assert result.signals == []
    assert result.baseline_status == BASELINE_INSUFFICIENT
    assert len(result.reasons) == 1


def test_result_type_validation():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(event_type="FILE_DELETED"), base)
    assert isinstance(result, BehaviorAnomaly)
    assert isinstance(result.event, BehaviorEvent)
    assert isinstance(result.anomaly_score, float)
    assert result.classification in {STATUS_NORMAL, STATUS_SUSPICIOUS,
                                     STATUS_ANOMALOUS, STATUS_INSUFFICIENT_HISTORY}
    assert isinstance(result.reasons, list)
    assert isinstance(result.signals, list)
    assert result.severity in {"INFO", "WARNING", "HIGH"}
    d = result.as_dict()
    assert set(d) >= {"anomaly_score", "classification", "severity", "reasons",
                      "signals", "baseline_status", "event"}


def test_baseline_and_anomaly_as_dict_json_serializable():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(source="USB", event_type="USB_CONNECTED"), base)
    json.dumps(base.as_dict())
    json.dumps(result.as_dict())


# ---------------------------------------------------------------------------
# I. Module wrappers, evaluate_all, configuration, DB convenience
# ---------------------------------------------------------------------------

def test_module_build_baseline_and_detect_anomalies():
    events = repeat(12) + [make_event(event_type="FILE_DELETED")]
    base = build_baseline(events, min_baseline_events=10)
    assert base.status == BASELINE_READY
    results = detect_anomalies(events, min_baseline_events=10)
    assert len(results) == len(events)
    assert all(isinstance(r, BehaviorAnomaly) for r in results)


def test_detect_anomalies_with_explicit_baseline():
    base = build_baseline(repeat(12), min_baseline_events=10)
    results = detect_anomalies([make_event(event_type="FILE_DELETED")],
                               baseline=base, min_baseline_events=10)
    assert results[0].classification == STATUS_SUSPICIOUS


def test_evaluate_all_builds_baseline_when_missing():
    eng = make_engine(min_baseline_events=10)
    results = eng.evaluate_all(repeat(12))
    assert len(results) == 12
    assert all(r.classification == STATUS_NORMAL for r in results)


def test_evaluate_all_none_raises():
    with pytest.raises(TypeError):
        make_engine().evaluate_all(None)


def test_engine_config_validation():
    with pytest.raises(ValueError):
        BehavioralBaselineEngine(min_baseline_events=0)
    with pytest.raises(ValueError):
        BehavioralBaselineEngine(min_subject_events=0)
    with pytest.raises(ValueError):
        BehavioralBaselineEngine(rare_threshold=2.0)
    with pytest.raises(ValueError):
        BehavioralBaselineEngine(z_threshold=-1.0)
    with pytest.raises(ValueError):
        BehavioralBaselineEngine(suspicious_score=80, anomalous_score=50)


def test_behavior_event_is_frozen():
    eng, base = normal_baseline()
    result = eng.evaluate(make_event(), base)
    with pytest.raises(FrozenInstanceError):
        result.event.source = "changed"


def test_analyze_database_is_read_only(monkeypatch):
    """analyze_database only *reads* via get_events; it performs no writes."""
    import backend.database.db as dbmod
    synthetic = [make_event() for _ in range(12)]
    monkeypatch.setattr(dbmod, "get_events", lambda limit=None: synthetic)
    baseline, anomalies = analyze_database(min_baseline_events=10)
    assert baseline.status == BASELINE_READY
    assert len(anomalies) == 12
    assert all(isinstance(a, BehaviorAnomaly) for a in anomalies)










