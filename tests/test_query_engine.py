"""Tests for the Phase 12 Natural-Language Investigation Engine.

These tests never require Ollama, a network, or the real ForensiX database:

* The local LLM layer is always mocked (a stub object with ``generate`` or a
  monkeypatched ``urlopen``), so nothing depends on Ollama being installed.
* Database retrieval runs against an isolated temporary SQLite file built with
  the real ``events`` schema, exercised through an injected ``connection_factory``.
  This lets us prove retrieval is parameterized, injection-safe, and read-only.

Safety is a first-class concern: dedicated tests assert the natural-language
input never becomes SQL, that no rows/tables/hashes are ever modified, and that
the LLM is only ever handed the retrieved evidence.
"""

import json
import sqlite3
from datetime import datetime

import pytest

from backend.database.models import Event
from backend.integrity.hasher import GENESIS_PREVIOUS_HASH, hash_event
from backend.ai import query_engine as qe
from backend.ai.query_engine import (
    InvestigationQueryEngine,
    InvestigationRequest,
    LLMResponseError,
    LLMUnavailableError,
    OllamaClient,
    build_prompt,
    build_retrieval_query,
    parse_question,
)

# Full events schema (mirrors backend/database/schema.py) for isolated temp DBs.
_CREATE_EVENTS = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO',
    user TEXT, device TEXT, file_path TEXT, metadata TEXT,
    event_hash TEXT, previous_hash TEXT
)
"""

_INSERT = ("INSERT INTO events (timestamp, source, event_type, description, "
           "severity, user, device, file_path, metadata, event_hash, "
           "previous_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")

import copy

from backend.ai.behavior import BASELINE_INSUFFICIENT, BASELINE_READY


def _make_event(**over):
    """Build an :class:`Event` (never has a DB id) with sensible defaults."""
    base = dict(
        timestamp=datetime(2026, 3, 1, 14, 30, 0),
        source="FileSystem",
        event_type="FILE_MODIFIED",
        description="modified file",
        severity="INFO",
        user="alice",
        device="HOST1",
        file_path="C:/data/report.docx",
        metadata="{}",
    )
    base.update(over)
    return Event(**base)


def _sample_events():
    """A varied, deterministic set covering every collector source."""
    return [
        _make_event(source="USB", event_type="USB_CONNECTED",
                    timestamp=datetime(2026, 3, 1, 14, 0, 0), user="alice",
                    device="HOST1", file_path="", severity="INFO",
                    description="usb device inserted",
                    metadata='{"vendor":"Kingston"}'),
        _make_event(source="FileSystem", event_type="FILE_DELETED",
                    timestamp=datetime(2026, 3, 1, 14, 5, 0), user="alice",
                    device="HOST1", file_path="C:/data/report.docx",
                    severity="WARNING", description="deleted report"),
        _make_event(source="FileSystem", event_type="FILE_CREATED",
                    timestamp=datetime(2026, 3, 1, 14, 6, 0), user="bob",
                    device="HOST2", file_path="C:/data/notes.txt",
                    severity="INFO", description="created notes"),
        _make_event(source="Browser", event_type="BROWSER_VISIT",
                    timestamp=datetime(2026, 3, 1, 9, 0, 0), user="bob",
                    device="HOST2", file_path="http://example.com/page",
                    severity="INFO", description="visited example.com"),
        _make_event(source="Defender", event_type="1116",
                    timestamp=datetime(2026, 3, 1, 22, 0, 0), user="alice",
                    device="HOST1", file_path="C:/data/report.docx",
                    severity="HIGH", description="threat detected near report"),
    ]

class _TempDB:
    """An isolated on-disk SQLite database with the real ``events`` schema."""

    def __init__(self, path):
        self.path = str(path)
        conn = sqlite3.connect(self.path)
        conn.execute(_CREATE_EVENTS)
        conn.commit()
        conn.close()

    def factory(self):
        """A ``connection_factory``: returns a fresh Row-enabled connection."""
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def seed(self, events, *, hashed=False):
        """Insert Event objects; when ``hashed`` build a valid Phase-9 chain."""
        conn = sqlite3.connect(self.path)
        prev = GENESIS_PREVIOUS_HASH
        for ev in events:
            ts = (ev.timestamp.isoformat()
                  if isinstance(ev.timestamp, datetime) else ev.timestamp)
            if hashed:
                event_hash, previous_hash = hash_event(ev, prev), prev
                prev = event_hash
            else:
                event_hash = previous_hash = None
            conn.execute(_INSERT, (ts, ev.source, ev.event_type, ev.description,
                                   ev.severity, ev.user, ev.device, ev.file_path,
                                   ev.metadata, event_hash, previous_hash))
        conn.commit()
        conn.close()

    def tamper(self, event_id, new_description):
        """Directly corrupt a stored row (simulates evidence tampering)."""
        conn = sqlite3.connect(self.path)
        conn.execute("UPDATE events SET description = ? WHERE id = ?",
                     (new_description, event_id))
        conn.commit()
        conn.close()

    def snapshot(self):
        conn = self.factory()
        try:
            return [tuple(r) for r in conn.execute(
                "SELECT * FROM events ORDER BY id").fetchall()]
        finally:
            conn.close()

    def hashes(self):
        conn = self.factory()
        try:
            return [(r["id"], r["event_hash"], r["previous_hash"])
                    for r in conn.execute(
                        "SELECT id, event_hash, previous_hash FROM events "
                        "ORDER BY id")]
        finally:
            conn.close()

    def count(self):
        conn = sqlite3.connect(self.path)
        try:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            conn.close()

    def tables(self):
        conn = sqlite3.connect(self.path)
        try:
            return {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()


@pytest.fixture
def tdb(tmp_path):
    return _TempDB(tmp_path / "events.db")


class _FakeLLM:
    """A stub local LLM: records what it was asked, returns a canned answer."""

    def __init__(self, answer="The evidence shows the retrieved events.",
                 model="fake-model"):
        self.answer = answer
        self.model = model
        self.calls = []

    def generate(self, prompt, *, system=None):
        self.calls.append({"prompt": prompt, "system": system})
        return self.answer


class _UnavailableLLM:
    """Simulates Ollama not being reachable."""
    model = "offline-model"

    def __init__(self):
        self.calls = 0

    def generate(self, prompt, *, system=None):
        self.calls += 1
        raise LLMUnavailableError("connection refused")


class _EmptyLLM:
    """Reachable, but returns an empty/whitespace response."""
    model = "empty-model"

    def generate(self, prompt, *, system=None):
        return "   \n  "


def _engine(tdb=None, *, llm=None, **kw):
    factory = tdb.factory if tdb is not None else None
    return InvestigationQueryEngine(
        llm=llm if llm is not None else _FakeLLM(),
        connection_factory=factory, **kw)

# ===========================================================================
# Section A -- deterministic parsing into a validated InvestigationRequest
# ===========================================================================


def test_parse_empty_query_defaults():
    req = parse_question("")
    assert req.original_question == ""
    assert req.intent == qe.INTENT_SEARCH
    assert req.sources == () and req.event_types == () and req.keywords == ()
    assert req.user is None and req.device is None and req.file_path is None
    assert req.severity is None
    assert req.limit == qe.DEFAULT_LIMIT
    assert not (req.include_correlations or req.include_behavior
                or req.verify_integrity)


def test_parse_none_query_is_safe():
    req = parse_question(None)
    assert req.original_question == "" and req.sources == ()


def test_parse_source_usb():
    assert "USB" in parse_question("Show USB activity").sources


def test_parse_source_defender():
    assert "Defender" in parse_question("any antivirus detections?").sources


def test_parse_event_type_file_deletion():
    req = parse_question("were there any file deletions?")
    assert "FILE_DELETED" in req.event_types


def test_parse_keyword_filename():
    assert "report.docx" in parse_question("everything about report.docx").keywords


def test_parse_explicit_path_sets_file_path():
    req = parse_question(r"activity on C:\Users\bob\secret.txt")
    assert req.file_path == r"C:\Users\bob\secret.txt"


def test_parse_user():
    assert parse_question("file changes for user alice").user == "alice"


def test_parse_device():
    assert parse_question("events on device HOST1").device == "HOST1"


def test_parse_severity_high():
    assert parse_question("high severity events").severity == "HIGH"

def test_parse_time_between():
    req = parse_question("Show activity between 2 PM and 3 PM")
    assert (req.hour_start, req.hour_end) == (14, 15)


def test_parse_time_around():
    req = parse_question("what happened around 3 PM?")
    assert (req.hour_start, req.hour_end) == (15, 15)


def test_parse_time_after():
    req = parse_question("show events after 5 pm")
    assert (req.hour_start, req.hour_end) == (17, 23)


def test_parse_combined_filters():
    req = parse_question(
        "high severity USB activity for user bob between 1 PM and 5 PM")
    assert req.severity == "HIGH"
    assert "USB" in req.sources
    assert req.user == "bob"
    assert (req.hour_start, req.hour_end) == (13, 17)


def test_parse_limit_override():
    assert parse_question("show events", limit=25).limit == 25


def test_parse_intent_suspicious_enables_behavior():
    req = parse_question("was there any suspicious activity?")
    assert req.include_behavior is True
    assert req.intent == qe.INTENT_BEHAVIOR


def test_parse_intent_related_enables_correlation():
    req = parse_question("what events are related to this?")
    assert req.include_correlations is True


def test_parse_intent_integrity_enables_verify():
    assert parse_question("has any evidence been tampered with?").verify_integrity


def test_overrides_take_precedence_over_text():
    # Text says HIGH, but the explicit override wins deterministically.
    assert parse_question("high severity", severity="LOW").severity == "LOW"


def test_deterministic_structured_request():
    q = "suspicious high severity USB file deletions for user alice at 2 PM"
    assert parse_question(q).as_dict() == parse_question(q).as_dict()


def test_missing_optional_fields_are_none():
    req = parse_question("show me the events")
    for name in ("user", "device", "file_path", "severity",
                 "start_time", "end_time", "hour_start", "hour_end"):
        assert getattr(req, name) is None

def test_invalid_severity_raises():
    with pytest.raises(ValueError):
        InvestigationRequest(severity="TOTALLY_BOGUS")


def test_invalid_limit_raises():
    with pytest.raises(ValueError):
        InvestigationRequest(limit=0)
    with pytest.raises(ValueError):
        InvestigationRequest(limit=-5)
    with pytest.raises(ValueError):
        InvestigationRequest(limit=True)  # bool is not a valid integer limit


def test_invalid_hour_out_of_range_raises():
    with pytest.raises(ValueError):
        InvestigationRequest(hour_start=10, hour_end=30)


def test_hour_bounds_required_together():
    with pytest.raises(ValueError):
        InvestigationRequest(hour_start=9)


def test_start_after_end_raises():
    with pytest.raises(ValueError):
        InvestigationRequest(start_time=datetime(2026, 1, 2),
                             end_time=datetime(2026, 1, 1))


def test_invalid_timestamp_type_raises():
    with pytest.raises(ValueError):
        InvestigationRequest(start_time="2026-01-01")  # must be a datetime


def test_limit_enforcement_caps_and_warns():
    req = InvestigationRequest(limit=99999)
    assert req.limit == qe.MAX_LIMIT
    assert any("capped" in w for w in req.warnings)


def test_severity_is_normalised_uppercase():
    assert InvestigationRequest(severity="high").severity == "HIGH"


def test_request_serialization_round_trips():
    req = parse_question("USB activity for user alice between 2 PM and 3 PM")
    data = req.as_dict()
    assert json.loads(json.dumps(data)) == data

# ===========================================================================
# Section B -- safe, parameterized, read-only retrieval
# ===========================================================================


def test_build_query_is_fully_parameterized():
    req = parse_question("", sources=("USB",), severity="HIGH",
                         user="SENTINELUSER", keywords=("SENTINELKW",))
    sql, params = build_retrieval_query(req)
    # User-derived values NEVER appear in the SQL text -- only bound '?' params.
    assert "SENTINELUSER" not in sql
    assert "SENTINELKW" not in sql
    assert sql.count("?") == len(params)
    assert "SENTINELUSER" in params
    assert any("SENTINELKW" in str(p) for p in params)
    assert sql.lstrip().upper().startswith("SELECT")
    assert "FROM events" in sql


def test_retrieve_by_source(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", sources=("USB",))
    assert ctx.evidence_count == 1
    assert ctx.retrieved_events[0].source == "USB"


def test_retrieve_by_event_type(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", event_types=("FILE_DELETED",))
    assert ctx.evidence_count == 1
    assert ctx.retrieved_events[0].event_type == "FILE_DELETED"


def test_retrieve_by_user(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", user="alice")
    assert ctx.evidence_count == 3
    assert all(e.user == "alice" for e in ctx.retrieved_events)


def test_retrieve_by_device(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", device="HOST2")
    assert ctx.evidence_count == 2
    assert all(e.device == "HOST2" for e in ctx.retrieved_events)


def test_retrieve_by_file_path_substring(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", file_path="report.docx")
    assert ctx.evidence_count == 2
    assert all("report.docx" in e.file_path for e in ctx.retrieved_events)

def test_retrieve_by_severity(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", severity="HIGH")
    assert ctx.evidence_count == 1
    assert ctx.retrieved_events[0].severity == "HIGH"


def test_retrieve_by_absolute_time_range(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context(
        "", start_time=datetime(2026, 3, 1, 14, 0, 0),
        end_time=datetime(2026, 3, 1, 15, 0, 0))
    assert ctx.evidence_count == 3  # the three 14:0x events, not 09:00 / 22:00


def test_retrieve_by_hour_of_day(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", hour_start=14, hour_end=14)
    assert ctx.evidence_count == 3
    assert all(e.timestamp.hour == 14 for e in ctx.retrieved_events)


def test_retrieve_by_keyword_searches_metadata(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", keywords=("Kingston",))
    assert ctx.evidence_count == 1
    assert "Kingston" in ctx.retrieved_events[0].metadata


def test_retrieve_combined_filters(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", sources=("FileSystem",), user="alice")
    assert ctx.evidence_count == 1
    assert ctx.retrieved_events[0].event_type == "FILE_DELETED"


def test_retrieve_respects_limit(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", limit=2)
    assert ctx.evidence_count == 2
    assert ctx.retrieval_metadata["truncated"] is True


def test_retrieve_orders_by_time(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("")
    times = [e.timestamp for e in ctx.retrieved_events]
    assert times == sorted(times)  # ORDER BY timestamp ASC


def test_event_ids_preserved_and_db_backed(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", severity="HIGH")
    rec = ctx.retrieved_events[0]
    assert rec.db_backed is True
    assert rec.event_id == 5  # the 5th inserted row (Defender, HIGH)
    assert rec.reference() == "event 5"

def test_sqlite_row_inputs_are_handled(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("")
    assert ctx.evidence_count == 5
    assert all(isinstance(e.event_id, int) and e.db_backed
               for e in ctx.retrieved_events)


def test_no_matching_events_returns_message(tdb):
    tdb.seed(_sample_events())
    fake = _FakeLLM()
    res = _engine(tdb, llm=fake).investigate("", user="nobody")
    assert res.context.evidence_count == 0
    assert res.answer == qe.NO_EVIDENCE_MESSAGE
    assert res.answer_source == qe.ANSWER_SOURCE_NO_EVIDENCE
    assert fake.calls == []  # the LLM is never consulted when there is no evidence


def test_deterministic_retrieval(tdb):
    tdb.seed(_sample_events())
    eng = _engine(tdb)
    a = eng.build_context("", sources=("FileSystem",))
    b = eng.build_context("", sources=("FileSystem",))
    assert a.evidence_ids == b.evidence_ids
    assert a.as_dict() == b.as_dict()


def test_no_sql_injection_through_keyword(tdb):
    tdb.seed(_sample_events())
    before = tdb.count()
    ctx = _engine(tdb).build_context(
        "", keywords=("'; DROP TABLE events; --",))
    assert ctx.evidence_count == 0            # treated as a literal, matches nothing
    assert "events" in tdb.tables()           # table still exists
    assert tdb.count() == before              # nothing deleted


def test_no_sql_injection_through_user_field(tdb):
    tdb.seed(_sample_events())
    ctx = _engine(tdb).build_context("", user="alice' OR '1'='1")
    assert ctx.evidence_count == 0            # not a wildcard match; bound literal
    assert tdb.count() == 5


def test_missing_table_is_graceful(tmp_path):
    path = str(tmp_path / "empty.db")
    sqlite3.connect(path).close()  # a database with no 'events' table

    def factory():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn

    res = InvestigationQueryEngine(
        llm=_FakeLLM(), connection_factory=factory).investigate("show events")
    assert res.context.evidence_count == 0
    assert res.answer == qe.NO_EVIDENCE_MESSAGE
    assert any("retrieval skipped" in w for w in res.context.warnings)

# ===========================================================================
# Section C -- Phase 10 correlation / Phase 11 behavior / Phase 9 integrity
# ===========================================================================


def _baseline_history(source="FileSystem", event_type="FILE_MODIFIED", n=25):
    """A large, uniform historical baseline (kept separate from the subject)."""
    return [_make_event(source=source, event_type=event_type,
                        timestamp=datetime(2026, 2, 1, 10, m, 0),
                        user="carol", device="WS1", severity="INFO",
                        file_path="C:/work/doc.txt", description="edited doc")
            for m in range(n)]


def test_correlation_integration_forms_incident():
    usb = _make_event(source="USB", event_type="USB_CONNECTED",
                      timestamp=datetime(2026, 3, 1, 14, 0, 0), file_path="")
    delete = _make_event(source="FileSystem", event_type="FILE_DELETED",
                         timestamp=datetime(2026, 3, 1, 14, 5, 0))
    eng = _engine(correlation_kwargs={"window_seconds": 600, "min_group_size": 2})
    ctx = eng.build_context("", events=[usb, delete], include_correlations=True)
    assert len(ctx.candidate_incidents) == 1
    assert set(ctx.candidate_incidents[0]["sources"]) == {"USB", "FileSystem"}


def test_behavioral_integration_flags_anomaly():
    history = _baseline_history()  # 25 FileSystem events
    subject = _make_event(source="USB", event_type="USB_CONNECTED",
                          timestamp=datetime(2026, 2, 1, 10, 0, 0),
                          user="carol", device="WS1", file_path="")
    ctx = _engine().build_context(
        "", events=[subject], baseline_events=history, include_behavior=True)
    assert ctx.behavioral_baseline_status == BASELINE_READY
    assert len(ctx.behavioral_anomalies) == 1
    assert ctx.behavioral_anomalies[0]["classification"] in ("SUSPICIOUS",
                                                             "ANOMALOUS")


def test_behavioral_baseline_is_separate_from_investigated():
    # Same subject event, two different histories -> different verdicts, proving
    # the baseline is learned from baseline_events, not from the subject itself.
    subject = _make_event(source="USB", event_type="USB_CONNECTED",
                          timestamp=datetime(2026, 2, 1, 10, 0, 0),
                          user="carol", device="WS1", file_path="")
    eng = _engine()
    unrelated = eng.build_context(
        "", events=[subject], baseline_events=_baseline_history(),
        include_behavior=True)
    matching = eng.build_context(
        "", events=[subject],
        baseline_events=_baseline_history(source="USB",
                                          event_type="USB_CONNECTED"),
        include_behavior=True)
    assert len(unrelated.behavioral_anomalies) == 1   # unusual vs file history
    assert matching.behavioral_anomalies == []        # normal vs usb history

def test_insufficient_behavioral_history_preserved():
    # No separate history + only a few events => baseline is a cold start and the
    # engine reports INSUFFICIENT_HISTORY rather than inventing an anomaly.
    ctx = _engine().build_context(
        "", events=_sample_events()[:3], include_behavior=True)
    assert ctx.behavioral_baseline_status == BASELINE_INSUFFICIENT
    assert ctx.behavioral_anomalies == []
    assert any("insufficient" in w.lower() for w in ctx.warnings)
    assert any("no separate historical data" in w for w in ctx.warnings)


def test_integrity_verification_valid_chain(tdb):
    tdb.seed(_sample_events(), hashed=True)
    ctx = _engine(tdb).build_context("", verify_integrity=True)
    assert ctx.integrity is not None
    assert ctx.integrity["valid"] is True
    assert ctx.integrity["hashed_events"] == 5
    assert all(e.integrity == qe.INTEGRITY_VERIFIED for e in ctx.retrieved_events)


def test_legacy_events_integrity_labeled(tdb):
    tdb.seed(_sample_events(), hashed=False)  # pre-Phase-9, NULL hashes
    ctx = _engine(tdb).build_context("", verify_integrity=True)
    assert ctx.integrity["valid"] is True
    assert ctx.integrity["legacy_events"] == 5
    assert all(e.integrity == qe.INTEGRITY_LEGACY for e in ctx.retrieved_events)


def test_tampered_evidence_detected(tdb):
    tdb.seed(_sample_events()[:3], hashed=True)
    tdb.tamper(2, "description quietly altered after the fact")
    ctx = _engine(tdb).build_context("", verify_integrity=True)
    assert ctx.integrity["valid"] is False
    assert 2 in [e["id"] for e in ctx.integrity["invalid_events"]]
    labels = {e.event_id: e.integrity for e in ctx.retrieved_events}
    assert labels[2] == qe.INTEGRITY_TAMPERED
    assert labels[1] == qe.INTEGRITY_VERIFIED
    assert labels[3] == qe.INTEGRITY_VERIFIED


def test_integrity_skipped_for_non_db_events():
    # Bare Event objects have no hash chain; verification is skipped, not faked.
    ctx = _engine().build_context(
        "", events=_sample_events(), verify_integrity=True)
    assert ctx.integrity is None
    assert all(e.integrity == qe.INTEGRITY_LEGACY for e in ctx.retrieved_events)


def test_event_object_handling_no_db_id():
    ctx = _engine().build_context("", events=_sample_events())
    assert ctx.evidence_count == 5
    assert all(e.event_id is None and e.db_backed is False
               for e in ctx.retrieved_events)
    assert ctx.retrieved_events[0].reference() == "an event with no database id"
    assert ctx.evidence_ids == []

# ===========================================================================
# Section D -- grounded LLM layer (always mocked; never needs Ollama)
# ===========================================================================


def test_llm_success_produces_grounded_answer(tdb):
    tdb.seed(_sample_events())
    fake = _FakeLLM(answer="Five events were retrieved.", model="test-llm")
    res = _engine(tdb, llm=fake).investigate("show all events")
    assert res.answer == "Five events were retrieved."
    assert res.answer_source == qe.ANSWER_SOURCE_LLM
    assert res.llm_available is True
    assert res.llm_model == "test-llm"
    assert len(fake.calls) == 1
    # The LLM is grounded via the fixed system prompt.
    assert fake.calls[0]["system"] == qe.GROUNDING_SYSTEM_PROMPT


def test_llm_unavailable_still_returns_deterministic_result(tdb):
    tdb.seed(_sample_events())
    res = _engine(tdb, llm=_UnavailableLLM()).investigate("show all events")
    assert res.answer is None
    assert res.answer_source == qe.ANSWER_SOURCE_FALLBACK
    assert res.message == qe.LLM_UNAVAILABLE_MESSAGE
    assert res.llm_available is False
    # Retrieval did not depend on the LLM: the evidence is still present.
    assert res.context.evidence_count == 5
    assert res.deterministic_summary.startswith("Retrieved 5")


def test_llm_empty_response_is_handled(tdb):
    tdb.seed(_sample_events())
    res = _engine(tdb, llm=_EmptyLLM()).investigate("show all events")
    assert res.answer is None
    assert res.message == qe.LLM_EMPTY_MESSAGE
    assert res.llm_available is True
    assert res.answer_source == qe.ANSWER_SOURCE_FALLBACK


def test_no_evidence_skips_llm(tdb):
    tdb.seed(_sample_events())
    fake = _FakeLLM()
    res = _engine(tdb, llm=fake).investigate("", severity="CRITICAL")
    assert res.answer == qe.NO_EVIDENCE_MESSAGE
    assert fake.calls == []


def test_generate_answer_false_returns_context_only(tdb):
    tdb.seed(_sample_events())
    fake = _FakeLLM()
    res = _engine(tdb, llm=fake).investigate("show all events",
                                             generate_answer=False)
    assert res.answer is None
    assert fake.calls == []
    assert res.context.evidence_count == 5

def test_grounding_system_prompt_contains_rules():
    system = qe.GROUNDING_SYSTEM_PROMPT
    assert "ONLY the evidence" in system
    assert "Do NOT invent" in system
    assert "causation" in system
    assert "anomaly" in system.lower()
    assert "event ID" in system


def test_prompt_only_references_retrieved_evidence(tdb):
    tdb.seed(_sample_events()[:2])  # ids 1 and 2 only
    ctx = _engine(tdb).build_context("show events")
    prompt, system = build_prompt(ctx)
    assert system == qe.GROUNDING_SYSTEM_PROMPT
    assert "QUESTION: show events" in prompt
    assert "event 1" in prompt and "event 2" in prompt
    assert "event 3" not in prompt  # never references events that were not retrieved
    assert "Events retrieved: 2" in prompt


def test_prompt_reports_no_evidence_block():
    ctx = _engine().build_context("", events=[])
    prompt, _system = build_prompt(ctx)
    assert "Events retrieved: 0" in prompt


def test_ollama_client_success(monkeypatch):
    class _Resp:
        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(qe.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp(b'{"response":"hello"}'))
    client = OllamaClient(model="m", host="http://localhost:11434")
    assert client.generate("hi") == "hello"


def test_ollama_client_connection_error_raises_unavailable(monkeypatch):
    def boom(req, timeout=None):
        raise qe.urllib.error.URLError("connection refused")

    monkeypatch.setattr(qe.urllib.request, "urlopen", boom)
    with pytest.raises(LLMUnavailableError):
        OllamaClient(model="m").generate("hi")


def test_ollama_client_malformed_json_raises_response_error(monkeypatch):
    class _Resp:
        def read(self):
            return b"this is not json"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(qe.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp())
    with pytest.raises(LLMResponseError):
        OllamaClient(model="m").generate("hi")

def test_ollama_client_missing_response_field_raises(monkeypatch):
    class _Resp:
        def read(self):
            return b'{"model":"m","done":true}'  # valid JSON, no 'response'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(qe.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp())
    with pytest.raises(LLMResponseError):
        OllamaClient(model="m").generate("hi")


def test_ollama_client_model_is_configurable(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert OllamaClient().model == "mistral"          # from env
    assert OllamaClient(model="phi3").model == "phi3"  # explicit arg wins


def test_unexpected_llm_error_degrades_gracefully(tdb):
    tdb.seed(_sample_events())

    class _Boom:
        model = "boom"

        def generate(self, prompt, *, system=None):
            raise RuntimeError("kaboom")  # not an LLMError

    res = _engine(tdb, llm=_Boom()).investigate("show all events")
    assert res.answer is None
    assert res.answer_source == qe.ANSWER_SOURCE_FALLBACK
    assert res.context.evidence_count == 5  # still fully usable

# ===========================================================================
# Section E -- read-only guarantees, determinism, serialization, limits
# ===========================================================================


def _investigate_everything(tdb):
    """Run every read path (retrieval + correlation + behavior + integrity)."""
    return _engine(
        tdb, correlation_kwargs={"window_seconds": 600},
    ).investigate("", verify_integrity=True, include_behavior=True,
                  include_correlations=True)


def test_no_db_rows_mutated(tdb):
    tdb.seed(_sample_events(), hashed=True)
    before = tdb.snapshot()
    _investigate_everything(tdb)
    assert tdb.snapshot() == before


def test_no_hashes_mutated(tdb):
    tdb.seed(_sample_events(), hashed=True)
    before = tdb.hashes()
    _investigate_everything(tdb)
    assert tdb.hashes() == before


def test_no_tables_created_or_dropped(tdb):
    tdb.seed(_sample_events(), hashed=True)
    before = tdb.tables()
    _investigate_everything(tdb)
    assert tdb.tables() == before


def test_event_objects_not_mutated():
    events = _sample_events()
    original = copy.deepcopy(events)
    _engine().build_context(
        "", events=events, baseline_events=_baseline_history(),
        include_correlations=True, include_behavior=True)
    assert events == original


def test_context_is_json_serializable(tdb):
    tdb.seed(_sample_events(), hashed=True)
    ctx = _investigate_everything(tdb).context
    text = json.dumps(ctx.as_dict())  # must not raise
    reloaded = json.loads(text)
    assert reloaded["evidence_count"] == 5
    assert reloaded["integrity"]["valid"] is True


def test_result_is_json_serializable(tdb):
    tdb.seed(_sample_events())
    res = _engine(tdb).investigate("show all events")
    data = json.loads(json.dumps(res.as_dict()))
    assert "answer" in data and "context" in data
    assert data["context"]["evidence_count"] == 5

def _many_events(n=40):
    return [_make_event(timestamp=datetime(2026, 3, 2, 8, i % 60, 0),
                        description=f"event number {i}")
            for i in range(n)]


def test_large_result_set_limit_enforced(tdb):
    tdb.seed(_many_events(40))
    ctx = _engine(tdb).build_context("", limit=10)
    assert ctx.evidence_count == 10
    assert ctx.retrieval_metadata["truncated"] is True


def test_default_limit_returns_all_when_under_cap(tdb):
    tdb.seed(_many_events(40))
    ctx = _engine(tdb, default_limit=100).build_context("")
    assert ctx.evidence_count == 40
    assert ctx.retrieval_metadata["truncated"] is False


def test_engine_default_limit_applied(tdb):
    tdb.seed(_many_events(40))
    ctx = _engine(tdb, default_limit=5).build_context("")
    assert ctx.evidence_count == 5


def test_deterministic_summary_no_evidence():
    ctx = _engine().build_context("", events=[])
    assert qe.build_deterministic_summary(ctx) == qe.NO_EVIDENCE_MESSAGE


def test_module_level_investigate(tdb):
    tdb.seed(_sample_events())
    fake = _FakeLLM(answer="ok")
    res = qe.investigate("show all events", connection_factory=tdb.factory,
                         llm=fake)
    assert res.answer == "ok"
    assert res.context.evidence_count == 5


def test_investigate_over_provided_events_end_to_end():
    fake = _FakeLLM(answer="grounded summary")
    res = qe.investigate(
        "any suspicious usb activity?", events=[
            _make_event(source="USB", event_type="USB_CONNECTED",
                        timestamp=datetime(2026, 2, 1, 10, 0, 0),
                        user="carol", device="WS1", file_path="")],
        baseline_events=_baseline_history(), llm=fake)
    assert res.context.evidence_count == 1
    assert res.answer == "grounded summary"
    assert len(res.context.behavioral_anomalies) == 1
