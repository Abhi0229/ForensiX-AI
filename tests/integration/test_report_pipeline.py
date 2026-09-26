"""Integration: InvestigationResult -> report generator -> structured/text report.

Verifies the Phase 13 report is a faithful, deterministic projection of the
investigation context (timeline, evidence, correlation/behavioral findings,
integrity, warnings) with a stable report id, and that an LLM narrative
failure never destroys the deterministic report. Runs with and without a
(stubbed) Ollama narrative; never touches a real model.
"""

from datetime import datetime

from backend.ai import report_generator
from backend.ai.query_engine import InvestigationQueryEngine

from .conftest import FakeLLM, UnavailableLLM


def _result(question="what happened overnight", *, llm=None, **overrides):
    """Deterministic investigation result with all analysis layers included."""
    return InvestigationQueryEngine(llm=llm).investigate(
        question, generate_answer=False, include_correlations=True,
        include_behavior=True, verify_integrity=True, **overrides)


def test_report_preserves_all_sections(seeded):
    report = report_generator.generate_report(_result())
    d = report.as_dict()
    assert d["report_id"].startswith("RPT-")
    for key in ("executive_summary", "timeline", "evidence",
                "correlation_findings", "behavioral_findings",
                "integrity_status", "conclusion", "limitations", "warnings"):
        assert key in d
    assert d["evidence"]                       # evidence preserved
    assert d["correlation_findings"]           # correlation preserved
    assert d["behavioral_findings"]            # behavior preserved
    assert d["integrity_status"]["valid"] is True
    assert d["llm_narrative"] is None          # opt-in, off by default


def test_report_timeline_chronological_and_grounded(seeded):
    d = report_generator.generate_report(_result()).as_dict()
    stamps = [e["timestamp"] for e in d["timeline"]
              if e.get("has_timestamp") and e.get("timestamp")]
    assert stamps == sorted(stamps)
    # Timeline entries map only to real evidence ids -- nothing fabricated.
    ev_ids = {e["event_id"] for e in d["evidence"]}
    tl_ids = {e["event_id"] for e in d["timeline"] if e.get("db_backed")}
    assert tl_ids and tl_ids <= ev_ids


def test_report_id_is_deterministic(seeded):
    result = _result()
    r1 = report_generator.generate_report(result)
    r2 = report_generator.generate_report(result)
    assert r1.report_id == r2.report_id
    # Independent of generation time.
    r3 = report_generator.generate_report(result,
                                          generated_at=datetime(2000, 1, 1))
    assert r3.report_id == r1.report_id


def test_report_id_changes_with_question(seeded):
    a = report_generator.generate_report(_result("what happened overnight"))
    b = report_generator.generate_report(
        _result("show only usb", sources=("USB",)))
    assert a.report_id != b.report_id


def test_report_with_llm_narrative_available(seeded):
    report = report_generator.generate_report(
        _result(), include_llm_narrative=True, llm=FakeLLM())
    assert report.llm_available is True
    assert report.llm_narrative


def test_report_llm_failure_preserves_deterministic_report(seeded):
    report = report_generator.generate_report(
        _result(), include_llm_narrative=True, llm=UnavailableLLM())
    assert report.llm_available is False
    assert report.llm_narrative is None
    # Deterministic content survives an LLM failure.
    d = report.as_dict()
    assert d["evidence"] and d["correlation_findings"]
    assert d["integrity_status"]["valid"] is True
    assert d["report_id"].startswith("RPT-")


def test_text_report_renders_sections(seeded):
    report = report_generator.generate_report(_result())
    text = report_generator.generate_text_report(report)
    assert isinstance(text, str) and text.strip()
    for heading in ("FORENSIX AI INVESTIGATION REPORT", "EXECUTIVE SUMMARY",
                    "FORENSIC TIMELINE", "INTEGRITY STATUS", "CONCLUSION"):
        assert heading in text
    assert report.report_id in text

