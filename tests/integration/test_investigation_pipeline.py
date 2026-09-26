"""Integration: NL question -> parser -> retrieval -> analysis -> (optional) LLM.

Covers the Phase 12 investigation flow end-to-end against a seeded temporary
database, plus both Ollama modes (unavailable -> deterministic fallback;
available -> grounded wording over the SAME deterministic evidence). No test
touches a real model or the network -- the LLM is always an in-process stub.
"""

import pytest

from backend.database import db as _db
from backend.ai.query_engine import (
    ANSWER_SOURCE_FALLBACK,
    ANSWER_SOURCE_LLM,
    ANSWER_SOURCE_NO_EVIDENCE,
    InvestigationQueryEngine,
    build_retrieval_query,
    parse_question,
)

from .conftest import FakeLLM, UnavailableLLM


class _CapturingLLM:
    """Records the prompt/system it is handed so grounding can be asserted."""

    model = "capture-model"

    def __init__(self):
        self.prompt = None
        self.system = None

    def generate(self, prompt, *, system=None):
        self.prompt = prompt
        self.system = system
        return "Grounded answer based only on the supplied evidence."


def _engine(llm):
    return InvestigationQueryEngine(llm=llm)


# --- Deterministic parser + parameterization --------------------------------

def test_parser_overrides_win():
    req = parse_question("anything at all", sources=("USB",),
                         severity="high", limit=10)
    assert "USB" in req.sources
    assert req.severity == "HIGH"        # normalized to upper-case
    assert req.limit == 10


def test_retrieval_query_is_parameterized():
    req = parse_question("show usb activity", sources=("USB",), user="alice")
    sql, params = build_retrieval_query(req)
    assert "?" in sql                     # placeholders, not interpolation
    assert "USB" in params and "alice" in params
    # Raw user-supplied values never appear in the SQL text itself.
    assert "USB" not in sql and "alice" not in sql


# --- Retrieval + analysis over the database ---------------------------------

def test_investigation_retrieves_only_matching_evidence(seeded):
    result = _engine(FakeLLM()).investigate("what happened", sources=("USB",))
    ctx = result.context
    assert ctx.evidence_count == 1
    assert all(r.source == "USB" for r in ctx.retrieved_events)
    assert result.llm_available is True
    assert result.answer_source == ANSWER_SOURCE_LLM
    assert result.answer


def test_investigation_includes_analysis_when_requested(seeded):
    result = _engine(FakeLLM()).investigate(
        "explain everything", include_correlations=True,
        include_behavior=True, verify_integrity=True)
    ctx = result.context
    assert ctx.candidate_incidents            # correlation included
    assert ctx.behavioral_anomalies           # behavior included
    assert ctx.integrity is not None          # integrity included
    assert ctx.integrity.get("valid") is True


def test_investigation_no_evidence_does_not_fabricate(seeded):
    # An over-restrictive filter matches nothing; no evidence is invented.
    result = _engine(FakeLLM()).investigate("what happened",
                                            user="nobody-xyz")
    assert result.context.evidence_count == 0
    assert result.context.retrieved_events == []
    assert result.answer_source == ANSWER_SOURCE_NO_EVIDENCE


def test_investigation_only_cites_real_stored_ids(seeded):
    result = _engine(FakeLLM()).investigate("show everything")
    cited = set(result.context.evidence_ids)
    existing = {row["id"] for row in _db.get_events()}
    assert cited and cited <= existing        # every cited id really exists


def test_invalid_query_fails_safely(seeded):
    with pytest.raises(ValueError):
        _engine(FakeLLM()).investigate("bad", severity="BOGUS")


# --- Ollama modes (Step 9) --------------------------------------------------

def test_llm_unavailable_degrades_to_deterministic(seeded):
    result = _engine(UnavailableLLM()).investigate("what happened")
    assert result.llm_available is False
    assert result.answer_source == ANSWER_SOURCE_FALLBACK
    assert result.message                       # a reason is provided
    assert result.context.evidence_count > 0    # deterministic evidence intact


def test_llm_available_reports_configured_model(seeded):
    spy = _CapturingLLM()
    result = _engine(spy).investigate("what happened")
    assert result.llm_available is True
    assert result.answer_source == ANSWER_SOURCE_LLM
    # The engine reports the injected/configured model, not a hard-coded name.
    assert result.llm_model == spy.model


def test_llm_prompt_is_grounded_in_supplied_evidence(seeded):
    spy = _CapturingLLM()
    _engine(spy).investigate("what happened", sources=("USB",))
    # Only the evidence actually retrieved is handed to the model...
    assert spy.prompt is not None
    assert "USB" in spy.prompt
    # ...under a system prompt that constrains it to the supplied evidence.
    assert spy.system and "evidence" in spy.system.lower()


