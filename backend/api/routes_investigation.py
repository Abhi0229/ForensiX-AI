"""Natural-language investigation endpoint (Phase 12).

Delegates entirely to :class:`InvestigationQueryEngine`, which is injected as a
dependency so tests can supply an offline LLM stub. The natural-language text is
never turned into SQL by this layer -- the engine binds every value as a
parameter. This module only maps the API's singular structured fields onto the
engine's override keyword arguments and reshapes the result for the frontend.
"""

from fastapi import APIRouter, Depends, HTTPException

from backend.ai.query_engine import InvestigationQueryEngine
from backend.api.deps import get_query_engine
from backend.api.schemas import InvestigationRequest, InvestigationResponse

router = APIRouter(prefix="/api", tags=["investigation"])


def _build_overrides(body: InvestigationRequest) -> dict:
    """Translate the request's structured fields into engine override kwargs.

    Only fields the client actually supplied become overrides, so we never
    clobber what the engine parses from the question with a ``None``. The
    analysis toggles are always forwarded because they are explicit API
    controls.
    """
    overrides = {
        "include_correlations": body.include_correlations,
        "include_behavior": body.include_behavior,
        "verify_integrity": body.verify_integrity,
    }
    if body.source:
        overrides["sources"] = (body.source,)
    if body.event_type:
        overrides["event_types"] = (body.event_type,)
    if body.severity:
        overrides["severity"] = body.severity
    if body.user:
        overrides["user"] = body.user
    if body.device:
        overrides["device"] = body.device
    if body.start_time is not None:
        overrides["start_time"] = body.start_time
    if body.end_time is not None:
        overrides["end_time"] = body.end_time
    if body.limit is not None:
        overrides["limit"] = body.limit
    return overrides


@router.post("/investigate", response_model=InvestigationResponse)
def investigate(
    body: InvestigationRequest,
    engine: InvestigationQueryEngine = Depends(get_query_engine),
) -> InvestigationResponse:
    """Answer a forensic question over the stored evidence.

    Runs the deterministic retrieval + optional correlation/behavior/integrity
    analysis, then (if requested and available) the LLM wording layer. Degrades
    to a deterministic answer when the LLM is unavailable.
    """
    overrides = _build_overrides(body)
    try:
        result = engine.investigate(
            body.question,
            generate_answer=body.generate_answer,
            **overrides,
        )
    except ValueError as exc:
        # Engine-side request validation (e.g. bad hour/time ordering).
        raise HTTPException(status_code=400, detail=str(exc))

    data = result.as_dict()
    ctx = data["context"]
    compact_context = {
        "original_question": ctx["original_question"],
        "request": ctx["request"],
        "evidence_count": ctx["evidence_count"],
        "evidence_ids": ctx["evidence_ids"],
        "behavioral_baseline_status": ctx["behavioral_baseline_status"],
        "retrieval_metadata": ctx["retrieval_metadata"],
        "warnings": ctx["warnings"],
    }
    return InvestigationResponse(
        question=ctx["original_question"],
        answer=data["answer"],
        answer_source=data["answer_source"],
        message=data["message"],
        llm_available=data["llm_available"],
        llm_model=data["llm_model"],
        deterministic_summary=data["deterministic_summary"],
        context=compact_context,
        evidence=ctx["retrieved_events"],
        evidence_count=ctx["evidence_count"],
        candidate_incidents=ctx["candidate_incidents"],
        behavioral_anomalies=ctx["behavioral_anomalies"],
        behavioral_baseline_status=ctx["behavioral_baseline_status"],
        integrity=ctx["integrity"],
        warnings=ctx["warnings"],
    )
