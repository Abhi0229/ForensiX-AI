"""Investigation report endpoints (Phase 13).

Builds the deterministic evidence context with the Phase 12 engine (with the
LLM answer step skipped -- the report has its own optional narrative layer),
then hands that context to the Phase 13 ``generate_report`` /
``generate_text_report``. No report content is produced here; this module only
wires inputs and reshapes the output.
"""

from fastapi import APIRouter, Depends, HTTPException

from backend.ai import report_generator
from backend.ai.query_engine import InvestigationQueryEngine
from backend.api.deps import get_llm, get_query_engine
from backend.api.schemas import (
    InvestigationReportResponse,
    ReportRequest,
    ReportTextResponse,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _report_overrides(body: ReportRequest) -> dict:
    """Translate report request fields into engine override kwargs."""
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


def _build_context(body: ReportRequest, engine: InvestigationQueryEngine):
    """Run the deterministic investigation (no LLM answer) and return the result."""
    try:
        return engine.investigate(
            body.question,
            generate_answer=False,
            **_report_overrides(body),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/investigation", response_model=InvestigationReportResponse)
def create_report(
    body: ReportRequest,
    engine: InvestigationQueryEngine = Depends(get_query_engine),
    llm=Depends(get_llm),
) -> InvestigationReportResponse:
    """Generate a structured forensic report for a natural-language question."""
    result = _build_context(body, engine)
    report = report_generator.generate_report(
        result,
        include_llm_narrative=body.include_llm_narrative,
        llm=llm,
    )
    return InvestigationReportResponse.model_validate(report.as_dict())


@router.post("/investigation/text", response_model=ReportTextResponse)
def create_report_text(
    body: ReportRequest,
    engine: InvestigationQueryEngine = Depends(get_query_engine),
    llm=Depends(get_llm),
) -> ReportTextResponse:
    """Return the human-readable text rendering of the investigation report."""
    result = _build_context(body, engine)
    report = report_generator.generate_report(
        result,
        include_llm_narrative=body.include_llm_narrative,
        llm=llm,
    )
    text = report_generator.generate_text_report(report)
    return ReportTextResponse(report_id=report.report_id, text=text)
