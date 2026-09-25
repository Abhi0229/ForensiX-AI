"""Hash-chain integrity endpoint (Phase 9).

Delegates to :func:`backend.integrity.verifier.verify_chain`, which reads the
events in chain order from the database (honouring a monkeypatched ``DB_PATH``
in tests). This module adds no verification logic of its own; it only derives a
human-readable status label and shapes the response.
"""

from fastapi import APIRouter

from backend.integrity.verifier import verify_chain
from backend.api.schemas import IntegrityResponse

router = APIRouter(prefix="/api", tags=["integrity"])


def _status_label(valid: bool, checked_events: int) -> str:
    """Derive a status label without changing the verifier's verdict."""
    if checked_events == 0:
        return "NO_EVENTS"
    return "VALID" if valid else "INVALID"


@router.get("/integrity", response_model=IntegrityResponse)
def get_integrity() -> IntegrityResponse:
    """Verify the tamper-evident hash chain over all stored events (read-only)."""
    result = verify_chain().as_dict()
    checked = result["checked_events"]
    return IntegrityResponse(
        valid=result["valid"],
        status=_status_label(result["valid"], checked),
        total_events=checked,
        checked_events=checked,
        hashed_events=result["hashed_events"],
        legacy_events=result["legacy_events"],
        invalid_events=result["invalid_events"],
        errors=result["errors"],
    )
