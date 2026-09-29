"""Additive runtime-status endpoint (``GET /api/runtime/status``).

Read-only: reports what the collector orchestrator is doing right now plus a
cached local-Ollama reachability probe. It never starts/stops collection and
never mutates evidence. Safe to poll -- the Ollama probe is short-timeout and
cached so a down daemon never stalls the response. GET fits the existing CORS
policy (no new methods, no auth, no contract change to other endpoints).
"""

from fastapi import APIRouter

from backend.api.schemas import RuntimeStatusResponse
from backend.runtime import manager as runtime

router = APIRouter(prefix="/api", tags=["runtime"])


@router.get("/runtime/status", response_model=RuntimeStatusResponse)
def runtime_status() -> RuntimeStatusResponse:
    """Return the current runtime status snapshot (never fabricated)."""
    return RuntimeStatusResponse(**runtime.get_runtime().status())
