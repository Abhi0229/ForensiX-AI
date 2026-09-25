"""Shared FastAPI dependencies for the ForensiX AI API layer.

These providers keep the route handlers thin and, crucially, make the API
testable without any external resources: tests override :func:`get_llm` with an
offline stub and monkeypatch ``backend.database.db.DB_PATH`` to an isolated
temporary database. Nothing here re-implements Phase 1-13 logic; the
dependencies simply construct the existing engines.
"""

import os

from fastapi import Depends

from backend.ai.query_engine import InvestigationQueryEngine, OllamaClient

# Development origins for the future React dashboard (CRA :3000, Vite :5173).
_DEFAULT_CORS_ORIGINS = ("http://localhost:3000", "http://localhost:5173")


def get_cors_origins():
    """Return the list of allowed CORS origins.

    Configurable via the ``FORENSIX_CORS_ORIGINS`` environment variable
    (comma-separated). Defaults to the local dev servers. We deliberately never
    fall back to ``"*"`` so that enabling credentials or authentication later
    cannot silently widen the policy into an unsafe one.
    """
    raw = os.environ.get("FORENSIX_CORS_ORIGINS", "").strip()
    if raw:
        return [origin.strip() for origin in raw.split(",") if origin.strip()]
    return list(_DEFAULT_CORS_ORIGINS)


def get_llm():
    """Provide the LLM client used by investigation/report endpoints.

    Returns a local Ollama client. Construction performs no network I/O -- the
    client only reads configuration from the environment -- so importing/serving
    the app never requires a running Ollama server. If the server is unreachable
    at generation time the engines degrade to a deterministic-only result.
    Tests override this dependency with an offline stub.
    """
    return OllamaClient()


def get_query_engine(llm=Depends(get_llm)):
    """Build the Phase 12 investigation engine with the injected LLM.

    ``connection_factory`` is left at its default so the engine uses
    ``db.get_connection`` and therefore honours a monkeypatched ``DB_PATH``
    during tests. The engine is cheap to construct and holds no mutable state.
    """
    return InvestigationQueryEngine(llm=llm)
