"""Entry point for the ForensiX-AI backend.

Besides the original console ``main()`` (preserved), this module builds and
exposes the FastAPI ``app`` that fronts the Phase 1-13 forensics functionality::

    uvicorn backend.app:app --reload

The API is a thin transport layer -- request validation, routing, serialization
and error handling only. All investigation, correlation, behavioral analysis,
integrity verification and reporting is delegated to the existing modules.
There is intentionally no authentication in this phase: ForensiX AI is a local,
single-endpoint Windows application.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api import (
    routes_analysis,
    routes_events,
    routes_integrity,
    routes_investigation,
    routes_reports,
)
from backend.api.deps import get_cors_origins
from backend.api.schemas import HealthResponse

logger = logging.getLogger("forensix.api")

API_TITLE = "ForensiX AI Investigation API"
API_VERSION = "1.0.0"
API_DESCRIPTION = (
    "Local, private REST API for the ForensiX AI digital-forensics platform. "
    "Exposes stored events and timelines, natural-language investigations, "
    "candidate-incident correlation, behavioral anomaly detection, "
    "tamper-evident integrity verification and automated forensic reports. "
    "All analysis is deterministic-first; the optional local LLM only rewords "
    "grounded results. Read endpoints never modify stored evidence."
)


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application."""
    app = FastAPI(
        title=API_TITLE,
        description=API_DESCRIPTION,
        version=API_VERSION,
    )

    # CORS for the future React dashboard (dev servers only, configurable).
    # allow_credentials stays False so the restricted origin list can never be
    # combined with credentials into an unsafe policy.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.get("/api/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        """Liveness probe. Does not require a populated database."""
        return HealthResponse()

    app.include_router(routes_events.router)
    app.include_router(routes_investigation.router)
    app.include_router(routes_reports.router)
    app.include_router(routes_integrity.router)
    app.include_router(routes_analysis.router)

    @app.exception_handler(Exception)
    async def _unhandled_exception(request: Request, exc: Exception):
        """Return a generic 500 without leaking internals to the client.

        The full error (including traceback) is logged server-side only.
        """
        logger.exception(
            "Unhandled error handling %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )

    return app


app = create_app()


def main() -> None:
    """Start the backend application."""
    print("ForensiX-AI backend is ready.")


if __name__ == "__main__":
    main()
