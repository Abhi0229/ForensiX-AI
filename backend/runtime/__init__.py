"""ForensiX AI runtime layer: continuous collector orchestration.

Public surface is intentionally small so callers (the FastAPI lifespan, the
status route, tests) never reach into internals. See ``manager`` for the design.
"""

from backend.runtime.manager import (
    IngestItem,
    RuntimeConfig,
    RuntimeManager,
    get_runtime,
    start_if_enabled,
    stop,
)

__all__ = [
    "RuntimeManager",
    "RuntimeConfig",
    "IngestItem",
    "get_runtime",
    "start_if_enabled",
    "stop",
]
