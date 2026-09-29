"""Local Ollama reachability probe for the ForensiX AI runtime (additive).

This does NOT rewrite or wrap the working Phase-12 investigation path. It only
answers a status question -- "is a local Ollama serving, and is the configured
model present?" -- for ``GET /api/runtime/status`` and for degradation
messaging. Core collection and deterministic analysis never depend on it.

It reuses ``OllamaClient`` purely for its resolved config (host/model/timeout)
and performs a single short-timeout **GET** ``{host}/api/tags`` -- a read-only
listing, never a generate call, never transmitting any evidence. Failures are
swallowed and reported as ``reachable=False``; the probe never raises. Results
are cached briefly so frequent status polls don't hang when Ollama is down.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger("forensix.runtime")

# The status GET must be far snappier than the 60s generate timeout so polling
# /runtime/status stays responsive when the daemon is absent.
DEFAULT_PROBE_TIMEOUT = 2.0
_CACHE_TTL_SECONDS = 20.0

_cache_lock = threading.Lock()
_cache: Optional[dict] = None
_cache_at = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _model_matches(configured: str, available: List[str]) -> bool:
    """True if the configured model is among the served tags.

    Ollama reports names as ``name:tag`` (e.g. ``llama3.1:8b``). A configured
    name without a tag matches any tag of the same base (``llama3.1`` matches
    ``llama3.1:latest``); a fully-qualified name must match exactly.
    """
    if not configured:
        return False
    base = configured.split(":", 1)[0]
    for name in available:
        if name == configured:
            return True
        if ":" not in configured and name.split(":", 1)[0] == base:
            return True
    return False


def _resolve_client(client):
    if client is not None:
        return client
    from backend.ai.query_engine import OllamaClient
    return OllamaClient()


def _do_probe(client, timeout: float) -> dict:
    try:
        client = _resolve_client(client)
        host = getattr(client, "host", "") or ""
        model = getattr(client, "model", "") or ""
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "reachable": False, "model": "", "model_present": None,
            "host": "", "checked_at": _now_iso(),
            "error": f"client init failed: {type(exc).__name__}",
        }

    url = host.rstrip("/") + "/api/tags"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        payload = json.loads(body)
        names = [m.get("name", "") for m in payload.get("models", [])
                 if isinstance(m, dict)]
        return {
            "reachable": True,
            "model": model,
            "model_present": _model_matches(model, names),
            "host": host,
            "checked_at": _now_iso(),
            "error": None,
        }
    except (urllib.error.URLError, OSError, ValueError,
            json.JSONDecodeError) as exc:
        return {
            "reachable": False,
            "model": model,
            "model_present": None,
            "host": host,
            "checked_at": _now_iso(),
            "error": type(exc).__name__,
        }


def probe_ollama(client=None, *, timeout: float = DEFAULT_PROBE_TIMEOUT,
                 use_cache: bool = True) -> dict:
    """Probe local Ollama reachability + model presence. Never raises.

    Returns a dict: ``{reachable, model, model_present, host, checked_at,
    error}``. Cached for ~20s so frequent status polls do not repeatedly block
    on a short network timeout when the daemon is down.
    """
    global _cache, _cache_at
    if use_cache:
        with _cache_lock:
            if (_cache is not None
                    and (time.monotonic() - _cache_at) < _CACHE_TTL_SECONDS):
                return dict(_cache)

    result = _do_probe(client, timeout)

    with _cache_lock:
        _cache = dict(result)
        _cache_at = time.monotonic()
    return result


def reset_cache() -> None:
    """Test helper: drop the cached probe so the next call re-probes."""
    global _cache, _cache_at
    with _cache_lock:
        _cache = None
        _cache_at = 0.0

