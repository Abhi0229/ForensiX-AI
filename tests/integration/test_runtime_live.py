"""Gated live runtime smoke test -- OPT-IN, runs the real orchestrator briefly.

Skipped unless ``FORENSIX_RUN_LIVE_TESTS=1`` (the same flag the other live
suites use), so normal ``pytest`` runs never depend on live Windows/USB/browser
state or a running Ollama daemon. When enabled, it starts the full
``RuntimeManager`` for a few seconds against a throwaway database (the autouse
``temp_db`` fixture in this package repoints ``DB_PATH`` into ``tmp_path``, and
the runtime state file is derived from it), lets the pollers run at least one
cycle, then stops gracefully and asserts the SHA-256 hash chain is intact.

Data safety: every collector is read-only; nothing on the host is created,
modified, or deleted; the only network call is the local, cached Ollama probe.
File Activity is intentionally left off (no ``FORENSIX_RUNTIME_FILE_PATH``).
"""

import os
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("FORENSIX_RUN_LIVE_TESTS") != "1",
    reason="live runtime test; set FORENSIX_RUN_LIVE_TESTS=1 to enable",
)


def test_runtime_collects_and_preserves_integrity(tmp_path):
    """Start the orchestrator, let it collect, stop it, verify the chain."""
    from backend.database import db
    from backend.integrity.verifier import verify_chain
    from backend.runtime.manager import RuntimeConfig, RuntimeManager

    cfg = RuntimeConfig(
        enabled=True,
        collectors=frozenset({"windows", "defender", "browser", "usb"}),
        windows_interval=1.0, defender_interval=1.0, browser_interval=1.0,
        analysis_interval=1.0, initial_backfill=50, max_batch=50,
    )
    manager = RuntimeManager(config=cfg)  # real EventPipeline -> temp DB
    manager.start()
    try:
        time.sleep(6.0)  # allow >= 1 poll cycle for each pollable collector
    finally:
        manager.stop(timeout=15.0)

    # The hash chain must be internally consistent regardless of how many
    # events landed: an empty chain is valid; a populated one proves the whole
    # Collectors -> Runtime -> Pipeline -> DB -> SHA-256 chain path end-to-end.
    result = verify_chain()
    assert result.valid is True, result.as_dict()

    count = db.count_events()
    assert count >= 0
    if count:
        # Something was collected -> integrity must cover every stored row.
        assert result.checked_events == count

    # status() renders a well-formed snapshot (the Ollama probe is local-only).
    snap = manager.status()
    for key in ("running", "collectors", "queue", "totals", "analysis",
                "ollama", "state_file"):
        assert key in snap
    assert snap["running"] is False  # cleanly stopped

