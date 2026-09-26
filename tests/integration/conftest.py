"""Shared fixtures and builders for the ForensiX AI integration suite.

Every fixture here keeps the suite hermetic and safe:

* ``temp_db`` (autouse) repoints ``backend.database.db.DB_PATH`` at a throwaway
  file under pytest's ``tmp_path`` and creates the schema, so no integration
  test can ever read from or write to the real forensic database.
* ``FakeLLM`` / ``UnavailableLLM`` stand in for the local Ollama client so the
  suite never touches the network or a running model.
* The event builders produce a deterministic, self-consistent scenario shared
  across the pipeline/correlation/behavior/investigation/report/API tests.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Make ``import backend...`` resolve no matter how pytest is invoked
# (`pytest`, `python -m pytest`, from any working directory).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.database import db as _db                     # noqa: E402
from backend.database import schema                        # noqa: E402
from backend.database.models import Event                  # noqa: E402
from backend.processing.pipeline import EventPipeline      # noqa: E402
from backend.ai.query_engine import LLMUnavailableError    # noqa: E402


# --- Offline LLM stubs ------------------------------------------------------

class FakeLLM:
    """Deterministic offline stand-in for OllamaClient (always answers)."""

    model = "fake-model"

    def generate(self, prompt, *, system=None):
        return "Deterministic grounded answer based only on the evidence."


class UnavailableLLM:
    """Stub whose generate() fails, to exercise graceful LLM degradation."""

    model = "unavailable-model"

    def generate(self, prompt, *, system=None):
        raise LLMUnavailableError("ollama not running")


# --- Database fixture (autouse: the real DB is never touched) ---------------

@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Point the DB layer at a throwaway file and create the schema."""
    test_db = tmp_path / "integration.db"
    monkeypatch.setattr(_db, "DB_PATH", str(test_db))
    schema.create_tables()
    yield str(test_db)


# --- Deterministic scenario builders ----------------------------------------

BASELINE_USER = "alice"
BASELINE_DEVICE = "HOST1"

# 20 routine business-hours logons: enough for a "ready" behavioral baseline
# (min_baseline_events defaults to 20) and a body of "normal" history.
BASELINE_START = datetime(2026, 9, 20, 9, 0, 0)

# A tight, off-hours cluster on one device that correlates across sources.
CLUSTER_START = datetime(2026, 9, 21, 3, 0, 0)

BASELINE_COUNT = 20
CLUSTER_COUNT = 5
SEED_COUNT = BASELINE_COUNT + CLUSTER_COUNT  # 25


def baseline_events():
    """20 routine business-hours logons for one user/device."""
    return [
        Event(timestamp=BASELINE_START + timedelta(minutes=i),
              source="Windows", event_type="LOGON",
              description=f"User logon {i}", severity="INFO",
              user=BASELINE_USER, device=BASELINE_DEVICE)
        for i in range(BASELINE_COUNT)
    ]


def cluster_events():
    """Off-hours multi-source cluster on one device (USB->file->threat->...)."""
    t = CLUSTER_START
    return [
        Event(timestamp=t, source="USB", event_type="USB_CONNECTED",
              description="USB device connected", severity="INFO",
              user="", device=BASELINE_DEVICE),
        Event(timestamp=t + timedelta(seconds=30), source="FileSystem",
              event_type="FILE_CREATED", description="File created",
              severity="INFO", user="", device=BASELINE_DEVICE,
              file_path="C:/secret.docx"),
        Event(timestamp=t + timedelta(seconds=60), source="Defender",
              event_type="THREAT_DETECTED", description="Threat found",
              severity="HIGH", user="", device=BASELINE_DEVICE,
              file_path="C:/secret.docx"),
        Event(timestamp=t + timedelta(seconds=90), source="Browser",
              event_type="BROWSER_VISIT", description="Visited a site",
              severity="INFO", user=BASELINE_USER, device=BASELINE_DEVICE,
              file_path="http://malware.test/download"),
        Event(timestamp=t + timedelta(seconds=120), source="Windows",
              event_type="LOGON", description="Off-hours logon",
              severity="WARNING", user=BASELINE_USER, device=BASELINE_DEVICE),
    ]


def seed_events(events):
    """Store events through the real Phase 8 pipeline (Phase 9 hashing on)."""
    return EventPipeline().process(events)


# --- Fixtures ---------------------------------------------------------------

@pytest.fixture
def seeded(temp_db):
    """Seed baseline + cluster via the real pipeline; return the row count."""
    result = seed_events(baseline_events() + cluster_events())
    assert result.inserted == SEED_COUNT
    return SEED_COUNT


@pytest.fixture
def client():
    """FastAPI TestClient with the LLM dependency replaced by an offline stub."""
    from fastapi.testclient import TestClient
    from backend.app import app
    from backend.api.deps import get_llm

    app.dependency_overrides[get_llm] = lambda: FakeLLM()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


