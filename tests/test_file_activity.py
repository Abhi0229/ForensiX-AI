"""Tests for the file-activity collector.

Pure mapping tests use lightweight stand-in events (no observer needed).
Live tests use pytest's tmp_path and a real Watchdog observer, kept
deterministic with condition-based waits rather than fixed sleeps. Nothing
outside the temporary directory is ever touched.
"""

import json
import os
from types import SimpleNamespace

import pytest

from backend.database.models import Event
from backend.database.db import get_events
from backend.collectors import file_activity
from backend.collectors.file_activity import (
    FileActivityCollector,
    _build_raw_event,
    event_to_forensix,
)

# Generous timeout: filesystem event delivery is asynchronous.
WAIT = 10.0
# Small settle so the observer thread is running before we generate events.
SETTLE = 0.3


def _fake_event(event_type, src_path, dest_path=None, is_directory=False):
    """A stand-in for a watchdog event, for pure mapping tests."""
    ns = SimpleNamespace(
        event_type=event_type,
        src_path=src_path,
        is_directory=is_directory,
    )
    if dest_path is not None:
        ns.dest_path = dest_path
    return ns


def _same_path(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _is(event_type, path):
    return lambda e: e.event_type == event_type and _same_path(e.file_path, path)


# ---------------------------------------------------------------------------
# A. Pure mapping unit tests (no observer)
# ---------------------------------------------------------------------------

def test_map_created_modified_deleted():
    created = _build_raw_event(_fake_event("created", r"C:\tmp\a.txt"))
    modified = _build_raw_event(_fake_event("modified", r"C:\tmp\a.txt"))
    deleted = _build_raw_event(_fake_event("deleted", r"C:\tmp\a.txt"))

    assert created["event_type"] == "FILE_CREATED"
    assert modified["event_type"] == "FILE_MODIFIED"
    assert deleted["event_type"] == "FILE_DELETED"
    assert created["source"] == "FileSystem"
    assert created["file_path"] == r"C:\tmp\a.txt"
    assert created["user"] == ""  # watchdog exposes no user


def test_map_rename_builds_old_and_new_path():
    raw = _build_raw_event(
        _fake_event("moved", r"C:\tmp\old.txt", dest_path=r"C:\tmp\new.txt")
    )

    assert raw["event_type"] == "FILE_RENAMED"
    assert raw["file_path"] == r"C:\tmp\new.txt"     # file_path = destination
    assert raw["metadata"]["old_path"] == r"C:\tmp\old.txt"
    assert raw["metadata"]["new_path"] == r"C:\tmp\new.txt"


def test_unmapped_event_type_returns_none():
    assert _build_raw_event(_fake_event("opened", r"C:\tmp\a.txt")) is None


def test_event_to_forensix_returns_event_instance():
    event = event_to_forensix(_fake_event("created", r"C:\tmp\a.txt"))
    assert isinstance(event, Event)
    assert event.source == "FileSystem"
    assert event.event_type == "FILE_CREATED"


def test_rename_metadata_survives_normalization():
    event = event_to_forensix(
        _fake_event("moved", r"C:\tmp\old.txt", dest_path=r"C:\tmp\new.txt")
    )
    metadata = json.loads(event.metadata)
    assert metadata["old_path"] == r"C:\tmp\old.txt"
    assert metadata["new_path"] == r"C:\tmp\new.txt"


# ---------------------------------------------------------------------------
# B. Live observer tests (real Watchdog, temp directory only)
# ---------------------------------------------------------------------------

def test_file_created(tmp_path):
    target = tmp_path / "created.txt"
    with FileActivityCollector(str(tmp_path)) as collector:
        import time; time.sleep(SETTLE)
        target.write_text("hello")
        found = collector.wait_for(_is("FILE_CREATED", str(target)), timeout=WAIT)

    assert found is not None, "FILE_CREATED not observed"
    assert found.source == "FileSystem"
    assert _same_path(found.file_path, str(target))


def test_file_modified(tmp_path):
    target = tmp_path / "mod.txt"
    target.write_text("initial")  # created before monitoring starts
    with FileActivityCollector(str(tmp_path)) as collector:
        import time; time.sleep(SETTLE)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("more data")
            handle.flush()
            os.fsync(handle.fileno())
        found = collector.wait_for(_is("FILE_MODIFIED", str(target)), timeout=WAIT)

    assert found is not None, "FILE_MODIFIED not observed"


def test_file_deleted(tmp_path):
    target = tmp_path / "del.txt"
    target.write_text("bye")
    with FileActivityCollector(str(tmp_path)) as collector:
        import time; time.sleep(SETTLE)
        os.remove(target)
        found = collector.wait_for(_is("FILE_DELETED", str(target)), timeout=WAIT)

    assert found is not None, "FILE_DELETED not observed"


def test_file_renamed(tmp_path):
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text("data")
    with FileActivityCollector(str(tmp_path)) as collector:
        import time; time.sleep(SETTLE)
        os.rename(old, new)
        found = collector.wait_for(_is("FILE_RENAMED", str(new)), timeout=WAIT)

    assert found is not None, "FILE_RENAMED not observed"
    metadata = json.loads(found.metadata)
    assert _same_path(metadata["old_path"], str(old))
    assert _same_path(metadata["new_path"], str(new))


def test_recursive_monitoring(tmp_path):
    nested = tmp_path / "sub" / "deep"
    nested.mkdir(parents=True)  # created before monitoring
    target = nested / "nested.txt"
    with FileActivityCollector(str(tmp_path), recursive=True) as collector:
        import time; time.sleep(SETTLE)
        target.write_text("nested")
        found = collector.wait_for(_is("FILE_CREATED", str(target)), timeout=WAIT)

    assert found is not None, "nested FILE_CREATED not observed"


def test_multiple_file_events(tmp_path):
    with FileActivityCollector(str(tmp_path)) as collector:
        import time; time.sleep(SETTLE)
        for i in range(5):
            (tmp_path / f"f{i}.txt").write_text(str(i))
        reached = collector.wait_for_count(5, timeout=WAIT)

    assert reached, f"expected >=5 events, got {len(collector.events)}"
    assert all(e.source == "FileSystem" for e in collector.events)


def test_invalid_path_raises(tmp_path):
    missing = tmp_path / "does_not_exist"
    with pytest.raises(ValueError):
        FileActivityCollector(str(missing)).start()


def test_observer_start_stop_behavior(tmp_path):
    collector = FileActivityCollector(str(tmp_path))
    collector.start()
    assert collector._observer is not None
    collector.stop()
    assert collector._observer is None
    # Stopping again must be safe (no exception).
    collector.stop()


def test_collector_does_not_write_to_database(tmp_path):
    """Generating file events must not add any rows to the database."""
    before = len(get_events())
    with FileActivityCollector(str(tmp_path)) as collector:
        import time; time.sleep(SETTLE)
        (tmp_path / "nowrite.txt").write_text("x")
        collector.wait_for(_is("FILE_CREATED", str(tmp_path / "nowrite.txt")), timeout=WAIT)
    after = len(get_events())

    assert before == after, "collector must not insert events into the database"
