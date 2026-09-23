"""Tests for Phase 9 hash-chain integrity (hasher + verifier + pipeline).

All database interaction happens against an isolated temporary SQLite file
(patched per test via an autouse fixture); the real development database is
never touched. Nothing here depends on Windows or any live OS resource.
"""

import sqlite3
from datetime import datetime, timedelta

import pytest

from backend.database import db as _db
from backend.database import schema
from backend.database.db import (
    get_events_in_chain_order,
    get_chain_tip,
    insert_event,
)
from backend.database.models import Event
from backend.processing.pipeline import process_events
from backend.integrity import hasher
from backend.integrity.hasher import (
    GENESIS_PREVIOUS_HASH,
    compute_hash,
    hash_event,
    event_fields_from_event,
    event_fields_from_row,
)
from backend.integrity.verifier import verify_chain, IntegrityResult


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Isolate every test on its own throwaway, freshly-migrated database."""
    test_db = tmp_path / "integrity_test.db"
    monkeypatch.setattr(_db, "DB_PATH", str(test_db))
    schema.create_tables()
    yield


def _event(**overrides) -> Event:
    base = dict(
        timestamp=datetime(2021, 1, 1, 12, 0, 0),
        source="Windows",
        event_type="TEST_EVENT",
        description="a test event",
        severity="INFO",
        user="alice",
        device="DESKTOP-01",
        file_path="",
        metadata="",
    )
    base.update(overrides)
    return Event(**base)


def _tamper(event_id, **columns):
    """Directly mutate stored columns to simulate out-of-band tampering."""
    conn = sqlite3.connect(_db.DB_PATH)
    try:
        assignments = ", ".join(f"{name} = ?" for name in columns)
        conn.execute(f"UPDATE events SET {assignments} WHERE id = ?",
                     (*columns.values(), event_id))
        conn.commit()
    finally:
        conn.close()


def _chain_ids():
    return [row["id"] for row in get_events_in_chain_order()]


# ---------------------------------------------------------------------------
# A. Hashing primitives (1-5)
# ---------------------------------------------------------------------------

def test_sha256_deterministic_hashing():
    fields = event_fields_from_event(_event())
    h1 = compute_hash(fields, GENESIS_PREVIOUS_HASH)
    h2 = compute_hash(fields, GENESIS_PREVIOUS_HASH)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex digest
    int(h1, 16)  # is valid hex


def test_same_event_same_hash():
    a = hash_event(_event(), GENESIS_PREVIOUS_HASH)
    b = hash_event(_event(), GENESIS_PREVIOUS_HASH)
    assert a == b


def test_different_event_different_hash():
    a = hash_event(_event(description="one"), GENESIS_PREVIOUS_HASH)
    b = hash_event(_event(description="two"), GENESIS_PREVIOUS_HASH)
    assert a != b


def test_genesis_first_event_rule():
    # The first event links to the empty-string genesis and still gets a hash.
    process_events([_event()])
    row = get_events_in_chain_order()[0]
    assert row["previous_hash"] == GENESIS_PREVIOUS_HASH
    assert row["event_hash"] is not None and len(row["event_hash"]) == 64


def test_previous_hash_is_included_in_the_hash():
    fields = event_fields_from_event(_event())
    with_genesis = compute_hash(fields, GENESIS_PREVIOUS_HASH)
    with_prev = compute_hash(fields, "abc123")
    # Same event data, different previous_hash => different event_hash.
    assert with_genesis != with_prev


# ---------------------------------------------------------------------------
# B. Chain building + valid verification (6, 7, 24, 25)
# ---------------------------------------------------------------------------

def test_multiple_events_form_a_valid_chain():
    base = datetime(2021, 1, 1)
    events = [_event(description=f"e{i}", timestamp=base + timedelta(minutes=i))
              for i in range(4)]
    process_events(events)

    rows = get_events_in_chain_order()
    assert rows[0]["previous_hash"] == GENESIS_PREVIOUS_HASH
    # Each event links to the one before it.
    for prev, cur in zip(rows, rows[1:]):
        assert cur["previous_hash"] == prev["event_hash"]


def test_valid_chain_verification_succeeds():
    process_events([_event(description=f"e{i}") for i in range(5)])
    result = verify_chain()
    assert isinstance(result, IntegrityResult)
    assert result.valid is True
    assert result.hashed_events == 5
    assert result.legacy_events == 0
    assert result.invalid_events == []


def test_empty_database_verification():
    result = verify_chain()
    assert result.valid is True
    assert result.checked_events == 0
    assert result.hashed_events == 0


def test_single_event_verification():
    process_events([_event()])
    result = verify_chain()
    assert result.valid is True
    assert result.hashed_events == 1


def test_multiple_event_verification():
    process_events([_event(description=f"e{i}") for i in range(10)])
    result = verify_chain()
    assert result.valid is True
    assert result.hashed_events == 10
    assert result.checked_events == 10


# ---------------------------------------------------------------------------
# C. Tampering detection (8-17, 22)
# ---------------------------------------------------------------------------

def _seed_three():
    process_events([_event(description=f"e{i}", file_path=f"C:/f{i}.txt",
                           metadata=f'{{"i": {i}}}',
                           timestamp=datetime(2021, 1, 1) + timedelta(minutes=i))
                    for i in range(3)])
    return _chain_ids()


def test_modified_description_detected():
    ids = _seed_three()
    _tamper(ids[1], description="TAMPERED")
    result = verify_chain()
    assert result.valid is False
    assert ids[1] in result.invalid_ids


def test_modified_file_path_detected():
    ids = _seed_three()
    _tamper(ids[1], file_path="C:/evil.exe")
    result = verify_chain()
    assert result.valid is False
    assert ids[1] in result.invalid_ids


def test_modified_metadata_detected():
    ids = _seed_three()
    _tamper(ids[2], metadata='{"i": 999}')
    result = verify_chain()
    assert result.valid is False
    assert ids[2] in result.invalid_ids


def test_modified_severity_detected():
    ids = _seed_three()
    _tamper(ids[0], severity="CRITICAL")
    result = verify_chain()
    assert result.valid is False
    assert ids[0] in result.invalid_ids


def test_modified_timestamp_detected():
    ids = _seed_three()
    _tamper(ids[1], timestamp="2099-12-31T23:59:59")
    result = verify_chain()
    assert result.valid is False
    assert ids[1] in result.invalid_ids


def test_modified_event_hash_detected():
    ids = _seed_three()
    _tamper(ids[1], event_hash="0" * 64)
    result = verify_chain()
    assert result.valid is False
    assert ids[1] in result.invalid_ids


def test_modified_previous_hash_detected():
    ids = _seed_three()
    _tamper(ids[2], previous_hash="0" * 64)
    result = verify_chain()
    assert result.valid is False
    assert ids[2] in result.invalid_ids


def test_deleted_middle_event_detected():
    ids = _seed_three()
    conn = sqlite3.connect(_db.DB_PATH)
    try:
        conn.execute("DELETE FROM events WHERE id = ?", (ids[1],))
        conn.commit()
    finally:
        conn.close()
    result = verify_chain()
    assert result.valid is False
    # The event after the hole no longer links correctly.
    assert ids[2] in result.invalid_ids


def test_inserted_invalid_event_detected():
    ids = _seed_three()
    # Insert a foreign event with a bogus (non-matching) hash into the chain.
    forged = _event(description="forged")
    insert_event(forged, event_hash="deadbeef" * 8, previous_hash="0" * 64)
    result = verify_chain()
    assert result.valid is False
    forged_id = _chain_ids()[-1]
    assert forged_id in result.invalid_ids


def test_broken_chain_continuity_detected():
    ids = _seed_three()
    # Rewrite one link so it no longer points at its predecessor's hash.
    _tamper(ids[1], previous_hash="beefbeef" * 8)
    result = verify_chain()
    assert result.valid is False
    assert any("chain" in " ".join(entry["reasons"]).lower()
               for entry in result.invalid_events)


def test_verification_identifies_the_affected_event():
    ids = _seed_three()
    _tamper(ids[1], description="only this one changed")
    result = verify_chain()
    # Exactly the tampered event is reported (its neighbours stay valid).
    assert result.invalid_ids == [ids[1]]
    assert result.hashed_events == 3


# ---------------------------------------------------------------------------
# D. Legacy handling, migration, pipeline integration, determinism (18-21)
# ---------------------------------------------------------------------------

def test_legacy_unhashed_events_handled_correctly():
    # Two pre-Phase-9 legacy rows (no hashes), then new hashed events.
    insert_event(_event(description="legacy 1"))
    insert_event(_event(description="legacy 2"))
    process_events([_event(description="new 1"), _event(description="new 2")])

    result = verify_chain()
    assert result.valid is True          # legacy prefix + valid chain
    assert result.legacy_events == 2
    assert result.hashed_events == 2
    # The first hashed event still links to genesis, not to a legacy row.
    hashed = [r for r in get_events_in_chain_order() if r["event_hash"]]
    assert hashed[0]["previous_hash"] == GENESIS_PREVIOUS_HASH


def test_migration_preserves_existing_events(tmp_path, monkeypatch):
    # Build a pre-Phase-9 database (old schema, no hash columns) with data.
    old_db = tmp_path / "old_schema.db"
    conn = sqlite3.connect(old_db)
    try:
        conn.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, source TEXT NOT NULL,
                event_type TEXT NOT NULL, description TEXT NOT NULL,
                severity TEXT, user TEXT, device TEXT, file_path TEXT,
                metadata TEXT
            )
        """)
        conn.executemany(
            "INSERT INTO events (timestamp, source, event_type, description) "
            "VALUES (?, ?, ?, ?)",
            [("2021-01-01T00:00:00", "Windows", "X", "one"),
             ("2021-01-01T00:01:00", "USB", "Y", "two")],
        )
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setattr(_db, "DB_PATH", str(old_db))
    schema.create_tables()  # runs the migration on the existing DB

    conn = sqlite3.connect(old_db)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    finally:
        conn.close()
    assert "event_hash" in columns and "previous_hash" in columns

    rows = get_events_in_chain_order()
    assert len(rows) == 2                       # data not destroyed
    assert rows[0]["description"] == "one"
    assert rows[0]["event_hash"] is None        # existing rows are legacy


def test_new_pipeline_events_receive_hashes_automatically():
    process_events([_event(description=f"e{i}") for i in range(3)])
    for row in get_events_in_chain_order():
        assert row["event_hash"] is not None
        assert row["previous_hash"] is not None
        assert len(row["event_hash"]) == 64


def test_hashes_deterministic_across_database_reads():
    process_events([_event(description=f"e{i}") for i in range(3)])

    def recompute_all():
        return [compute_hash(event_fields_from_row(r), r["previous_hash"])
                for r in get_events_in_chain_order()]

    first = recompute_all()          # fresh connection
    second = recompute_all()         # another fresh connection
    stored = [r["event_hash"] for r in get_events_in_chain_order()]
    assert first == second == stored


def test_get_chain_tip_tracks_the_last_hashed_event():
    assert get_chain_tip() is None                       # empty chain
    process_events([_event(description="only")])
    tip = get_chain_tip()
    assert tip == get_events_in_chain_order()[-1]["event_hash"]



