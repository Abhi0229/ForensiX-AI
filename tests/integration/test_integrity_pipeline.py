"""Integration: pipeline -> database -> SHA-256 hash chain -> verification.

Exercises the full Phase 8 + Phase 9 path end-to-end and performs controlled
tampering against a TEMPORARY database only. The real forensic DB is never
touched (see the autouse ``temp_db`` fixture in conftest).
"""

from backend.database import db as _db
from backend.database.db import get_chain_tip, get_events_in_chain_order
from backend.integrity.hasher import GENESIS_PREVIOUS_HASH
from backend.integrity.verifier import verify_chain

from .conftest import SEED_COUNT, baseline_events, cluster_events, seed_events


def _chain_rows():
    return list(get_events_in_chain_order())


def _update_field(event_id, column, value):
    """Directly mutate a stored row in the temp DB (simulated tampering)."""
    conn = _db.get_connection()
    try:
        conn.execute(f"UPDATE events SET {column} = ? WHERE id = ?",
                     (value, event_id))
        conn.commit()
    finally:
        conn.close()


def _delete_row(event_id):
    conn = _db.get_connection()
    try:
        conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
        conn.commit()
    finally:
        conn.close()


def _middle_hashed_id():
    rows = _chain_rows()
    return rows[len(rows) // 2]["id"]


# --- Happy-path chain -------------------------------------------------------

def test_chain_builds_and_verifies(seeded):
    result = verify_chain()
    assert result.valid is True
    assert result.hashed_events == SEED_COUNT
    assert result.legacy_events == 0
    assert result.invalid_events == []
    assert result.errors == []


def test_genesis_and_links(seeded):
    rows = _chain_rows()
    # First hashed event links to the documented genesis value.
    assert rows[0]["previous_hash"] == GENESIS_PREVIOUS_HASH
    assert rows[0]["event_hash"]
    # Every subsequent event references the prior event's stored hash.
    for prev, cur in zip(rows, rows[1:]):
        assert cur["previous_hash"] == prev["event_hash"]
    # The chain tip equals the last stored event's hash.
    assert get_chain_tip() == rows[-1]["event_hash"]


def test_chain_valid_after_multiple_batches():
    # Three separate pipeline runs must link into one continuous chain.
    assert seed_events(baseline_events()[:5]).inserted == 5
    assert seed_events(cluster_events()).inserted == 5
    assert seed_events(baseline_events()[5:10]).inserted == 5
    result = verify_chain()
    assert result.valid is True
    assert result.hashed_events == 15
    rows = _chain_rows()
    assert rows[0]["previous_hash"] == GENESIS_PREVIOUS_HASH
    for prev, cur in zip(rows, rows[1:]):
        assert cur["previous_hash"] == prev["event_hash"]


def test_legacy_prefix_then_hashed():
    # Legacy (unhashed) rows inserted first form a valid contiguous prefix;
    # rows added afterwards through the pipeline become hashed.
    _db.insert_event(baseline_events()[0])   # legacy: NULL hashes
    _db.insert_event(baseline_events()[1])   # legacy: NULL hashes
    assert seed_events(cluster_events()).inserted == 5
    result = verify_chain()
    assert result.valid is True
    assert result.legacy_events == 2
    assert result.hashed_events == 5


# --- Tampering detection (temp DB only) -------------------------------------

def test_tamper_description_detected(seeded):
    _update_field(_middle_hashed_id(), "description", "TAMPERED DESCRIPTION")
    assert verify_chain().valid is False


def test_tamper_metadata_detected(seeded):
    _update_field(_middle_hashed_id(), "metadata", '{"x":"tampered"}')
    assert verify_chain().valid is False


def test_tamper_timestamp_detected(seeded):
    _update_field(_middle_hashed_id(), "timestamp", "1999-01-01T00:00:00")
    assert verify_chain().valid is False


def test_tamper_previous_hash_detected(seeded):
    _update_field(_middle_hashed_id(), "previous_hash", "deadbeef" * 8)
    assert verify_chain().valid is False


def test_tamper_event_hash_detected(seeded):
    _update_field(_middle_hashed_id(), "event_hash", "deadbeef" * 8)
    assert verify_chain().valid is False


def test_deleted_middle_event_detected(seeded):
    assert verify_chain().valid is True
    _delete_row(_middle_hashed_id())
    after = verify_chain()
    assert after.valid is False
    # The broken link is reported, never silently swallowed.
    assert after.invalid_events


