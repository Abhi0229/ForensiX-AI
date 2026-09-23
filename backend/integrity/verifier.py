"""Hash-chain integrity verification for ForensiX AI (Phase 9).

Walks stored events in chain order (insertion / ``id`` order) and reports
whether the SHA-256 hash chain is intact. This detects *evidence* of tampering
with stored records; see the limitations note at the bottom of this module.

What is checked, per hashed event:
  * ``event_hash`` recomputed from the event's canonical data + its stored
    ``previous_hash`` must equal the stored ``event_hash`` (detects any change
    to a protected field, or to ``event_hash`` / ``previous_hash`` itself);
  * ``previous_hash`` must equal the ``event_hash`` of the preceding hashed
    event, or ``GENESIS_PREVIOUS_HASH`` for the first (detects deletions,
    reordering, and broken continuity).

Legacy events (created before Phase 9, ``event_hash`` NULL) are expected only
as a contiguous prefix. A legacy/unhashed row appearing *after* the chain has
started is treated as a suspicious insertion and flagged.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from backend.database.db import get_events_in_chain_order
from backend.integrity.hasher import (
    GENESIS_PREVIOUS_HASH,
    compute_hash,
    event_fields_from_row,
)


@dataclass
class IntegrityResult:
    """Structured outcome of a chain verification.

    * ``valid``          -- True only if nothing invalid and no errors
    * ``checked_events`` -- total rows examined
    * ``hashed_events``  -- hash-chained rows verified
    * ``legacy_events``  -- pre-Phase-9 unhashed prefix rows
    * ``invalid_events`` -- list of ``{"id", "reasons"}`` for affected rows
    * ``errors``         -- unexpected failures during verification
    """

    valid: bool = True
    checked_events: int = 0
    hashed_events: int = 0
    legacy_events: int = 0
    invalid_events: List[dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def invalid_ids(self) -> List:
        """The ids of every event that failed verification."""
        return [entry["id"] for entry in self.invalid_events]

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "checked_events": self.checked_events,
            "hashed_events": self.hashed_events,
            "legacy_events": self.legacy_events,
            "invalid_events": list(self.invalid_events),
            "errors": list(self.errors),
        }


def verify_chain(rows: Optional[list] = None) -> IntegrityResult:
    """Verify the hash chain over ``rows`` (default: the whole database).

    Args:
        rows: Optional pre-fetched rows in chain order. When None, reads them
            via ``get_events_in_chain_order()``. Passing rows lets callers
            verify an isolated/temporary database.

    Returns:
        An :class:`IntegrityResult`.
    """
    if rows is None:
        rows = get_events_in_chain_order()

    result = IntegrityResult()
    expected_previous = GENESIS_PREVIOUS_HASH
    chain_started = False

    for row in rows:
        result.checked_events += 1
        event_id = row["id"]
        stored_hash = row["event_hash"]
        stored_previous = row["previous_hash"]
        is_hashed = stored_hash not in (None, "")

        if not is_hashed:
            if chain_started:
                # An unhashed row after the chain began is not a legitimate
                # legacy prefix event -- it looks like an insertion.
                result.invalid_events.append({
                    "id": event_id,
                    "reasons": ["unhashed event after chain start "
                                "(possible inserted/removed record)"],
                })
            else:
                result.legacy_events += 1
            continue

        chain_started = True
        result.hashed_events += 1

        reasons: List[str] = []
        try:
            recomputed = compute_hash(event_fields_from_row(row), stored_previous)
        except Exception as exc:  # canonicalization should not fail, but be safe
            result.errors.append(f"event {event_id}: hashing error: {exc}")
            result.invalid_events.append({
                "id": event_id, "reasons": [f"hashing error: {exc}"],
            })
            # Advance using stored hash so later events are still checked.
            expected_previous = stored_hash
            continue

        if recomputed != stored_hash:
            reasons.append("event_hash does not match canonical data")
        if _norm(stored_previous) != _norm(expected_previous):
            reasons.append("previous_hash does not match preceding chained "
                           "event (chain broken)")

        if reasons:
            result.invalid_events.append({"id": event_id, "reasons": reasons})

        # The next event must link to THIS event's stored hash.
        expected_previous = stored_hash

    result.valid = not result.invalid_events and not result.errors
    return result


def _norm(value) -> str:
    """Treat NULL and empty string as equal for link comparison."""
    return "" if value is None else str(value)
