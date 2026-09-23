"""SHA-256 hash-chaining for ForensiX AI (Phase 9).

This module produces the deterministic, tamper-evident hash for a single
event. It is the ONLY place that defines how an event is canonicalized and
hashed, so the pipeline (when writing) and the verifier (when checking) always
agree byte-for-byte.

This is **SHA-256 hash chaining** (a tamper-evident hash chain), NOT a
blockchain: there is no distributed consensus, mining, or networking. Each
stored event's hash depends on the previous event's hash, so:

    current_hash = SHA256( canonical(event_fields) + previous_hash )

Canonicalization
----------------
Events are serialized as JSON with ``sort_keys=True`` and compact separators
``(",", ":")``, then UTF-8 encoded. This is deterministic and independent of
Python's ``str()``/``repr()``. The ``timestamp`` is canonicalized as its ISO
8601 string so a hash computed from a live ``Event`` matches one recomputed
from the string stored in (and read back from) SQLite.

Genesis rule
------------
The first hashed event in the chain uses ``previous_hash = GENESIS_PREVIOUS_HASH``
(the empty string ``""``). It still receives a real SHA-256 ``event_hash``.
"""

import hashlib
import json
from datetime import datetime
from typing import Mapping, Optional

from backend.database.models import Event

# The documented genesis value: the first hashed event links to "".
GENESIS_PREVIOUS_HASH = ""

# The integrity-protected fields, in a fixed set. ``previous_hash`` is added
# to the canonical payload separately so tampering with the link is detected.
HASHED_FIELDS = (
    "timestamp",
    "source",
    "event_type",
    "description",
    "severity",
    "user",
    "device",
    "file_path",
    "metadata",
)


def _normalize(value) -> str:
    """Coerce a field value into its canonical string form.

    ``None`` becomes ``""`` and a ``datetime`` becomes its ISO 8601 string so
    that Event objects and the strings read back from SQLite hash identically.
    """
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def event_fields_from_event(event: Event) -> dict:
    """Extract the integrity-protected fields from an ``Event`` object."""
    return {
        "timestamp": _normalize(event.timestamp),
        "source": _normalize(event.source),
        "event_type": _normalize(event.event_type),
        "description": _normalize(event.description),
        "severity": _normalize(event.severity),
        "user": _normalize(event.user),
        "device": _normalize(event.device),
        "file_path": _normalize(event.file_path),
        "metadata": _normalize(event.metadata),
    }


def event_fields_from_row(row) -> dict:
    """Extract the integrity-protected fields from a stored DB row.

    ``row`` may be a ``sqlite3.Row`` or any mapping exposing the column names.
    """
    return {name: _normalize(row[name]) for name in HASHED_FIELDS}


def canonical_bytes(fields: Mapping[str, object],
                    previous_hash: Optional[str]) -> bytes:
    """Return the deterministic canonical byte serialization to be hashed.

    Only the fixed ``HASHED_FIELDS`` plus ``previous_hash`` are included, each
    normalized to a string, then dumped as sorted-key compact JSON in UTF-8.
    """
    payload = {name: _normalize(fields.get(name)) for name in HASHED_FIELDS}
    payload["previous_hash"] = _normalize(previous_hash)
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_hash(fields: Mapping[str, object],
                 previous_hash: Optional[str]) -> str:
    """Compute the SHA-256 hex digest for the given fields + previous hash."""
    return hashlib.sha256(canonical_bytes(fields, previous_hash)).hexdigest()


def hash_event(event: Event, previous_hash: Optional[str]) -> str:
    """Convenience: compute the ``event_hash`` for an ``Event``.

    Pass ``GENESIS_PREVIOUS_HASH`` (or None, treated the same) for the first
    event in the chain.
    """
    return compute_hash(event_fields_from_event(event), previous_hash)
