import sqlite3
from pathlib import Path

# Path to the SQLite database
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "forensix_ai.db"


def get_connection():
    """
    Create and return a connection to the ForensiX AI database.
    """
    connection = sqlite3.connect(DB_PATH)

    # Allows us to access columns by name
    connection.row_factory = sqlite3.Row

    return connection


def insert_event(event, event_hash=None, previous_hash=None):
    """
    Insert an Event object into the events table.

    Optionally records the Phase 9 hash-chain fields. When ``event_hash`` /
    ``previous_hash`` are omitted the event is stored as a legacy/unhashed row
    (both columns NULL), preserving the pre-Phase-9 behaviour.
    """
    connection = get_connection()

    connection.execute("""
        INSERT INTO events (
            timestamp,
            source,
            event_type,
            description,
            severity,
            user,
            device,
            file_path,
            metadata,
            event_hash,
            previous_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.timestamp.isoformat(),
        event.source,
        event.event_type,
        event.description,
        event.severity,
        event.user,
        event.device,
        event.file_path,
        event.metadata,
        event_hash,
        previous_hash
    ))

    connection.commit()
    connection.close()


def get_events(limit=None):
    """
    Retrieve events from the events table in chronological order.
    
    Args:
        limit: Optional maximum number of events to retrieve.
               If None, retrieves all events.
    
    Returns:
        List of sqlite3.Row objects ordered by timestamp (oldest first).
        Each row can be accessed by column name (e.g., row['timestamp'])
        or converted to dict with dict(row).
    """
    connection = get_connection()

    if limit is not None:
        cursor = connection.execute("""
            SELECT * FROM events
            ORDER BY timestamp ASC
            LIMIT ?
        """, (limit,))
    else:
        cursor = connection.execute("""
            SELECT * FROM events
            ORDER BY timestamp ASC
        """)

    events = cursor.fetchall()
    connection.close()

    return events


def get_event_by_id(event_id):
    """
    Retrieve a single event from the events table by its ID.

    Args:
        event_id: The ID of the event to retrieve.

    Returns:
        A sqlite3.Row object if the event exists, None otherwise.
        The row can be accessed by column name (e.g., row['timestamp'])
        or converted to dict with dict(row).
    """
    connection = get_connection()

    cursor = connection.execute("""
        SELECT * FROM events WHERE id = ?
    """, (event_id,))

    event = cursor.fetchone()
    connection.close()

    return event


def get_events_in_chain_order():
    """
    Retrieve every event ordered by insertion id (ascending).

    This is the deterministic hash-chain order (Phase 9): the chain links
    events in the order they were stored, which SQLite's monotonically
    increasing ``id`` reflects. This differs from ``get_events`` (timestamp
    order) and is what the integrity verifier walks.
    """
    connection = get_connection()

    cursor = connection.execute("""
        SELECT * FROM events
        ORDER BY id ASC
    """)

    events = cursor.fetchall()
    connection.close()

    return events


def get_chain_tip():
    """
    Return the ``event_hash`` of the most recently stored hashed event.

    This is the current end (tip) of the hash chain and becomes the
    ``previous_hash`` of the next event to be chained. Legacy/unhashed rows
    (``event_hash IS NULL``) are ignored, so the chain links only hashed
    events. Returns None when no hashed event exists yet.
    """
    connection = get_connection()

    cursor = connection.execute("""
        SELECT event_hash FROM events
        WHERE event_hash IS NOT NULL
        ORDER BY id DESC
        LIMIT 1
    """)

    row = cursor.fetchone()
    connection.close()

    return row[0] if row is not None else None


# Columns a GET endpoint may filter on by exact match. Fixed literal constants
# -- never built from user input -- so a request can never influence the shape
# of the SQL, only the bound parameter values.
_FILTERABLE_COLUMNS = ("source", "event_type", "severity", "user", "device")


def _build_event_filters(source=None, event_type=None, severity=None,
                         user=None, device=None, start_time=None, end_time=None):
    """Build a parameterized WHERE clause for the optional event filters.

    Returns ``(where_sql, params)``. Column names are fixed literals and every
    user-supplied value is a bound ``?`` parameter, so this cannot be used for
    SQL injection.
    """
    clauses = []
    params = []
    for column, value in (("source", source), ("event_type", event_type),
                          ("severity", severity), ("user", user),
                          ("device", device)):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    if start_time is not None:
        clauses.append("timestamp >= ?")
        params.append(start_time)
    if end_time is not None:
        clauses.append("timestamp <= ?")
        params.append(end_time)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def query_events(*, limit=100, offset=0, source=None, event_type=None,
                 severity=None, user=None, device=None,
                 start_time=None, end_time=None, order="ASC"):
    """Read events with optional parameterized filters (read-only).

    ``order`` is coerced to ASC/DESC only. ``start_time``/``end_time`` are ISO
    timestamp strings; stored timestamps are ISO text, so a lexical comparison
    is also chronological. Returns a list of ``sqlite3.Row``.
    """
    where, params = _build_event_filters(source, event_type, severity, user,
                                         device, start_time, end_time)
    direction = "DESC" if str(order).upper() == "DESC" else "ASC"
    sql = (f"SELECT * FROM events{where} "
           f"ORDER BY timestamp {direction}, id {direction} LIMIT ? OFFSET ?")
    params = params + [int(limit), int(offset)]

    connection = get_connection()
    try:
        rows = connection.execute(sql, params).fetchall()
    finally:
        connection.close()
    return rows


def count_events(*, source=None, event_type=None, severity=None, user=None,
                 device=None, start_time=None, end_time=None):
    """Count events matching the same optional parameterized filters (read-only)."""
    where, params = _build_event_filters(source, event_type, severity, user,
                                         device, start_time, end_time)
    sql = f"SELECT COUNT(*) FROM events{where}"

    connection = get_connection()
    try:
        total = connection.execute(sql, params).fetchone()[0]
    finally:
        connection.close()
    return int(total)


# Columns a summary endpoint may GROUP BY. Fixed literal allowlist -- the column
# is always a constant chosen by server code, never user input.
_GROUPABLE_COLUMNS = ("source", "severity", "event_type", "user", "device")


def count_events_by(column):
    """Return ``{value: count}`` grouped by an allowlisted column (read-only).

    ``column`` must be one of ``_GROUPABLE_COLUMNS``; anything else raises
    ``ValueError``. NULL values are reported under the empty-string key so the
    result is JSON-friendly.
    """
    if column not in _GROUPABLE_COLUMNS:
        raise ValueError(f"column not groupable: {column!r}")
    sql = f"SELECT {column} AS k, COUNT(*) AS n FROM events GROUP BY {column}"

    connection = get_connection()
    try:
        rows = connection.execute(sql).fetchall()
    finally:
        connection.close()
    return {(row["k"] if row["k"] is not None else ""): row["n"] for row in rows}