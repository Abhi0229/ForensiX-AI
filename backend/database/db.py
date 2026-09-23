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