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


def insert_event(event):
    """
    Insert an Event object into the events table.
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
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.timestamp.isoformat(),
        event.source,
        event.event_type,
        event.description,
        event.severity,
        event.user,
        event.device,
        event.file_path,
        event.metadata
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