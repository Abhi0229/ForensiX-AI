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