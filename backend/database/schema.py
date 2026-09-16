"""Database schema creation for ForensiX-AI."""

from .db import get_connection


CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


def create_tables() -> None:
    """Create all application tables if they do not exist."""
    with get_connection() as connection:
        connection.execute(CREATE_EVENTS_TABLE)


if __name__ == "__main__":
    create_tables()