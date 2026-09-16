"""SQLite connection helpers for the forensic event database."""

from pathlib import Path
import sqlite3


DATABASE_PATH = Path(__file__).with_name("forensic.db")


def get_connection() -> sqlite3.Connection:
    """Return a connection to the local SQLite database."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection