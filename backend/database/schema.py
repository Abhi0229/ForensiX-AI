from backend.database.db import get_connection

# Columns added in Phase 9 (SHA-256 hash chaining). Kept as a table so the
# same definition drives both fresh creation and migration of older DBs.
_HASH_COLUMNS = (
    ("event_hash", "TEXT"),
    ("previous_hash", "TEXT"),
)


def _existing_columns(connection, table="events"):
    """Return the set of column names currently on ``table``."""
    rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    # PRAGMA table_info columns: (cid, name, type, notnull, dflt_value, pk)
    return {row[1] for row in rows}


def _migrate(connection):
    """Add any missing Phase 9 columns to an existing events table.

    Migration-safe and non-destructive: existing rows are preserved and simply
    receive NULL for the new columns (they become legacy/unhashed events). The
    column names are fixed constants, never user input, so the ALTER strings
    are safe.
    """
    existing = _existing_columns(connection, "events")
    for name, col_type in _HASH_COLUMNS:
        if name not in existing:
            connection.execute(f"ALTER TABLE events ADD COLUMN {name} {col_type}")


def create_tables():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT DEFAULT 'INFO',
            user TEXT,
            device TEXT,
            file_path TEXT,
            metadata TEXT,
            event_hash TEXT,
            previous_hash TEXT
        )
    """)

    # Bring pre-Phase-9 databases up to date without dropping their data.
    _migrate(connection)

    connection.commit()
    connection.close()


if __name__ == "__main__":
    create_tables()
    print("Database tables created successfully.")
