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

    # Allows us to access columns by name later
    connection.row_factory = sqlite3.Row

    return connection