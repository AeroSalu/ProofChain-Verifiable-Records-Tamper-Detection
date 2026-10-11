"""The registry's SQLite database.

The database is the registry's working store and nothing more. The verifier
never reads it, and the audit treats it as something to check against the
ledger, not something to trust.
"""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .models import ADDED_COLUMNS, ADOPT_OWNERS, INDEXES, SCHEMA

DEFAULT_DB_PATH = "data/registry.db"


def default_path() -> str:
    return os.environ.get("PROOFCHAIN_DB_PATH", DEFAULT_DB_PATH)


def connect(path) -> sqlite3.Connection:
    """Open one connection. Each request gets its own and closes it afterwards."""
    # Autocommit mode: writes that belong together use transaction() below.
    # A request's connection can be opened on one worker thread and used on another.
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path) -> None:
    """Create the database file and its tables if they do not exist yet."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(records)")}
        if "salt" not in columns:
            raise RuntimeError(
                f"{path} was created before records were salted and cannot be used. Stop both services and "
                "delete the registry database, the ledger file and any pin file together, then start again.")
        _add_missing_columns(conn)
        conn.executescript(INDEXES)
    finally:
        conn.close()


def _add_missing_columns(conn) -> None:
    """Bring a database made by an earlier version up to the current tables, keeping its data."""
    added = set()
    for table, column, definition in ADDED_COLUMNS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            added.add((table, column))
    if ("batches", "owner") in added:
        conn.execute(ADOPT_OWNERS)


@contextmanager
def transaction(conn):
    """Run several statements as one unit, holding the write lock throughout."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
