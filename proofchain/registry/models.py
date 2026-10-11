"""The registry's tables and the queries on them.

records   one row per uploaded document: its content, fingerprint, salt,
          suggested and confirmed metadata, and its place in a batch
batches   one row per batch: open while it collects records, sealed once its
          root is published
meta      small key/value store (the ledger public key seen at the first seal)
staff     the people allowed to sign in: a username and a salted password hash

Metadata is descriptive only. It is never part of a fingerprint, leaf or root.
"""

import json
import secrets
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    id                TEXT PRIMARY KEY,
    status            TEXT NOT NULL CHECK (status IN ('open', 'sealed')),
    root              TEXT,
    tree_size         INTEGER,
    ledger_seq        INTEGER,
    ledger_entry_hash TEXT,
    sealed_at         TEXT
);
CREATE TABLE IF NOT EXISTS records (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    filename           TEXT NOT NULL,
    content            BLOB NOT NULL,
    canon              TEXT NOT NULL,
    fingerprint        TEXT NOT NULL,
    salt               TEXT NOT NULL,
    suggested_metadata TEXT NOT NULL DEFAULT '{}',
    metadata           TEXT,
    metadata_confirmed INTEGER NOT NULL DEFAULT 0,
    confirmed_by       TEXT,
    batch_id           TEXT REFERENCES batches (id),
    leaf_index         INTEGER,
    created_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS staff (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"""

METADATA_FIELDS = ("issuer", "date", "document_type", "category")
LEDGER_PUBLIC_KEY = "ledger_public_key"

# Everything except the content blob, which is only read when it is needed.
_COLUMNS = ("id, filename, canon, fingerprint, salt, suggested_metadata, metadata, "
            "metadata_confirmed, confirmed_by, batch_id, leaf_index, created_at")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_object(text) -> dict:
    """Decode a JSON column, tolerating anything an edited database may hold."""
    try:
        value = json.loads(text) if text else {}
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _record(row) -> dict:
    record = dict(row)
    record["suggested_metadata"] = _json_object(record["suggested_metadata"])
    record["metadata"] = _json_object(record["metadata"])
    record["metadata_confirmed"] = bool(record["metadata_confirmed"])
    return record


# ---- records

def new_salt() -> str:
    """A fresh random salt: 32 bytes as 64 hex characters."""
    return secrets.token_hex(32)


def add_record(conn, filename: str, content: bytes, canon: str, fingerprint: str, suggested: dict) -> int:
    """Store an upload. Every record gets its own salt, so each registration is a distinct leaf."""
    cursor = conn.execute(
        "INSERT INTO records (filename, content, canon, fingerprint, salt, suggested_metadata, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (filename, content, canon, fingerprint, new_salt(), json.dumps(suggested), now()),
    )
    return cursor.lastrowid


def same_content(conn, fingerprint: str, exclude_id: int | None = None) -> list[dict]:
    """Other records that hold exactly this content, oldest first."""
    rows = conn.execute(
        "SELECT id, filename, batch_id, metadata_confirmed FROM records WHERE fingerprint = ? AND id IS NOT ? "
        "ORDER BY id", (fingerprint, exclude_id))
    return [dict(row) for row in rows]


def get_record(conn, record_id: int) -> dict | None:
    row = conn.execute(f"SELECT {_COLUMNS} FROM records WHERE id = ?", (record_id,)).fetchone()
    return None if row is None else _record(row)


def record_content(conn, record_id: int):
    row = conn.execute("SELECT content FROM records WHERE id = ?", (record_id,)).fetchone()
    return None if row is None else row["content"]


def discard_pending(conn, record_id: int) -> bool:
    """Remove an upload that was never confirmed. A confirmed record is never removed."""
    cursor = conn.execute(
        "DELETE FROM records WHERE id = ? AND metadata_confirmed = 0 AND batch_id IS NULL", (record_id,))
    return cursor.rowcount == 1


def pending_records(conn) -> list[dict]:
    """Uploaded but not yet confirmed by a person."""
    rows = conn.execute(f"SELECT {_COLUMNS} FROM records WHERE metadata_confirmed = 0 ORDER BY id")
    return [_record(row) for row in rows]


def batch_records(conn, batch_id: str) -> list[dict]:
    """A batch's records in leaf order."""
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM records WHERE batch_id = ? ORDER BY leaf_index, id", (batch_id,)
    )
    return [_record(row) for row in rows]


def records_with_content(conn) -> list[dict]:
    """Every record, content included. Used by the audit."""
    rows = conn.execute(f"SELECT {_COLUMNS}, content FROM records ORDER BY id")
    return [_record(row) for row in rows]


def place_in_batch(conn, record_id: int, metadata: dict, confirmed_by: str, batch_id: str, leaf_index: int) -> None:
    conn.execute(
        "UPDATE records SET metadata = ?, metadata_confirmed = 1, confirmed_by = ?, batch_id = ?, leaf_index = ? "
        "WHERE id = ?",
        (json.dumps(metadata), confirmed_by, batch_id, leaf_index, record_id),
    )


# ---- batches

def get_batch(conn, batch_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM batches WHERE id = ?", (batch_id,)).fetchone()
    return None if row is None else dict(row)


def list_batches(conn) -> list[dict]:
    """Open batch first, then sealed batches, newest first."""
    rows = conn.execute("SELECT * FROM batches ORDER BY status = 'sealed', id DESC")
    return [dict(row) for row in rows]


def open_batch(conn) -> dict | None:
    row = conn.execute("SELECT * FROM batches WHERE status = 'open' ORDER BY id LIMIT 1").fetchone()
    return None if row is None else dict(row)


def create_batch(conn) -> str:
    count = conn.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
    batch_id = f"batch-{count + 1:04d}"
    conn.execute("INSERT INTO batches (id, status) VALUES (?, 'open')", (batch_id,))
    return batch_id


def mark_sealed(conn, batch_id: str, root: str, tree_size: int, entry: dict) -> None:
    conn.execute(
        "UPDATE batches SET status = 'sealed', root = ?, tree_size = ?, ledger_seq = ?, "
        "ledger_entry_hash = ?, sealed_at = ? WHERE id = ?",
        (root, tree_size, entry["seq"], entry["entry_hash"], entry["published_at"], batch_id),
    )


def latest_pin(conn) -> tuple[int, str] | None:
    """The newest ledger entry this registry has published: its own checkpoint."""
    row = conn.execute(
        "SELECT ledger_seq, ledger_entry_hash FROM batches "
        "WHERE status = 'sealed' AND ledger_seq IS NOT NULL ORDER BY ledger_seq DESC LIMIT 1"
    ).fetchone()
    return None if row is None else (row["ledger_seq"], row["ledger_entry_hash"])


# ---- meta

def get_meta(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else row["value"]


def set_meta(conn, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))
