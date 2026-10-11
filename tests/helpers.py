"""Shared helpers for the registry and audit tests."""

import json
import sqlite3

from proofchain.core.merkle import merkle_root
from proofchain.core.proof import leaf_values
from proofchain.registry import models, sessions, staff
from proofchain.registry.ledger_client import LedgerConflict, LedgerError, LedgerUnavailable
from proofchain.verifier.verify import Pin

# The root of the brief's unsalted worked example. The registry salts every record, so its
# roots never equal this; the tests use it as "some well-formed root" and as a contrast.
BRIEF_ROOT = "3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8effeda95e98c40"

# The four documents of the brief's worked example, in leaf order.
DOCS = [(f"document-{letter.lower()}.txt", f"Document {letter}".encode()) for letter in "ABCD"]


# The secret the test ledger expects for an append, set in the environment by conftest.py.
LEDGER_TOKEN = "test-ledger-token-5c1e9a0b7d3f4e62"
LEDGER_AUTH = {"Authorization": f"Bearer {LEDGER_TOKEN}"}

# The staff account the tests sign in with. Hashed once: scrypt is slow on purpose.
STAFF = "asha"
STAFF_PASSWORD = "correct horse battery"
_STAFF_HASH = staff.hash_password(STAFF_PASSWORD)


class InProcessLedger:
    """Stands in for the registry's HTTP client, talking to a real ledger app in-process."""

    def __init__(self, client, token=LEDGER_TOKEN):
        self.client, self.down, self.token = client, False, token

    def _check(self):
        if self.down:
            raise LedgerUnavailable("the ledger is down")

    def publish(self, batch_id, root, tree_size):
        self._check()
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        r = self.client.post("/entries", json={"batch_id": batch_id, "root": root, "tree_size": tree_size},
                             headers=headers)
        if r.status_code == 409:
            raise LedgerConflict(batch_id)
        if r.status_code != 201:
            raise LedgerError(r.text)
        return r.json()

    def entries(self):
        self._check()
        return self.client.get("/entries").json()

    def entry(self, batch_id):
        self._check()
        r = self.client.get(f"/entries/{batch_id}")
        return None if r.status_code == 404 else r.json()

    def public_key(self):
        self._check()
        return self.client.get("/pubkey").json()["public_key"]


# ---- signing in


def add_staff(db_path, username=STAFF):
    """Create the test account (password STAFF_PASSWORD) if it is not there yet."""
    execute(db_path, "INSERT OR IGNORE INTO staff (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, _STAFF_HASH, models.now()))


def sign_in(client, username=STAFF):
    """Give a running registry's test client a session, without paying for a password hash each time."""
    add_staff(client.app.state.db_path, username)
    client.cookies.set(sessions.COOKIE, sessions.issue(username, client.app.state.session_secret))
    return client


def sign_out(client):
    client.cookies.delete(sessions.COOKIE)
    return client


# ---- driving the registry the way the pages do


def upload(client, name, content, canon="raw-bytes-v1", **kwargs):
    return client.post("/records", files={"file": (name, content)}, data={"canon": canon}, **kwargs)


def confirm(client, record_id, issuer="Example University", document_type="Certificate", date="2026-10-11",
            category="Education", confirmed_by=None, **kwargs):
    """Confirm a record as the signed-in account. confirmed_by, if given, is posted to show it is ignored."""
    data = {"issuer": issuer, "document_type": document_type, "date": date, "category": category}
    if confirmed_by is not None:
        data["confirmed_by"] = confirmed_by
    return client.post(f"/records/{record_id}/confirm", data=data, **kwargs)


def seal(client, batch_id="batch-0001", **kwargs):
    return client.post(f"/batches/{batch_id}/seal", **kwargs)


def register(client, docs=DOCS):
    """Upload and confirm documents. Assumes no other records are waiting."""
    for name, content in docs:
        assert upload(client, name, content).status_code == 200


def confirm_all(client, db_path):
    for row in query(db_path, "SELECT id FROM records WHERE metadata_confirmed = 0 ORDER BY id"):
        assert confirm(client, row["id"]).status_code == 200


def sealed_batch(client, db_path, docs=DOCS, batch_id="batch-0001"):
    """Register, confirm and seal a batch of documents."""
    register(client, docs)
    confirm_all(client, db_path)
    assert seal(client, batch_id).status_code == 200


def proof_of(client, record_id) -> dict:
    reply = client.get(f"/records/{record_id}/proof")
    assert reply.status_code == 200, reply.text
    return json.loads(reply.content)


def ledger_view(ledger):
    """What an outside verifier holds: the entries, the key, and a pin on the head."""
    entries = ledger.entries()
    pin = Pin(entries[-1]["seq"], entries[-1]["entry_hash"]) if entries else None
    return entries, bytes.fromhex(ledger.public_key()), pin


def stored_root(db_path, batch_id="batch-0001") -> str:
    """The root that the batch's stored fingerprints and salts rebuild, in leaf order."""
    rows = query(db_path, "SELECT fingerprint, salt FROM records WHERE batch_id = ? ORDER BY leaf_index, id",
                 (batch_id,))
    return merkle_root(leaf_values([r["fingerprint"] for r in rows], [r["salt"] for r in rows])).hex()


def published_root(ledger, batch_id="batch-0001") -> str:
    return ledger.entry(batch_id)["root"]


# ---- reading and editing the database directly, as an insider would


def query(db_path, sql, args=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(sql, args)]
    finally:
        conn.close()


def execute(db_path, sql, args=()):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(sql, args)
        conn.commit()
    finally:
        conn.close()
