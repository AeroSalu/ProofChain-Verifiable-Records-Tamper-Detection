"""Shared helpers for the registry and audit tests."""

import json
import sqlite3

from proofchain.registry.ledger_client import LedgerConflict, LedgerError, LedgerUnavailable
from proofchain.verifier.verify import Pin

BRIEF_ROOT = "3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8effeda95e98c40"

# The four documents of the brief's worked example, in leaf order.
DOCS = [(f"document-{letter.lower()}.txt", f"Document {letter}".encode()) for letter in "ABCD"]


class InProcessLedger:
    """Stands in for the registry's HTTP client, talking to a real ledger app in-process."""

    def __init__(self, client):
        self.client, self.down = client, False

    def _check(self):
        if self.down:
            raise LedgerUnavailable("the ledger is down")

    def publish(self, batch_id, root, tree_size):
        self._check()
        r = self.client.post("/entries", json={"batch_id": batch_id, "root": root, "tree_size": tree_size})
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


# ---- driving the registry the way the pages do


def upload(client, name, content, canon="raw-bytes-v1", **kwargs):
    return client.post("/records", files={"file": (name, content)}, data={"canon": canon}, **kwargs)


def confirm(client, record_id, issuer="Example University", document_type="Certificate", date="2026-10-11",
            category="Education", confirmed_by="Asha Rao", **kwargs):
    return client.post(f"/records/{record_id}/confirm", data={
        "issuer": issuer, "document_type": document_type, "date": date,
        "category": category, "confirmed_by": confirmed_by,
    }, **kwargs)


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
