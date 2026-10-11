"""Batches per custodian: who a batch belongs to, and who may seal it."""

import json
import re
import sqlite3
import subprocess
import sys
import threading

import pytest
from fastapi.testclient import TestClient

from proofchain.registry import app as registry_app
from proofchain.registry import batching, db, staff
from proofchain.registry.audit import run_audit
from proofchain.verifier.verify import verify

from .helpers import (
    STAFF,
    add_staff,
    confirm,
    execute,
    ledger_view,
    proof_of,
    query,
    seal,
    sign_in,
    upload,
)

META = {"issuer": "Example University", "date": "", "document_type": "Certificate", "category": ""}


def batches(db_path):
    return query(db_path, "SELECT id, status, owner, sealed_by FROM batches ORDER BY id")


def placed(db_path):
    return query(db_path, "SELECT id, batch_id, leaf_index, confirmed_by FROM records "
                          "WHERE batch_id IS NOT NULL ORDER BY id")


def make_admin(db_path, username, admin=True):
    add_staff(db_path, username)
    execute(db_path, "UPDATE staff SET is_admin = ? WHERE username = ?", (1 if admin else 0, username))


def upload_many(client, count):
    for number in range(1, count + 1):
        assert upload(client, f"doc-{number}.txt", f"Document {number}".encode()).status_code == 200


# ---- a record joins the batch of whoever confirms it


def test_each_custodian_fills_their_own_open_batch(registry, db_path):
    upload_many(registry, 5)
    confirm(sign_in(registry, STAFF), 1)
    confirm(sign_in(registry, "bilal"), 2)
    confirm(sign_in(registry, STAFF), 3)
    confirm(sign_in(registry, "bilal"), 4)
    confirm(sign_in(registry, "chen"), 5)

    assert batches(db_path) == [
        {"id": "batch-0001", "status": "open", "owner": STAFF, "sealed_by": None},
        {"id": "batch-0002", "status": "open", "owner": "bilal", "sealed_by": None},
        {"id": "batch-0003", "status": "open", "owner": "chen", "sealed_by": None},
    ]
    assert placed(db_path) == [
        {"id": 1, "batch_id": "batch-0001", "leaf_index": 0, "confirmed_by": STAFF},
        {"id": 2, "batch_id": "batch-0002", "leaf_index": 0, "confirmed_by": "bilal"},
        {"id": 3, "batch_id": "batch-0001", "leaf_index": 1, "confirmed_by": STAFF},
        {"id": 4, "batch_id": "batch-0002", "leaf_index": 1, "confirmed_by": "bilal"},
        {"id": 5, "batch_id": "batch-0003", "leaf_index": 0, "confirmed_by": "chen"},
    ]


def test_batch_ids_are_neutral(registry, db_path):
    upload_many(registry, 3)
    for record_id, user in ((1, "zainab"), (2, "bilal"), (3, STAFF)):
        confirm(sign_in(registry, user), record_id)
    ids = [batch["id"] for batch in batches(db_path)]
    assert ids == ["batch-0001", "batch-0002", "batch-0003"]  # numbered in order of creation
    for batch_id in ids:
        assert re.fullmatch(r"batch-\d{4}", batch_id)
        assert not any(name in batch_id for name in ("zainab", "bilal", STAFF))


def test_a_new_batch_opens_for_a_custodian_after_they_seal(registry, db_path):
    upload_many(registry, 3)
    confirm(sign_in(registry, STAFF), 1)
    confirm(sign_in(registry, "bilal"), 2)
    assert seal(sign_in(registry, STAFF), "batch-0001").status_code == 200
    confirm(registry, 3)
    assert batches(db_path) == [
        {"id": "batch-0001", "status": "sealed", "owner": STAFF, "sealed_by": STAFF},
        {"id": "batch-0002", "status": "open", "owner": "bilal", "sealed_by": None},
        {"id": "batch-0003", "status": "open", "owner": STAFF, "sealed_by": None},
    ]
    assert placed(db_path)[2] == {"id": 3, "batch_id": "batch-0003", "leaf_index": 0, "confirmed_by": STAFF}


def test_the_database_allows_one_open_batch_per_custodian(registry, db_path):
    upload_many(registry, 1)
    confirm(registry, 1)
    with pytest.raises(sqlite3.IntegrityError):
        execute(db_path, "INSERT INTO batches (id, status, owner) VALUES ('batch-0002', 'open', ?)", (STAFF,))
    # Another custodian's open batch, a sealed batch of the same custodian, and ownerless rows are all fine.
    execute(db_path, "INSERT INTO batches (id, status, owner) VALUES ('batch-0002', 'open', 'bilal')")
    execute(db_path, "INSERT INTO batches (id, status, owner) VALUES ('batch-0003', 'sealed', ?)", (STAFF,))
    execute(db_path, "INSERT INTO batches (id, status) VALUES ('batch-0004', 'open')")
    execute(db_path, "INSERT INTO batches (id, status) VALUES ('batch-0005', 'open')")
    assert len(batches(db_path)) == 5


# ---- confirming at the same time


def test_two_users_confirming_at_the_same_time_get_separate_batches(registry, db_path):
    upload_many(registry, 16)
    add_staff(db_path, "bilal")
    who = {record_id: (STAFF if record_id % 2 else "bilal") for record_id in range(1, 17)}
    start, errors = threading.Barrier(16), []

    def work(record_id):
        conn = db.connect(db_path)
        try:
            start.wait()
            batching.confirm_record(conn, record_id, META, who[record_id])
        except Exception as exc:  # collected and asserted on below
            errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=work, args=(record_id,)) for record_id in who]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    found = batches(db_path)
    assert sorted(batch["id"] for batch in found) == ["batch-0001", "batch-0002"]
    assert sorted(batch["owner"] for batch in found) == sorted([STAFF, "bilal"])
    owner_of = {batch["id"]: batch["owner"] for batch in found}
    rows = placed(db_path)
    assert len(rows) == 16
    for row in rows:
        assert owner_of[row["batch_id"]] == row["confirmed_by"] == who[row["id"]]
    for batch_id in owner_of:  # no gaps and no repeats in either batch's leaf order
        assert sorted(r["leaf_index"] for r in rows if r["batch_id"] == batch_id) == list(range(8))


def test_many_custodians_starting_at_the_same_moment_each_get_one_batch(registry, db_path):
    users = [f"user{number}" for number in range(1, 9)]
    upload_many(registry, len(users))
    start, errors = threading.Barrier(len(users)), []

    def work(record_id, user):
        conn = db.connect(db_path)
        try:
            start.wait()
            batching.confirm_record(conn, record_id, META, user)
        except Exception as exc:
            errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=work, args=(i, user)) for i, user in enumerate(users, start=1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    found = batches(db_path)
    assert len({batch["id"] for batch in found}) == len(users)
    assert sorted(batch["owner"] for batch in found) == sorted(users)
    assert all(row["leaf_index"] == 0 for row in placed(db_path))


def test_two_users_confirming_at_the_same_time_through_the_pages(registry, db_path):
    upload_many(registry, 12)
    add_staff(db_path, "bilal")
    asha, bilal = sign_in(registry, STAFF), sign_in(TestClient(registry.app), "bilal")
    start, replies = threading.Barrier(2), {}

    def work(client, name, record_ids):
        start.wait()
        replies[name] = [confirm(client, record_id, follow_redirects=False).status_code for record_id in record_ids]

    threads = [threading.Thread(target=work, args=(asha, STAFF, range(1, 13, 2))),
               threading.Thread(target=work, args=(bilal, "bilal", range(2, 13, 2)))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert replies == {STAFF: [303] * 6, "bilal": [303] * 6}
    found = batches(db_path)
    assert len(found) == 2 and {batch["owner"] for batch in found} == {STAFF, "bilal"}
    owner_of = {batch["id"]: batch["owner"] for batch in found}
    for row in placed(db_path):
        assert owner_of[row["batch_id"]] == row["confirmed_by"]
        assert row["confirmed_by"] == (STAFF if row["id"] % 2 else "bilal")
    for batch_id in owner_of:
        assert sorted(r["leaf_index"] for r in placed(db_path) if r["batch_id"] == batch_id) == list(range(6))


# ---- who may seal


@pytest.fixture
def two_batches(registry, db_path):
    """batch-0001 is asha's (records 1 and 3) and batch-0002 is bilal's (record 2). Signed in as asha."""
    upload_many(registry, 3)
    confirm(sign_in(registry, STAFF), 1)
    confirm(sign_in(registry, "bilal"), 2)
    confirm(sign_in(registry, STAFF), 3)
    return registry


def test_the_owner_seals_their_own_batch(two_batches, db_path, ledger):
    assert seal(two_batches, "batch-0001").status_code == 200
    assert batches(db_path)[0] == {"id": "batch-0001", "status": "sealed", "owner": STAFF, "sealed_by": STAFF}
    assert [entry["batch_id"] for entry in ledger.entries()] == ["batch-0001"]


def test_a_non_owner_cannot_seal(two_batches, db_path, ledger):
    reply = seal(sign_in(two_batches, "bilal"), "batch-0001")
    assert reply.status_code == 403
    assert f"batch-0001 belongs to {STAFF}" in reply.text and "Only its owner or an admin can seal it." in reply.text
    assert batches(db_path)[0] == {"id": "batch-0001", "status": "open", "owner": STAFF, "sealed_by": None}
    assert ledger.entries() == []
    assert query(db_path, "SELECT root, ledger_seq FROM batches WHERE id = 'batch-0001'") == [
        {"root": None, "ledger_seq": None}]

    # Nor the other way round, and each can still seal their own.
    assert seal(sign_in(two_batches, STAFF), "batch-0002").status_code == 403
    assert seal(sign_in(two_batches, "bilal"), "batch-0002").status_code == 200
    assert seal(sign_in(two_batches, STAFF), "batch-0001").status_code == 200
    assert [(b["owner"], b["sealed_by"]) for b in batches(db_path)] == [(STAFF, STAFF), ("bilal", "bilal")]


def test_a_non_owner_is_not_offered_the_seal_button(two_batches):
    page = sign_in(two_batches, "bilal").get("/records").text
    assert 'action="/batches/batch-0002/seal"' in page       # their own
    assert 'action="/batches/batch-0001/seal"' not in page   # someone else's
    assert f"Only {STAFF} or an admin can seal this batch." in page


def test_an_admin_can_seal_any_open_batch(two_batches, db_path, ledger):
    make_admin(db_path, "chen")
    admin = sign_in(two_batches, "chen")
    page = admin.get("/records").text
    assert 'action="/batches/batch-0001/seal"' in page and 'action="/batches/batch-0002/seal"' in page
    assert "as an admin you can seal any open batch" in page

    assert seal(admin, "batch-0001").status_code == 200
    assert seal(admin, "batch-0002").status_code == 200
    # The batch still belongs to whoever filled it; sealed_by says the admin sealed it.
    assert batches(db_path) == [
        {"id": "batch-0001", "status": "sealed", "owner": STAFF, "sealed_by": "chen"},
        {"id": "batch-0002", "status": "sealed", "owner": "bilal", "sealed_by": "chen"},
    ]
    entries, public_key, pin = ledger_view(ledger)
    assert [entry["batch_id"] for entry in entries] == ["batch-0001", "batch-0002"]
    assert verify(b"Document 3", proof_of(admin, 3), entries, public_key, pin).ok
    assert verify(b"Document 2", proof_of(admin, 2), entries, public_key, pin).ok


def test_an_admin_seals_their_own_batch_like_anyone_else(registry, db_path):
    make_admin(db_path, "chen")
    upload_many(registry, 1)
    confirm(sign_in(registry, "chen"), 1)
    assert seal(registry, "batch-0001").status_code == 200
    assert batches(db_path) == [{"id": "batch-0001", "status": "sealed", "owner": "chen", "sealed_by": "chen"}]


def test_taking_admin_away_takes_the_right_away(two_batches, db_path):
    make_admin(db_path, "chen")
    make_admin(db_path, "chen", admin=False)
    assert seal(sign_in(two_batches, "chen"), "batch-0001").status_code == 403
    assert batches(db_path)[0]["status"] == "open"


def test_being_an_admin_is_read_from_the_database_not_the_request(two_batches, db_path):
    bilal = sign_in(two_batches, "bilal")
    reply = bilal.post("/batches/batch-0001/seal", data={"admin": "1", "is_admin": "true", "sealed_by": STAFF,
                                                         "owner": "bilal"})
    assert reply.status_code == 403
    assert batches(db_path)[0] == {"id": "batch-0001", "status": "open", "owner": STAFF, "sealed_by": None}


def test_a_batch_with_no_owner_can_be_sealed_only_by_an_admin(registry, db_path):
    upload_many(registry, 1)
    confirm(registry, 1)
    execute(db_path, "UPDATE batches SET owner = NULL")
    reply = seal(registry, "batch-0001")
    assert reply.status_code == 403 and "batch-0001 has no owner" in reply.text
    page = registry.get("/records").text
    assert "Only an admin can seal this batch." in page and "no owner" in page

    make_admin(db_path, "chen")
    assert seal(sign_in(registry, "chen"), "batch-0001").status_code == 200
    assert batches(db_path) == [{"id": "batch-0001", "status": "sealed", "owner": None, "sealed_by": "chen"}]


def test_sealed_unknown_and_empty_batches_answer_as_before(two_batches, db_path):
    assert seal(two_batches, "batch-0001").status_code == 200
    assert seal(two_batches, "batch-0001").status_code == 409                      # already sealed
    assert seal(sign_in(two_batches, "bilal"), "batch-0001").status_code == 409    # for anyone
    assert seal(two_batches, "batch-9999").status_code == 404


def test_seal_batch_needs_to_know_who_is_sealing(two_batches, db_path, ledger):
    conn = db.connect(db_path)
    try:
        with pytest.raises(TypeError):
            batching.seal_batch(conn, "batch-0001", ledger)
        with pytest.raises(batching.Forbidden):
            batching.seal_batch(conn, "batch-0001", ledger, "bilal")
        with pytest.raises(batching.Forbidden):
            batching.seal_batch(conn, "batch-0001", ledger, "")
        assert batching.seal_batch(conn, "batch-0001", ledger, "bilal", admin=True)["batch_id"] == "batch-0001"
    finally:
        conn.close()
    assert batches(db_path)[0]["sealed_by"] == "bilal"


# ---- the Records and batches page


def test_page_shows_the_signed_in_users_batches_first_and_others_below(two_batches, db_path):
    seal(two_batches, "batch-0001")
    upload(two_batches, "doc-4.txt", b"Document 4")
    confirm(two_batches, 4)     # asha now has sealed batch-0001 and open batch-0003; bilal has open batch-0002

    def layout(page):
        mine, others = page.index('id="your-batches"'), page.index('id="other-batches"')
        cards = {batch_id: page.index(f'<section class="card" id="{batch_id}">')
                 for batch_id in ("batch-0001", "batch-0002", "batch-0003")}
        assert mine < others
        return {batch_id: ("mine" if position < others else "others") for batch_id, position in cards.items()}

    asha_page = sign_in(two_batches, STAFF).get("/records").text
    assert layout(asha_page) == {"batch-0001": "mine", "batch-0002": "others", "batch-0003": "mine"}
    bilal_page = sign_in(two_batches, "bilal").get("/records").text
    assert layout(bilal_page) == {"batch-0001": "others", "batch-0002": "mine", "batch-0003": "others"}

    # Owner and sealed-by columns, in the overview of each section.
    assert asha_page.count("<th>Owner</th><th>Sealed by</th>") == 2
    row = re.search(r'<td><a href="#batch-0001">batch-0001</a></td>(.*?)</tr>', asha_page, re.S).group(1)
    assert f"<td>{STAFF}</td>" in row and row.count(f"<td>{STAFF}</td>") == 2  # owner and sealed by
    open_row = re.search(r'<td><a href="#batch-0002">batch-0002</a></td>(.*?)</tr>', asha_page, re.S).group(1)
    assert "<td>bilal</td>" in open_row and "<td>–</td>" in open_row


def test_page_for_someone_with_no_batches(two_batches):
    page = sign_in(two_batches, "chen").get("/records").text
    assert "You have no batches yet." in page
    assert page.index("You have no batches yet.") < page.index('id="other-batches"') < page.index('id="batch-0001"')


def test_page_with_no_batches_at_all(registry):
    page = registry.get("/records")
    assert page.status_code == 200
    assert "You have no batches yet." in page.text and "No other custodian has a batch." in page.text


def test_anyone_signed_in_can_still_download_from_another_custodians_sealed_batch(two_batches, ledger):
    seal(two_batches, "batch-0001")
    bilal = sign_in(two_batches, "bilal")
    assert bilal.get("/records/1/document").content == b"Document 1"
    entries, public_key, pin = ledger_view(ledger)
    assert verify(b"Document 1", proof_of(bilal, 1), entries, public_key, pin).ok


# ---- ownership stays out of what is verified


def test_owner_and_sealer_appear_in_neither_the_proof_nor_the_ledger(two_batches, db_path, ledger):
    make_admin(db_path, "chen")
    seal(sign_in(two_batches, "chen"), "batch-0001")
    proof = proof_of(two_batches, 1)
    assert set(proof) == {"version", "canon", "fingerprint", "salt", "batch_id", "leaf_index", "tree_size",
                          "path", "root"}
    entry = ledger.entries()[0]
    assert set(entry) == {"seq", "batch_id", "root", "tree_size", "published_at", "prev_hash", "entry_hash",
                          "signature"}
    published = json.dumps([proof, entry])
    assert STAFF not in published and "chen" not in published


def test_audit_is_clean_across_several_custodians_batches(two_batches, db_path, ledger):
    seal(sign_in(two_batches, "bilal"), "batch-0002")
    seal(sign_in(two_batches, STAFF), "batch-0001")
    conn = db.connect(db_path)
    try:
        report = run_audit(conn, ledger)
    finally:
        conn.close()
    assert report.ok and [finding.subject for finding in report.batches] == ["batch-0001", "batch-0002"]
    assert two_batches.get("/audit").status_code == 200


# ---- databases made before batches had owners

OLD_SCHEMA = """
CREATE TABLE batches (
    id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK (status IN ('open', 'sealed')), root TEXT,
    tree_size INTEGER, ledger_seq INTEGER, ledger_entry_hash TEXT, sealed_at TEXT
);
CREATE TABLE records (
    id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT NOT NULL, content BLOB NOT NULL, canon TEXT NOT NULL,
    fingerprint TEXT NOT NULL, salt TEXT NOT NULL, suggested_metadata TEXT NOT NULL DEFAULT '{}', metadata TEXT,
    metadata_confirmed INTEGER NOT NULL DEFAULT 0, confirmed_by TEXT, batch_id TEXT REFERENCES batches (id),
    leaf_index INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
OLD_STAFF = """
CREATE TABLE staff (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
"""


def old_database(path, with_staff=True, open_batch_confirmers=("bilal",)):
    """A registry database as an earlier version left it: one custodian's sealed batch, a sealed batch
    confirmed under two names, an open batch, and a record still waiting."""
    import hashlib

    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA + (OLD_STAFF if with_staff else ""))
    conn.execute("INSERT INTO batches VALUES ('batch-0001', 'sealed', ?, 2, 0, ?, '2026-10-11T09:00:00Z')",
                 ("aa" * 32, "bb" * 32))
    conn.execute("INSERT INTO batches VALUES ('batch-0002', 'sealed', ?, 2, 1, ?, '2026-10-11T10:00:00Z')",
                 ("cc" * 32, "dd" * 32))
    conn.execute("INSERT INTO batches (id, status) VALUES ('batch-0003', 'open')")
    placements = [("batch-0001", 0, "asha"), ("batch-0001", 1, "asha"), ("batch-0002", 0, "asha"),
                  ("batch-0002", 1, "Typed Name")]
    placements += [("batch-0003", index, name) for index, name in enumerate(open_batch_confirmers)]
    for number, (batch_id, leaf_index, confirmed_by) in enumerate(placements + [(None, None, None)], start=1):
        content = f"Old document {number}".encode()
        conn.execute(
            "INSERT INTO records (filename, content, canon, fingerprint, salt, metadata, metadata_confirmed, "
            "confirmed_by, batch_id, leaf_index, created_at) VALUES (?, ?, 'raw-bytes-v1', ?, ?, ?, ?, ?, ?, ?, ?)",
            (f"old-{number}.txt", content, hashlib.sha256(content).hexdigest(), f"{number:02x}" * 32,
             json.dumps(META) if batch_id else None, 1 if batch_id else 0, confirmed_by, batch_id, leaf_index,
             "2026-10-11T08:00:00Z"))
    if with_staff:
        conn.execute("INSERT INTO staff VALUES ('asha', 'scrypt$16384$8$1$00$00', '2026-10-11T08:00:00Z')")
    conn.commit()
    conn.close()


def columns(path, table):
    return [row["name"] for row in query(path, f"PRAGMA table_info({table})")]


@pytest.mark.parametrize("with_staff", [True, False], ids=["from-before-owners", "from-before-accounts"])
def test_an_older_database_gains_the_new_columns_and_keeps_its_data(with_staff, db_path):
    old_database(db_path, with_staff)
    before = query(db_path, "SELECT * FROM records ORDER BY id")
    assert "owner" not in columns(db_path, "batches")

    db.init_db(db_path)

    assert columns(db_path, "batches")[-2:] == ["owner", "sealed_by"]
    assert "is_admin" in columns(db_path, "staff")
    assert query(db_path, "SELECT * FROM records ORDER BY id") == before
    assert query(db_path, "SELECT id, status, root, ledger_seq, owner, sealed_by FROM batches ORDER BY id") == [
        # Every record confirmed under one name: that name becomes the owner.
        {"id": "batch-0001", "status": "sealed", "root": "aa" * 32, "ledger_seq": 0, "owner": "asha",
         "sealed_by": None},
        # Confirmed under two names: nobody is guessed as the owner.
        {"id": "batch-0002", "status": "sealed", "root": "cc" * 32, "ledger_seq": 1, "owner": None,
         "sealed_by": None},
        {"id": "batch-0003", "status": "open", "root": None, "ledger_seq": None, "owner": "bilal",
         "sealed_by": None},
    ]
    if with_staff:
        assert query(db_path, "SELECT username, is_admin FROM staff") == [{"username": "asha", "is_admin": 0}]

    # Running it again changes nothing, including an owner someone has since corrected.
    execute(db_path, "UPDATE batches SET owner = 'chen' WHERE id = 'batch-0002'")
    snapshot = query(db_path, "SELECT * FROM batches ORDER BY id")
    db.init_db(db_path)
    db.init_db(db_path)
    assert query(db_path, "SELECT * FROM batches ORDER BY id") == snapshot


def test_an_upgraded_database_works_with_the_service(db_path, ledger):
    old_database(db_path)
    with TestClient(registry_app.create_app(db_path, ledger)) as registry:
        page = sign_in(registry, "bilal").get("/records")
        assert page.status_code == 200
        assert "not recorded" in page.text and "no owner" in page.text   # sealed before sealers and owners were kept

        # bilal's open batch is still theirs to add to and to seal; asha cannot seal it.
        assert seal(sign_in(registry, "asha"), "batch-0003").status_code == 403
        assert confirm(sign_in(registry, "bilal"), 6).status_code == 200
        assert placed(db_path)[-1] == {"id": 6, "batch_id": "batch-0003", "leaf_index": 1, "confirmed_by": "bilal"}
        assert seal(registry, "batch-0003").status_code == 200
        assert batches(db_path)[2] == {"id": "batch-0003", "status": "sealed", "owner": "bilal", "sealed_by": "bilal"}

        # A new custodian's first confirmation opens the next batch in the sequence.
        upload(registry, "new.txt", b"New document")
        confirm(sign_in(registry, "chen"), 7)
        assert batches(db_path)[3] == {"id": "batch-0004", "status": "open", "owner": "chen", "sealed_by": None}
        assert registry.get("/audit").status_code == 200


def test_an_old_open_batch_confirmed_under_two_names_needs_an_admin(db_path, ledger):
    old_database(db_path, open_batch_confirmers=("asha", "bilal"))
    with TestClient(registry_app.create_app(db_path, ledger)) as registry:
        assert batches(db_path)[2] == {"id": "batch-0003", "status": "open", "owner": None, "sealed_by": None}
        for user in ("asha", "bilal"):
            assert seal(sign_in(registry, user), "batch-0003").status_code == 403
        # Their next confirmations go to batches of their own, not into the ownerless one.
        confirm(sign_in(registry, "asha"), 7)
        assert placed(db_path)[-1]["batch_id"] == "batch-0004"

        make_admin(db_path, "chen")
        assert seal(sign_in(registry, "chen"), "batch-0003").status_code == 200
        assert batches(db_path)[2] == {"id": "batch-0003", "status": "sealed", "owner": None, "sealed_by": "chen"}


def test_an_old_batch_with_an_unnamed_confirmation_gets_no_owner(db_path):
    old_database(db_path)
    execute(db_path, "UPDATE records SET confirmed_by = NULL WHERE id = 2")
    db.init_db(db_path)
    assert batches(db_path)[0]["owner"] is None


def test_a_new_database_has_the_columns_from_the_start(registry, db_path):
    assert columns(db_path, "batches")[-2:] == ["owner", "sealed_by"]
    assert "is_admin" in columns(db_path, "staff")
    assert query(db_path, "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'one_open_batch_per_owner'")


# ---- admin accounts


def staff_cli(*args, password="", cwd):
    return subprocess.run([sys.executable, "-m", "proofchain.registry.staff", *[str(a) for a in args]],
                          input=password + "\n", capture_output=True, text=True, cwd=cwd, timeout=60)


def test_accounts_are_not_admins_unless_marked(db_path, registry):
    conn = db.connect(db_path)
    try:
        staff.add_staff(conn, "bilal", "long-enough-1")
        staff.add_staff(conn, "chen", "long-enough-1", admin=True)
        assert not staff.is_admin(conn, STAFF) and not staff.is_admin(conn, "bilal") and staff.is_admin(conn, "chen")
        assert not staff.is_admin(conn, "nobody")

        assert staff.set_admin(conn, "Bilal") == "bilal" and staff.is_admin(conn, "bilal")
        staff.set_admin(conn, "chen", False)
        assert not staff.is_admin(conn, "chen")
        with pytest.raises(staff.StaffError, match="no account named ghost"):
            staff.set_admin(conn, "ghost")
        # Changing a password does not change who is an admin.
        staff.add_staff(conn, "bilal", "another-password", reset=True, admin=False)
        assert staff.is_admin(conn, "bilal")
        assert [(a["username"], a["is_admin"]) for a in staff.list_staff(conn)] == [
            (STAFF, False), ("bilal", True), ("chen", False)]
    finally:
        conn.close()


def test_account_command_can_create_mark_and_list_admins(tmp_path):
    database = tmp_path / "registry.db"
    assert staff_cli("add", "asha", "--db", database, password="long-enough-1", cwd=tmp_path).returncode == 0
    made = staff_cli("add", "chen", "--admin", "--db", database, password="long-enough-1", cwd=tmp_path)
    assert made.returncode == 0 and "Created admin account chen" in made.stdout
    assert staff_cli("list", "--db", database, cwd=tmp_path).stdout.splitlines() == ["asha", "chen  (admin)"]

    promoted = staff_cli("admin", "asha", "--db", database, cwd=tmp_path)
    assert promoted.returncode == 0 and "asha is now an admin" in promoted.stdout
    revoked = staff_cli("admin", "chen", "--revoke", "--db", database, cwd=tmp_path)
    assert revoked.returncode == 0 and "chen is no longer an admin" in revoked.stdout
    assert staff_cli("list", "--db", database, cwd=tmp_path).stdout.splitlines() == ["asha  (admin)", "chen"]

    missing = staff_cli("admin", "ghost", "--db", database, cwd=tmp_path)
    assert missing.returncode == 2 and "no account named ghost" in missing.stderr
    both = staff_cli("add", "asha", "--reset", "--admin", "--db", database, password="long-enough-1", cwd=tmp_path)
    assert both.returncode == 2 and "use the admin command" in both.stderr


def test_there_is_no_way_to_become_an_admin_over_http(two_batches, db_path):
    bilal = sign_in(two_batches, "bilal")
    for path in ("/admin", "/staff/admin", "/staff/bilal/admin", "/users/bilal"):
        assert bilal.post(path, data={"is_admin": "1"}).status_code in (404, 405)
    bilal.post("/login", data={"username": "bilal", "password": "correct horse battery", "is_admin": "1"})
    assert query(db_path, "SELECT username FROM staff WHERE is_admin = 1") == []
