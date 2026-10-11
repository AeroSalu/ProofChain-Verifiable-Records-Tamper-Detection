"""Salted leaves, and the warning when content is registered twice.

Every record gets a random salt, and its leaf value is SHA-256(0x02 || salt ||
fingerprint). Two registrations of the same content are then different leaves
with different proofs, and a sibling hash in one holder's proof cannot be
matched against a guess at someone else's document.
"""

import copy
import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from proofchain.core import proof
from proofchain.core.canonical import RAW_BYTES_V1
from proofchain.core.merkle import leaf_hash, leaf_value, merkle_root
from proofchain.core.proof import ProofFormatError, create_bundle, leaf_values
from proofchain.registry import app as registry_app
from proofchain.registry import db, models
from proofchain.registry.audit import BATCH_ROOT_DIVERGED, OK, UNCHECKED, run_audit
from proofchain.verifier.verify import verify

from .helpers import confirm, confirm_all, execute, ledger_view, proof_of, query, seal, stored_root, upload


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


FPS = [sha(f"record {i}".encode()) for i in range(5)]
SALTS = [f"{i + 1:064x}" for i in range(5)]


# ---- the leaf value


def test_unsalted_leaf_value_is_the_fingerprint():
    fingerprint = bytes.fromhex(FPS[0])
    assert leaf_value(fingerprint) == fingerprint


def test_salted_leaf_value_is_a_prefixed_hash_of_salt_and_fingerprint():
    fingerprint, salt = bytes.fromhex(FPS[0]), bytes.fromhex(SALTS[0])
    assert leaf_value(fingerprint, salt) == hashlib.sha256(b"\x02" + salt + fingerprint).digest()
    # Its own prefix, so a salted value can never be read as a leaf (0x00) or a node (0x01).
    assert leaf_value(fingerprint, salt) != hashlib.sha256(b"\x00" + salt + fingerprint).digest()
    assert leaf_value(fingerprint, salt) != hashlib.sha256(b"\x01" + salt + fingerprint).digest()
    assert leaf_value(fingerprint, salt) != leaf_value(fingerprint, bytes.fromhex(SALTS[1]))


@pytest.mark.parametrize("salt", [b"", b"short", b"x" * 33, "ab" * 32])
def test_salt_must_be_32_bytes(salt):
    with pytest.raises(ValueError):
        leaf_value(bytes.fromhex(FPS[0]), salt)


def test_leaf_values_needs_one_salt_per_fingerprint():
    assert leaf_values(FPS) == [bytes.fromhex(fp) for fp in FPS]
    assert len(leaf_values(FPS, SALTS)) == 5
    with pytest.raises(ValueError):
        leaf_values(FPS, SALTS[:4])


# ---- version 2 bundles


def test_salted_bundle_is_version_2_and_carries_its_own_salt_only():
    bundle = create_bundle(RAW_BYTES_V1, "batch-0001", FPS, 2, SALTS)
    data = bundle.to_dict()
    assert data["version"] == 2 and data["salt"] == SALTS[2] and data["fingerprint"] == FPS[2]
    assert set(data) == {"version", "canon", "fingerprint", "salt", "batch_id", "leaf_index", "tree_size", "path", "root"}
    text = bundle.dumps()
    assert not any(other in text for other in SALTS[:2] + SALTS[3:] + FPS[:2] + FPS[3:])
    assert bundle.computed_root() == bundle.root == merkle_root(leaf_values(FPS, SALTS)).hex()
    assert proof.loads(text) == bundle


def test_unsalted_bundle_is_still_version_1():
    bundle = create_bundle(RAW_BYTES_V1, "batch-0001", FPS, 2)
    assert bundle.version == 1 and bundle.salt is None and "salt" not in bundle.to_dict()
    assert bundle.root != create_bundle(RAW_BYTES_V1, "batch-0001", FPS, 2, SALTS).root


@pytest.mark.parametrize("n", range(1, 10))
def test_every_record_of_a_salted_batch_folds_to_the_same_root(n):
    fps = [sha(f"r{i}".encode()) for i in range(n)]
    salts = [f"{i + 7:064x}" for i in range(n)]
    bundles = [create_bundle(RAW_BYTES_V1, "b", fps, i, salts) for i in range(n)]
    assert {b.root for b in bundles} == {merkle_root(leaf_values(fps, salts)).hex()}
    assert all(b.computed_root() == b.root for b in bundles)


def test_same_content_twice_is_two_different_leaves():
    twice, salts = [FPS[0], FPS[1], FPS[0]], SALTS[:3]
    first, second = (create_bundle(RAW_BYTES_V1, "b", twice, i, salts) for i in (0, 2))
    assert first.fingerprint == second.fingerprint and first.root == second.root
    assert first.leaf_value() != second.leaf_value()
    # Unsalted, the two would have been the same leaf value.
    assert leaf_values(twice)[0] == leaf_values(twice)[2]


def salted():
    return create_bundle(RAW_BYTES_V1, "batch-0001", FPS, 2, SALTS).to_dict()


@pytest.mark.parametrize("change, message", [
    (lambda d: d.pop("salt"), "bundle is missing: salt"),
    (lambda d: d.update(salt=d["salt"].upper().replace("0", "A")), "salt must be 64 lowercase hex"),
    (lambda d: d.update(salt="12"), "salt must be 64 lowercase hex"),
    (lambda d: d.update(salt=None), "salt must be 64 lowercase hex"),
    (lambda d: d.update(version=1), "bundle has unknown fields: salt"),
    (lambda d: d.update(version=3), "unsupported bundle version: 3"),
    (lambda d: d.update(version="2"), "version must be an integer"),
    (lambda d: d.update(version=True), "version must be an integer"),
    (lambda d: d.pop("version"), "bundle is missing: version"),
])
def test_malformed_salted_bundles_are_rejected(change, message):
    data = salted()
    change(data)
    with pytest.raises(ProofFormatError, match=message):
        proof.from_dict(data)


def test_a_version_1_bundle_may_not_carry_a_salt_and_a_version_2_bundle_must():
    unsalted = create_bundle(RAW_BYTES_V1, "b", FPS, 0).to_dict()
    with pytest.raises(ProofFormatError, match="unknown fields: salt"):
        proof.from_dict({**unsalted, "salt": SALTS[0]})
    with pytest.raises(ProofFormatError, match="missing: salt"):
        proof.from_dict({**unsalted, "version": 2})


# ---- the registry salts every record, and the verifier checks the salt


@pytest.fixture
def twice(registry, db_path):
    """The same content registered twice, with another document between, all sealed in one batch."""
    upload(registry, "certificate.txt", b"Same content")
    upload(registry, "other.txt", b"Other content")
    upload(registry, "certificate.txt", b"Same content")
    confirm_all(registry, db_path)
    assert seal(registry).status_code == 200
    return registry


def test_every_record_gets_its_own_random_salt(registry, db_path):
    for _ in range(3):
        upload(registry, "a.txt", b"Same content")
    salts = [row["salt"] for row in query(db_path, "SELECT salt FROM records")]
    assert len(set(salts)) == 3 and all(len(bytes.fromhex(s)) == 32 for s in salts)
    assert models.new_salt() != models.new_salt()


def test_two_registrations_of_the_same_content_get_distinct_leaves_and_proofs(twice, db_path, ledger):
    first, second = proof_of(twice, 1), proof_of(twice, 3)
    assert first["fingerprint"] == second["fingerprint"] == sha(b"Same content")
    assert first["salt"] != second["salt"] and first["leaf_index"] != second["leaf_index"]
    assert first["root"] == second["root"] == stored_root(db_path)

    entries, public_key, pin = ledger_view(ledger)
    # The content is what was registered, so it verifies with either registration's proof.
    assert verify(b"Same content", first, entries, public_key, pin).ok
    assert verify(b"Same content", second, entries, public_key, pin).ok
    assert verify(b"Other content", first, entries, public_key, pin).codes == ["DOCUMENT_MODIFIED"]

    conn = db.connect(db_path)
    try:
        assert run_audit(conn, ledger).ok
    finally:
        conn.close()


def test_a_proof_does_not_work_with_another_records_salt(twice, ledger):
    first, second = proof_of(twice, 1), proof_of(twice, 3)
    entries, public_key, pin = ledger_view(ledger)
    swapped = {**first, "salt": second["salt"]}
    assert verify(b"Same content", swapped, entries, public_key, pin).codes == ["PROOF_INVALID"]


def test_removing_the_salt_does_not_downgrade_a_proof(twice, ledger):
    entries, public_key, pin = ledger_view(ledger)
    downgraded = copy.deepcopy(proof_of(twice, 1))
    del downgraded["salt"]
    downgraded["version"] = 1
    # Well formed as a version 1 bundle, but its path no longer leads anywhere.
    result = verify(b"Same content", downgraded, entries, public_key, pin)
    assert result.codes == ["PROOF_INVALID"] and result.checks[0].status == "pass"


def test_a_sibling_hash_cannot_be_matched_against_a_guessed_document(twice):
    # The holder of record 1 sees record 2's leaf as a sibling. Knowing the exact content of
    # record 2 is not enough to recognise it there, because its salt is not in the proof.
    sibling = proof_of(twice, 1)["path"][0]["hash"]
    guess = bytes.fromhex(sha(b"Other content"))
    assert sibling != leaf_hash(guess).hex()


def test_a_changed_salt_is_batch_root_diverged(twice, db_path, ledger):
    execute(db_path, "UPDATE records SET salt = ? WHERE id = 2", ("cd" * 32,))
    conn = db.connect(db_path)
    try:
        report = run_audit(conn, ledger)
    finally:
        conn.close()
    assert report.codes == [BATCH_ROOT_DIVERGED]
    assert [f.state for f in report.records] == [UNCHECKED] * 3

    entries, public_key, pin = ledger_view(ledger)
    assert verify(b"Other content", proof_of(twice, 2), entries, public_key, pin).codes == ["ROOT_MISMATCH"]


@pytest.mark.parametrize("salt", ["zz", "", "ab" * 31])
def test_an_invalid_stored_salt_does_not_crash_anything(twice, db_path, ledger, salt):
    execute(db_path, "UPDATE records SET salt = ? WHERE id = 2", (salt,))
    assert "BATCH_ROOT_DIVERGED" in twice.get("/audit").text
    assert twice.get("/records").status_code == 200
    assert twice.get("/records/2/proof").status_code == 409
    execute(db_path, "UPDATE batches SET status = 'open'")
    assert seal(twice).status_code == 409


def test_a_database_from_before_salting_is_refused_with_a_clear_message(tmp_path, ledger):
    old = tmp_path / "old.db"
    conn = sqlite3.connect(old)
    conn.executescript(models.SCHEMA.replace("    salt               TEXT NOT NULL,\n", ""))
    conn.close()
    with pytest.raises(RuntimeError, match="created before records were salted"):
        db.init_db(old)
    with pytest.raises(RuntimeError, match="delete the registry database, the ledger file"):
        with TestClient(registry_app.create_app(old, ledger)):
            pass


# ---- the warning when content is registered a second time


def test_first_upload_of_some_content_gives_no_warning(registry):
    reply = upload(registry, "a.txt", b"Document A")
    assert reply.status_code == 200 and "already registered" not in reply.text
    assert "Same content as" not in registry.get("/register").text


def test_uploading_content_that_is_waiting_warns_and_still_stores_it(registry, db_path):
    upload(registry, "a.txt", b"Document A")
    reply = upload(registry, "copy of a.txt", b"Document A")
    assert reply.status_code == 200
    assert "This exact content is already registered as record 1 (waiting for confirmation)." in reply.text
    assert "Confirm it only if a second registration is intended." in reply.text
    assert 'class="banner warn"' in reply.text
    rows = query(db_path, "SELECT fingerprint, salt, metadata_confirmed FROM records ORDER BY id")
    assert len(rows) == 2 and rows[0]["fingerprint"] == rows[1]["fingerprint"] and rows[0]["salt"] != rows[1]["salt"]
    assert [row["metadata_confirmed"] for row in rows] == [0, 0]


def test_the_warning_names_the_batch_of_a_registered_copy(registry, db_path):
    upload(registry, "a.txt", b"Document A")
    confirm(registry, 1)
    seal(registry)
    upload(registry, "b.txt", b"Document A")
    reply = upload(registry, "c.txt", b"Document A", follow_redirects=False)
    assert reply.status_code == 303 and "warning=" in reply.headers["location"]
    page = registry.get(reply.headers["location"]).text
    assert "already registered as record 1 (batch-0001), record 2 (waiting for confirmation)." in page


def test_the_register_page_keeps_showing_which_records_share_the_content(registry, db_path):
    upload(registry, "a.txt", b"Document A")
    confirm(registry, 1)
    upload(registry, "b.txt", b"Document A")
    upload(registry, "unique.txt", b"Something else")
    page = registry.get("/register").text  # opened afresh: the one-off banner is gone
    assert "This exact content is already registered" not in page
    assert page.count("Same content as") == 1
    assert "Same content as record 1 (batch-0001)." in page
    assert "Confirming this registers it a second time" in page


def test_the_warning_does_not_block_a_second_registration(registry, db_path, ledger):
    upload(registry, "a.txt", b"Document A")
    upload(registry, "a.txt", b"Document A")
    confirm_all(registry, db_path)
    assert seal(registry).status_code == 200
    assert query(db_path, "SELECT tree_size FROM batches")[0]["tree_size"] == 2
    assert [f.state for f in audit_of(db_path, ledger).records] == [OK, OK]


def test_different_content_with_the_same_name_gives_no_warning(registry):
    upload(registry, "certificate.txt", b"Document A")
    reply = upload(registry, "certificate.txt", b"Document B")
    assert "already registered" not in reply.text
    assert "Same content as" not in registry.get("/register").text


def audit_of(db_path, ledger):
    conn = db.connect(db_path)
    try:
        return run_audit(conn, ledger)
    finally:
        conn.close()
