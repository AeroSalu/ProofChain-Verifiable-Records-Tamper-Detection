"""The self-audit, tested by editing the database directly as an insider would."""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from proofchain.core.ledger_format import next_entry
from proofchain.ledger import app as ledger_app
from proofchain.ledger.keys import load_or_create_key, sign_entry_hash
from proofchain.registry import db
from proofchain.registry.audit import (
    BATCH_ROOT_DIVERGED,
    OK,
    PROBLEM,
    STORED_CONTENT_CHANGED,
    STORED_FINGERPRINT_CHANGED,
    UNCHECKED,
    run_audit,
)
from proofchain.verifier.verify import verify

from .helpers import (confirm, execute, ledger_view, proof_of, published_root, query, sealed_batch,
                      stored_root, upload)

FORGED = b"Document C, with a better grade"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit(db_path, ledger):
    conn = db.connect(db_path)
    try:
        return run_audit(conn, ledger)
    finally:
        conn.close()


def findings(report) -> dict:
    return {finding.subject: finding for finding in report.batches + report.records}


def states(report) -> dict:
    return {subject: finding.state for subject, finding in findings(report).items()}


@pytest.fixture
def populated(registry, db_path):
    """batch-0001 sealed with Documents A to D (records 1 to 4), record 5 in the
    open batch-0002, and record 6 uploaded but not confirmed."""
    sealed_batch(registry, db_path)
    upload(registry, "document-e.txt", b"Document E")
    confirm(registry, 5)
    upload(registry, "document-f.txt", b"Document F")
    return registry


# ---- nothing changed


def test_untouched_registry_is_clean(populated, db_path, ledger):
    report = audit(db_path, ledger)
    assert report.ok and report.codes == []
    assert report.ledger_state == OK and report.ledger_problems == []
    assert "1 entry." in report.ledger_detail
    assert states(report) == {
        "batch-0001": OK, "batch-0002": OK,
        "record 1": OK, "record 2": OK, "record 3": OK, "record 4": OK, "record 5": OK, "record 6": OK,
    }
    by_subject = findings(report)
    assert by_subject["batch-0001"].computed == by_subject["batch-0001"].expected == published_root(ledger)
    assert "nothing published yet" in by_subject["batch-0002"].detail
    assert "fits the published root" in by_subject["record 3"].detail
    assert "no published root to compare with yet" in by_subject["record 5"].detail
    assert "no published root to compare with yet" in by_subject["record 6"].detail

    page = populated.get("/audit")
    assert page.status_code == 200
    assert "Everything stored here matches its published reference." in page.text
    assert ">sound<" in page.text and "not published yet" in page.text


def test_empty_registry_is_clean(registry, db_path, ledger):
    report = audit(db_path, ledger)
    assert report.ok and report.records == [] and report.batches == []
    assert "0 entries." in report.ledger_detail


# ---- edits to the stored data


def test_changed_content_is_stored_content_changed(populated, db_path, ledger):
    issued_before = proof_of(populated, 3)
    execute(db_path, "UPDATE records SET content = ? WHERE id = 3", (FORGED,))

    report = audit(db_path, ledger)
    assert report.codes == [STORED_CONTENT_CHANGED] and not report.ok
    finding = findings(report)["record 3"]
    assert finding.state == PROBLEM and finding.code == STORED_CONTENT_CHANGED
    assert finding.computed == sha(FORGED) and finding.expected == sha(b"Document C")
    # The stored fingerprints still rebuild the published root, so the batch is fine.
    assert states(report)["batch-0001"] == OK
    assert all(states(report)[f"record {i}"] == OK for i in (1, 2, 4, 5, 6))

    # The holder's original still verifies; the registry's altered copy does not.
    entries, public_key, pin = ledger_view(ledger)
    assert verify(b"Document C", issued_before, entries, public_key, pin).ok
    assert verify(b"Document C", proof_of(populated, 3), entries, public_key, pin).ok
    assert verify(FORGED, proof_of(populated, 3), entries, public_key, pin).codes == ["DOCUMENT_MODIFIED"]

    page = populated.get("/audit").text
    assert "STORED_CONTENT_CHANGED" in page and sha(FORGED) in page
    assert "The stored data does not fully match the ledger." in page


def test_changed_fingerprint_is_stored_fingerprint_changed(populated, db_path, ledger):
    execute(db_path, "UPDATE records SET fingerprint = ? WHERE id = 3", (sha(FORGED),))

    report = audit(db_path, ledger)
    assert report.codes == [BATCH_ROOT_DIVERGED, STORED_FINGERPRINT_CHANGED]
    by_subject = findings(report)
    assert by_subject["record 3"].code == STORED_FINGERPRINT_CHANGED
    assert by_subject["record 3"].computed == sha(b"Document C")
    assert by_subject["record 3"].expected == sha(FORGED)
    assert by_subject["batch-0001"].code == BATCH_ROOT_DIVERGED
    assert by_subject["batch-0001"].expected == published_root(ledger)
    # The other records of the batch cannot be confirmed against a root that no longer rebuilds.
    assert [by_subject[f"record {i}"].state for i in (1, 2, 4)] == [UNCHECKED] * 3
    assert [by_subject[f"record {i}"].code for i in (1, 2, 4)] == [None] * 3
    assert [by_subject[f"record {i}"].state for i in (5, 6)] == [OK, OK]

    page = populated.get("/audit").text
    assert "STORED_FINGERPRINT_CHANGED" in page and "BATCH_ROOT_DIVERGED" in page and "not confirmed" in page


def test_consistent_rewrite_of_content_fingerprint_and_root_is_batch_root_diverged(populated, db_path, ledger):
    # The attack of requirement R8: the insider changes everything the database holds.
    execute(db_path, "UPDATE records SET content = ?, fingerprint = ? WHERE id = 3", (FORGED, sha(FORGED)))
    forged_root = stored_root(db_path)
    execute(db_path, "UPDATE batches SET root = ? WHERE id = 'batch-0001'", (forged_root,))

    report = audit(db_path, ledger)
    assert report.codes == [BATCH_ROOT_DIVERGED]
    by_subject = findings(report)
    assert by_subject["batch-0001"].computed == forged_root and by_subject["batch-0001"].expected == published_root(ledger)
    # The audit cannot say which record changed: the ledger holds only the root.
    assert [by_subject[f"record {i}"].state for i in (1, 2, 3, 4)] == [UNCHECKED] * 4

    # The fresh, internally consistent proof still fails outside the registry.
    fresh = proof_of(populated, 3)
    assert fresh["root"] == forged_root and fresh["fingerprint"] == sha(FORGED)
    entries, public_key, pin = ledger_view(ledger)
    assert verify(FORGED, fresh, entries, public_key, pin).codes == ["ROOT_MISMATCH"]
    assert populated.get("/records").status_code == 200


def test_changed_root_column_alone_is_batch_root_diverged(populated, db_path, ledger):
    execute(db_path, "UPDATE batches SET root = ? WHERE id = 'batch-0001'", ("ab" * 32,))
    report = audit(db_path, ledger)
    assert report.codes == [BATCH_ROOT_DIVERGED]
    finding = findings(report)["batch-0001"]
    assert "batches table" in finding.detail
    assert finding.computed == "ab" * 32 and finding.expected == published_root(ledger)
    # The fingerprints themselves still rebuild the published root, so the records are fine.
    assert all(states(report)[f"record {i}"] == OK for i in (1, 2, 3, 4))


def test_swapped_leaf_indexes_are_batch_root_diverged(populated, db_path, ledger):
    execute(db_path, "UPDATE records SET leaf_index = 1 WHERE id = 1")
    execute(db_path, "UPDATE records SET leaf_index = 0 WHERE id = 2")
    report = audit(db_path, ledger)
    assert report.codes == [BATCH_ROOT_DIVERGED]
    assert "stored fingerprints" in findings(report)["batch-0001"].detail


def test_record_removed_from_its_sealed_batch_is_batch_root_diverged(populated, db_path, ledger):
    execute(db_path, "UPDATE records SET batch_id = NULL, leaf_index = NULL WHERE id = 2")
    assert audit(db_path, ledger).codes == [BATCH_ROOT_DIVERGED]
    assert populated.get("/records/2/proof").status_code == 409


def test_deleted_record_is_batch_root_diverged(populated, db_path, ledger):
    execute(db_path, "DELETE FROM records WHERE id = 4")
    report = audit(db_path, ledger)
    assert report.codes == [BATCH_ROOT_DIVERGED]
    assert "record 4" not in findings(report)
    assert populated.get("/records/4/proof").status_code == 404


def test_sealed_batch_marked_open_again_is_batch_root_diverged(populated, db_path, ledger):
    execute(db_path, "UPDATE batches SET status = 'sealed' WHERE id = 'batch-0002'")  # keep one open batch only
    execute(db_path, "UPDATE batches SET status = 'open' WHERE id = 'batch-0001'")
    by_subject = findings(audit(db_path, ledger))
    assert by_subject["batch-0001"].code == BATCH_ROOT_DIVERGED
    assert "marked open here" in by_subject["batch-0001"].detail
    assert by_subject["batch-0001"].expected == published_root(ledger)


def test_sealed_batch_the_ledger_never_saw_is_batch_root_diverged(populated, db_path, ledger):
    execute(db_path,
            "INSERT INTO batches (id, status, root, tree_size, ledger_seq, ledger_entry_hash, sealed_at) "
            "VALUES ('batch-0009', 'sealed', ?, 1, 5, ?, '2026-10-11T09:00:00Z')", ("cd" * 32, "ef" * 32))
    execute(db_path, "UPDATE records SET batch_id = 'batch-0009', leaf_index = 0 WHERE id = 6")

    report = audit(db_path, ledger)
    assert report.codes == [BATCH_ROOT_DIVERGED]
    assert "the ledger has no entry for it" in findings(report)["batch-0009"].detail
    # The invented batch also claims a checkpoint the ledger does not contain.
    assert report.ledger_state == PROBLEM
    assert any("pinned entry 5 is missing" in problem for problem in report.ledger_problems)
    assert states(report)["batch-0001"] == OK


@pytest.mark.parametrize(
    "sql, args, expected",
    [
        ("UPDATE records SET fingerprint = 'not hex at all' WHERE id = 3", (),
         [BATCH_ROOT_DIVERGED, STORED_FINGERPRINT_CHANGED]),
        ("UPDATE records SET fingerprint = '' WHERE id = 3", (),
         [BATCH_ROOT_DIVERGED, STORED_FINGERPRINT_CHANGED]),
        ("UPDATE records SET content = 'plain text, not a blob' WHERE id = 3", (), [STORED_CONTENT_CHANGED]),
        ("UPDATE records SET canon = 'no-such-form' WHERE id = 3", (), [STORED_CONTENT_CHANGED]),
        ("UPDATE records SET metadata = '{ broken', suggested_metadata = '[1, 2]' WHERE id = 3", (), []),
        ("UPDATE records SET metadata = NULL, confirmed_by = NULL WHERE id = 3", (), []),
        ("UPDATE batches SET root = NULL, tree_size = NULL WHERE id = 'batch-0001'", (), [BATCH_ROOT_DIVERGED]),
    ],
    ids=["non-hex-fingerprint", "empty-fingerprint", "text-content", "unknown-canon", "broken-metadata-json",
         "null-metadata", "null-root"],
)
def test_malformed_stored_values_are_reported_and_pages_still_render(sql, args, expected, populated, db_path, ledger):
    execute(db_path, sql, args)
    assert audit(db_path, ledger).codes == expected
    for path in ("/audit", "/records", "/register"):
        assert populated.get(path).status_code == 200
    assert populated.get("/records/3/document").status_code == 200
    assert populated.get("/records/3/proof").status_code in (200, 409)


def test_metadata_edits_are_outside_what_the_ledger_commits_to(populated, db_path, ledger):
    # Metadata is not hashed into the leaf, so the audit has no reference to check it against.
    execute(db_path, "UPDATE records SET metadata = ? WHERE id = 3", (json.dumps({"issuer": "Someone Else"}),))
    assert audit(db_path, ledger).ok


# ---- the ledger side


def test_ledger_down_leaves_sealed_batches_unchecked(populated, db_path, ledger):
    ledger.down = True
    report = audit(db_path, ledger)
    assert not report.ok and report.codes == []
    assert report.ledger_state == UNCHECKED and "the ledger is down" in report.ledger_detail
    by_subject = findings(report)
    assert by_subject["batch-0001"].state == UNCHECKED
    assert "could not be read" in by_subject["batch-0001"].detail
    assert by_subject["batch-0002"].state == OK

    page = populated.get("/audit")
    assert page.status_code == 200
    assert ">not read<" in page.text and "does not fully match" in page.text


def test_ledger_down_still_reports_changed_content(populated, db_path, ledger):
    execute(db_path, "UPDATE records SET content = ? WHERE id = 3", (FORGED,))
    ledger.down = True
    assert audit(db_path, ledger).codes == [STORED_CONTENT_CHANGED]


def rebuild_ledger(ledger_paths, entries, root_for):
    """Rewrite the ledger file from the start, signed with the real ledger key."""
    key = load_or_create_key(ledger_paths[1])
    rebuilt, previous = [], None
    for e in entries:
        previous = next_entry(previous, e["batch_id"], root_for(e), e["tree_size"], e["published_at"])
        previous["signature"] = sign_entry_hash(key, previous["entry_hash"])
        rebuilt.append(previous)
    with open(ledger_paths[0], "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(json.dumps(e) + "\n" for e in rebuilt)
    return rebuilt


def test_ledger_rebuilt_and_resigned_with_the_real_key_is_caught_by_the_registry_pin(
    populated, db_path, ledger, ledger_paths
):
    # The insider holds the ledger key too: they rewrite record 3, its fingerprint, the batch
    # root, and republish that root in a ledger rebuilt from the first entry.
    execute(db_path, "UPDATE records SET content = ?, fingerprint = ? WHERE id = 3", (FORGED, sha(FORGED)))
    forged_root = stored_root(db_path)
    execute(db_path, "UPDATE batches SET root = ? WHERE id = 'batch-0001'", (forged_root,))
    rebuild_ledger(ledger_paths, ledger.entries(), lambda e: forged_root)

    with TestClient(ledger_app.create_app(*ledger_paths)) as restarted:
        ledger.client = restarted  # the ledger service comes back up on the rewritten file
        assert ledger.entries()[0]["root"] == forged_root

        report = audit(db_path, ledger)
        # Storage and ledger now agree with each other, so no storage code fires...
        assert report.codes == []
        # ...but the entry this registry recorded when it sealed is no longer there.
        assert report.ledger_state == PROBLEM and not report.ok
        assert any("pinned entry 0 has changed" in problem for problem in report.ledger_problems)

        page = populated.get("/audit").text
        assert "LEDGER_INVALID" in page and "has changed" in page

        proof = proof_of(populated, 3)
        reply = populated.post("/verify", files={"document": ("c.txt", FORGED),
                                                 "proof": ("c.proof.json", json.dumps(proof).encode())})
        assert "<strong>Not verified.</strong>" in reply.text and "LEDGER_INVALID" in reply.text

        # A verifier with no checkpoint cannot tell: the honest limit.
        entries, public_key, _ = ledger_view(ledger)
        assert verify(FORGED, proof, entries, public_key).ok


@pytest.mark.parametrize("value", ["ab" * 32, "this is not hex", ""], ids=["another-key", "not-hex", "empty"])
def test_replaced_ledger_key_is_a_ledger_problem(value, populated, db_path, ledger):
    execute(db_path, "UPDATE meta SET value = ? WHERE key = 'ledger_public_key'", (value,))
    report = audit(db_path, ledger)
    if value == "":
        # An empty value is treated as "no key recorded", and the ledger's current key is used.
        assert report.ledger_state == OK
        return
    assert report.ledger_state == PROBLEM and not report.ok
    assert report.codes == []
    assert populated.get("/audit").status_code == 200
    assert "LEDGER_INVALID" in populated.get("/audit").text


def test_registry_keeps_the_key_it_saw_at_the_first_seal(populated, db_path, ledger, ledger_paths, tmp_path):
    # A ledger that comes back with a different key is not the ledger this registry published to.
    other_key = tmp_path / "other_key.pem"
    key = load_or_create_key(other_key)
    entries = ledger.entries()
    rebuilt, previous = [], None
    for e in entries:
        previous = next_entry(previous, e["batch_id"], e["root"], e["tree_size"], e["published_at"])
        previous["signature"] = sign_entry_hash(key, previous["entry_hash"])
        rebuilt.append(previous)
    other_file = tmp_path / "other_ledger.jsonl"
    other_file.write_text("".join(json.dumps(e) + "\n" for e in rebuilt), encoding="utf-8", newline="\n")

    with TestClient(ledger_app.create_app(other_file, other_key)) as impostor:
        ledger.client = impostor
        assert ledger.entries() == rebuilt  # same roots, same hashes, different signatures
        report = audit(db_path, ledger)
        assert report.ledger_state == PROBLEM
        assert any("signature" in problem for problem in report.ledger_problems)
