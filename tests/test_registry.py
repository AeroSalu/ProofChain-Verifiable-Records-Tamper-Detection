import hashlib
import json
import socket
import sqlite3
import threading

import pytest
import uvicorn
from fastapi.testclient import TestClient

from proofchain.ledger import app as ledger_app
from proofchain.registry import app as registry_app
from proofchain.registry import db
from proofchain.registry.ledger_client import LedgerClient, LedgerConflict, LedgerUnavailable
from proofchain.verifier.verify import verify

from .helpers import (
    STAFF,
    sign_in,
    BRIEF_ROOT,
    DOCS,
    confirm,
    confirm_all,
    execute,
    ledger_view,
    proof_of,
    query,
    register,
    seal,
    sealed_batch,
    stored_root,
    upload,
)

ALL_CODES = ["DOCUMENT_MODIFIED", "PROOF_INVALID", "BATCH_NOT_PUBLISHED", "ROOT_MISMATCH", "LEDGER_INVALID"]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def post_verify(client, document, proof, name="document-c.txt"):
    if not isinstance(proof, bytes):
        proof = json.dumps(proof).encode()
    return client.post("/verify", files={"document": (name, document), "proof": ("c.proof.json", proof)})


# ---- pages


@pytest.mark.parametrize("path", ["/", "/register", "/records", "/audit", "/verify"])
def test_pages_render_on_an_empty_database(path, registry):
    reply = registry.get(path)
    assert reply.status_code == 200
    assert "ProofChain" in reply.text
    assert "tamper-evident, not tamper-proof" in reply.text


def test_home_goes_to_the_register_page(registry):
    assert registry.get("/").url.path == "/register"


def test_static_files_are_served(registry):
    assert registry.get("/static/style.css").status_code == 200
    assert "crypto.subtle.digest" in registry.get("/static/app.js").text


# ---- uploading


def test_uploading_fingerprints_a_file_and_leaves_it_pending(registry, db_path):
    register(registry)
    rows = query(db_path, "SELECT * FROM records ORDER BY id")
    assert [row["filename"] for row in rows] == [name for name, _ in DOCS]
    assert [row["fingerprint"] for row in rows] == [sha(content) for _, content in DOCS]
    assert [bytes(row["content"]) for row in rows] == [content for _, content in DOCS]
    for row in rows:
        assert row["canon"] == "raw-bytes-v1"
        assert row["metadata_confirmed"] == 0 and row["metadata"] is None
        assert row["batch_id"] is None and row["leaf_index"] is None
    assert query(db_path, "SELECT * FROM batches") == []

    page = registry.get("/register").text
    for name, content in DOCS:
        assert name in page and sha(content) in page


def test_upload_redirects_to_the_register_page(registry):
    reply = upload(registry, "a.txt", b"Document A", follow_redirects=False)
    assert reply.status_code == 303
    assert reply.headers["location"].startswith("/register?notice=")


def test_upload_keeps_only_the_file_name(registry, db_path):
    upload(registry, "C:\\Users\\someone\\secret\\degree.pdf", b"x")
    upload(registry, "../../etc/passwd", b"y")
    assert [row["filename"] for row in query(db_path, "SELECT filename FROM records ORDER BY id")] == [
        "degree.pdf", "passwd"]


@pytest.mark.parametrize(
    "content, canon, status",
    [
        (b"", "raw-bytes-v1", 422),
        (b"Document A", "raw-bytes-v2", 422),
        (b"x" * (10 * 1024 * 1024 + 1), "raw-bytes-v1", 413),
        (b"{ not json", "json-sorted-v1", 422),
        (b'{"gpa": 3.5}', "json-sorted-v1", 422),
        (b'{"a": 1, "a": 2}', "json-sorted-v1", 422),
    ],
    ids=["empty", "unknown-canon", "over-10-mb", "invalid-json", "float", "duplicate-key"],
)
def test_upload_rejections_store_nothing(content, canon, status, registry, db_path):
    assert upload(registry, "file.bin", content, canon).status_code == status
    assert query(db_path, "SELECT id FROM records") == []


def test_structured_record_gets_the_canonical_fingerprint(registry, db_path, vectors):
    ex = vectors["canon"]
    assert upload(registry, "one.json", ex["raw1"].encode(), "json-sorted-v1").status_code == 200
    assert upload(registry, "two.json", ex["raw2"].encode(), "json-sorted-v1").status_code == 200
    assert upload(registry, "raw.json", ex["raw2"].encode(), "raw-bytes-v1").status_code == 200
    rows = query(db_path, "SELECT fingerprint, canon FROM records ORDER BY id")
    assert rows[0]["fingerprint"] == rows[1]["fingerprint"] == ex["canonical_hash"]
    assert rows[2]["fingerprint"] == ex["raw2_hash"]


# ---- confirming


@pytest.mark.parametrize(
    "fields",
    [{"issuer": ""}, {"issuer": "  "}, {"document_type": ""}],
    ids=["no-issuer", "blank-issuer", "no-document-type"],
)
def test_confirm_needs_the_required_details(fields, registry, db_path):
    upload(registry, "a.txt", b"Document A")
    assert confirm(registry, 1, **fields).status_code == 422
    row = query(db_path, "SELECT * FROM records")[0]
    assert row["metadata"] is None and row["metadata_confirmed"] == 0
    assert row["confirmed_by"] is None and row["batch_id"] is None
    assert query(db_path, "SELECT * FROM batches") == []


def test_confirm_unknown_record_and_confirming_twice(registry, db_path):
    assert confirm(registry, 99).status_code == 404
    upload(registry, "a.txt", b"Document A")
    assert confirm(registry, 1).status_code == 200
    assert confirm(registry, 1, issuer="Someone Else").status_code == 409
    row = query(db_path, "SELECT metadata, leaf_index FROM records")[0]
    assert json.loads(row["metadata"])["issuer"] == "Example University"
    assert row["leaf_index"] == 0


def test_confirmed_records_fill_the_open_batch_in_order(registry, db_path):
    register(registry)
    for record_id in (1, 2, 3, 4):
        reply = confirm(registry, record_id, issuer=f"Issuer {record_id}", follow_redirects=False)
        assert reply.status_code == 303 and reply.headers["location"].startswith("/records?notice=")

    rows = query(db_path, "SELECT * FROM records ORDER BY id")
    assert [row["batch_id"] for row in rows] == ["batch-0001"] * 4
    assert [row["leaf_index"] for row in rows] == [0, 1, 2, 3]
    assert [row["confirmed_by"] for row in rows] == [STAFF] * 4
    assert json.loads(rows[2]["metadata"]) == {
        "issuer": "Issuer 3", "date": "2026-10-11", "document_type": "Certificate", "category": "Education"}
    assert query(db_path, "SELECT id, status, root FROM batches") == [
        {"id": "batch-0001", "status": "open", "root": None}]

    assert "No records are waiting." in registry.get("/register").text
    page = registry.get("/records").text
    assert "batch-0001" in page and f"<td>{STAFF}</td>" in page and "Seal batch and publish root" in page


def test_metadata_has_no_effect_on_fingerprints_or_the_root(registry, db_path, ledger):
    register(registry)
    for record_id in (1, 2, 3, 4):
        confirm(registry, record_id, issuer="A completely different issuer", category="Other",
                document_type="Contract", date="")
    assert seal(registry).status_code == 200
    # The root is a function of fingerprints and salts alone; nothing confirmed above is in it.
    assert query(db_path, "SELECT root FROM batches")[0]["root"] == stored_root(db_path)
    assert [r["fingerprint"] for r in query(db_path, "SELECT fingerprint FROM records ORDER BY id")] == \
        [sha(content) for _, content in DOCS]


# ---- sealing and proofs


def test_no_proof_before_sealing_or_for_unknown_records(registry, db_path):
    register(registry)
    assert registry.get("/records/1/proof").status_code == 409  # not confirmed yet
    confirm_all(registry, db_path)
    assert registry.get("/records/1/proof").status_code == 409  # confirmed, batch still open
    assert registry.get("/records/99/proof").status_code == 404
    assert registry.get("/records/99/document").status_code == 404


def test_seal_with_the_ledger_down_changes_nothing(registry, db_path, ledger):
    register(registry)
    confirm_all(registry, db_path)
    ledger.down = True
    reply = seal(registry)
    assert reply.status_code == 502
    assert "still open" in reply.text
    assert query(db_path, "SELECT status, root, tree_size, ledger_seq, ledger_entry_hash, sealed_at FROM batches") == [
        {"status": "open", "root": None, "tree_size": None, "ledger_seq": None,
         "ledger_entry_hash": None, "sealed_at": None}]
    assert query(db_path, "SELECT * FROM meta") == []

    ledger.down = False
    assert ledger.entries() == []
    assert seal(registry).status_code == 200
    assert query(db_path, "SELECT status FROM batches")[0]["status"] == "sealed"


def test_sealing_publishes_the_root_of_the_salted_fingerprints(registry, db_path, ledger):
    register(registry)
    confirm_all(registry, db_path)
    root = stored_root(db_path)
    assert root != BRIEF_ROOT  # the same four documents, but salted
    reply = seal(registry, follow_redirects=False)
    assert reply.status_code == 303 and reply.headers["location"].startswith("/records?notice=")

    entries = ledger.entries()
    assert len(entries) == 1
    entry = entries[0]
    assert (entry["seq"], entry["batch_id"], entry["root"], entry["tree_size"]) == (0, "batch-0001", root, 4)

    assert query(db_path, "SELECT * FROM batches") == [{
        "id": "batch-0001", "status": "sealed", "root": root, "tree_size": 4, "ledger_seq": 0,
        "ledger_entry_hash": entry["entry_hash"], "sealed_at": entry["published_at"],
        "owner": STAFF, "sealed_by": STAFF}]
    assert query(db_path, "SELECT * FROM meta") == [{"key": "ledger_public_key", "value": ledger.public_key()}]

    page = registry.get("/records").text
    assert root in page and "/records/3/proof" in page and "Seal batch and publish root" not in page


def test_seal_again_unknown_batch_and_empty_batch(registry, db_path, ledger):
    sealed_batch(registry, db_path)
    assert seal(registry).status_code == 409
    assert seal(registry, "batch-9999").status_code == 404
    execute(db_path, "INSERT INTO batches (id, status, owner) VALUES ('batch-0002', 'open', ?)", (STAFF,))
    assert seal(registry, "batch-0002").status_code == 409
    assert len(ledger.entries()) == 1


def test_every_downloaded_proof_passes_the_independent_verifier(registry, db_path, ledger, vectors):
    sealed_batch(registry, db_path)
    entries, public_key, pin = ledger_view(ledger)
    for record_id, (name, content) in enumerate(DOCS, start=1):
        document = registry.get(f"/records/{record_id}/document")
        assert document.content == content
        assert document.headers["content-disposition"] == f'attachment; filename="{name}"'
        reply = registry.get(f"/records/{record_id}/proof")
        assert reply.headers["content-disposition"] == f'attachment; filename="{name}.proof.json"'

        result = verify(document.content, json.loads(reply.content), entries, public_key, pin)
        assert result.ok and result.batch_id == "batch-0001" and result.ledger_seq == 0

    proof = proof_of(registry, 3)
    # Same position as Document C in the brief's example, so the same path shape; salted, so other hashes.
    assert [step["side"] for step in proof["path"]] == [step["side"] for step in vectors["tree4"]["path"]]
    assert [step["hash"] for step in proof["path"]] != [step["hash"] for step in vectors["tree4"]["path"]]
    assert proof["version"] == 2 and proof["leaf_index"] == 2 and proof["tree_size"] == 4
    assert proof["root"] == stored_root(db_path) == entries[0]["root"]
    assert proof["fingerprint"] == sha(b"Document C")
    assert proof["salt"] == query(db_path, "SELECT salt FROM records WHERE id = 3")[0]["salt"]


def test_a_proof_holds_nothing_about_the_record_but_its_fingerprint_and_salt(registry, db_path):
    sealed_batch(registry, db_path)
    assert set(proof_of(registry, 1)) == {
        "version", "canon", "fingerprint", "salt", "batch_id", "leaf_index", "tree_size", "path", "root"}


def test_download_names_are_made_safe(registry, db_path):
    upload(registry, "my degree; (final) #2.pdf", b"Document A")
    confirm_all(registry, db_path)
    seal(registry)
    assert registry.get("/records/1/proof").headers["content-disposition"] == (
        'attachment; filename="my_degree___final___2.pdf.proof.json"')


def test_confirming_after_a_seal_starts_a_new_batch(registry, db_path, ledger):
    sealed_batch(registry, db_path)
    upload(registry, "e.txt", b"Document E")
    assert confirm(registry, 5).status_code == 200
    row = query(db_path, "SELECT batch_id, leaf_index FROM records WHERE id = 5")[0]
    assert row == {"batch_id": "batch-0002", "leaf_index": 0}
    assert query(db_path, "SELECT id, status FROM batches ORDER BY id") == [
        {"id": "batch-0001", "status": "sealed"}, {"id": "batch-0002", "status": "open"}]

    assert seal(registry, "batch-0002").status_code == 200
    entries, public_key, pin = ledger_view(ledger)
    assert [e["seq"] for e in entries] == [0, 1] and entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert verify(b"Document E", proof_of(registry, 5), entries, public_key, pin).ok
    assert verify(b"Document C", proof_of(registry, 3), entries, public_key, pin).ok


def test_seal_adopts_a_root_the_ledger_already_holds(registry, db_path, ledger):
    # The registry stopped after the ledger accepted the root but before marking the batch sealed.
    register(registry)
    confirm_all(registry, db_path)
    published = ledger.publish("batch-0001", stored_root(db_path), 4)

    assert seal(registry).status_code == 200
    assert ledger.entries() == [published]
    batch = query(db_path, "SELECT * FROM batches")[0]
    assert batch["status"] == "sealed" and batch["root"] == published["root"]
    assert batch["ledger_entry_hash"] == published["entry_hash"]


def test_a_published_root_cannot_be_replaced(registry, db_path, ledger):
    sealed_batch(registry, db_path)
    original = stored_root(db_path)
    execute(db_path, "UPDATE batches SET status = 'open' WHERE id = 'batch-0001'")
    execute(db_path, "UPDATE records SET fingerprint = ? WHERE id = 3", (sha(b"forged"),))

    reply = seal(registry)
    assert reply.status_code == 409
    assert "cannot be replaced" in reply.text
    assert len(ledger.entries()) == 1 and ledger.entries()[0]["root"] == original
    assert query(db_path, "SELECT status FROM batches")[0]["status"] == "open"


def test_seal_refuses_when_the_ledger_holds_another_tree_size(registry, db_path, ledger):
    register(registry)
    confirm_all(registry, db_path)
    ledger.publish("batch-0001", BRIEF_ROOT, 5)
    assert seal(registry).status_code == 409


# ---- the Verify page


def test_verify_page_accepts_an_untouched_document(registry, db_path):
    sealed_batch(registry, db_path)
    reply = post_verify(registry, b"Document C", proof_of(registry, 3))
    assert reply.status_code == 200
    assert "<strong>Verified.</strong>" in reply.text and "Not verified." not in reply.text
    assert reply.text.count(">passed<") == 5
    assert not any(code in reply.text for code in ALL_CODES)
    assert "document-c.txt matches the record registered in batch-0001 (ledger entry 0)" in reply.text
    assert stored_root(db_path) in reply.text and sha(b"Document C") in reply.text
    assert "does not prove who created the document" in reply.text
    assert "written by AI" not in reply.text


def test_verify_page_reports_an_edited_document(registry, db_path):
    sealed_batch(registry, db_path)
    reply = post_verify(registry, b"Document C!", proof_of(registry, 3))
    assert reply.status_code == 200
    assert "<strong>Not verified.</strong>" in reply.text and "<strong>Verified.</strong>" not in reply.text
    assert [code for code in ALL_CODES if code in reply.text] == ["DOCUMENT_MODIFIED"]
    assert reply.text.count(">passed<") == 4
    assert sha(b"Document C!") in reply.text and sha(b"Document C") in reply.text


@pytest.mark.parametrize("proof", [b"{ not json", b"\xff\xfe\x00", b"[]", b'{"version": 1}'],
                         ids=["not-json", "not-text", "list", "incomplete"])
def test_verify_page_reports_an_unreadable_proof(proof, registry, db_path):
    sealed_batch(registry, db_path)
    reply = post_verify(registry, b"Document C", proof)
    assert reply.status_code == 200
    assert [code for code in ALL_CODES if code in reply.text] == ["PROOF_INVALID"]
    assert reply.text.count(">not run<") == 3 and reply.text.count(">passed<") == 1


def test_verify_page_does_not_trust_the_registry_database(registry, db_path):
    # An insider rewrites record 3 and its fingerprint, then issues a fresh proof for the forgery.
    sealed_batch(registry, db_path)
    issued_before = proof_of(registry, 1)
    forged = b"Document C, with a better grade"
    execute(db_path, "UPDATE records SET content = ?, fingerprint = ? WHERE id = 3", (forged, sha(forged)))
    reply = post_verify(registry, forged, proof_of(registry, 3))
    assert [code for code in ALL_CODES if code in reply.text] == ["ROOT_MISMATCH"]
    # A holder's original, with the proof issued before the edit, is unaffected.
    assert "<strong>Verified.</strong>" in post_verify(registry, b"Document A", issued_before).text


def test_verify_page_gives_no_verdict_when_the_ledger_is_down(registry, db_path, ledger):
    sealed_batch(registry, db_path)
    proof = proof_of(registry, 3)
    ledger.down = True
    reply = post_verify(registry, b"Document C", proof)
    assert reply.status_code == 502
    assert "No verdict" in reply.text
    assert "<strong>" not in reply.text and not any(code in reply.text for code in ALL_CODES)


# ---- AI hooks


def suggestions(filename, content):
    return {"issuer": "Example University", "document_type": "Degree <certificate>", "category": "Education"}


def test_suggestions_are_shown_but_nothing_is_stored_until_a_person_confirms(db_path, ledger):
    with TestClient(registry_app.create_app(db_path, ledger, suggest=suggestions)) as client:
        sign_in(client)
        assert upload(client, "a.txt", b"Document A").status_code == 200
        page = client.get("/register").text
        assert "Suggested: Example University" in page
        assert "Degree &lt;certificate&gt;" in page and "<certificate>" not in page
        assert "produced automatically" in page

        row = query(db_path, "SELECT * FROM records")[0]
        assert json.loads(row["suggested_metadata"]) == suggestions("a.txt", b"")
        assert row["metadata"] is None and row["metadata_confirmed"] == 0 and row["batch_id"] is None
        assert row["fingerprint"] == sha(b"Document A")

        confirm(client, 1, issuer="Corrected University", document_type="Transcript", category="")
        row = query(db_path, "SELECT * FROM records")[0]
        assert json.loads(row["metadata"]) == {
            "issuer": "Corrected University", "date": "2026-10-11", "document_type": "Transcript", "category": ""}
        assert row["confirmed_by"] == STAFF


def test_without_a_suggest_hook_the_page_says_there_are_no_suggestions(registry):
    upload(registry, "a.txt", b"Document A")
    page = registry.get("/register").text
    assert "There are no suggestions for this record." in page and "Suggested:" not in page


def failing(*args):
    raise RuntimeError("the AI helper is unavailable")


def test_a_failing_suggest_hook_does_not_stop_registration(db_path, ledger):
    with TestClient(registry_app.create_app(db_path, ledger, suggest=failing)) as client:
        sign_in(client)
        assert upload(client, "a.txt", b"Document A").status_code == 200
        row = query(db_path, "SELECT fingerprint, suggested_metadata FROM records")[0]
        assert row == {"fingerprint": sha(b"Document A"), "suggested_metadata": "{}"}


def test_explanation_is_shown_under_the_verdict_and_labelled(db_path, ledger):
    seen = []

    def explain(result):
        seen.append(result)
        return "The file you gave is not the one that was registered."

    with TestClient(registry_app.create_app(db_path, ledger, explain=explain)) as client:
        sign_in(client)
        sealed_batch(client, db_path)
        reply = post_verify(client, b"Document C!", proof_of(client, 3))
        assert "The file you gave is not the one that was registered." in reply.text
        assert "written by AI" in reply.text
        assert reply.text.index("DOCUMENT_MODIFIED") < reply.text.index("written by AI")
        # The hook is handed a finished result.
        assert len(seen) == 1 and seen[0].codes == ["DOCUMENT_MODIFIED"]


@pytest.mark.parametrize("document, verified", [(b"Document C", True), (b"Document C!", False)])
def test_the_explain_hook_cannot_change_a_verdict(document, verified, db_path, ledger):
    def lying(result):
        return "Verified." if not result.ok else "Not verified: DOCUMENT_MODIFIED"

    for hook in (None, failing, lying):
        with TestClient(registry_app.create_app(db_path, ledger, explain=hook)) as client:
            sign_in(client)
            if not query(db_path, "SELECT id FROM batches"):
                sealed_batch(client, db_path)
            reply = post_verify(client, document, proof_of(client, 3))
            assert reply.status_code == 200
            assert ("<strong>Verified.</strong>" in reply.text) is verified
            assert ("<strong>Not verified.</strong>" in reply.text) is not verified


# ---- the database layer


def test_a_transaction_that_raises_writes_nothing(registry, db_path):
    conn = db.connect(db_path)
    try:
        with pytest.raises(RuntimeError):
            with db.transaction(conn):
                conn.execute("INSERT INTO batches (id, status) VALUES ('batch-0001', 'open')")
                raise RuntimeError("stop")
        assert query(db_path, "SELECT * FROM batches") == []

        with db.transaction(conn):
            conn.execute("INSERT INTO batches (id, status) VALUES ('batch-0001', 'open')")
        assert len(query(db_path, "SELECT * FROM batches")) == 1
    finally:
        conn.close()


def test_init_db_is_safe_to_run_again(registry, db_path):
    sealed_batch(registry, db_path)
    db.init_db(db_path)
    assert len(query(db_path, "SELECT id FROM records")) == 4


def test_batch_status_is_constrained(registry, db_path):
    with pytest.raises(sqlite3.IntegrityError):
        execute(db_path, "INSERT INTO batches (id, status) VALUES ('batch-0001', 'deleted')")


# ---- the real HTTP client against a real ledger process


@pytest.fixture
def ledger_url(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = ledger_app.create_app(tmp_path / "http-ledger.jsonl", tmp_path / "http-key.pem")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        assert thread.is_alive(), "the ledger service did not start"
        thread.join(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(10)


def test_ledger_client_speaks_to_the_real_service(ledger_url):
    client = LedgerClient(ledger_url + "/")
    assert client.entries() == []
    assert client.entry("batch-0001") is None
    assert len(bytes.fromhex(client.public_key())) == 32

    entry = client.publish("batch-0001", BRIEF_ROOT, 4)
    assert entry["seq"] == 0 and entry["root"] == BRIEF_ROOT
    assert client.entries() == [entry]
    assert client.entry("batch-0001") == entry
    with pytest.raises(LedgerConflict):
        client.publish("batch-0001", BRIEF_ROOT, 4)


def test_registry_seals_through_the_real_http_client(ledger_url, db_path):
    client = LedgerClient(ledger_url)
    with TestClient(registry_app.create_app(db_path, client)) as registry:
        sign_in(registry)
        sealed_batch(registry, db_path)
        entries, public_key, pin = ledger_view(client)
        assert entries[0]["root"] == stored_root(db_path)
        assert verify(b"Document C", proof_of(registry, 3), entries, public_key, pin).ok
        assert "Everything stored here matches its published reference." in registry.get("/audit").text


def test_ledger_client_reports_an_unreachable_ledger(db_path):
    client = LedgerClient("http://127.0.0.1:9", timeout=2)
    with pytest.raises(LedgerUnavailable):
        client.entries()
    with TestClient(registry_app.create_app(db_path, client)) as registry:
        sign_in(registry)
        register(registry)
        confirm_all(registry, db_path)
        assert seal(registry).status_code == 502
        assert query(db_path, "SELECT status FROM batches")[0]["status"] == "open"


def test_ledger_url_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("PROOFCHAIN_LEDGER_URL", "http://ledger.example:9001/")
    assert LedgerClient().base_url == "http://ledger.example:9001"
    monkeypatch.delenv("PROOFCHAIN_LEDGER_URL")
    assert LedgerClient().base_url == "http://localhost:8001"


# ---- discarding an upload that was never confirmed


def test_a_pending_upload_can_be_discarded(registry, db_path):
    upload(registry, "keep.txt", b"Document A")
    upload(registry, "mistake.txt", b"Document B")
    page = registry.get("/register").text
    assert "Waiting for confirmation (2)" in page
    assert 'formaction="/records/2/discard"' in page and "Discard this upload" in page

    reply = registry.post("/records/2/discard")
    assert reply.status_code == 200 and "Discarded mistake.txt. It was never registered." in reply.text
    assert [row["filename"] for row in query(db_path, "SELECT filename FROM records")] == ["keep.txt"]
    assert "Waiting for confirmation (1)" in reply.text and "mistake.txt</h3>" not in reply.text


def test_discard_does_not_need_the_confirmation_fields(registry, db_path):
    upload(registry, "mistake.txt", b"Document A")
    assert registry.post("/records/1/discard", data={"issuer": "", "confirmed_by": ""}).status_code == 200
    assert query(db_path, "SELECT id FROM records") == []
    assert "No records are waiting." in registry.get("/register").text


def test_a_confirmed_record_cannot_be_discarded(registry, db_path, ledger):
    upload(registry, "a.txt", b"Document A")
    confirm(registry, 1)
    reply = registry.post("/records/1/discard")
    assert reply.status_code == 409 and "A registered record cannot be removed." in reply.text
    seal(registry)
    assert registry.post("/records/1/discard").status_code == 409
    assert len(query(db_path, "SELECT id FROM records")) == 1
    assert "Everything stored here matches its published reference." in registry.get("/audit").text


def test_discarding_an_unknown_record_is_not_found(registry):
    assert registry.post("/records/99/discard").status_code == 404


def test_discarding_a_duplicate_clears_the_warning_on_the_other_record(registry, db_path):
    upload(registry, "a.txt", b"Document A")
    upload(registry, "a again.txt", b"Document A")
    assert registry.get("/register").text.count("Same content as") == 2
    registry.post("/records/2/discard")
    assert "Same content as" not in registry.get("/register").text
