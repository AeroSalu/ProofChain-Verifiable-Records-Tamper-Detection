import copy
import json
import re
import subprocess
import sys
import threading

import pytest
from fastapi.testclient import TestClient

from proofchain.core.canonical import RAW_BYTES_V1
from proofchain.core.ledger_format import (
    GENESIS_PREV_HASH,
    LedgerFormatError,
    chain_problems,
    check_entry,
    entry_hash,
    next_entry,
)
from proofchain.core.proof import create_bundle
from proofchain.ledger.app import create_app
from proofchain.ledger.keys import load_or_create_key, public_key_bytes, public_key_hex, sign_entry_hash
from proofchain.ledger.store import DuplicateBatch, LedgerCorrupt, LedgerStore
from proofchain.verifier.verify import LEDGER_INVALID, Pin, ledger_problems, verify

# ---- entry format and hash chain (core/ledger_format.py) ----


@pytest.fixture
def chain(vectors):
    return copy.deepcopy(vectors["chain"])


def rehash(entry):
    entry["entry_hash"] = entry_hash(entry)
    return entry


def test_entry_hashes_match_the_brief(chain):
    assert [entry_hash(e) for e in chain] == [e["entry_hash"] for e in chain]
    assert chain[1]["entry_hash"].startswith("075867b2")
    assert chain[1]["prev_hash"].startswith("739e5bed")


def test_entry_hash_ignores_the_stored_hash_and_signature(chain):
    entry = chain[1]
    expected = entry["entry_hash"]
    entry["entry_hash"] = "00" * 32
    entry["signature"] = "c2lnbmF0dXJl"
    assert entry_hash(entry) == expected


def test_entry_hash_covers_each_of_the_six_fields(chain):
    original = chain[1]
    changes = {
        "seq": 7,
        "batch_id": "batch-9999",
        "root": "11" * 32,
        "tree_size": 6,
        "published_at": "2026-10-12T09:00:01Z",
        "prev_hash": "22" * 32,
    }
    for field, value in changes.items():
        assert entry_hash(dict(original, **{field: value})) != original["entry_hash"]


def test_brief_chain_is_sound(chain):
    assert chain_problems(chain) == []
    assert chain_problems([]) == []
    assert chain_problems(chain[:1]) == []


def test_next_entry_rebuilds_the_brief_chain(chain):
    built, previous = [], None
    for e in chain:
        previous = next_entry(previous, e["batch_id"], e["root"], e["tree_size"], e["published_at"])
        built.append(previous)
    assert built == chain
    assert built[0]["prev_hash"] == GENESIS_PREV_HASH


def test_edited_entry_is_detected(chain):
    chain[1]["root"] = "ab" * 32
    problems = chain_problems(chain)
    assert len(problems) == 1
    assert "entry 1" in problems[0] and "entry_hash" in problems[0]


def test_edited_entry_with_a_recomputed_hash_breaks_the_next_link(chain):
    chain[1]["root"] = "ab" * 32
    rehash(chain[1])
    problems = chain_problems(chain)
    assert len(problems) == 1
    assert "entry 2" in problems[0] and "prev_hash" in problems[0]


def test_deleted_entry_is_detected(chain):
    del chain[1]
    assert chain_problems(chain)


def test_deleted_first_entry_is_detected(chain):
    assert chain_problems(chain[1:])


def test_swapped_entries_are_detected(chain):
    chain[1], chain[2] = chain[2], chain[1]
    assert chain_problems(chain)


def test_inserted_entry_is_detected(chain):
    forged = next_entry(chain[0], "batch-forged", "cd" * 32, 3, "2026-10-11T12:00:00Z")
    chain.insert(1, forged)
    assert chain_problems(chain)


def test_first_entry_must_link_to_the_genesis_value(chain):
    chain[0]["prev_hash"] = "ff" * 32
    rehash(chain[0])
    problems = chain_problems(chain[:1])
    assert len(problems) == 1 and "prev_hash" in problems[0]


def test_a_batch_published_twice_is_detected(chain):
    again = next_entry(chain[2], chain[0]["batch_id"], "ee" * 32, 4, "2026-10-14T09:00:00Z")
    problems = chain_problems(chain + [again])
    assert len(problems) == 1 and "already published" in problems[0]


def test_all_problems_are_reported_not_just_the_first(chain):
    chain[0]["tree_size"] = 40
    chain[2]["batch_id"] = "batch-other"
    assert len(chain_problems(chain)) == 2


def test_malformed_entry_is_reported_and_the_walk_continues(chain):
    del chain[1]["root"]
    problems = chain_problems(chain)
    assert len(problems) == 1 and "position 1" in problems[0] and "root" in problems[0]


@pytest.mark.parametrize(
    "field, value",
    [
        ("seq", -1),
        ("seq", "1"),
        ("seq", True),
        ("batch_id", ""),
        ("batch_id", 2),
        ("root", "3de1575b"),
        ("root", "3DE1575B7131B491D8E4FA6A9BC83AA648776F8BE745E1EF1EAAE8EC8443316E"),
        ("tree_size", 0),
        ("tree_size", 5.0),
        ("published_at", "12 October 2026"),
        ("published_at", "2026-10-12T09:00:00+05:30"),
        ("prev_hash", None),
        ("entry_hash", "xyz"),
        ("signature", 123),
    ],
)
def test_malformed_fields_are_rejected(chain, field, value):
    chain[1][field] = value
    with pytest.raises(LedgerFormatError):
        check_entry(chain[1])


def test_entry_must_be_an_object_with_every_field(chain):
    with pytest.raises(LedgerFormatError):
        check_entry(["seq", 1])
    del chain[1]["entry_hash"]
    with pytest.raises(LedgerFormatError):
        check_entry(chain[1])
    with pytest.raises(LedgerFormatError):
        entry_hash({"seq": 0})


# ---- the ledger service (ledger/app.py) ----

ROOT_A = "3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8effeda95e98c40"
ROOT_B = "3de1575b7131b491d8e4fa6a9bc83aa648776f8be745e1ef1eaae8ec8443316e"
ROOT_C = "b562b8da4b3bf0bca0dc09c749ec16ef6abf9e3562cfd8fcb30a4fcbac1434a7"

BRIEF_BATCHES = [("batch-0001", ROOT_A, 4), ("batch-0002", ROOT_B, 5), ("batch-0003", ROOT_C, 7)]


@pytest.fixture
def paths(tmp_path):
    return tmp_path / "ledger.jsonl", tmp_path / "key.pem"


@pytest.fixture
def client(paths):
    with TestClient(create_app(*paths), headers=LEDGER_AUTH) as running:
        yield running


from .helpers import LEDGER_AUTH  # noqa: E402  (every client below presents the append token)


def post(client, batch_id, root, tree_size):
    return client.post("/entries", json={"batch_id": batch_id, "root": root, "tree_size": tree_size})


def publish_brief_batches(client):
    return [post(client, *batch).json() for batch in BRIEF_BATCHES]


def test_new_ledger_is_empty_and_publishes_its_key(client):
    assert client.get("/entries").json() == []
    assert client.get("/head").status_code == 404
    reply = client.get("/pubkey")
    assert reply.status_code == 200
    assert list(reply.json()) == ["public_key"]
    assert re.fullmatch(r"[0-9a-f]{64}", reply.json()["public_key"])


def test_first_append(client):
    reply = post(client, "batch-0001", ROOT_A, 4)
    assert reply.status_code == 201
    entry = reply.json()
    assert entry["seq"] == 0
    assert entry["prev_hash"] == "0" * 64 == GENESIS_PREV_HASH
    assert entry["entry_hash"] == entry_hash(entry)
    assert (entry["batch_id"], entry["root"], entry["tree_size"]) == ("batch-0001", ROOT_A, 4)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", entry["published_at"])
    assert set(entry) == {"seq", "batch_id", "root", "tree_size", "published_at",
                          "prev_hash", "entry_hash", "signature"}
    assert client.get("/entries").json() == [entry]
    assert client.get("/head").json() == {"seq": 0, "entry_hash": entry["entry_hash"]}


def test_second_append_links_to_the_first(client):
    first = post(client, "batch-0001", ROOT_A, 4).json()
    second = post(client, "batch-0002", ROOT_B, 5).json()
    assert second["seq"] == 1
    assert second["prev_hash"] == first["entry_hash"]
    assert client.get("/entries").json() == [first, second]
    assert client.get("/head").json() == {"seq": 1, "entry_hash": second["entry_hash"]}


def test_a_batch_can_be_published_only_once(client):
    first = post(client, "batch-0001", ROOT_A, 4).json()
    again = post(client, "batch-0001", ROOT_B, 5)
    assert again.status_code == 409
    assert post(client, "batch-0001", ROOT_A, 4).status_code == 409
    assert client.get("/entries").json() == [first]


@pytest.mark.parametrize(
    "body",
    [
        {"batch_id": "", "root": ROOT_A, "tree_size": 4},
        {"batch_id": "b", "root": ROOT_A.upper(), "tree_size": 4},
        {"batch_id": "b", "root": "3a41957e", "tree_size": 4},
        {"batch_id": "b", "root": ROOT_A + "00", "tree_size": 4},
        {"batch_id": "b", "root": "z" * 64, "tree_size": 4},
        {"batch_id": "b", "root": ROOT_A, "tree_size": 0},
        {"batch_id": "b", "root": ROOT_A, "tree_size": -3},
        {"batch_id": "b", "root": ROOT_A, "tree_size": "4"},
        {"batch_id": "b", "root": ROOT_A, "tree_size": 4.5},
        {"batch_id": "b", "root": ROOT_A, "tree_size": True},
        {"batch_id": 7, "root": ROOT_A, "tree_size": 4},
        {"root": ROOT_A, "tree_size": 4},
        {"batch_id": "b", "tree_size": 4},
        {"batch_id": "b", "root": ROOT_A},
        {},
    ],
    ids=["empty-batch-id", "uppercase-root", "short-root", "long-root", "non-hex-root", "tree-size-zero",
         "tree-size-negative", "tree-size-text", "tree-size-fraction", "tree-size-bool", "batch-id-number",
         "no-batch-id", "no-root", "no-tree-size", "empty-body"],
)
def test_malformed_requests_are_refused_and_nothing_is_written(body, client, paths):
    assert client.post("/entries", json=body).status_code == 422
    assert client.get("/entries").json() == []
    assert not paths[0].exists()


def test_client_cannot_choose_seq_time_or_links(client):
    reply = client.post("/entries", json={
        "batch_id": "batch-0001", "root": ROOT_A, "tree_size": 4,
        "seq": 99, "prev_hash": "ab" * 32, "published_at": "2001-01-01T00:00:00Z",
        "entry_hash": "cd" * 32, "signature": "forged",
    })
    assert reply.status_code == 201
    entry = reply.json()
    assert entry["seq"] == 0 and entry["prev_hash"] == GENESIS_PREV_HASH
    assert entry["published_at"] != "2001-01-01T00:00:00Z"
    assert entry["entry_hash"] == entry_hash(entry)
    assert entry["signature"] != "forged"


def test_get_entry_by_batch_id(client):
    entries = publish_brief_batches(client)
    assert client.get("/entries/batch-0002").json() == entries[1]
    missing = client.get("/entries/batch-9999")
    assert missing.status_code == 404


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
@pytest.mark.parametrize("url", ["/entries", "/entries/batch-0001"])
def test_there_is_no_way_to_change_or_remove_an_entry(method, url, client, paths):
    entries = publish_brief_batches(client)
    before = paths[0].read_bytes()
    reply = client.request(method, url, json={"batch_id": "batch-0001", "root": ROOT_B, "tree_size": 4})
    assert reply.status_code == 405
    assert client.get("/entries").json() == entries
    assert paths[0].read_bytes() == before


def test_post_to_a_single_entry_is_not_allowed(client):
    publish_brief_batches(client)
    assert client.post("/entries/batch-0001", json={"root": ROOT_B}).status_code == 405


def test_only_the_five_documented_routes_exist(client):
    routes = {(method, route.path) for route in client.app.routes if hasattr(route, "methods")
              for method in route.methods if not route.path.startswith(("/docs", "/redoc", "/openapi"))}
    routes = {(method, path) for method, path in routes if method != "HEAD"}
    assert routes == {
        ("POST", "/entries"), ("GET", "/entries"), ("GET", "/entries/{batch_id}"),
        ("GET", "/head"), ("GET", "/pubkey"),
    }


def test_served_ledger_satisfies_the_verifier(client):
    publish_brief_batches(client)
    entries = client.get("/entries").json()
    public_key = bytes.fromhex(client.get("/pubkey").json()["public_key"])
    assert ledger_problems(entries, public_key) == []
    head = client.get("/head").json()
    assert ledger_problems(entries, public_key, Pin(head["seq"], head["entry_hash"])) == []


def test_document_c_verifies_against_the_served_ledger(client, vectors):
    publish_brief_batches(client)
    entries = client.get("/entries").json()
    public_key = bytes.fromhex(client.get("/pubkey").json()["public_key"])
    head = client.get("/head").json()
    pin = Pin(head["seq"], head["entry_hash"])
    bundle = create_bundle(RAW_BYTES_V1, "batch-0001", vectors["tree4"]["fingerprints"], 2)

    result = verify(b"Document C", bundle, entries, public_key, pin)
    assert result.ok and result.pinned and result.ledger_seq == 0
    assert verify(b"Document C (edited)", bundle, entries, public_key, pin).codes == ["DOCUMENT_MODIFIED"]


def test_file_on_disk_is_one_json_entry_per_line(client, paths):
    entries = publish_brief_batches(client)
    lines = paths[0].read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == 4
    assert b"\r" not in paths[0].read_bytes()
    assert [json.loads(line) for line in lines[:-1]] == entries


def test_restart_keeps_the_key_and_extends_the_same_chain(paths):
    with TestClient(create_app(*paths), headers=LEDGER_AUTH) as first_run:
        key_before = first_run.get("/pubkey").json()
        old = publish_brief_batches(first_run)

    with TestClient(create_app(*paths), headers=LEDGER_AUTH) as second_run:
        assert second_run.get("/pubkey").json() == key_before
        assert second_run.get("/entries").json() == old
        added = post(second_run, "batch-0004", "cd" * 32, 2).json()
        assert added["seq"] == 3
        assert added["prev_hash"] == old[-1]["entry_hash"]
        assert post(second_run, "batch-0002", ROOT_B, 5).status_code == 409
        entries = second_run.get("/entries").json()

    assert ledger_problems(entries, bytes.fromhex(key_before["public_key"])) == []


def test_paths_come_from_the_environment_when_not_given(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFCHAIN_LEDGER_PATH", str(tmp_path / "env" / "ledger.jsonl"))
    monkeypatch.setenv("PROOFCHAIN_LEDGER_KEY_PATH", str(tmp_path / "env" / "key.pem"))
    with TestClient(create_app(), headers=LEDGER_AUTH) as running:
        assert post(running, "batch-0001", ROOT_A, 4).status_code == 201
    assert (tmp_path / "env" / "ledger.jsonl").exists()
    assert (tmp_path / "env" / "key.pem").exists()


def test_importing_the_service_touches_no_files(tmp_path):
    done = subprocess.run([sys.executable, "-c", "import proofchain.ledger.app"],
                          cwd=tmp_path, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert list(tmp_path.iterdir()) == []


# ---- a damaged ledger file stops the service from starting ----


def write_lines(path, entries):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines((e if isinstance(e, str) else json.dumps(e)) + "\n" for e in entries)


def edit_root(entries):
    entries[1]["root"] = "ab" * 32


def edit_root_and_rehash(entries):
    entries[1]["root"] = "ab" * 32
    entries[1]["entry_hash"] = entry_hash(entries[1])


def delete_first(entries):
    del entries[0]


def delete_middle(entries):
    del entries[1]


def swap(entries):
    entries[1], entries[2] = entries[2], entries[1]


def junk_line(entries):
    entries.insert(2, "{ this line is not JSON")


def not_an_object(entries):
    entries.append("[1, 2, 3]")


def wrong_signature(entries):
    entries[2]["signature"] = entries[0]["signature"]


def garbage_signature(entries):
    entries[0]["signature"] = "not base64!"


def missing_signature(entries):
    del entries[1]["signature"]


def numeric_signature(entries):
    entries[1]["signature"] = 12345


DAMAGE = [edit_root, edit_root_and_rehash, delete_first, delete_middle, swap, junk_line, not_an_object,
          wrong_signature, garbage_signature, missing_signature, numeric_signature]


@pytest.fixture
def written(paths):
    """A three-entry ledger written by a service that has since stopped."""
    with TestClient(create_app(*paths), headers=LEDGER_AUTH) as running:
        entries = publish_brief_batches(running)
    return entries


@pytest.mark.parametrize("damage", DAMAGE, ids=lambda f: f.__name__)
def test_damaged_file_is_refused_by_the_store_and_the_service(damage, written, paths):
    damage(written)
    write_lines(paths[0], written)
    before = paths[0].read_bytes()

    with pytest.raises(LedgerCorrupt):
        LedgerStore(paths[0], load_or_create_key(paths[1]))
    with pytest.raises(LedgerCorrupt):
        with TestClient(create_app(*paths), headers=LEDGER_AUTH):
            pass
    assert paths[0].read_bytes() == before


def test_file_signed_by_a_different_key_is_refused(written, paths, tmp_path):
    other_key = tmp_path / "other.pem"
    with pytest.raises(LedgerCorrupt, match="not signed by this ledger's key"):
        LedgerStore(paths[0], load_or_create_key(other_key))
    with pytest.raises(LedgerCorrupt):
        with TestClient(create_app(paths[0], other_key), headers=LEDGER_AUTH):
            pass


def test_rebuilt_chain_signed_by_a_different_key_is_refused(written, paths, tmp_path):
    forger = load_or_create_key(tmp_path / "forger.pem")
    rebuilt, previous = [], None
    for e in written:
        previous = next_entry(previous, e["batch_id"], "ee" * 32, e["tree_size"], e["published_at"])
        previous["signature"] = sign_entry_hash(forger, previous["entry_hash"])
        rebuilt.append(previous)
    assert chain_problems(rebuilt) == []
    write_lines(paths[0], rebuilt)
    with pytest.raises(LedgerCorrupt):
        LedgerStore(paths[0], load_or_create_key(paths[1]))


def test_truncating_the_end_is_caught_only_by_a_pinned_verifier(written, paths, vectors):
    # The honest limit: a file with its last entries removed is still a sound chain.
    pin = Pin(written[-1]["seq"], written[-1]["entry_hash"])
    write_lines(paths[0], written[:1])

    with TestClient(create_app(*paths), headers=LEDGER_AUTH) as running:
        entries = running.get("/entries").json()
        public_key = bytes.fromhex(running.get("/pubkey").json()["public_key"])
    assert entries == written[:1]

    bundle = create_bundle(RAW_BYTES_V1, "batch-0001", vectors["tree4"]["fingerprints"], 2)
    assert verify(b"Document C", bundle, entries, public_key).ok
    assert verify(b"Document C", bundle, entries, public_key, pin).codes == [LEDGER_INVALID]


# ---- the store and the key file ----


def test_store_append_get_head_and_duplicates(paths):
    store = LedgerStore(paths[0], load_or_create_key(paths[1]))
    assert store.entries() == [] and store.head() is None and store.get("batch-0001") is None

    first = store.append("batch-0001", ROOT_A, 4)
    second = store.append("batch-0002", ROOT_B, 5)
    assert store.entries() == [first, second]
    assert store.head() == second
    assert store.get("batch-0001") == first
    with pytest.raises(DuplicateBatch):
        store.append("batch-0001", ROOT_C, 7)
    assert store.entries() == [first, second]


def test_store_hands_out_copies_not_its_own_entries(paths):
    store = LedgerStore(paths[0], load_or_create_key(paths[1]))
    returned = store.append("batch-0001", ROOT_A, 4)
    for handed_out in (returned, store.entries()[0], store.get("batch-0001"), store.head()):
        handed_out["root"] = "ab" * 32
    assert store.entries()[0]["root"] == ROOT_A
    assert store.append("batch-0002", ROOT_B, 5)["prev_hash"] == entry_hash(store.entries()[0])


def test_store_refuses_a_malformed_append_without_writing(paths):
    store = LedgerStore(paths[0], load_or_create_key(paths[1]))
    for batch_id, root, tree_size in [("", ROOT_A, 4), ("b", "xyz", 4), ("b", ROOT_A, 0), ("b", ROOT_A, "4")]:
        with pytest.raises(LedgerFormatError):
            store.append(batch_id, root, tree_size)
    assert store.entries() == []
    assert not paths[0].exists()


def test_twenty_appends_from_twenty_threads_form_one_chain(paths):
    key = load_or_create_key(paths[1])
    store = LedgerStore(paths[0], key)
    for batch in BRIEF_BATCHES:
        store.append(*batch)

    start = threading.Barrier(20)
    errors = []

    def publish(number):
        try:
            start.wait()
            store.append(f"batch-t{number:02d}", f"{number:02x}" * 32, number + 1)
        except Exception as exc:  # collected and asserted on below
            errors.append(exc)

    threads = [threading.Thread(target=publish, args=(n,)) for n in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    for entries in (store.entries(), LedgerStore(paths[0], key).entries()):
        assert len(entries) == 23
        assert [e["seq"] for e in entries] == list(range(23))
        assert len({e["batch_id"] for e in entries}) == 23
        assert ledger_problems(entries, public_key_bytes(key)) == []


def test_key_is_created_once_and_reloaded(tmp_path):
    path = tmp_path / "keys" / "ledger_key.pem"
    created = load_or_create_key(path)
    assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    reloaded = load_or_create_key(path)
    assert public_key_hex(reloaded) == public_key_hex(created)
    assert len(public_key_bytes(created)) == 32
    assert public_key_hex(load_or_create_key(tmp_path / "other.pem")) != public_key_hex(created)


def test_signature_is_base64_over_the_raw_entry_hash(tmp_path):
    import base64

    key = load_or_create_key(tmp_path / "key.pem")
    signature = sign_entry_hash(key, ROOT_A)
    raw = base64.b64decode(signature, validate=True)
    assert len(raw) == 64
    key.public_key().verify(raw, bytes.fromhex(ROOT_A))  # raises if wrong


@pytest.mark.parametrize(
    "content",
    [b"this is not a key", b"", b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"],
    ids=["text", "empty", "broken-pem"],
)
def test_key_file_that_is_not_a_key_is_rejected(content, tmp_path):
    path = tmp_path / "key.pem"
    path.write_bytes(content)
    with pytest.raises(ValueError):
        load_or_create_key(path)
    assert path.read_bytes() == content


def test_key_file_holding_another_kind_of_key_is_rejected(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    path = tmp_path / "key.pem"
    path.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(ValueError, match="Ed25519"):
        load_or_create_key(path)
