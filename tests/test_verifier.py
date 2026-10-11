import base64
import copy
import hashlib
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofchain.core.canonical import JSON_SORTED_V1, RAW_BYTES_V1
from proofchain.core.ledger_format import entry_hash, next_entry
from proofchain.core.proof import create_bundle
from proofchain.verifier import cli
from proofchain.verifier.verify import (
    BATCH_NOT_PUBLISHED,
    DOCUMENT_MODIFIED,
    FAIL,
    LEDGER_INVALID,
    PASS,
    PROOF_INVALID,
    ROOT_MISMATCH,
    SKIPPED,
    Pin,
    parse_pin,
    verify,
)

DOCUMENT = b"Document C"
BATCH = "batch-0001"


# ---- building a signed ledger ----


def public_bytes(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(entry, key):
    entry["signature"] = base64.b64encode(key.sign(bytes.fromhex(entry["entry_hash"]))).decode()
    return entry


def make_chain(key, batches):
    """A signed chain publishing (batch_id, root, tree_size, published_at) in order."""
    chain, previous = [], None
    for batch_id, root, tree_size, published_at in batches:
        previous = sign(next_entry(previous, batch_id, root, tree_size, published_at), key)
        chain.append(previous)
    return chain


def batches_of(chain):
    return [(e["batch_id"], e["root"], e["tree_size"], e["published_at"]) for e in chain]


@pytest.fixture(scope="module")
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def pubkey(key):
    return public_bytes(key)


@pytest.fixture
def ledger(vectors, key):
    """The brief's three-entry chain, signed."""
    return [sign(copy.deepcopy(entry), key) for entry in vectors["chain"]]


@pytest.fixture
def pin(ledger):
    return Pin(ledger[-1]["seq"], ledger[-1]["entry_hash"])


@pytest.fixture
def bundle(vectors):
    """The proof for Document C in the four-document batch, as decoded JSON."""
    return create_bundle(RAW_BYTES_V1, BATCH, vectors["tree4"]["fingerprints"], 2).to_dict()


def statuses(result):
    return [check.status for check in result.checks]


def check(result, code):
    return next(c for c in result.checks if c.code == code)


# ---- the honest case ----


def test_untouched_document_verifies(bundle, ledger, pubkey, pin):
    result = verify(DOCUMENT, bundle, ledger, pubkey, pin)
    assert result.ok
    assert result.codes == []
    assert statuses(result) == [PASS] * 5
    assert [c.code for c in result.checks] == [
        DOCUMENT_MODIFIED, PROOF_INVALID, BATCH_NOT_PUBLISHED, ROOT_MISMATCH, LEDGER_INVALID,
    ]
    assert result.batch_id == BATCH
    assert result.ledger_seq == 0
    assert result.pinned


def test_result_shows_the_hashes_it_computed(bundle, ledger, pubkey, pin, vectors):
    result = verify(DOCUMENT, bundle, ledger, pubkey, pin)
    fp = check(result, DOCUMENT_MODIFIED)
    assert fp.computed == fp.expected == hashlib.sha256(DOCUMENT).hexdigest()
    folded = check(result, PROOF_INVALID)
    assert folded.computed == folded.expected == vectors["tree4"]["root"]
    root = check(result, ROOT_MISMATCH)
    assert root.computed == root.expected == ledger[0]["root"]


def test_a_proof_bundle_object_is_accepted_too(vectors, ledger, pubkey, pin):
    bundle = create_bundle(RAW_BYTES_V1, BATCH, vectors["tree4"]["fingerprints"], 2)
    assert verify(DOCUMENT, bundle, ledger, pubkey, pin).ok


def test_every_document_in_both_batches_verifies(vectors, ledger, pubkey, pin):
    docs = [f"Document {letter}".encode() for letter in "ABCDE"]
    for batch_id, tree in [("batch-0001", "tree4"), ("batch-0002", "tree5")]:
        fps = vectors[tree]["fingerprints"]
        for i in range(len(fps)):
            proof = create_bundle(RAW_BYTES_V1, batch_id, fps, i)
            assert verify(docs[i], proof, ledger, pubkey, pin).ok


def test_structured_record_verifies_however_it_is_written(vectors, key, pubkey):
    ex = vectors["canon"]
    fps = [ex["canonical_hash"], hashlib.sha256(b"other").hexdigest()]
    proof = create_bundle(JSON_SORTED_V1, "batch-json", fps, 0)
    chain = make_chain(key, [("batch-json", proof.root, 2, "2026-10-11T09:00:00Z")])
    assert verify(ex["raw1"].encode(), proof, chain, pubkey).ok
    assert verify(ex["raw2"].encode(), proof, chain, pubkey).ok
    changed = ex["raw1"].replace("2026", "2027").encode()
    assert verify(changed, proof, chain, pubkey).codes == [DOCUMENT_MODIFIED]
    assert verify(b"not json", proof, chain, pubkey).codes == [DOCUMENT_MODIFIED]


# ---- one failure code at a time ----


def test_edited_document_is_document_modified_and_nothing_else(bundle, ledger, pubkey, pin):
    result = verify(DOCUMENT + b"!", bundle, ledger, pubkey, pin)
    assert result.codes == [DOCUMENT_MODIFIED]
    assert statuses(result) == [FAIL, PASS, PASS, PASS, PASS]
    failed = check(result, DOCUMENT_MODIFIED)
    assert failed.computed == hashlib.sha256(DOCUMENT + b"!").hexdigest()
    assert failed.expected == bundle["fingerprint"]


def test_changed_sibling_hash_is_proof_invalid_and_nothing_else(bundle, ledger, pubkey, pin, vectors):
    bundle["path"][0]["hash"] = "00" * 32
    result = verify(DOCUMENT, bundle, ledger, pubkey, pin)
    assert result.codes == [PROOF_INVALID]
    assert statuses(result) == [PASS, FAIL, PASS, PASS, PASS]
    failed = check(result, PROOF_INVALID)
    assert failed.expected == vectors["tree4"]["root"]
    assert failed.computed != failed.expected


def test_edited_document_and_changed_sibling_report_both(bundle, ledger, pubkey, pin):
    bundle["path"][1]["hash"] = "ab" * 32
    result = verify(b"Document C (edited)", bundle, ledger, pubkey, pin)
    assert result.codes == [DOCUMENT_MODIFIED, PROOF_INVALID]


@pytest.mark.parametrize(
    "damage",
    [
        lambda b: None,
        lambda b: "a string",
        lambda b: [b],
        lambda b: {k: v for k, v in b.items() if k != "root"},
        lambda b: dict(b, fingerprint="xyz"),
        lambda b: dict(b, leaf_index=4),
        lambda b: dict(b, path=b["path"] + b["path"]),
        lambda b: dict(b, path=b["path"][:1]),
        lambda b: dict(b, path=[dict(b["path"][0], side="left"), b["path"][1]]),
    ],
    ids=["not-json", "text", "list", "no-root", "bad-hex", "index-outside-tree",
         "path-too-long", "path-truncated", "wrong-side-flag"],
)
def test_malformed_bundle_is_proof_invalid_and_nothing_else(damage, bundle, ledger, pubkey, pin):
    result = verify(DOCUMENT, damage(bundle), ledger, pubkey, pin)
    assert result.codes == [PROOF_INVALID]
    assert statuses(result) == [SKIPPED, FAIL, SKIPPED, SKIPPED, PASS]
    assert not result.ok
    assert result.batch_id is None


def test_unknown_batch_is_batch_not_published_and_nothing_else(vectors, ledger, pubkey, pin):
    proof = create_bundle(RAW_BYTES_V1, "batch-9999", vectors["tree4"]["fingerprints"], 2)
    result = verify(DOCUMENT, proof, ledger, pubkey, pin)
    assert result.codes == [BATCH_NOT_PUBLISHED]
    assert statuses(result) == [PASS, PASS, FAIL, SKIPPED, PASS]
    assert result.ledger_seq is None


def test_empty_ledger_is_batch_not_published(bundle, pubkey):
    result = verify(DOCUMENT, bundle, [], pubkey)
    assert result.codes == [BATCH_NOT_PUBLISHED]
    assert statuses(result) == [PASS, PASS, FAIL, SKIPPED, PASS]


def test_insiders_fresh_proof_for_forged_content_is_root_mismatch(vectors, ledger, pubkey, pin):
    # The insider rewrites the record, its fingerprint and the batch root in the
    # registry database, then issues a new, internally consistent proof.
    forged = b"Document C, with a better grade"
    fps = list(vectors["tree4"]["fingerprints"])
    fps[2] = hashlib.sha256(forged).hexdigest()
    proof = create_bundle(RAW_BYTES_V1, BATCH, fps, 2)

    result = verify(forged, proof, ledger, pubkey, pin)
    assert result.codes == [ROOT_MISMATCH]
    assert statuses(result) == [PASS, PASS, PASS, FAIL, PASS]
    failed = check(result, ROOT_MISMATCH)
    assert failed.computed == proof.root
    assert failed.expected == vectors["tree4"]["root"]


def test_tree_size_that_differs_from_the_ledger_is_root_mismatch(bundle, ledger, key, pubkey):
    batches = batches_of(ledger)
    batches[0] = (BATCH, ledger[0]["root"], 5, ledger[0]["published_at"])
    result = verify(DOCUMENT, bundle, make_chain(key, batches), pubkey)
    assert result.codes == [ROOT_MISMATCH]


# ---- attacks on the ledger ----


def test_edited_ledger_entry_is_ledger_invalid_and_nothing_else(bundle, ledger, pubkey, pin):
    ledger[1]["root"] = "ab" * 32
    result = verify(DOCUMENT, bundle, ledger, pubkey, pin)
    assert result.codes == [LEDGER_INVALID]
    assert statuses(result) == [PASS, PASS, PASS, PASS, FAIL]


def test_editing_the_published_root_itself_is_caught_twice(bundle, ledger, pubkey, pin):
    ledger[0]["root"] = "ab" * 32
    assert verify(DOCUMENT, bundle, ledger, pubkey, pin).codes == [ROOT_MISMATCH, LEDGER_INVALID]


def test_edited_entry_with_recomputed_hash_still_fails(bundle, ledger, pubkey):
    # Without the key the attacker cannot re-sign, and the next link breaks as well.
    ledger[1]["tree_size"] = 50
    ledger[1]["entry_hash"] = entry_hash(ledger[1])
    result = verify(DOCUMENT, bundle, ledger, pubkey)
    assert result.codes == [LEDGER_INVALID]
    detail = check(result, LEDGER_INVALID).detail
    assert "signature" in detail and "prev_hash" in detail


def test_swapped_entries_are_ledger_invalid(bundle, ledger, pubkey):
    ledger[1], ledger[2] = ledger[2], ledger[1]
    assert verify(DOCUMENT, bundle, ledger, pubkey).codes == [LEDGER_INVALID]


def test_ledger_truncated_below_the_pin_is_ledger_invalid(bundle, ledger, pubkey, pin):
    assert verify(DOCUMENT, bundle, ledger[:2], pubkey).ok
    result = verify(DOCUMENT, bundle, ledger[:2], pubkey, pin)
    assert result.codes == [LEDGER_INVALID]
    assert "missing" in check(result, LEDGER_INVALID).detail


def test_unsigned_entry_is_ledger_invalid(bundle, ledger, pubkey, pin):
    del ledger[2]["signature"]
    result = verify(DOCUMENT, bundle, ledger, pubkey, pin)
    assert result.codes == [LEDGER_INVALID]
    assert "not signed" in check(result, LEDGER_INVALID).detail


@pytest.mark.parametrize("signature", ["", "not base64!", "AAAA", base64.b64encode(b"\x00" * 64).decode()])
def test_bad_signature_is_ledger_invalid(signature, bundle, ledger, pubkey):
    ledger[0]["signature"] = signature
    assert verify(DOCUMENT, bundle, ledger, pubkey).codes == [LEDGER_INVALID]


def test_signature_copied_from_another_entry_is_ledger_invalid(bundle, ledger, pubkey):
    ledger[1]["signature"] = ledger[0]["signature"]
    assert verify(DOCUMENT, bundle, ledger, pubkey).codes == [LEDGER_INVALID]


def test_ledger_signed_with_another_key_is_ledger_invalid(bundle, vectors, pubkey):
    other = Ed25519PrivateKey.generate()
    chain = [sign(copy.deepcopy(e), other) for e in vectors["chain"]]
    assert verify(DOCUMENT, bundle, chain, pubkey).codes == [LEDGER_INVALID]
    assert verify(DOCUMENT, bundle, chain, public_bytes(other)).ok


@pytest.mark.parametrize("bad_key", [b"", b"\x00" * 31, b"\x01" * 33])
def test_unusable_public_key_is_ledger_invalid(bad_key, bundle, ledger):
    assert verify(DOCUMENT, bundle, ledger, bad_key).codes == [LEDGER_INVALID]


def test_rebuilt_and_resigned_ledger_passes_without_a_pin_and_fails_with_one(
    vectors, ledger, key, pubkey, pin
):
    # The ledger key holder republishes batch-0001 with a forged root and signs
    # the whole chain again. Every link and signature is valid.
    forged = b"Document C, with a better grade"
    fps = list(vectors["tree4"]["fingerprints"])
    fps[2] = hashlib.sha256(forged).hexdigest()
    proof = create_bundle(RAW_BYTES_V1, BATCH, fps, 2)
    batches = batches_of(ledger)
    batches[0] = (BATCH, proof.root, 4, ledger[0]["published_at"])
    rebuilt = make_chain(key, batches)

    # The honest limit: a verifier with no checkpoint cannot tell.
    unpinned = verify(forged, proof, rebuilt, pubkey)
    assert unpinned.ok and not unpinned.pinned
    assert "no checkpoint pinned" in check(unpinned, LEDGER_INVALID).detail

    # Anyone who pinned the old head can.
    pinned = verify(forged, proof, rebuilt, pubkey, pin)
    assert pinned.codes == [LEDGER_INVALID]
    assert "has changed" in check(pinned, LEDGER_INVALID).detail


def test_a_pin_on_an_earlier_entry_survives_new_entries(bundle, ledger, key, pubkey):
    old_pin = Pin(1, ledger[1]["entry_hash"])
    longer = ledger + [sign(next_entry(ledger[-1], "batch-0004", "cd" * 32, 2, "2026-10-14T09:00:00Z"), key)]
    assert verify(DOCUMENT, bundle, longer, pubkey, old_pin).ok


def test_entry_that_is_not_an_object_is_ledger_invalid(bundle, ledger, pubkey, pin):
    ledger.insert(1, "{ this line is not JSON")
    result = verify(DOCUMENT, bundle, ledger, pubkey, pin)
    assert LEDGER_INVALID in result.codes
    assert "malformed" in check(result, LEDGER_INVALID).detail


def test_all_checks_run_and_every_failure_is_listed(bundle, ledger, pubkey, pin):
    bundle["path"][0]["hash"] = "00" * 32
    ledger[0]["root"] = "ab" * 32
    result = verify(b"something else", bundle, ledger, pubkey, pin)
    assert result.codes == [DOCUMENT_MODIFIED, PROOF_INVALID, ROOT_MISMATCH, LEDGER_INVALID]
    assert len(result.checks) == 5


def test_result_serialises_to_json(bundle, ledger, pubkey, pin):
    data = json.loads(json.dumps(verify(DOCUMENT + b"!", bundle, ledger, pubkey, pin).to_dict()))
    assert data["ok"] is False
    assert data["codes"] == [DOCUMENT_MODIFIED]
    assert len(data["checks"]) == 5
    assert data["checks"][0]["status"] == FAIL


def test_parse_pin():
    assert parse_pin(" 12:" + "ab" * 32 + "\n") == Pin(12, "ab" * 32)
    assert str(Pin(12, "ab" * 32)) == "12:" + "ab" * 32
    for bad in ["", "12", "12:abcd", "x:" + "ab" * 32, "1:" + "AB" * 32, "-1:" + "ab" * 32]:
        with pytest.raises(ValueError):
            parse_pin(bad)


# ---- command line ----


@pytest.fixture
def files(tmp_path, bundle, ledger):
    doc = tmp_path / "degree.txt"
    doc.write_bytes(DOCUMENT)
    proof = tmp_path / "degree.proof.json"
    proof.write_text(json.dumps(bundle), encoding="utf-8")
    ledger_file = tmp_path / "ledger.jsonl"
    ledger_file.write_text("".join(json.dumps(e) + "\n" for e in ledger), encoding="utf-8")
    return {"doc": str(doc), "proof": str(proof), "ledger": str(ledger_file), "dir": tmp_path}


def run_verify(files, *extra):
    return cli.main(["verify", "--doc", files["doc"], "--proof", files["proof"],
                     "--ledger", files["ledger"], *extra])


def test_cli_verifies_offline_from_a_ledger_file(files, pubkey, pin, capsys):
    assert run_verify(files, "--pubkey", pubkey.hex(), "--pin", str(pin)) == 0
    out = capsys.readouterr().out
    assert out.count("PASS") == 5
    assert "VERIFIED: the document matches the record registered in batch batch-0001 (ledger entry 0)." in out
    assert "does not prove who created the document" in out
    assert "3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8effeda95e98c40" in out


def test_cli_reports_a_modified_document(files, pubkey, pin, capsys):
    with open(files["doc"], "ab") as handle:
        handle.write(b"!")
    assert run_verify(files, "--pubkey", pubkey.hex(), "--pin", str(pin)) == 1
    out = capsys.readouterr().out
    assert "FAIL  1. Fingerprint check  [DOCUMENT_MODIFIED]" in out
    assert "NOT VERIFIED: DOCUMENT_MODIFIED" in out
    assert "computed  " + hashlib.sha256(DOCUMENT + b"!").hexdigest() in out
    assert "expected  " + hashlib.sha256(DOCUMENT).hexdigest() in out
    assert out.count("PASS") == 4


def test_cli_reports_a_proof_that_is_not_json(files, pubkey, capsys):
    with open(files["proof"], "w", encoding="utf-8") as handle:
        handle.write("{ not json")
    assert run_verify(files, "--pubkey", pubkey.hex()) == 1
    out = capsys.readouterr().out
    assert "NOT VERIFIED: PROOF_INVALID" in out
    assert out.count("SKIP") == 3


def test_cli_reports_an_unparseable_ledger_line(files, pubkey, capsys):
    with open(files["ledger"], "a", encoding="utf-8") as handle:
        handle.write("{ this line is not JSON\n")
    assert run_verify(files, "--pubkey", pubkey.hex()) == 1
    assert "NOT VERIFIED: LEDGER_INVALID" in capsys.readouterr().out


def test_cli_json_output(files, pubkey, pin, capsys):
    assert run_verify(files, "--pubkey", pubkey.hex(), "--pin", str(pin), "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["codes"] == [] and data["pinned"] is True
    assert data["warning"] is None


def test_cli_pin_then_verify_with_the_pin_file(files, pubkey, pin, capsys):
    pin_file = str(files["dir"] / "ledger.pin.json")
    assert cli.main(["pin", "--ledger", files["ledger"], "--pubkey", pubkey.hex(), "--out", pin_file]) == 0
    assert capsys.readouterr().out.strip() == str(pin)
    with open(pin_file, encoding="utf-8") as handle:
        saved = json.load(handle)
    assert saved["public_key"] == pubkey.hex()
    assert (saved["seq"], saved["entry_hash"]) == (pin.seq, pin.entry_hash)

    # The pin file supplies both the checkpoint and the key.
    assert run_verify(files, "--pin-file", pin_file) == 0
    assert "pinned entry 2 is present" in capsys.readouterr().out


def test_cli_pin_file_catches_a_rewritten_ledger(files, ledger, key, pubkey, capsys):
    pin_file = str(files["dir"] / "ledger.pin.json")
    assert cli.main(["pin", "--ledger", files["ledger"], "--pubkey", pubkey.hex(), "--out", pin_file]) == 0
    batches = batches_of(ledger)
    batches[2] = ("batch-0003", "ee" * 32, 7, ledger[2]["published_at"])
    with open(files["ledger"], "w", encoding="utf-8") as handle:
        handle.writelines(json.dumps(e) + "\n" for e in make_chain(key, batches))
    capsys.readouterr()

    assert run_verify(files, "--pubkey", pubkey.hex()) == 0
    assert run_verify(files, "--pin-file", pin_file) == 1
    assert "NOT VERIFIED: LEDGER_INVALID" in capsys.readouterr().out


def test_cli_pin_refuses_an_unsound_ledger(files, ledger, pubkey, capsys):
    ledger[1]["root"] = "ab" * 32
    with open(files["ledger"], "w", encoding="utf-8") as handle:
        handle.writelines(json.dumps(e) + "\n" for e in ledger)
    out_file = files["dir"] / "ledger.pin.json"
    assert cli.main(["pin", "--ledger", files["ledger"], "--pubkey", pubkey.hex(), "--out", str(out_file)]) == 1
    assert "nothing was pinned" in capsys.readouterr().out
    assert not out_file.exists()


def test_cli_missing_ledger_file_is_exit_2(files, pubkey, capsys):
    files["ledger"] = str(files["dir"] / "no-such-ledger.jsonl")
    assert run_verify(files, "--pubkey", pubkey.hex()) == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "VERIFIED" not in captured.out


def test_cli_ledger_file_without_a_key_is_exit_2(files, capsys):
    assert run_verify(files) == 2
    assert "--pubkey or --pin-file" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [["--pubkey", "abcd"], ["--pubkey", "zz" * 32], ["--pin", "not-a-pin"], ["--pin-file", "no-such-pin.json"]],
    ids=["short-key", "non-hex-key", "bad-pin", "missing-pin-file"],
)
def test_cli_unusable_arguments_are_exit_2(extra, files, pubkey, capsys):
    if extra[0] != "--pubkey":
        extra = extra + ["--pubkey", pubkey.hex()]
    assert run_verify(files, *extra) == 2
    assert "VERIFIED" not in capsys.readouterr().out


@pytest.mark.parametrize("missing", ["doc", "proof"])
def test_cli_missing_document_or_proof_is_exit_2(missing, files, pubkey, capsys):
    files[missing] = str(files["dir"] / "no-such-file")
    assert run_verify(files, "--pubkey", pubkey.hex()) == 2
    assert "VERIFIED" not in capsys.readouterr().out


def test_cli_pin_on_an_empty_ledger_is_exit_2(files, pubkey, capsys):
    open(files["ledger"], "w").close()
    assert cli.main(["pin", "--ledger", files["ledger"], "--pubkey", pubkey.hex()]) == 2
    assert "empty" in capsys.readouterr().err


def test_python_dash_m_sets_the_exit_code(files, pubkey, pin):
    def run(doc):
        return subprocess.run(
            [sys.executable, "-m", "proofchain.verifier", "verify", "--doc", doc, "--proof", files["proof"],
             "--ledger", files["ledger"], "--pubkey", pubkey.hex(), "--pin", str(pin)],
            capture_output=True, text=True,
        )

    honest = run(files["doc"])
    assert honest.returncode == 0, honest.stderr
    assert "VERIFIED" in honest.stdout

    tampered = run(files["proof"])  # any other file stands in for a modified document
    assert tampered.returncode == 1
    assert "NOT VERIFIED: DOCUMENT_MODIFIED" in tampered.stdout


# ---- command line against a ledger served over HTTP ----


@pytest.fixture
def ledger_url(ledger, pubkey):
    """A stand-in for the ledger service: GET /entries and GET /pubkey."""
    replies = {"/entries": ledger, "/pubkey": {"public_key": pubkey.hex()}}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in replies:
                self.send_error(404)
                return
            body = json.dumps(replies[self.path]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


def test_cli_verifies_against_a_ledger_url_and_warns_about_the_key(files, ledger_url, pin, capsys):
    files["ledger"] = ledger_url
    assert run_verify(files, "--pin", str(pin)) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert "the public key was fetched from the ledger itself" in out


def test_cli_does_not_warn_when_the_key_is_supplied(files, ledger_url, pubkey, pin, capsys):
    files["ledger"] = ledger_url + "/"
    assert run_verify(files, "--pubkey", pubkey.hex(), "--pin", str(pin)) == 0
    assert "fetched from the ledger itself" not in capsys.readouterr().out


def test_cli_a_key_served_by_the_ledger_cannot_override_the_supplied_one(files, ledger_url, capsys):
    files["ledger"] = ledger_url
    other = public_bytes(Ed25519PrivateKey.generate())
    assert run_verify(files, "--pubkey", other.hex()) == 1
    assert "NOT VERIFIED: LEDGER_INVALID" in capsys.readouterr().out


def test_cli_pin_from_a_ledger_url(files, ledger_url, pubkey, pin, capsys):
    out_file = files["dir"] / "ledger.pin.json"
    assert cli.main(["pin", "--ledger", ledger_url, "--out", str(out_file)]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == str(pin)
    assert "fetched from the ledger itself" in captured.err
    assert json.loads(out_file.read_text(encoding="utf-8"))["public_key"] == pubkey.hex()


def test_cli_unreachable_ledger_url_is_exit_2(files, pubkey, capsys):
    files["ledger"] = "http://127.0.0.1:9"
    assert run_verify(files, "--pubkey", pubkey.hex()) == 2
    assert "error:" in capsys.readouterr().err
