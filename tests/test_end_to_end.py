"""The demo path, run for real.

A ledger service listens on a real port. The demo scripts and the verifier are
run as separate processes, the way the README tells a person to run them, and
the registry's own audit is run against the same ledger. The static browser
verifier's rules are run under Node and must agree with the Python verifier.
"""

import base64
import json
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import uvicorn

from proofchain.core.canonical import CanonicalError, JSON_SORTED_V1, fingerprint
from proofchain.core.merkle import leaf_hash
from proofchain.ledger import app as ledger_app
from proofchain.registry import audit, db
from proofchain.registry.ledger_client import LedgerClient

from .helpers import query

ROOT = Path(__file__).resolve().parent.parent
RUNNER = Path(__file__).with_name("web_verifier_runner.mjs")
NODE = shutil.which("node")

needs_node = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def run(*args, stdin=None):
    return subprocess.run([str(a) for a in args], cwd=ROOT, input=stdin, capture_output=True, text=True, timeout=120)


def script(name, *args):
    return run(sys.executable, ROOT / "scripts" / name, *args)


@pytest.fixture
def world(tmp_path):
    """A running ledger and the paths a demo uses, all under a temporary folder."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    paths = {"db": tmp_path / "registry.db", "ledger_file": tmp_path / "ledger.jsonl",
             "key_file": tmp_path / "ledger_key.pem", "out": tmp_path / "demo", "url": f"http://127.0.0.1:{port}"}
    app = ledger_app.create_app(paths["ledger_file"], paths["key_file"])
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        assert thread.is_alive(), "the ledger service did not start"
        thread.join(0.05)
    yield paths
    server.should_exit = True
    thread.join(10)


@pytest.fixture
def seeded(world):
    done = script("demo_seed.py", "--db", world["db"], "--ledger", world["url"], "--out", world["out"])
    assert done.returncode == 0, done.stderr
    return world


def cli_verify(world, document, proof, ledger=None, pin=True, pubkey=None):
    args = [sys.executable, "-m", "proofchain.verifier", "verify", "--doc", document, "--proof", proof,
            "--ledger", ledger or world["url"], "--json"]
    if pin:
        args += ["--pin-file", world["out"] / "pin.json"]
    if pubkey:
        args += ["--pubkey", pubkey]
    done = run(*args)
    assert done.returncode in (0, 1), done.stderr
    result = json.loads(done.stdout)
    assert result["ok"] is (done.returncode == 0)
    return result


def run_audit(world):
    conn = db.connect(world["db"])
    try:
        return audit.run_audit(conn, LedgerClient(world["url"]))
    finally:
        conn.close()


def tamper(world, action, *args):
    done = script("tamper.py", action, "--db", world["db"], "--out", world["out"], *args)
    assert done.returncode == 0, done.stderr
    return done.stdout


SAMPLES = ["degree_asha_rao.txt", "transcript_asha_rao.txt", "supply_agreement.txt", "food_licence.json"]


# ---- seeding


def test_seed_registers_seals_and_writes_verifiable_files(seeded):
    out = seeded["out"]
    assert sorted(p.name for p in out.iterdir()) == sorted(SAMPLES + [f"{n}.proof.json" for n in SAMPLES] + ["pin.json"])
    assert query(seeded["db"], "SELECT id, status, owner, sealed_by FROM batches") == [
        {"id": "batch-0001", "status": "sealed", "owner": "demo", "sealed_by": "demo"}]
    pending = query(seeded["db"], "SELECT filename, suggested_metadata FROM records WHERE metadata_confirmed = 0")
    assert [p["filename"] for p in pending] == ["award_letter.txt"]
    assert json.loads(pending[0]["suggested_metadata"])["issuer"] == "City Arts Council"

    for name in SAMPLES:
        result = cli_verify(seeded, out / name, out / f"{name}.proof.json")
        assert result["ok"] and result["batch_id"] == "batch-0001" and result["pinned"], name
    assert run_audit(seeded).ok


def test_seed_refuses_a_database_that_already_has_records(seeded):
    again = script("demo_seed.py", "--db", seeded["db"], "--ledger", seeded["url"], "--out", seeded["out"])
    assert again.returncode == 2 and "already holds 5 records" in again.stderr
    assert len(query(seeded["db"], "SELECT id FROM records")) == 5

    added = script("demo_seed.py", "--db", seeded["db"], "--ledger", seeded["url"], "--out", seeded["out"], "--add")
    assert added.returncode == 0, added.stderr
    assert [b["status"] for b in query(seeded["db"], "SELECT status FROM batches ORDER BY id")] == ["sealed", "sealed"]
    assert run_audit(seeded).ok


def test_seed_needs_the_ledger(tmp_path):
    done = script("demo_seed.py", "--db", tmp_path / "r.db", "--ledger", "http://127.0.0.1:9", "--out", tmp_path / "o")
    assert done.returncode == 2 and "Start the ledger first" in done.stderr
    assert not (tmp_path / "o").exists()


# ---- the tamper demo


def test_holder_edit_is_document_modified(seeded):
    out = seeded["out"]
    edited = out / "edited.txt"
    edited.write_bytes((out / "degree_asha_rao.txt").read_bytes().replace(b"First Class", b"Upper Second"))
    assert cli_verify(seeded, edited, out / "degree_asha_rao.txt.proof.json")["codes"] == ["DOCUMENT_MODIFIED"]


def test_corrupted_proof_is_proof_invalid(seeded):
    out = seeded["out"]
    proof = json.loads((out / "degree_asha_rao.txt.proof.json").read_text())
    proof["path"][0]["hash"] = "ab" * 32
    (out / "bad.proof.json").write_text(json.dumps(proof))
    assert cli_verify(seeded, out / "degree_asha_rao.txt", out / "bad.proof.json")["codes"] == ["PROOF_INVALID"]


def test_changed_content_is_caught_by_the_audit_and_restore_undoes_it(seeded):
    assert "STORED_CONTENT_CHANGED" in tamper(seeded, "content")
    report = run_audit(seeded)
    assert report.codes == ["STORED_CONTENT_CHANGED"] and not report.ok
    out = seeded["out"]
    # The holder still has the original, and it still verifies.
    assert cli_verify(seeded, out / "transcript_asha_rao.txt", out / "transcript_asha_rao.txt.proof.json")["ok"]

    assert "Restored" in tamper(seeded, "restore")
    assert run_audit(seeded).ok
    assert "Nothing to restore" in tamper(seeded, "restore")


def test_changed_fingerprint_is_caught_by_the_audit(seeded):
    tamper(seeded, "fingerprint", "--record", "1")
    assert sorted(run_audit(seeded).codes) == ["BATCH_ROOT_DIVERGED", "STORED_FINGERPRINT_CHANGED"]


def test_full_rewrite_is_root_mismatch_even_though_the_database_agrees_with_itself(seeded):
    out = seeded["out"]
    said = tamper(seeded, "rewrite")
    assert "ROOT_MISMATCH" in said
    forged, proof = out / "forged_transcript_asha_rao.txt", out / "forged_transcript_asha_rao.txt.proof.json"

    # Inside the database nothing looks wrong: content hashes to its fingerprint ...
    row = query(seeded["db"], "SELECT content, fingerprint, canon FROM records WHERE id = 2")[0]
    assert fingerprint(row["canon"], row["content"]) == row["fingerprint"]
    assert forged.read_bytes() == row["content"] and b"altered after registration" in row["content"]
    # ... yet the verifier rejects the forged document with its fresh proof,
    result = cli_verify(seeded, forged, proof)
    assert result["codes"] == ["ROOT_MISMATCH"]
    statuses = {c["name"]: c["status"] for c in result["checks"]}
    assert statuses["Fingerprint check"] == statuses["Proof check"] == "pass"
    # the audit flags the batch, and every honest holder's document is unaffected.
    assert run_audit(seeded).codes == ["BATCH_ROOT_DIVERGED"]
    for name in SAMPLES:
        assert cli_verify(seeded, out / name, out / f"{name}.proof.json")["ok"], name


def test_rewritten_ledger_fools_an_unpinned_verifier_and_is_caught_by_a_pinned_one(seeded):
    out = seeded["out"]
    tamper(seeded, "rewrite")
    said = tamper(seeded, "ledger", "--ledger-file", seeded["ledger_file"], "--key-file", seeded["key_file"])
    rewritten = out / "ledger_rewritten.jsonl"
    assert rewritten.exists() and "LEDGER_INVALID" in said
    forged, proof = out / "forged_transcript_asha_rao.txt", out / "forged_transcript_asha_rao.txt.proof.json"
    key = json.loads((out / "pin.json").read_text())["public_key"]

    # The attacker holds the ledger key, so chain and signatures are sound: without a pin the forgery passes.
    assert cli_verify(seeded, forged, proof, ledger=rewritten, pin=False, pubkey=key)["ok"]
    # A verifier that pinned the real head earlier sees that history was replaced.
    assert cli_verify(seeded, forged, proof, ledger=rewritten)["codes"] == ["LEDGER_INVALID"]
    # The real ledger file was left alone.
    assert cli_verify(seeded, out / "degree_asha_rao.txt", out / "degree_asha_rao.txt.proof.json",
                      ledger=seeded["ledger_file"])["ok"]


def test_tamper_reports_what_it_cannot_do(seeded):
    for args, message in (
        (["content", "--record", "99"], "there is no record 99"),
        (["content", "--record", "5"], "not in a sealed batch"),
        (["content", "--record", "4"], "does not fit that form"),
        (["ledger", "--ledger-file", seeded["ledger_file"], "--key-file", seeded["key_file"]], "run `rewrite` first"),
    ):
        done = script("tamper.py", *args, "--db", seeded["db"], "--out", seeded["out"])
        assert done.returncode == 2 and message in done.stderr, done.stderr
    assert run_audit(seeded).ok


# ---- the ledger can be read from a web page


def test_ledger_allows_cross_origin_reads_only(world):
    import urllib.request

    request = urllib.request.Request(world["url"] + "/entries", headers={"Origin": "null"})
    with urllib.request.urlopen(request) as response:
        assert response.headers["access-control-allow-origin"] == "*"
    preflight = urllib.request.Request(world["url"] + "/entries", method="OPTIONS", headers={
        "Origin": "http://elsewhere.example", "Access-Control-Request-Method": "POST"})
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(preflight)
    assert refused.value.code == 400


# ---- the static browser verifier agrees with the Python verifier


def web_verify(world, document, proof, ledger=None, pin=True):
    saved = json.loads((world["out"] / "pin.json").read_text())
    args = [NODE, RUNNER, "verify", document, proof, ledger or world["ledger_file"], saved["public_key"]]
    if pin:
        args.append(f"{saved['seq']}:{saved['entry_hash']}")
    done = run(*args)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@needs_node
def test_web_verifier_gives_the_same_verdicts_as_the_cli(seeded):
    out = seeded["out"]
    cases = [(out / name, out / f"{name}.proof.json", None, True) for name in SAMPLES]

    edited = out / "edited.txt"
    edited.write_bytes((out / "degree_asha_rao.txt").read_bytes() + b"!")
    cases.append((edited, out / "degree_asha_rao.txt.proof.json", None, True))

    edited_json = out / "edited.json"
    edited_json.write_bytes((out / "food_licence.json").read_bytes().replace(b"2026-12-31", b"2027-12-31"))
    cases.append((edited_json, out / "food_licence.json.proof.json", None, True))
    reordered = out / "reordered.json"   # same record, different key order and spacing: still the same record
    record = json.loads((out / "food_licence.json").read_text())
    reordered.write_text(json.dumps(dict(reversed(list(record.items()))), separators=(",", ":")))
    cases.append((reordered, out / "food_licence.json.proof.json", None, True))
    not_json = out / "not.json"
    not_json.write_bytes(b"{not json")
    cases.append((not_json, out / "food_licence.json.proof.json", None, True))

    proof = json.loads((out / "degree_asha_rao.txt.proof.json").read_text())
    variants = {
        "sibling": lambda p: p["path"][0].update(hash="ab" * 32),
        "batch": lambda p: p.update(batch_id="batch-0099"),
        "size": lambda p: p.update(tree_size=3, path=p["path"][:1] if p["leaf_index"] == 2 else p["path"]),
        "extra": lambda p: p.update(note="hello"),
        "upper": lambda p: p.update(root=p["root"].upper()),
        "version": lambda p: p.update(version=3),
        "wrong_salt": lambda p: p.update(salt="cd" * 32),
        "no_salt": lambda p: p.pop("salt"),
        "upper_salt": lambda p: p.update(salt=p["salt"].upper().replace("0", "A")),
        "downgrade": lambda p: (p.pop("salt"), p.update(version=1)),
        "unsalted": lambda p: (p.pop("salt"), p.update(version=1, leaf_index=0, tree_size=1, path=[],
                                                     root=leaf_hash(bytes.fromhex(p["fingerprint"])).hex())),
        "float": lambda p: p.update(leaf_index=0.0),
    }
    for label, change in variants.items():
        altered = json.loads(json.dumps(proof))
        change(altered)
        path = out / f"proof_{label}.json"
        path.write_text(json.dumps(altered))
        cases.append((out / "degree_asha_rao.txt", path, None, True))
    (out / "proof_garbage.json").write_bytes(b"\xff\xfe not json")
    cases.append((out / "degree_asha_rao.txt", out / "proof_garbage.json", None, True))

    tamper(seeded, "rewrite")
    tamper(seeded, "ledger", "--ledger-file", seeded["ledger_file"], "--key-file", seeded["key_file"])
    forged, forged_proof = out / "forged_transcript_asha_rao.txt", out / "forged_transcript_asha_rao.txt.proof.json"
    cases += [(forged, forged_proof, None, True),
              (forged, forged_proof, out / "ledger_rewritten.jsonl", True),
              (forged, forged_proof, out / "ledger_rewritten.jsonl", False)]

    lines = seeded["ledger_file"].read_text().splitlines()
    broken = out / "ledger_broken.jsonl"
    entry = json.loads(lines[0])
    entry["tree_size"] = 9
    broken.write_text(json.dumps(entry) + "\nnot json\n")
    cases.append((out / "degree_asha_rao.txt", out / "degree_asha_rao.txt.proof.json", broken, False))
    unsigned = out / "ledger_unsigned.jsonl"
    entry = json.loads(lines[0])
    del entry["signature"]
    unsigned.write_text(json.dumps(entry) + "\n")
    cases.append((out / "degree_asha_rao.txt", out / "degree_asha_rao.txt.proof.json", unsigned, True))

    key = json.loads((out / "pin.json").read_text())["public_key"]
    seen = set()
    for document, proof_path, ledger, pin in cases:
        expected = cli_verify(seeded, document, proof_path, ledger=ledger or seeded["ledger_file"], pin=pin,
                              pubkey=None if pin else key)
        got = web_verify(seeded, document, proof_path, ledger=ledger, pin=pin)
        label = f"{document.name} / {proof_path.name} / {ledger.name if ledger else 'ledger'} / pin={pin}"
        assert got["ok"] == expected["ok"] and got["codes"] == expected["codes"], label
        assert [c["status"] for c in got["checks"]] == [c["status"] for c in expected["checks"]], label
        assert [(c["computed"], c["expected"]) for c in got["checks"]] == \
               [(c["computed"], c["expected"]) for c in expected["checks"]], label
        seen.update(expected["codes"])
        seen.add("ok" if expected["ok"] else "failed")
    # The comparison is only worth something if it exercised every outcome.
    assert seen == {"ok", "failed", "DOCUMENT_MODIFIED", "PROOF_INVALID", "BATCH_NOT_PUBLISHED",
                    "ROOT_MISMATCH", "LEDGER_INVALID"}


@needs_node
def test_web_verifier_canonical_json_matches_python(vectors):
    documents = [
        vectors["canon"]["raw1"].encode(), vectors["canon"]["raw2"].encode(),
        b'{"b":[1,2,{"z":null,"a":true}],"a":"x"}', b' [ ] ', b'"text"', b"0", b"-0", b"12345678901234567890123456789",
        '{"caf\u00e9":1}'.encode(), '{"cafe\u0301":1}'.encode(),            # composed and decomposed: one record
        '{"\U0001F600":1,"\uffff":2,"a":3}'.encode(),                        # code point order, not UTF-16 order
        b'{"esc":"line\\nbreak \\"quoted\\" back\\\\slash \\u0001 \\u00e9 \\ud83d\\ude00 /"}',
        '{"sep":"\u2028\u2029\u007f"}'.encode(),
        b'{"a":1.0}', b'{"a":1e3}', b'{"a":NaN}', b'{"a":1,"a":2}', b"{'a':1}", b'{"a":1,}', b"[1,]", b"01", b"",
        b'{"a":"\\ud800"}', b"\xff\xfe", b'\xef\xbb\xbf{"a":1}', b'{"a":"tab\there"}', b'{"a":1} x',
        '{"\u00e9":1,"e\u0301":2}'.encode(),                                  # duplicate only after normalisation
    ]
    expected = []
    for document in documents:
        try:
            expected.append(fingerprint(JSON_SORTED_V1, document))
        except CanonicalError:
            expected.append(None)
    assert expected[0] == expected[1] == vectors["canon"]["canonical_hash"]
    assert expected.count(None) == 15

    done = run(NODE, RUNNER, "canon", stdin=json.dumps([base64.b64encode(d).decode() for d in documents]))
    assert done.returncode == 0, done.stderr
    got = [item.get("fingerprint") for item in json.loads(done.stdout)]
    assert got == expected
