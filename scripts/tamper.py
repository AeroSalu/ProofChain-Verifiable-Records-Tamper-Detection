"""Play the insider: change stored records behind the registry's back.

    python scripts/tamper.py content      [--record N]   change a record's stored content only
    python scripts/tamper.py fingerprint  [--record N]   change a record's stored fingerprint only
    python scripts/tamper.py rewrite      [--record N]   change content, fingerprint and batch root together,
                                                         and issue a fresh, self-consistent proof
    python scripts/tamper.py ledger                      write a rewritten, re-signed copy of the ledger that
                                                         agrees with the altered database
    python scripts/tamper.py restore                     put the database back as it was

The database is edited with plain SQL, the way someone with file access would
do it, and never through the registry service. A copy of the database is kept
before the first change so `restore` can undo everything.

`ledger` models a stronger attacker who also holds the ledger's key. It never
touches the real ledger file: it writes a rewritten copy for the verifier to be
pointed at, which a pinned checkpoint then exposes.
"""

import argparse
import json
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proofchain.core.canonical import CanonicalError, fingerprint  # noqa: E402
from proofchain.core.ledger_format import GENESIS_PREV_HASH, entry_hash  # noqa: E402
from proofchain.core.merkle import merkle_root  # noqa: E402
from proofchain.core.proof import create_bundle, leaf_values  # noqa: E402
from proofchain.ledger.keys import load_or_create_key, sign_entry_hash  # noqa: E402

DEFAULT_DB = "data/registry.db"
ALTERATION = b"\n(altered after registration)\n"


class TamperError(Exception):
    pass


def _backup_path(db_path) -> Path:
    return Path(f"{db_path}.before-tamper")


def _open(db_path) -> sqlite3.Connection:
    if not Path(db_path).exists():
        raise TamperError(f"there is no database at {db_path}")
    backup = _backup_path(db_path)
    if not backup.exists():
        shutil.copyfile(db_path, backup)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _sealed_record(conn, record_id):
    row = conn.execute(
        "SELECT r.*, b.status FROM records r LEFT JOIN batches b ON b.id = r.batch_id WHERE r.id = ?", (record_id,)
    ).fetchone()
    if row is None:
        raise TamperError(f"there is no record {record_id}")
    if row["status"] != "sealed":
        raise TamperError(f"record {record_id} is not in a sealed batch, so there is nothing published to contradict")
    return row


def _forged(row, text) -> tuple[bytes, str]:
    content = text.encode("utf-8") if text is not None else bytes(row["content"]) + ALTERATION
    try:
        return content, fingerprint(row["canon"], content)
    except CanonicalError as exc:
        raise TamperError(f"record {row['id']} is a {row['canon']} record and the new content does not fit that "
                          f"form ({exc}). Pass valid content with --text, or pick another record.") from exc


def change_content(db_path, record_id, text=None) -> dict:
    """Replace a record's stored content, leaving its fingerprint alone."""
    conn = _open(db_path)
    try:
        row = _sealed_record(conn, record_id)
        content, _ = _forged(row, text)
        conn.execute("UPDATE records SET content = ? WHERE id = ?", (content, record_id))
        conn.commit()
        return {"record": record_id, "filename": row["filename"], "batch_id": row["batch_id"]}
    finally:
        conn.close()


def change_fingerprint(db_path, record_id, text=None) -> dict:
    """Replace a record's stored fingerprint, leaving its content alone."""
    conn = _open(db_path)
    try:
        row = _sealed_record(conn, record_id)
        _, forged_fingerprint = _forged(row, text)
        conn.execute("UPDATE records SET fingerprint = ? WHERE id = ?", (forged_fingerprint, record_id))
        conn.commit()
        return {"record": record_id, "filename": row["filename"], "batch_id": row["batch_id"]}
    finally:
        conn.close()


def rewrite(db_path, record_id, out_dir, text=None) -> dict:
    """Change content, fingerprint and batch root together, then issue a fresh proof.

    Afterwards the database is consistent with itself: the forged document
    hashes to its stored fingerprint, and the stored fingerprints rebuild the
    stored root. Only the ledger still holds the root that was published.
    """
    conn = _open(db_path)
    try:
        row = _sealed_record(conn, record_id)
        content, forged_fingerprint = _forged(row, text)
        conn.execute("UPDATE records SET content = ?, fingerprint = ? WHERE id = ?",
                     (content, forged_fingerprint, record_id))
        leaves = conn.execute("SELECT fingerprint, salt FROM records WHERE batch_id = ? ORDER BY leaf_index, id",
                              (row["batch_id"],)).fetchall()
        fingerprints, salts = [r["fingerprint"] for r in leaves], [r["salt"] for r in leaves]
        root = merkle_root(leaf_values(fingerprints, salts)).hex()
        conn.execute("UPDATE batches SET root = ? WHERE id = ?", (root, row["batch_id"]))
        conn.commit()
        bundle = create_bundle(row["canon"], row["batch_id"], fingerprints, row["leaf_index"], salts)
    finally:
        conn.close()

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    document = out_dir / f"forged_{row['filename']}"
    proof = out_dir / f"forged_{row['filename']}.proof.json"
    document.write_bytes(content)
    bundle.save(proof)
    return {"record": record_id, "filename": row["filename"], "batch_id": row["batch_id"], "root": root,
            "document": str(document), "proof": str(proof)}


def rewrite_ledger(db_path, ledger_file, key_file, out_file) -> dict:
    """Write a copy of the ledger whose roots agree with the database, re-signed with the ledger key."""
    if not Path(ledger_file).exists() or not Path(key_file).exists():
        raise TamperError(f"this needs the ledger file ({ledger_file}) and the ledger key ({key_file})")
    conn = sqlite3.connect(db_path)
    try:
        roots = dict(conn.execute("SELECT id, root FROM batches WHERE status = 'sealed'"))
    finally:
        conn.close()
    entries = [json.loads(line) for line in Path(ledger_file).read_text(encoding="utf-8").splitlines() if line.strip()]
    key = load_or_create_key(key_file)

    changed, previous = [], GENESIS_PREV_HASH
    for entry in entries:
        if roots.get(entry["batch_id"], entry["root"]) != entry["root"]:
            entry["root"] = roots[entry["batch_id"]]
            changed.append(entry["batch_id"])
        entry["prev_hash"] = previous
        entry["entry_hash"] = entry_hash(entry)
        entry["signature"] = sign_entry_hash(key, entry["entry_hash"])
        previous = entry["entry_hash"]
    if not changed:
        raise TamperError("the ledger already agrees with the database; run `rewrite` first")

    out_file = Path(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8", newline="\n")
    return {"changed": changed, "out": str(out_file), "entries": len(entries)}


def restore(db_path) -> bool:
    """Put back the copy taken before the first change. False if there was none."""
    backup = _backup_path(db_path)
    if not backup.exists():
        return False
    shutil.copyfile(backup, db_path)
    backup.unlink()
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Alter the registry's stored data, as an insider would.")
    parser.add_argument("action", choices=("content", "fingerprint", "rewrite", "ledger", "restore"))
    parser.add_argument("--db", default=DEFAULT_DB, help="registry database (default: %(default)s)")
    parser.add_argument("--record", type=int, default=2, help="record id to alter (default: %(default)s)")
    parser.add_argument("--text", help="replacement content (default: the original with a line added)")
    parser.add_argument("--out", default="data/demo", help="folder for forged files (default: %(default)s)")
    parser.add_argument("--ledger-file", default="data/ledger.jsonl", help="for `ledger` (default: %(default)s)")
    parser.add_argument("--key-file", default="data/ledger_key.pem", help="for `ledger` (default: %(default)s)")
    args = parser.parse_args(argv)
    out = Path(args.out)

    try:
        if args.action == "content":
            done = change_content(args.db, args.record, args.text)
            print(f"Changed the stored content of record {done['record']} ({done['filename']}). Fingerprint untouched.")
            print("Audit page: expect STORED_CONTENT_CHANGED. The holder's original document still verifies.")
        elif args.action == "fingerprint":
            done = change_fingerprint(args.db, args.record, args.text)
            print(f"Changed the stored fingerprint of record {done['record']} ({done['filename']}). Content untouched.")
            print("Audit page: expect STORED_FINGERPRINT_CHANGED and BATCH_ROOT_DIVERGED.")
        elif args.action == "rewrite":
            done = rewrite(args.db, args.record, out)
            print(f"Rewrote record {done['record']} ({done['filename']}): content, fingerprint and the root of {done['batch_id']}.")
            print(f"The database now agrees with itself. Forged document and fresh proof: {done['document']}")
            print("Audit page: expect BATCH_ROOT_DIVERGED. Verifier: expect ROOT_MISMATCH:")
            print(f"  python -m proofchain.verifier verify --doc {done['document']} --proof {done['proof']} "
                  f"--ledger http://localhost:8001 --pin-file {out / 'pin.json'}")
        elif args.action == "ledger":
            target = out / "ledger_rewritten.jsonl"
            done = rewrite_ledger(args.db, args.ledger_file, args.key_file, target)
            print(f"Wrote {done['out']}: {done['entries']} entries, re-signed, with new roots for {', '.join(done['changed'])}.")
            print("The real ledger file was not touched. Point the verifier at the rewritten copy:")
            print("  with the pin file: expect LEDGER_INVALID. Without a pin: the forged document passes.")
        else:
            if restore(args.db):
                print(f"Restored {args.db} to its state before tampering.")
            else:
                print("Nothing to restore: no copy was taken, so the database has not been altered by this script.")
    except TamperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
