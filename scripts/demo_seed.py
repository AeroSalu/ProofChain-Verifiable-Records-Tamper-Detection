"""Put the demo into a known starting state.

    python scripts/demo_seed.py [--db data/registry.db] [--ledger http://localhost:8001] [--out data/demo]

Needs the ledger service running, and PROOFCHAIN_LEDGER_TOKEN set in this
terminal to the same value the ledger was started with; the registry may be
running or stopped. It registers four sample documents, seals them into one
batch, and leaves a fifth waiting for confirmation so the Register page has
something to show. Each sealed document is written to the output folder with
its proof bundle, and the ledger head is pinned to pin.json there.

It also creates a staff account named "demo" with a random password, printed
once, for signing in to the pages. The sample records are confirmed under that
account by this script, which stands in for the person who would normally check
them. That is acceptable for demo data only.
"""

import argparse
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proofchain.ai import fallback  # noqa: E402
from proofchain.core.canonical import JSON_SORTED_V1, RAW_BYTES_V1, fingerprint  # noqa: E402
from proofchain.registry import batching, db, models, staff  # noqa: E402
from proofchain.registry.ledger_client import LedgerClient, LedgerError, default_url  # noqa: E402
from proofchain.verifier.verify import ledger_problems  # noqa: E402

DEMO_ACCOUNT = "demo"

DEGREE = b"""RIVERSIDE UNIVERSITY
Office of the Registrar

Degree Certificate

This is to certify that Asha Rao has been awarded the degree of
Bachelor of Science in Computer Science, with First Class Honours.

Date of award: 30 June 2026
Certificate number: RU-2026-004417
"""

TRANSCRIPT = b"""RIVERSIDE UNIVERSITY
Transcript of Academic Record

Student: Asha Rao            Programme: BSc Computer Science
Data Structures       A
Operating Systems     A-
Cryptography          A
Distributed Systems   B+

Issued: 2 July 2026
"""

CONTRACT = b"""SUPPLY AGREEMENT

Between Northwind Traders Ltd (the Supplier) and Harbour Cafe (the Buyer).

1. The Supplier will deliver 40 kg of roasted coffee each month.
2. The price is 18.50 per kg, fixed for twelve months.
3. Either party may end this agreement with 30 days' written notice.

Signed on 14 March 2026.
"""

LICENCE = json.dumps({
    "licence_no": "TL-88213",
    "holder": "Harbour Cafe",
    "issued_by": "City Licensing Office",
    "type": "Food premises licence",
    "valid_from": "2026-01-01",
    "valid_to": "2026-12-31",
}, indent=2).encode()

AWARD = b"""CITY ARTS COUNCIL

Letter of Award

Dear Ms Rao,
We are pleased to confirm a grant of 2,500 towards your community coding workshop.

Issued by: City Arts Council
5 September 2026
"""

# (file name, content, canonical form, confirmed metadata)
SEALED = (
    ("degree_asha_rao.txt", DEGREE, RAW_BYTES_V1,
     {"issuer": "Riverside University", "date": "2026-06-30", "document_type": "Degree certificate", "category": "Education"}),
    ("transcript_asha_rao.txt", TRANSCRIPT, RAW_BYTES_V1,
     {"issuer": "Riverside University", "date": "2026-07-02", "document_type": "Transcript", "category": "Education"}),
    ("supply_agreement.txt", CONTRACT, RAW_BYTES_V1,
     {"issuer": "Northwind Traders Ltd", "date": "2026-03-14", "document_type": "Contract", "category": "Legal"}),
    ("food_licence.json", LICENCE, JSON_SORTED_V1,
     {"issuer": "City Licensing Office", "date": "2026-01-01", "document_type": "Licence", "category": "Licensing"}),
)
PENDING = ("award_letter.txt", AWARD, RAW_BYTES_V1)


class SeedError(Exception):
    pass


def _add(conn, filename, content, canon) -> int:
    suggested = fallback.suggest_from_text(filename, content.decode("utf-8"))
    return models.add_record(conn, filename, content, canon, fingerprint(canon, content), suggested)


def _demo_account(conn) -> str | None:
    """Create the demo account. Returns its new password, or None if the account was already there."""
    if staff.exists(conn, DEMO_ACCOUNT):
        return None
    password = secrets.token_urlsafe(9)
    staff.add_staff(conn, DEMO_ACCOUNT, password)
    return password


def seed(db_path, ledger_url, out_dir, add=False) -> dict:
    """Seed the registry and write the demo files. Returns a summary of what was done."""
    out_dir = Path(out_dir)
    ledger = LedgerClient(ledger_url)
    if not ledger.token:
        raise SeedError("PROOFCHAIN_LEDGER_TOKEN is not set in this terminal. Set it to the value the ledger "
                        "was started with, so the sample batch can be published.")
    db.init_db(db_path)
    conn = db.connect(db_path)
    try:
        existing = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        if existing and not add:
            raise SeedError(f"{db_path} already holds {existing} records. Start from empty data "
                            "(see the README), or pass --add to add the samples anyway.")
        try:
            ledger.entries()
        except LedgerError as exc:
            raise SeedError(f"{exc}. Start the ledger first: uvicorn proofchain.ledger.app:app --port 8001") from exc

        password = _demo_account(conn)
        record_ids = []
        for filename, content, canon, metadata in SEALED:
            record_id = _add(conn, filename, content, canon)
            batch_id = batching.confirm_record(conn, record_id, metadata, DEMO_ACCOUNT)
            record_ids.append(record_id)
        try:
            entry = batching.seal_batch(conn, batch_id, ledger)
        except LedgerError as exc:
            raise SeedError(f"{exc}. The samples were added and {batch_id} is still open; start from empty "
                            "data again once this is fixed.") from exc
        pending_id = _add(conn, *PENDING)

        out_dir.mkdir(parents=True, exist_ok=True)
        files = []
        for record_id, (filename, content, _, _) in zip(record_ids, SEALED):
            _, bundle = batching.build_proof(conn, record_id)
            (out_dir / filename).write_bytes(content)
            bundle.save(out_dir / f"{filename}.proof.json")
            files.append(filename)
    finally:
        conn.close()

    entries, public_key = ledger.entries(), ledger.public_key()
    problems = ledger_problems(entries, bytes.fromhex(public_key))
    if problems:
        raise SeedError("the ledger is not sound, so nothing was pinned: " + "; ".join(problems))
    head = entries[-1]
    pin = {"ledger": ledger_url, "public_key": public_key, "seq": head["seq"], "entry_hash": head["entry_hash"]}
    (out_dir / "pin.json").write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")

    return {"batch_id": batch_id, "root": entry["root"], "ledger_seq": entry["seq"], "record_ids": record_ids,
            "pending_id": pending_id, "files": files, "out_dir": str(out_dir),
            "account": DEMO_ACCOUNT, "password": password}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Seed the ProofChain demo with sample documents.")
    parser.add_argument("--db", default=db.default_path(), help="registry database (default: %(default)s)")
    parser.add_argument("--ledger", default=default_url(), help="ledger service URL (default: %(default)s)")
    parser.add_argument("--out", default="data/demo", help="folder for documents, proofs and the pin (default: %(default)s)")
    parser.add_argument("--add", action="store_true", help="add the samples even if the database already has records")
    args = parser.parse_args(argv)
    try:
        done = seed(args.db, args.ledger, args.out, args.add)
    except SeedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = Path(done["out_dir"])
    first = done["files"][0]
    print(f"Sealed {len(done['files'])} documents into {done['batch_id']} (ledger entry {done['ledger_seq']}).")
    print(f"Root: {done['root']}")
    print(f"Record {done['pending_id']} ({PENDING[0]}) is waiting for confirmation on the Register page.")
    print(f"Documents, proofs and pin.json are in {out}.")
    print()
    if done["password"]:
        print(f"Sign in to the registry pages as:  {done['account']}  /  {done['password']}")
        print("This password is shown once and only its hash is stored. It is for the demo; create real")
        print("accounts with: python -m proofchain.registry.staff add <username>")
    else:
        print(f"The account {done['account']} already existed, so its password was left as it was.")
    print()
    print("Verify one independently:")
    print(f"  python -m proofchain.verifier verify --doc {out / first} --proof {out / (first + '.proof.json')} "
          f"--ledger {args.ledger} --pin-file {out / 'pin.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
