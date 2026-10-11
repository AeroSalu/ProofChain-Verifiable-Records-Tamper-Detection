"""The registry checking its own storage against the ledger.

For every record the fingerprint is recomputed from the stored content. For
every sealed batch the root is rebuilt from the stored fingerprints and
compared with the root the ledger published. The ledger is the reference; the
database is what is being checked.

STORED_CONTENT_CHANGED      a record's content no longer hashes to its stored
                            fingerprint
STORED_FINGERPRINT_CHANGED  a record's content still fits the published root,
                            but its stored fingerprint does not
BATCH_ROOT_DIVERGED         a batch's stored fingerprints no longer rebuild the
                            published root
"""

from dataclasses import dataclass, field

from ..core.canonical import CanonicalError, fingerprint
from ..core.merkle import merkle_root
from ..verifier.verify import Pin, ledger_problems
from . import models
from .ledger_client import LedgerError

STORED_CONTENT_CHANGED = "STORED_CONTENT_CHANGED"
STORED_FINGERPRINT_CHANGED = "STORED_FINGERPRINT_CHANGED"
BATCH_ROOT_DIVERGED = "BATCH_ROOT_DIVERGED"

OK = "ok"
PROBLEM = "problem"
UNCHECKED = "unchecked"


@dataclass(frozen=True)
class Finding:
    subject: str  # "record 3" or "batch-0001"
    label: str  # the file name, or the batch status
    state: str
    detail: str
    code: str | None = None
    computed: str | None = None
    expected: str | None = None


@dataclass
class AuditReport:
    records: list[Finding] = field(default_factory=list)
    batches: list[Finding] = field(default_factory=list)
    ledger_state: str = OK
    ledger_detail: str = ""
    ledger_problems: list[str] = field(default_factory=list)

    @property
    def codes(self) -> list[str]:
        return [f.code for f in self.batches + self.records if f.code]

    @property
    def ok(self) -> bool:
        return self.ledger_state == OK and all(f.state == OK for f in self.batches + self.records)


def registry_pin(conn) -> Pin | None:
    pin = models.latest_pin(conn)
    return None if pin is None else Pin(*pin)


def known_public_key(conn, ledger) -> bytes:
    """The ledger key recorded at the first seal, or the ledger's current one."""
    text = models.get_meta(conn, models.LEDGER_PUBLIC_KEY) or ledger.public_key()
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""  # reported by the ledger check as an invalid key


def _recomputed(record) -> str | None:
    try:
        return fingerprint(record["canon"], record["content"])
    except CanonicalError:
        return None


def _root(fingerprints) -> str | None:
    try:
        return merkle_root([bytes.fromhex(fp) for fp in fingerprints]).hex()
    except (TypeError, ValueError):
        return None  # empty batch, or something that is not a 32-byte hash


def _published(entries) -> dict:
    by_batch = {}
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("batch_id"), str):
            by_batch.setdefault(entry["batch_id"], entry)
    return by_batch


def run_audit(conn, ledger) -> AuditReport:
    report = AuditReport()
    records = models.records_with_content(conn)
    recomputed = {record["id"]: _recomputed(record) for record in records}

    try:
        entries = ledger.entries()
        problems = ledger_problems(entries, known_public_key(conn, ledger), registry_pin(conn))
    except LedgerError as exc:
        entries = None
        report.ledger_state, report.ledger_detail = UNCHECKED, str(exc)
    else:
        report.ledger_problems = problems
        report.ledger_state = PROBLEM if problems else OK
        if problems:
            report.ledger_detail = "The ledger is not the sound chain this registry published to."
        else:
            count = "1 entry" if len(entries) == 1 else f"{len(entries)} entries"
            report.ledger_detail = (f"{count}. Chain links, entry hashes and signatures hold, and the newest "
                                    "entry this registry published is still in place.")
    published = _published(entries or [])

    # For each batch: do the stored fingerprints, and do the fingerprints
    # recomputed from content, rebuild the published root?
    fits = {}
    for batch in sorted(models.list_batches(conn), key=lambda b: b["id"]):
        members = [r for r in records if r["batch_id"] == batch["id"]]
        members.sort(key=lambda r: (r["leaf_index"] is None, r["leaf_index"], r["id"]))
        entry = published.get(batch["id"])
        subject, label = batch["id"], batch["status"]

        if batch["status"] == "open":
            if entry is not None:
                report.batches.append(Finding(subject, label, PROBLEM,
                                              "marked open here, but the ledger already holds a root for it",
                                              BATCH_ROOT_DIVERGED, expected=entry.get("root")))
            else:
                report.batches.append(Finding(subject, label, OK, "open: nothing published yet"))
            continue
        if entries is None:
            report.batches.append(Finding(subject, label, UNCHECKED, "not checked: the ledger could not be read"))
            continue
        if entry is None:
            report.batches.append(Finding(subject, label, PROBLEM,
                                          "sealed here, but the ledger has no entry for it", BATCH_ROOT_DIVERGED))
            continue

        stored_root = _root([r["fingerprint"] for r in members])
        content_root = _root([recomputed[r["id"]] for r in members])
        fits[batch["id"]] = (stored_root == entry.get("root"), content_root == entry.get("root"))
        if stored_root != entry.get("root"):
            detail = "the root rebuilt from the stored fingerprints is not the published root"
        elif len(members) != entry.get("tree_size"):
            detail = f"{len(members)} records are stored; the ledger says {entry.get('tree_size')}"
        elif batch["root"] != entry.get("root"):
            detail = "the root recorded in the batches table is not the published root"
        else:
            report.batches.append(Finding(subject, label, OK, "the stored fingerprints rebuild the published root",
                                          computed=stored_root, expected=entry.get("root")))
            continue
        report.batches.append(Finding(subject, label, PROBLEM, detail, BATCH_ROOT_DIVERGED,
                                      stored_root if stored_root != entry.get("root") else batch["root"],
                                      entry.get("root")))

    for record in records:
        subject, label = f"record {record['id']}", record["filename"]
        computed, stored = recomputed[record["id"]], record["fingerprint"]
        stored_fits, content_fits = fits.get(record["batch_id"], (None, None))
        if computed != stored:
            if content_fits and not stored_fits:
                report.records.append(Finding(subject, label, PROBLEM,
                                              "the content still fits the published root; the stored fingerprint does not",
                                              STORED_FINGERPRINT_CHANGED, computed, stored))
            else:
                report.records.append(Finding(subject, label, PROBLEM,
                                              "the stored content no longer hashes to the stored fingerprint",
                                              STORED_CONTENT_CHANGED, computed, stored))
        elif stored_fits is False:
            report.records.append(Finding(subject, label, UNCHECKED,
                                          f"cannot be confirmed: {record['batch_id']} no longer rebuilds its published root",
                                          computed=computed, expected=stored))
        elif stored_fits is None:
            report.records.append(Finding(subject, label, OK,
                                          "content matches its fingerprint; no published root to compare with yet",
                                          computed=computed, expected=stored))
        else:
            report.records.append(Finding(subject, label, OK,
                                          "content matches its fingerprint, which fits the published root",
                                          computed=computed, expected=stored))
    return report
