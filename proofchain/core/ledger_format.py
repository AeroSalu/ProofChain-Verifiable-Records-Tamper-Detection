"""The ledger entry format and the hash chain rules.

Each entry publishes one batch root and names the entry before it:

    entry_hash = SHA-256(canonical JSON of seq, batch_id, root, tree_size,
                         published_at, prev_hash)

The ledger service writes entries in this format and the verifier checks them
with the same code. Signatures are Ed25519 over entry_hash; checking them needs
a third-party library, so it is left to the ledger and the verifier.
"""

import re

from .canonical import canonical_json, sha256_hex

GENESIS_PREV_HASH = "0" * 64

BODY_FIELDS = ("seq", "batch_id", "root", "tree_size", "published_at", "prev_hash")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class LedgerFormatError(ValueError):
    """A ledger entry is malformed."""


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex64(value) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def check_body(entry) -> None:
    """Raise LedgerFormatError unless the six hashed fields are well formed."""
    if not isinstance(entry, dict):
        raise LedgerFormatError("entry must be a JSON object")
    missing = [name for name in BODY_FIELDS if name not in entry]
    if missing:
        raise LedgerFormatError(f"entry is missing: {', '.join(missing)}")
    if not _is_int(entry["seq"]) or entry["seq"] < 0:
        raise LedgerFormatError("seq must be a non-negative integer")
    if not isinstance(entry["batch_id"], str) or not entry["batch_id"]:
        raise LedgerFormatError("batch_id must be a non-empty string")
    if not _is_hex64(entry["root"]):
        raise LedgerFormatError("root must be 64 lowercase hex characters")
    if not _is_int(entry["tree_size"]) or entry["tree_size"] < 1:
        raise LedgerFormatError("tree_size must be a positive integer")
    if not isinstance(entry["published_at"], str) or not _TIMESTAMP.fullmatch(entry["published_at"]):
        raise LedgerFormatError("published_at must look like 2026-10-12T09:00:00Z")
    if not _is_hex64(entry["prev_hash"]):
        raise LedgerFormatError("prev_hash must be 64 lowercase hex characters")


def check_entry(entry) -> None:
    """Raise LedgerFormatError unless the entry is well formed, entry_hash included."""
    check_body(entry)
    if not _is_hex64(entry.get("entry_hash")):
        raise LedgerFormatError("entry_hash must be 64 lowercase hex characters")
    if "signature" in entry and not isinstance(entry["signature"], str):
        raise LedgerFormatError("signature must be a string")


def entry_hash(entry) -> str:
    """SHA-256 of the canonical JSON of the six body fields, as hex."""
    check_body(entry)
    return sha256_hex(canonical_json({name: entry[name] for name in BODY_FIELDS}))


def next_entry(previous, batch_id: str, root: str, tree_size: int, published_at: str) -> dict:
    """The unsigned entry that follows previous (None for the first entry)."""
    entry = {
        "seq": 0 if previous is None else previous["seq"] + 1,
        "batch_id": batch_id,
        "root": root,
        "tree_size": tree_size,
        "published_at": published_at,
        "prev_hash": GENESIS_PREV_HASH if previous is None else previous["entry_hash"],
    }
    entry["entry_hash"] = entry_hash(entry)
    return entry


def chain_problems(entries) -> list[str]:
    """Walk the chain and describe everything wrong with it. Empty means sound.

    Checks each entry's format, that seq counts up from 0, that entry_hash is
    the hash of the entry's own fields, that prev_hash equals the previous
    entry's hash, and that no batch is published twice. It does not check
    signatures or pinned checkpoints.
    """
    problems = []
    expected_prev = GENESIS_PREV_HASH
    seen_batches = {}
    for position, entry in enumerate(entries):
        try:
            check_entry(entry)
        except LedgerFormatError as exc:
            problems.append(f"entry at position {position} is malformed: {exc}")
            expected_prev = None
            continue
        if entry["seq"] != position:
            problems.append(f"entry at position {position} has seq {entry['seq']}")
        computed = entry_hash(entry)
        if entry["entry_hash"] != computed:
            problems.append(
                f"entry {position}: entry_hash is {entry['entry_hash']} but its fields hash to {computed}"
            )
        if expected_prev is not None and entry["prev_hash"] != expected_prev:
            problems.append(
                f"entry {position}: prev_hash is {entry['prev_hash']} but the previous entry_hash is {expected_prev}"
            )
        if entry["batch_id"] in seen_batches:
            problems.append(
                f"entry {position}: batch {entry['batch_id']} was already published in entry {seen_batches[entry['batch_id']]}"
            )
        else:
            seen_batches[entry["batch_id"]] = position
        expected_prev = entry["entry_hash"]
    return problems
