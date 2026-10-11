"""The five verification checks.

A verdict is built from three things only: the document, its proof bundle and
the published ledger. Nothing here reads the registry or its database.

All five checks run every time, and each one isolates a single cause:

1. fingerprint   the document hashes to the bundle's fingerprint
2. proof         the path, folded from the bundle's own fingerprint, reaches
                 the bundle's root (so an edited document does not also raise
                 a proof error)
3. publication   the ledger has an entry for the bundle's batch
4. root          the bundle's root and tree size equal that entry's
5. ledger        chain links, entry hashes, signatures and the pinned
                 checkpoint all hold

Signatures are Ed25519 over the 32 raw bytes of entry_hash, stored as base64.
"""

import base64
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..core.canonical import CanonicalError, fingerprint
from ..core.ledger_format import LedgerFormatError, chain_problems, check_entry
from ..core.proof import ProofBundle, ProofFormatError, from_dict

DOCUMENT_MODIFIED = "DOCUMENT_MODIFIED"
PROOF_INVALID = "PROOF_INVALID"
BATCH_NOT_PUBLISHED = "BATCH_NOT_PUBLISHED"
ROOT_MISMATCH = "ROOT_MISMATCH"
LEDGER_INVALID = "LEDGER_INVALID"

PASS = "pass"
FAIL = "fail"
SKIPPED = "skipped"

_PIN = re.compile(r"(\d+):([0-9a-f]{64})")


@dataclass(frozen=True)
class Check:
    name: str
    code: str  # reported when this check fails
    status: str
    detail: str
    computed: str | None = None
    expected: str | None = None


@dataclass(frozen=True)
class Pin:
    """A ledger entry the verifier has seen before and expects to see again."""

    seq: int
    entry_hash: str

    def __str__(self) -> str:
        return f"{self.seq}:{self.entry_hash}"


@dataclass(frozen=True)
class Result:
    checks: tuple[Check, ...]
    batch_id: str | None = None
    ledger_seq: int | None = None
    pinned: bool = False

    @property
    def ok(self) -> bool:
        return all(check.status == PASS for check in self.checks)

    @property
    def codes(self) -> list[str]:
        return [check.code for check in self.checks if check.status == FAIL]

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "codes": self.codes,
            "batch_id": self.batch_id,
            "ledger_seq": self.ledger_seq,
            "pinned": self.pinned,
            "checks": [vars(check) for check in self.checks],
        }


def parse_pin(text: str) -> Pin:
    match = _PIN.fullmatch(text.strip())
    if not match:
        raise ValueError("a pin looks like <seq>:<64 lowercase hex characters>")
    return Pin(int(match.group(1)), match.group(2))


def _well_formed(entry) -> bool:
    try:
        check_entry(entry)
    except LedgerFormatError:
        return False
    return True


def signature_problems(entries, public_key: bytes) -> list[str]:
    """Describe every entry whose signature is missing or wrong."""
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        return ["the ledger public key is not a valid Ed25519 key"]
    problems = []
    for position, entry in enumerate(entries):
        if not _well_formed(entry):
            continue  # already reported by chain_problems
        if "signature" not in entry:
            problems.append(f"entry {position} is not signed")
            continue
        try:
            signature = base64.b64decode(entry["signature"], validate=True)
            key.verify(signature, bytes.fromhex(entry["entry_hash"]))
        except (InvalidSignature, ValueError):
            problems.append(f"entry {position}: signature does not match its entry_hash")
    return problems


def pin_problems(entries, pin: Pin) -> list[str]:
    if pin.seq >= len(entries):
        return [f"pinned entry {pin.seq} is missing: the ledger has only {len(entries)} entries"]
    entry = entries[pin.seq]
    found = entry.get("entry_hash") if isinstance(entry, dict) else None
    if found != pin.entry_hash:
        return [f"pinned entry {pin.seq} has changed: entry_hash is {found}, pinned {pin.entry_hash}"]
    return []


def ledger_problems(entries, public_key: bytes, pin: Pin | None = None) -> list[str]:
    """Everything wrong with the ledger. Empty means it is sound."""
    problems = chain_problems(entries) + signature_problems(entries, public_key)
    if pin is not None:
        problems += pin_problems(entries, pin)
    return problems


def _find_entry(entries, batch_id: str):
    for entry in entries:
        if _well_formed(entry) and entry["batch_id"] == batch_id:
            return entry
    return None


def _check_fingerprint(document: bytes, bundle: ProofBundle) -> Check:
    name = "Fingerprint check"
    try:
        computed = fingerprint(bundle.canon, document)
    except CanonicalError as exc:
        return Check(name, DOCUMENT_MODIFIED, FAIL,
                     f"the document cannot be put into {bundle.canon} form: {exc}",
                     expected=bundle.fingerprint)
    if computed != bundle.fingerprint:
        return Check(name, DOCUMENT_MODIFIED, FAIL,
                     "the document does not hash to the fingerprint in the proof",
                     computed, bundle.fingerprint)
    return Check(name, DOCUMENT_MODIFIED, PASS,
                 "the document hashes to the fingerprint in the proof",
                 computed, bundle.fingerprint)


def _check_proof(bundle: ProofBundle) -> Check:
    name = "Proof check"
    computed = bundle.computed_root()
    if computed != bundle.root:
        return Check(name, PROOF_INVALID, FAIL,
                     "the path does not lead from the proof's fingerprint to the proof's root",
                     computed, bundle.root)
    return Check(name, PROOF_INVALID, PASS,
                 "the path leads from the proof's fingerprint to the proof's root",
                 computed, bundle.root)


def _check_publication(bundle: ProofBundle, entry) -> Check:
    name = "Publication check"
    if entry is None:
        return Check(name, BATCH_NOT_PUBLISHED, FAIL,
                     f"the ledger has no entry for batch {bundle.batch_id}")
    return Check(name, BATCH_NOT_PUBLISHED, PASS,
                 f"batch {bundle.batch_id} was published in ledger entry {entry['seq']}")


def _check_root(bundle: ProofBundle, entry) -> Check:
    name = "Root check"
    if entry is None:
        return Check(name, ROOT_MISMATCH, SKIPPED, "not run: there is no published root to compare with")
    if bundle.root != entry["root"]:
        return Check(name, ROOT_MISMATCH, FAIL,
                     "the proof's root is not the root published for this batch",
                     bundle.root, entry["root"])
    if bundle.tree_size != entry["tree_size"]:
        return Check(name, ROOT_MISMATCH, FAIL,
                     f"the proof says the batch has {bundle.tree_size} records; "
                     f"the ledger says {entry['tree_size']}",
                     bundle.root, entry["root"])
    return Check(name, ROOT_MISMATCH, PASS,
                 "the proof's root and tree size equal the published entry",
                 bundle.root, entry["root"])


def _check_ledger(entries, public_key: bytes, pin: Pin | None) -> Check:
    name = "Ledger check"
    problems = ledger_problems(entries, public_key, pin)
    if problems:
        return Check(name, LEDGER_INVALID, FAIL, "; ".join(problems))
    detail = f"{len(entries)} entries: chain links, entry hashes and signatures hold"
    if pin is None:
        detail += " (no checkpoint pinned, so a fully rewritten ledger would not be noticed)"
    else:
        detail += f", and pinned entry {pin.seq} is present"
    return Check(name, LEDGER_INVALID, PASS, detail)


def verify(document: bytes, bundle, entries, public_key: bytes, pin: Pin | None = None) -> Result:
    """Run all five checks.

    bundle is a ProofBundle or the decoded JSON of one. entries is the whole
    ledger in order. public_key is the ledger's raw 32-byte Ed25519 key.
    """
    entries = list(entries)
    ledger_check = _check_ledger(entries, public_key, pin)

    if not isinstance(bundle, ProofBundle):
        try:
            bundle = from_dict(bundle)
        except ProofFormatError as exc:
            reason = "not run: the proof bundle could not be read"
            return Result(
                checks=(
                    Check("Fingerprint check", DOCUMENT_MODIFIED, SKIPPED, reason),
                    Check("Proof check", PROOF_INVALID, FAIL, f"the proof bundle is malformed: {exc}"),
                    Check("Publication check", BATCH_NOT_PUBLISHED, SKIPPED, reason),
                    Check("Root check", ROOT_MISMATCH, SKIPPED, reason),
                    ledger_check,
                ),
                pinned=pin is not None,
            )

    entry = _find_entry(entries, bundle.batch_id)
    return Result(
        checks=(
            _check_fingerprint(document, bundle),
            _check_proof(bundle),
            _check_publication(bundle, entry),
            _check_root(bundle, entry),
            ledger_check,
        ),
        batch_id=bundle.batch_id,
        ledger_seq=None if entry is None else entry["seq"],
        pinned=pin is not None,
    )
