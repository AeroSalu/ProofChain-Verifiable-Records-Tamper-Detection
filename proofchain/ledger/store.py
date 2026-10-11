"""The ledger file: one signed JSON entry per line, only ever appended to.

There is no method here to change or remove an entry. The file is opened in
append mode for every write, and the whole chain is checked when the store
opens, so a ledger that was edited on disk is refused instead of extended.
"""

import base64
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core.ledger_format import chain_problems, next_entry
from .keys import sign_entry_hash


class LedgerCorrupt(Exception):
    """The ledger file on disk does not form a sound, signed chain."""


class DuplicateBatch(Exception):
    """A root has already been published for this batch."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(path: Path) -> list:
    if not path.exists():
        return []
    entries = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError as exc:
            raise LedgerCorrupt(f"line {number} of {path} is not JSON") from exc
    return entries


class LedgerStore:
    def __init__(self, path, key: Ed25519PrivateKey):
        self.path = Path(path)
        self._key = key
        self._lock = threading.Lock()
        self._entries = _read(self.path)
        problems = chain_problems(self._entries) + self._signature_problems()
        if problems:
            raise LedgerCorrupt("; ".join(problems))
        self._by_batch = {entry["batch_id"]: entry for entry in self._entries}

    def _signature_problems(self) -> list[str]:
        public_key = self._key.public_key()
        problems = []
        for position, entry in enumerate(self._entries):
            if not isinstance(entry, dict) or not isinstance(entry.get("entry_hash"), str):
                continue  # already reported by chain_problems
            try:
                signature = base64.b64decode(entry.get("signature", ""), validate=True)
                public_key.verify(signature, bytes.fromhex(entry["entry_hash"]))
            except (InvalidSignature, ValueError, TypeError):
                problems.append(f"entry {position} was not signed by this ledger's key")
        return problems

    def append(self, batch_id: str, root: str, tree_size: int) -> dict:
        """Publish one batch root. Returns the signed entry."""
        with self._lock:
            if batch_id in self._by_batch:
                raise DuplicateBatch(batch_id)
            previous = self._entries[-1] if self._entries else None
            entry = next_entry(previous, batch_id, root, tree_size, _now())
            entry["signature"] = sign_entry_hash(self._key, entry["entry_hash"])

            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
                os.fsync(handle.fileno())

            self._entries.append(entry)
            self._by_batch[batch_id] = entry
            return dict(entry)

    def entries(self) -> list[dict]:
        return [dict(entry) for entry in self._entries]

    def get(self, batch_id: str) -> dict | None:
        entry = self._by_batch.get(batch_id)
        return None if entry is None else dict(entry)

    def head(self) -> dict | None:
        return dict(self._entries[-1]) if self._entries else None
