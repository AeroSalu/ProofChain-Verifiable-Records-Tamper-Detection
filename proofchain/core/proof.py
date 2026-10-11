"""The proof bundle handed to a document holder.

A bundle is a small JSON file holding the registered fingerprint, where the
record sits in its batch, the sibling path, and the root the path should reach.
It contains nothing else from the batch.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .canonical import CANONS
from .merkle import PathStep, expected_sides, fold_path, merkle_path, merkle_root

PROOF_VERSION = 1

_FIELDS = ("version", "canon", "fingerprint", "batch_id", "leaf_index", "tree_size", "path", "root")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ProofFormatError(ValueError):
    """The bundle is malformed."""


def _hex64(value, name: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProofFormatError(f"{name} must be 64 lowercase hex characters")
    return value


def _integer(value, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProofFormatError(f"{name} must be an integer")
    return value


@dataclass(frozen=True)
class ProofBundle:
    canon: str
    fingerprint: str
    batch_id: str
    leaf_index: int
    tree_size: int
    path: tuple[PathStep, ...]
    root: str
    version: int = PROOF_VERSION

    def computed_root(self) -> str:
        """Fold the path from the bundle's own fingerprint."""
        return fold_path(bytes.fromhex(self.fingerprint), self.path).hex()

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "canon": self.canon,
            "fingerprint": self.fingerprint,
            "batch_id": self.batch_id,
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "path": [{"side": step.side, "hash": step.hash.hex()} for step in self.path],
            "root": self.root,
        }

    def dumps(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def save(self, path) -> None:
        Path(path).write_text(self.dumps(), encoding="utf-8")


def create_bundle(canon: str, batch_id: str, fingerprints, leaf_index: int) -> ProofBundle:
    """Build the bundle for one record from the batch's fingerprints in leaf order."""
    fps = [bytes.fromhex(fp) for fp in fingerprints]
    bundle = ProofBundle(
        canon=canon,
        fingerprint=fingerprints[leaf_index],
        batch_id=batch_id,
        leaf_index=leaf_index,
        tree_size=len(fps),
        path=tuple(merkle_path(fps, leaf_index)),
        root=merkle_root(fps).hex(),
    )
    return from_dict(bundle.to_dict())


def from_dict(data) -> ProofBundle:
    """Check that a decoded bundle is well formed and return it.

    This checks structure only. Whether the path actually reaches the root, and
    whether the root was published, is for the verifier to decide.
    """
    if not isinstance(data, dict):
        raise ProofFormatError("bundle must be a JSON object")
    missing = [name for name in _FIELDS if name not in data]
    if missing:
        raise ProofFormatError(f"bundle is missing: {', '.join(missing)}")
    unknown = sorted(set(data) - set(_FIELDS))
    if unknown:
        raise ProofFormatError(f"bundle has unknown fields: {', '.join(unknown)}")

    if _integer(data["version"], "version") != PROOF_VERSION:
        raise ProofFormatError(f"unsupported bundle version: {data['version']}")
    if data["canon"] not in CANONS:
        raise ProofFormatError(f"unknown canonical form: {data['canon']!r}")
    if not isinstance(data["batch_id"], str) or not data["batch_id"]:
        raise ProofFormatError("batch_id must be a non-empty string")

    tree_size = _integer(data["tree_size"], "tree_size")
    leaf_index = _integer(data["leaf_index"], "leaf_index")
    if tree_size < 1:
        raise ProofFormatError("tree_size must be at least 1")
    if not 0 <= leaf_index < tree_size:
        raise ProofFormatError(f"leaf_index {leaf_index} is outside a tree of {tree_size} leaves")

    if not isinstance(data["path"], list):
        raise ProofFormatError("path must be a list")
    steps = []
    for number, step in enumerate(data["path"], start=1):
        if not isinstance(step, dict) or set(step) != {"side", "hash"}:
            raise ProofFormatError(f"path step {number} must have exactly 'side' and 'hash'")
        steps.append(PathStep(step["side"], bytes.fromhex(_hex64(step["hash"], f"path step {number} hash"))))

    sides = expected_sides(leaf_index, tree_size)
    if len(steps) != len(sides):
        raise ProofFormatError(
            f"path has {len(steps)} steps; leaf {leaf_index} of {tree_size} needs {len(sides)}"
        )
    for number, (step, side) in enumerate(zip(steps, sides), start=1):
        if step.side != side:
            raise ProofFormatError(
                f"path step {number} is on the {step.side!r} side; leaf {leaf_index} of {tree_size} needs {side!r}"
            )

    return ProofBundle(
        version=data["version"],
        canon=data["canon"],
        fingerprint=_hex64(data["fingerprint"], "fingerprint"),
        batch_id=data["batch_id"],
        leaf_index=leaf_index,
        tree_size=tree_size,
        path=tuple(steps),
        root=_hex64(data["root"], "root"),
    )


def loads(text) -> ProofBundle:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ProofFormatError(f"bundle is not valid JSON: {exc}") from exc
    return from_dict(data)


def load(path) -> ProofBundle:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ProofFormatError("bundle is not UTF-8 text") from exc
    return loads(text)
