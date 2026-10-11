"""Merkle tree over a batch of fingerprints.

leaf = SHA-256(0x00 || fingerprint)
node = SHA-256(0x01 || left || right)

Leaves and nodes carry different prefixes so one can never be presented as the
other (as in RFC 6962). When a level has an odd number of entries the last one
moves up unchanged; it is never duplicated, which is what made two different
leaf lists share a root in CVE-2012-2459.

Everything here works on raw 32-byte digests. Hex belongs to the proof format.
"""

import hashlib
from typing import NamedTuple

HASH_SIZE = 32
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

LEFT = "left"
RIGHT = "right"


class PathStep(NamedTuple):
    """One sibling on the way to the root, and the side it sits on."""

    side: str
    hash: bytes


def _digest(value, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != HASH_SIZE:
        raise ValueError(f"{name} must be {HASH_SIZE} bytes")
    return bytes(value)


def leaf_hash(fingerprint: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + _digest(fingerprint, "fingerprint")).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + _digest(left, "left") + _digest(right, "right")).digest()


def build_levels(fingerprints) -> list[list[bytes]]:
    """Every level of the tree, leaves first and the root last."""
    if len(fingerprints) == 0:
        raise ValueError("a batch must contain at least one fingerprint")
    levels = [[leaf_hash(fp) for fp in fingerprints]]
    while len(levels[-1]) > 1:
        current, above = levels[-1], []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                above.append(node_hash(current[i], current[i + 1]))
            else:
                above.append(current[i])
        levels.append(above)
    return levels


def merkle_root(fingerprints) -> bytes:
    return build_levels(fingerprints)[-1][0]


def merkle_path(fingerprints, index: int) -> list[PathStep]:
    """The sibling hashes needed to recompute the root from the leaf at index."""
    if not 0 <= index < len(fingerprints):
        raise IndexError(f"leaf index {index} is outside a tree of {len(fingerprints)} leaves")
    path = []
    for level in build_levels(fingerprints)[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            path.append(PathStep(LEFT if sibling < index else RIGHT, level[sibling]))
        index //= 2
    return path


def fold_path(fingerprint: bytes, path) -> bytes:
    """Recompute the root from one fingerprint and its sibling path."""
    current = leaf_hash(fingerprint)
    for side, sibling in path:
        if side == LEFT:
            current = node_hash(sibling, current)
        elif side == RIGHT:
            current = node_hash(current, sibling)
        else:
            raise ValueError(f"path side must be 'left' or 'right', got {side!r}")
    return current


def expected_sides(index: int, tree_size: int) -> list[str]:
    """The sides a path must have for this leaf position and tree size.

    The shape of a path is fixed by the position alone, so a proof whose sides
    differ from this cannot belong to the leaf index it claims.
    """
    if tree_size < 1:
        raise ValueError("tree size must be at least 1")
    if not 0 <= index < tree_size:
        raise IndexError(f"leaf index {index} is outside a tree of {tree_size} leaves")
    sides, width = [], tree_size
    while width > 1:
        sibling = index ^ 1
        if sibling < width:
            sides.append(LEFT if sibling < index else RIGHT)
        index //= 2
        width = (width + 1) // 2
    return sides
