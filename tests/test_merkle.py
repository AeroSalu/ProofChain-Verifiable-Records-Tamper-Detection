import hashlib

import pytest

from proofchain.core.merkle import (
    LEFT,
    RIGHT,
    PathStep,
    build_levels,
    expected_sides,
    fold_path,
    leaf_hash,
    merkle_path,
    merkle_root,
    node_hash,
)


def fps(n):
    return [hashlib.sha256(f"record {i}".encode()).digest() for i in range(n)]


def L(fp):
    return hashlib.sha256(b"\x00" + fp).digest()


def N(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def hand_computed_root(f):
    """The root for 1 to 9 leaves, written out pair by pair."""
    l = [L(x) for x in f]
    n = len(l)
    if n == 1:
        return l[0]
    if n == 2:
        return N(l[0], l[1])
    if n == 3:
        return N(N(l[0], l[1]), l[2])
    quad = N(N(l[0], l[1]), N(l[2], l[3]))
    if n == 4:
        return quad
    if n == 5:
        return N(quad, l[4])
    if n == 6:
        return N(quad, N(l[4], l[5]))
    if n == 7:
        return N(quad, N(N(l[4], l[5]), l[6]))
    octet = N(quad, N(N(l[4], l[5]), N(l[6], l[7])))
    if n == 8:
        return octet
    return N(octet, l[8])


# ---- the brief's worked examples ----


@pytest.mark.parametrize("name", ["tree4", "tree5"])
def test_levels_root_and_path_match_brief(vectors, name):
    ex = vectors[name]
    f = [bytes.fromhex(x) for x in ex["fingerprints"]]

    assert [[h.hex() for h in level] for level in build_levels(f)] == ex["levels"]
    assert merkle_root(f).hex() == ex["root"]

    path = merkle_path(f, ex["index"])
    assert [{"hash": s.hash.hex(), "side": s.side} for s in path] == ex["path"]
    assert fold_path(f[ex["index"]], path).hex() == ex["root"]


def test_fingerprints_are_the_documents_named_in_the_brief(vectors):
    docs = ["Document A", "Document B", "Document C", "Document D", "Document E"]
    assert [hashlib.sha256(d.encode()).hexdigest() for d in docs] == vectors["tree5"]["fingerprints"]


def test_four_document_root_starts_3a41957e(vectors):
    f = [bytes.fromhex(x) for x in vectors["tree4"]["fingerprints"]]
    assert merkle_root(f).hex().startswith("3a41957e")


def test_proof_for_document_c_folds_step_by_step(vectors):
    ex = vectors["tree4"]
    f = [bytes.fromhex(x) for x in ex["fingerprints"]]
    path = merkle_path(f, 2)

    assert [s.side for s in path] == [RIGHT, LEFT]
    assert path[0].hash.hex().startswith("3f3f18a1")
    assert path[1].hash.hex().startswith("989e2e6f")

    steps = [leaf_hash(f[2])]
    steps.append(node_hash(steps[-1], path[0].hash))
    steps.append(node_hash(path[1].hash, steps[-1]))
    assert [s.hex() for s in steps] == ex["fold_steps"]


def test_edited_document_c_folds_to_a_different_root(vectors):
    ex = vectors["tree4"]
    f = [bytes.fromhex(x) for x in ex["fingerprints"]]
    edited = hashlib.sha256(b"Document C (edited)").digest()
    assert edited.hex() == ex["tampered_fp"]
    assert fold_path(edited, merkle_path(f, 2)).hex() == ex["tampered_root"]
    assert ex["tampered_root"] != ex["root"]


def test_unpaired_fifth_leaf_needs_one_hash(vectors):
    f = [bytes.fromhex(x) for x in vectors["tree5"]["fingerprints"]]
    path = merkle_path(f, 4)
    assert len(path) == 1
    assert path[0] == PathStep(LEFT, merkle_root(f[:4]))


# ---- trees of 1 to 9 leaves ----


@pytest.mark.parametrize("n", range(1, 10))
def test_root_matches_hand_computed_value(n):
    f = fps(n)
    assert merkle_root(f) == hand_computed_root(f)


@pytest.mark.parametrize("n", range(1, 10))
def test_every_leaf_proves_into_the_root(n):
    f = fps(n)
    root = merkle_root(f)
    for i in range(n):
        path = merkle_path(f, i)
        assert fold_path(f[i], path) == root
        assert [s.side for s in path] == expected_sides(i, n)
        assert len(path) <= (n - 1).bit_length()


def test_single_leaf_tree_has_an_empty_path():
    f = fps(1)
    assert merkle_path(f, 0) == []
    assert merkle_root(f) == leaf_hash(f[0])


# ---- what the construction must rule out ----


def test_leaf_and_node_hashes_are_domain_separated():
    a, b = fps(2)
    assert leaf_hash(a) == hashlib.sha256(b"\x00" + a).digest()
    assert node_hash(a, b) == hashlib.sha256(b"\x01" + a + b).digest()
    assert leaf_hash(a) != hashlib.sha256(a).digest()
    assert node_hash(a, b) != hashlib.sha256(a + b).digest()


def test_last_leaf_is_promoted_not_duplicated():
    f = fps(3)
    assert merkle_root(f) != merkle_root(f + [f[-1]])


def test_root_depends_on_order_and_on_every_leaf():
    f = fps(6)
    root = merkle_root(f)
    assert merkle_root(list(reversed(f))) != root
    for i in range(6):
        changed = list(f)
        changed[i] = hashlib.sha256(b"changed").digest()
        assert merkle_root(changed) != root


@pytest.mark.parametrize("n", range(2, 10))
def test_a_wrong_side_flag_does_not_reach_the_root(n):
    f = fps(n)
    root = merkle_root(f)
    for i in range(n):
        path = merkle_path(f, i)
        for k, step in enumerate(path):
            flipped = list(path)
            flipped[k] = PathStep(LEFT if step.side == RIGHT else RIGHT, step.hash)
            assert fold_path(f[i], flipped) != root


def test_a_truncated_or_altered_path_does_not_reach_the_root():
    f = fps(9)
    root = merkle_root(f)
    path = merkle_path(f, 3)
    assert fold_path(f[3], path[:-1]) != root
    altered = [PathStep(path[0].side, hashlib.sha256(b"x").digest())] + path[1:]
    assert fold_path(f[3], altered) != root


def test_a_path_does_not_prove_a_different_leaf():
    f = fps(8)
    assert fold_path(f[1], merkle_path(f, 0)) != merkle_root(f)


# ---- bad input ----


def test_empty_batch_is_rejected():
    with pytest.raises(ValueError):
        merkle_root([])


def test_wrong_length_digests_are_rejected():
    with pytest.raises(ValueError):
        leaf_hash(b"short")
    with pytest.raises(ValueError):
        node_hash(b"\x00" * 32, b"\x00" * 31)
    with pytest.raises(ValueError):
        leaf_hash("ab" * 32)


@pytest.mark.parametrize("index", [-1, 4, 100])
def test_index_outside_the_tree_is_rejected(index):
    with pytest.raises(IndexError):
        merkle_path(fps(4), index)
    with pytest.raises(IndexError):
        expected_sides(index, 4)


def test_unknown_side_is_rejected():
    f = fps(2)
    with pytest.raises(ValueError):
        fold_path(f[0], [("up", f[1])])
