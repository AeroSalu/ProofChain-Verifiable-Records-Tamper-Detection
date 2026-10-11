import copy
import hashlib
import json

import pytest

from proofchain.core import proof
from proofchain.core.canonical import RAW_BYTES_V1
from proofchain.core.proof import ProofFormatError, create_bundle

# The bundle printed in section 7.2 of the brief: Document C in the four-document batch.
BRIEF_BUNDLE = {
    "version": 1,
    "canon": "raw-bytes-v1",
    "fingerprint": "90eafcf01a14b00bf7d8e2ab6abd10b1e6944ad0fc3d7ac1dfeacff8976ba4aa",
    "batch_id": "batch-0001",
    "leaf_index": 2,
    "tree_size": 4,
    "path": [
        {"side": "right", "hash": "3f3f18a16988ee47522a0f08f4c21bd7687b126030323cb2d3c60b38cae7f494"},
        {"side": "left", "hash": "989e2e6fd32d70ca8443ba766cb386a3750c114c5ed75dd38ff84495447a4ff1"},
    ],
    "root": "3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8effeda95e98c40",
}


def fps(n):
    return [hashlib.sha256(f"record {i}".encode()).hexdigest() for i in range(n)]


def broken(**changes):
    data = copy.deepcopy(BRIEF_BUNDLE)
    data.update(changes)
    return data


def test_created_bundle_matches_the_brief(vectors):
    bundle = create_bundle(RAW_BYTES_V1, "batch-0001", vectors["tree4"]["fingerprints"], 2)
    assert bundle.to_dict() == BRIEF_BUNDLE
    assert list(bundle.to_dict()) == list(BRIEF_BUNDLE)


def test_brief_bundle_is_well_formed_and_folds_to_its_root():
    bundle = proof.from_dict(BRIEF_BUNDLE)
    assert bundle.computed_root() == BRIEF_BUNDLE["root"]


def test_bundle_carries_only_log_n_hashes_from_the_batch():
    bundle = create_bundle(RAW_BYTES_V1, "batch-big", fps(1000), 517)
    assert len(bundle.path) == 10
    text = bundle.dumps()
    others = [fp for i, fp in enumerate(fps(1000)) if i != 517]
    assert not any(fp in text for fp in others)


@pytest.mark.parametrize("n", range(1, 10))
def test_every_record_gets_a_bundle_that_folds_to_the_batch_root(n):
    bundles = [create_bundle(RAW_BYTES_V1, "b", fps(n), i) for i in range(n)]
    assert len({b.root for b in bundles}) == 1
    for i, bundle in enumerate(bundles):
        assert bundle.leaf_index == i
        assert bundle.tree_size == n
        assert bundle.computed_root() == bundle.root


def test_json_round_trip():
    bundle = proof.from_dict(BRIEF_BUNDLE)
    assert json.loads(bundle.dumps()) == BRIEF_BUNDLE
    assert proof.loads(bundle.dumps()) == bundle


def test_save_and_load(tmp_path):
    bundle = proof.from_dict(BRIEF_BUNDLE)
    target = tmp_path / "degree.proof.json"
    bundle.save(target)
    assert proof.load(target) == bundle


def test_a_well_formed_bundle_can_still_have_a_path_that_misses_its_root():
    # Structure is checked here; whether the path reaches the root is the verifier's check.
    data = copy.deepcopy(BRIEF_BUNDLE)
    data["path"][0]["hash"] = "00" * 32
    bundle = proof.from_dict(data)
    assert bundle.computed_root() != bundle.root


def path_with(index, **changes):
    path = copy.deepcopy(BRIEF_BUNDLE["path"])
    path[index].update(changes)
    return path


MALFORMED = {
    "not-an-object": [BRIEF_BUNDLE],
    "missing-root": {k: v for k, v in BRIEF_BUNDLE.items() if k != "root"},
    "missing-path": {k: v for k, v in BRIEF_BUNDLE.items() if k != "path"},
    "unknown-field": broken(metadata={"issuer": "x"}),
    "version-2": broken(version=2),
    "version-as-text": broken(version="1"),
    "version-as-bool": broken(version=True),
    "unknown-canon": broken(canon="pdf-text-v1"),
    "empty-batch-id": broken(batch_id=""),
    "batch-id-not-text": broken(batch_id=1),
    "fingerprint-too-short": broken(fingerprint="90eafcf0"),
    "fingerprint-not-hex": broken(fingerprint="z" * 64),
    "fingerprint-uppercase": broken(fingerprint=BRIEF_BUNDLE["fingerprint"].upper()),
    "fingerprint-not-text": broken(fingerprint=12345),
    "root-too-long": broken(root=BRIEF_BUNDLE["root"] + "00"),
    "root-not-hex": broken(root="g" * 64),
    "index-equals-tree-size": broken(leaf_index=4),
    "index-beyond-tree-size": broken(leaf_index=9),
    "index-negative": broken(leaf_index=-1),
    "index-as-text": broken(leaf_index="2"),
    "index-as-float": broken(leaf_index=2.0),
    "tree-size-zero": broken(tree_size=0, leaf_index=0),
    "tree-size-as-bool": broken(tree_size=True, leaf_index=0),
    "path-not-a-list": broken(path="none"),
    "path-too-long": broken(path=BRIEF_BUNDLE["path"] + [BRIEF_BUNDLE["path"][0]]),
    "path-truncated": broken(path=BRIEF_BUNDLE["path"][:1]),
    "path-empty": broken(path=[]),
    "path-step-not-an-object": broken(path=["right", "left"]),
    "path-step-missing-side": broken(path=[{"hash": "00" * 32}, BRIEF_BUNDLE["path"][1]]),
    "path-step-extra-key": broken(path=[dict(BRIEF_BUNDLE["path"][0], level=0), BRIEF_BUNDLE["path"][1]]),
    "path-hash-not-hex": broken(path=path_with(0, hash="q" * 64)),
    "path-hash-too-short": broken(path=path_with(1, hash="989e2e6f")),
    "path-side-flipped": broken(path=path_with(0, side="left")),
    "path-side-unknown": broken(path=path_with(1, side="up")),
    "path-sides-for-another-leaf": broken(leaf_index=3),
    "tree-size-that-needs-a-longer-path": broken(tree_size=9),
}


@pytest.mark.parametrize("data", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_bundles_are_rejected(data):
    with pytest.raises(ProofFormatError):
        proof.from_dict(data)


@pytest.mark.parametrize("text", ["", "not json", "[1, 2", "null", "42", '"bundle"'])
def test_text_that_is_not_a_bundle_is_rejected(text):
    with pytest.raises(ProofFormatError):
        proof.loads(text)


def test_a_file_that_is_not_text_is_rejected(tmp_path):
    target = tmp_path / "bad.proof.json"
    target.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(ProofFormatError):
        proof.load(target)


def test_create_bundle_rejects_an_index_outside_the_batch():
    with pytest.raises(IndexError):
        create_bundle(RAW_BYTES_V1, "b", fps(4), 4)
    with pytest.raises(IndexError):
        create_bundle(RAW_BYTES_V1, "b", fps(4), -1)
