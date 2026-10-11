import copy

import pytest

from proofchain.core.ledger_format import (
    GENESIS_PREV_HASH,
    LedgerFormatError,
    chain_problems,
    check_entry,
    entry_hash,
    next_entry,
)

# ---- entry format and hash chain (core/ledger_format.py) ----


@pytest.fixture
def chain(vectors):
    return copy.deepcopy(vectors["chain"])


def rehash(entry):
    entry["entry_hash"] = entry_hash(entry)
    return entry


def test_entry_hashes_match_the_brief(chain):
    assert [entry_hash(e) for e in chain] == [e["entry_hash"] for e in chain]
    assert chain[1]["entry_hash"].startswith("075867b2")
    assert chain[1]["prev_hash"].startswith("739e5bed")


def test_entry_hash_ignores_the_stored_hash_and_signature(chain):
    entry = chain[1]
    expected = entry["entry_hash"]
    entry["entry_hash"] = "00" * 32
    entry["signature"] = "c2lnbmF0dXJl"
    assert entry_hash(entry) == expected


def test_entry_hash_covers_each_of_the_six_fields(chain):
    original = chain[1]
    changes = {
        "seq": 7,
        "batch_id": "batch-9999",
        "root": "11" * 32,
        "tree_size": 6,
        "published_at": "2026-10-12T09:00:01Z",
        "prev_hash": "22" * 32,
    }
    for field, value in changes.items():
        assert entry_hash(dict(original, **{field: value})) != original["entry_hash"]


def test_brief_chain_is_sound(chain):
    assert chain_problems(chain) == []
    assert chain_problems([]) == []
    assert chain_problems(chain[:1]) == []


def test_next_entry_rebuilds_the_brief_chain(chain):
    built, previous = [], None
    for e in chain:
        previous = next_entry(previous, e["batch_id"], e["root"], e["tree_size"], e["published_at"])
        built.append(previous)
    assert built == chain
    assert built[0]["prev_hash"] == GENESIS_PREV_HASH


def test_edited_entry_is_detected(chain):
    chain[1]["root"] = "ab" * 32
    problems = chain_problems(chain)
    assert len(problems) == 1
    assert "entry 1" in problems[0] and "entry_hash" in problems[0]


def test_edited_entry_with_a_recomputed_hash_breaks_the_next_link(chain):
    chain[1]["root"] = "ab" * 32
    rehash(chain[1])
    problems = chain_problems(chain)
    assert len(problems) == 1
    assert "entry 2" in problems[0] and "prev_hash" in problems[0]


def test_deleted_entry_is_detected(chain):
    del chain[1]
    assert chain_problems(chain)


def test_deleted_first_entry_is_detected(chain):
    assert chain_problems(chain[1:])


def test_swapped_entries_are_detected(chain):
    chain[1], chain[2] = chain[2], chain[1]
    assert chain_problems(chain)


def test_inserted_entry_is_detected(chain):
    forged = next_entry(chain[0], "batch-forged", "cd" * 32, 3, "2026-10-11T12:00:00Z")
    chain.insert(1, forged)
    assert chain_problems(chain)


def test_first_entry_must_link_to_the_genesis_value(chain):
    chain[0]["prev_hash"] = "ff" * 32
    rehash(chain[0])
    problems = chain_problems(chain[:1])
    assert len(problems) == 1 and "prev_hash" in problems[0]


def test_a_batch_published_twice_is_detected(chain):
    again = next_entry(chain[2], chain[0]["batch_id"], "ee" * 32, 4, "2026-10-14T09:00:00Z")
    problems = chain_problems(chain + [again])
    assert len(problems) == 1 and "already published" in problems[0]


def test_all_problems_are_reported_not_just_the_first(chain):
    chain[0]["tree_size"] = 40
    chain[2]["batch_id"] = "batch-other"
    assert len(chain_problems(chain)) == 2


def test_malformed_entry_is_reported_and_the_walk_continues(chain):
    del chain[1]["root"]
    problems = chain_problems(chain)
    assert len(problems) == 1 and "position 1" in problems[0] and "root" in problems[0]


@pytest.mark.parametrize(
    "field, value",
    [
        ("seq", -1),
        ("seq", "1"),
        ("seq", True),
        ("batch_id", ""),
        ("batch_id", 2),
        ("root", "3de1575b"),
        ("root", "3DE1575B7131B491D8E4FA6A9BC83AA648776F8BE745E1EF1EAAE8EC8443316E"),
        ("tree_size", 0),
        ("tree_size", 5.0),
        ("published_at", "12 October 2026"),
        ("published_at", "2026-10-12T09:00:00+05:30"),
        ("prev_hash", None),
        ("entry_hash", "xyz"),
        ("signature", 123),
    ],
)
def test_malformed_fields_are_rejected(chain, field, value):
    chain[1][field] = value
    with pytest.raises(LedgerFormatError):
        check_entry(chain[1])


def test_entry_must_be_an_object_with_every_field(chain):
    with pytest.raises(LedgerFormatError):
        check_entry(["seq", 1])
    del chain[1]["entry_hash"]
    with pytest.raises(LedgerFormatError):
        check_entry(chain[1])
    with pytest.raises(LedgerFormatError):
        entry_hash({"seq": 0})
