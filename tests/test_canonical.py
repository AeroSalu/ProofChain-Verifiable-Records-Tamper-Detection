import hashlib

import pytest

from proofchain.core.canonical import (
    JSON_SORTED_V1,
    RAW_BYTES_V1,
    CanonicalError,
    canonical_json,
    canonicalize,
    fingerprint,
)


def test_raw_fingerprint_matches_brief(vectors):
    ex = vectors["avalanche"]
    assert fingerprint(RAW_BYTES_V1, ex["a_text"].encode()) == ex["a"]
    assert fingerprint(RAW_BYTES_V1, ex["b_text"].encode()) == ex["b"]


def test_avalanche_bit_count_matches_brief(vectors):
    ex = vectors["avalanche"]
    a, b = bytes.fromhex(ex["a"]), bytes.fromhex(ex["b"])
    assert sum(bin(x ^ y).count("1") for x, y in zip(a, b)) == ex["bits_changed"]


def test_raw_fingerprint_is_plain_sha256():
    data = bytes(range(256)) * 10
    assert fingerprint(RAW_BYTES_V1, data) == hashlib.sha256(data).hexdigest()


def test_raw_bytes_are_never_normalised():
    assert canonicalize(RAW_BYTES_V1, b"line\r\n") == b"line\r\n"
    assert fingerprint(RAW_BYTES_V1, b"line\r\n") != fingerprint(RAW_BYTES_V1, b"line\n")
    # Valid JSON is still just bytes under raw-bytes-v1.
    assert fingerprint(RAW_BYTES_V1, b'{"a": 1}') != fingerprint(RAW_BYTES_V1, b'{"a":1}')


def test_two_spellings_of_a_record_share_one_canonical_form(vectors):
    ex = vectors["canon"]
    raw1, raw2 = ex["raw1"].encode(), ex["raw2"].encode()

    assert fingerprint(RAW_BYTES_V1, raw1) == ex["raw1_hash"]
    assert fingerprint(RAW_BYTES_V1, raw2) == ex["raw2_hash"]

    assert canonicalize(JSON_SORTED_V1, raw1) == ex["canonical"].encode()
    assert canonicalize(JSON_SORTED_V1, raw2) == ex["canonical"].encode()
    assert fingerprint(JSON_SORTED_V1, raw1) == ex["canonical_hash"]
    assert fingerprint(JSON_SORTED_V1, raw2) == ex["canonical_hash"]


def test_canonical_form_is_stable_when_recanonicalised(vectors):
    once = canonicalize(JSON_SORTED_V1, vectors["canon"]["raw2"].encode())
    assert canonicalize(JSON_SORTED_V1, once) == once


def test_nested_keys_are_sorted_and_whitespace_removed():
    data = b'{ "b" : [ 3, {"z": null, "a": true} ], "a" : { "d": -1, "c": "x y" } }'
    assert canonicalize(JSON_SORTED_V1, data) == b'{"a":{"c":"x y","d":-1},"b":[3,{"a":true,"z":null}]}'


def test_array_order_is_preserved():
    assert fingerprint(JSON_SORTED_V1, b"[1,2]") != fingerprint(JSON_SORTED_V1, b"[2,1]")


def test_unicode_is_normalised_to_nfc_and_written_as_utf8():
    composed = '{"name":"Zoë"}'.encode("utf-8")
    decomposed = '{"name":"Zoë"}'.encode("utf-8")
    escaped = b'{"name":"Zo\\u00eb"}'
    assert composed != decomposed
    assert canonicalize(JSON_SORTED_V1, decomposed) == composed
    assert canonicalize(JSON_SORTED_V1, escaped) == composed


def test_large_integers_are_kept_exactly():
    assert canonicalize(JSON_SORTED_V1, b'{"n": 123456789012345678901234567890}') == (
        b'{"n":123456789012345678901234567890}'
    )


@pytest.mark.parametrize(
    "data",
    [
        b'{"gpa": 3.5}',
        b'{"gpa": 4.0}',
        b'{"n": 1e3}',
        b'{"n": NaN}',
        b'{"n": Infinity}',
        b'{"a": 1, "a": 2}',
        '{"é": 1, "é": 2}'.encode("utf-8"),
        b'{"a": 1',
        b"",
        b"\xff\xfe",
        b'\xef\xbb\xbf{"a": 1}',
        b'{"s": "\\ud800"}',
    ],
    ids=[
        "float",
        "float-with-zero-fraction",
        "exponent",
        "nan",
        "infinity",
        "duplicate-key",
        "duplicate-key-after-nfc",
        "truncated",
        "empty",
        "not-utf8",
        "byte-order-mark",
        "lone-surrogate",
    ],
)
def test_json_form_rejects(data):
    with pytest.raises(CanonicalError):
        canonicalize(JSON_SORTED_V1, data)


def test_canonical_json_rejects_floats_and_odd_types():
    with pytest.raises(CanonicalError):
        canonical_json({"a": 1.5})
    with pytest.raises(CanonicalError):
        canonical_json({1: "a"})
    with pytest.raises(CanonicalError):
        canonical_json({"a": b"bytes"})


def test_unknown_canonical_form_is_rejected():
    with pytest.raises(CanonicalError):
        fingerprint("raw-bytes-v2", b"data")


def test_text_is_not_accepted_in_place_of_bytes():
    with pytest.raises(CanonicalError):
        fingerprint(RAW_BYTES_V1, "text")
