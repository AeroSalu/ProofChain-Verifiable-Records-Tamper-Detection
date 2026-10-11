"""Canonical forms and the SHA-256 fingerprint.

A hash covers bytes, not meaning, so every document is first reduced to one
exact byte form. Two forms exist and every proof names the one it used:

raw-bytes-v1    The exact bytes of a file, unchanged. Never normalised.
json-sorted-v1  A structured record as JSON: UTF-8, Unicode NFC, object keys
                sorted by code point, no whitespace between tokens, integers
                only. Modelled on RFC 8785.
"""

import hashlib
import json
import unicodedata

RAW_BYTES_V1 = "raw-bytes-v1"
JSON_SORTED_V1 = "json-sorted-v1"
CANONS = (RAW_BYTES_V1, JSON_SORTED_V1)


class CanonicalError(ValueError):
    """The input cannot be put into the requested canonical form."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalise(value):
    """Return value with every string in NFC, rejecting what the form forbids."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalError("floating-point numbers are not allowed; use integers or strings")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"object keys must be strings, got {type(key).__name__}")
            key = unicodedata.normalize("NFC", key)
            if key in out:
                raise CanonicalError(f"duplicate object key after normalisation: {key!r}")
            out[key] = _normalise(item)
        return out
    raise CanonicalError(f"unsupported value type: {type(value).__name__}")


def canonical_json(obj) -> bytes:
    """Serialise a Python object to its json-sorted-v1 bytes."""
    text = json.dumps(
        _normalise(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalError("text contains characters that cannot be encoded as UTF-8") from exc


def _reject_float(text):
    raise CanonicalError(f"floating-point numbers are not allowed: {text}")


def _reject_constant(text):
    raise CanonicalError(f"{text} is not valid JSON")


def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError(f"duplicate object key: {key!r}")
        out[key] = value
    return out


def parse_json(data: bytes):
    """Parse JSON text strictly: UTF-8, no floats, no duplicate keys."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalError("structured records must be UTF-8") from exc
    try:
        return json.loads(
            text,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_pairs,
        )
    except CanonicalError:
        raise
    except ValueError as exc:
        raise CanonicalError(f"not valid JSON: {exc}") from exc


def canonicalize(canon: str, data: bytes) -> bytes:
    """Return the canonical bytes of a document under the named form."""
    if not isinstance(data, (bytes, bytearray)):
        raise CanonicalError("document must be bytes")
    if canon == RAW_BYTES_V1:
        return bytes(data)
    if canon == JSON_SORTED_V1:
        return canonical_json(parse_json(bytes(data)))
    raise CanonicalError(f"unknown canonical form: {canon!r}")


def fingerprint(canon: str, data: bytes) -> str:
    """SHA-256 of the document's canonical form, as 64 lowercase hex characters."""
    return sha256_hex(canonicalize(canon, data))
