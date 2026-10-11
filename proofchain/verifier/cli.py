"""Command line for the verifier.

    python -m proofchain.verifier verify --doc FILE --proof FILE --ledger SOURCE
                                         [--pin SEQ:HASH | --pin-file FILE] [--pubkey HEX] [--json]
    python -m proofchain.verifier pin --ledger SOURCE [--pubkey HEX] [--out FILE]

SOURCE is the ledger service's URL or a local copy of the ledger file (one JSON
entry per line), so verification also works offline.

Exit codes: 0 every check passed, 1 verification failed, 2 the inputs could not
be read (which is not a verdict).
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .verify import FAIL, PASS, Pin, ledger_problems, parse_pin, verify

EXIT_VERIFIED = 0
EXIT_FAILED = 1
EXIT_INPUT_ERROR = 2

_MARKS = {PASS: "PASS", FAIL: "FAIL"}


class InputError(Exception):
    """An input could not be read, so no verdict can be given."""


def _is_url(source: str) -> bool:
    return source.startswith(("http://", "https://"))


def _get_json(url: str):
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise InputError(f"cannot read {url}: {exc}") from exc


def load_entries(source: str) -> list:
    """The whole ledger, in order.

    A line that is not JSON is kept as text, so the ledger check reports it
    instead of the tool refusing to run.
    """
    if _is_url(source):
        entries = _get_json(source.rstrip("/") + "/entries")
        if not isinstance(entries, list):
            raise InputError(f"{source}/entries did not return a list")
        return entries
    try:
        text = Path(source).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read ledger file {source}: {exc}") from exc
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError:
            entries.append(line)
    return entries


def _key_from_hex(text, origin: str) -> bytes:
    try:
        key = bytes.fromhex(text)
    except (TypeError, ValueError):
        key = b""
    if len(key) != 32:
        raise InputError(f"{origin} is not a 32-byte public key in hex")
    return key


def _read_pin_file(path: str) -> tuple[Pin, str]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return parse_pin(f"{data['seq']}:{data['entry_hash']}"), data["public_key"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InputError(f"cannot read pin file {path}: {exc}") from exc


def resolve_key_and_pin(args) -> tuple[bytes, Pin | None, str | None]:
    """Pick the public key and the pin.

    The third value is a warning, set when the key had to be taken from the
    very ledger that is being checked.
    """
    pin, saved_key = None, None
    if getattr(args, "pin_file", None):
        pin, saved_key = _read_pin_file(args.pin_file)
    if getattr(args, "pin", None):
        try:
            pin = parse_pin(args.pin)
        except ValueError as exc:
            raise InputError(str(exc)) from exc

    if args.pubkey:
        return _key_from_hex(args.pubkey, "--pubkey"), pin, None
    if saved_key:
        return _key_from_hex(saved_key, "the pin file's public_key"), pin, None
    if _is_url(args.ledger):
        reply = _get_json(args.ledger.rstrip("/") + "/pubkey")
        text = reply.get("public_key") if isinstance(reply, dict) else None
        warning = ("the public key was fetched from the ledger itself; pass --pubkey or --pin-file "
                   "to use a key you obtained earlier")
        return _key_from_hex(text, f"{args.ledger}/pubkey"), pin, warning
    raise InputError("a ledger file needs --pubkey or --pin-file to check its signatures")


def _print_result(result, warning) -> None:
    for number, check in enumerate(result.checks, start=1):
        mark = _MARKS.get(check.status, "SKIP")
        code = f"  [{check.code}]" if check.status == FAIL else ""
        print(f"{mark}  {number}. {check.name}{code}")
        print(f"      {check.detail}")
        if check.computed is not None:
            print(f"      computed  {check.computed}")
        if check.expected is not None:
            print(f"      expected  {check.expected}")
    print()
    if warning:
        print(f"Note: {warning}.")
    if result.ok:
        print(f"VERIFIED: the document matches the record registered in batch {result.batch_id} "
              f"(ledger entry {result.ledger_seq}).")
        print("This does not prove who created the document or that its contents are true.")
    else:
        print(f"NOT VERIFIED: {', '.join(result.codes)}")


def cmd_verify(args) -> int:
    try:
        document = Path(args.doc).read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read document {args.doc}: {exc}") from exc
    try:
        bundle = json.loads(Path(args.proof).read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"cannot read proof {args.proof}: {exc}") from exc
    except ValueError:
        bundle = None  # unreadable proof: the verifier reports PROOF_INVALID

    entries = load_entries(args.ledger)
    public_key, pin, warning = resolve_key_and_pin(args)
    result = verify(document, bundle, entries, public_key, pin)

    if args.json:
        print(json.dumps({**result.to_dict(), "warning": warning}, indent=2))
    else:
        _print_result(result, warning)
    return EXIT_VERIFIED if result.ok else EXIT_FAILED


def cmd_pin(args) -> int:
    entries = load_entries(args.ledger)
    public_key, _, warning = resolve_key_and_pin(args)
    if not entries:
        raise InputError("the ledger is empty; there is nothing to pin yet")
    problems = ledger_problems(entries, public_key)
    if problems:
        print("The ledger is not sound, so nothing was pinned:")
        for problem in problems:
            print(f"  {problem}")
        return EXIT_FAILED
    head = entries[-1]
    pin = Pin(head["seq"], head["entry_hash"])
    print(pin)
    if warning:
        print(f"Note: {warning}.", file=sys.stderr)
    if args.out:
        saved = {"ledger": args.ledger, "public_key": public_key.hex(),
                 "seq": pin.seq, "entry_hash": pin.entry_hash}
        Path(args.out).write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
        print(f"saved to {args.out}", file=sys.stderr)
    return EXIT_VERIFIED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m proofchain.verifier",
                                     description="Verify a document against a published Merkle root.")
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("verify", help="run the five checks on one document")
    check.add_argument("--doc", required=True, help="the document to check")
    check.add_argument("--proof", required=True, help="its proof bundle (JSON)")
    check.add_argument("--ledger", required=True, help="ledger URL or local ledger file")
    check.add_argument("--pubkey", help="the ledger's public key, 64 hex characters")
    pins = check.add_mutually_exclusive_group()
    pins.add_argument("--pin", help="checkpoint to require, as seq:entry_hash")
    pins.add_argument("--pin-file", help="file written by the pin command")
    check.add_argument("--json", action="store_true", help="print the result as JSON")
    check.set_defaults(run=cmd_verify)

    pin = commands.add_parser("pin", help="record the ledger's current head as a checkpoint")
    pin.add_argument("--ledger", required=True, help="ledger URL or local ledger file")
    pin.add_argument("--pubkey", help="the ledger's public key, 64 hex characters")
    pin.add_argument("--out", help="save the checkpoint and public key to this file")
    pin.set_defaults(run=cmd_pin)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
