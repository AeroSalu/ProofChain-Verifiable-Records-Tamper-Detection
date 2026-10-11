"""Staff accounts: who may sign in to the registry.

    python -m proofchain.registry.staff add <username> [--admin] [--reset] [--db PATH]
    python -m proofchain.registry.staff admin <username> [--revoke] [--db PATH]
    python -m proofchain.registry.staff list [--db PATH]

There is no sign-up page. An account is created from the command line by
someone with access to the machine, and the password is asked for, never passed
as an argument.

Only a salted scrypt hash is stored. An account says who registered and
confirmed a record. It has no bearing on verification, which never needs one.

Each custodian seals their own batch. An admin account may seal any open batch.
"""

import argparse
import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
import sys

from . import db, models

MIN_PASSWORD_LENGTH = 8

# scrypt cost: 2**14 iterations, 8-byte blocks, about 16 MB of memory per hash.
_N, _R, _P, _KEY_LENGTH = 2**14, 8, 1, 32
_USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


class StaffError(ValueError):
    """The account cannot be created as asked."""


def normalise_username(username) -> str:
    """Usernames are case-insensitive: 'Asha' and 'asha' are one account."""
    return username.strip().lower() if isinstance(username, str) else ""


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=_KEY_LENGTH)


def hash_password(password: str) -> str:
    """A salted hash, with its parameters, as one string: scrypt$n$r$p$salt$hash."""
    salt = secrets.token_bytes(16)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${_scrypt(password, salt, _N, _R, _P).hex()}"


def verify_password(password: str, stored) -> bool:
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        computed = _scrypt(password, bytes.fromhex(salt), int(n), int(r), int(p))
        return hmac.compare_digest(computed, bytes.fromhex(expected))
    except (AttributeError, TypeError, ValueError):
        return False  # a stored value that is not a hash matches nothing


# Checked when the username is unknown, so that a wrong username takes as long as a wrong password.
_NO_ACCOUNT = hash_password(secrets.token_hex(16))


def exists(conn, username: str) -> bool:
    return conn.execute("SELECT 1 FROM staff WHERE username = ?", (username,)).fetchone() is not None


def is_admin(conn, username: str) -> bool:
    row = conn.execute("SELECT is_admin FROM staff WHERE username = ?", (username,)).fetchone()
    return row is not None and bool(row["is_admin"])


def set_admin(conn, username: str, admin: bool = True) -> str:
    """Mark an existing account as an admin, or take that away. Returns the username."""
    username = normalise_username(username)
    changed = conn.execute("UPDATE staff SET is_admin = ? WHERE username = ?", (1 if admin else 0, username))
    if changed.rowcount == 0:
        raise StaffError(f"there is no account named {username}")
    return username


def list_staff(conn) -> list[dict]:
    rows = conn.execute("SELECT username, is_admin, created_at FROM staff ORDER BY username")
    return [{"username": r["username"], "is_admin": bool(r["is_admin"]), "created_at": r["created_at"]} for r in rows]


def authenticate(conn, username, password) -> str | None:
    """The account's username if the password is right, otherwise None."""
    username = normalise_username(username)
    if not isinstance(password, str):
        password = ""
    row = conn.execute("SELECT password_hash FROM staff WHERE username = ?", (username,)).fetchone()
    if row is None:
        verify_password(password, _NO_ACCOUNT)
        return None
    return username if verify_password(password, row["password_hash"]) else None


def add_staff(conn, username: str, password: str, reset: bool = False, admin: bool = False) -> str:
    """Create an account, or with reset replace an existing account's password. Returns the username.

    admin makes a new account an admin. It is ignored with reset: use set_admin for an existing account.
    """
    username = normalise_username(username)
    if not _USERNAME.fullmatch(username):
        raise StaffError("a username is 1 to 64 characters: letters, digits, dot, dash or underscore, "
                         "starting with a letter or digit")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise StaffError(f"a password must be at least {MIN_PASSWORD_LENGTH} characters")
    hashed = hash_password(password)
    if reset:
        changed = conn.execute("UPDATE staff SET password_hash = ? WHERE username = ?", (hashed, username))
        if changed.rowcount == 0:
            raise StaffError(f"there is no account named {username} to reset")
        return username
    try:
        conn.execute("INSERT INTO staff (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)",
                     (username, hashed, models.now(), 1 if admin else 0))
    except sqlite3.IntegrityError:
        raise StaffError(f"an account named {username} already exists; pass --reset to change its password") from None
    return username


def _ask_password() -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\r\n")  # piped in by a script
    password = getpass.getpass("Password: ")
    if getpass.getpass("Again: ") != password:
        raise StaffError("the two passwords did not match")
    return password


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m proofchain.registry.staff",
                                     description="Manage the accounts that may sign in to the registry.")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="create an account; the password is asked for")
    add.add_argument("username")
    add.add_argument("--db", default=db.default_path(), help="registry database (default: %(default)s)")
    add.add_argument("--reset", action="store_true", help="replace the password of an existing account")
    add.add_argument("--admin", action="store_true", help="make the new account an admin, who may seal any open batch")
    admin = commands.add_parser("admin", help="make an existing account an admin, or with --revoke undo that")
    admin.add_argument("username")
    admin.add_argument("--revoke", action="store_true", help="make the account an ordinary custodian again")
    listing = commands.add_parser("list", help="show the accounts and which are admins")
    for command in (admin, listing):
        command.add_argument("--db", default=db.default_path(), help="registry database (default: %(default)s)")
    args = parser.parse_args(argv)

    try:
        if args.command == "add":
            if args.reset and args.admin:
                raise StaffError("--reset changes a password only; use the admin command to change who is an admin")
            password = _ask_password()
        db.init_db(args.db)
        conn = db.connect(args.db)
        try:
            if args.command == "add":
                username = add_staff(conn, args.username, password, args.reset, args.admin)
                done = "Changed the password of" if args.reset else \
                    "Created admin account" if args.admin else "Created account"
                print(f"{done} {username} in {args.db}.")
            elif args.command == "admin":
                username = set_admin(conn, args.username, not args.revoke)
                print(f"{username} is {'no longer' if args.revoke else 'now'} an admin in {args.db}.")
            else:
                accounts = list_staff(conn)
                for account in accounts:
                    print(f"{account['username']}{'  (admin)' if account['is_admin'] else ''}")
                if not accounts:
                    print(f"There are no accounts in {args.db}.")
        finally:
            conn.close()
    except (StaffError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
