"""Signed session cookies for the registry's pages.

A cookie holds a username and an expiry time, followed by an HMAC-SHA256 of
both under a secret only the registry knows. It is not encrypted: it carries
nothing secret, only a claim the registry can check it issued.

The secret comes from PROOFCHAIN_SESSION_SECRET. If that is unset, one is
generated beside the database the first time the registry runs, the way the
ledger creates its key.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

COOKIE = "proofchain_session"
MAX_AGE = 12 * 60 * 60  # seconds
MIN_SECRET_LENGTH = 32
SECRET_FILE = "session_secret"


def load_secret(db_path) -> bytes:
    """The signing secret: from the environment, or a file beside the database."""
    configured = os.environ.get("PROOFCHAIN_SESSION_SECRET", "")
    if configured:
        if len(configured) < MIN_SECRET_LENGTH:
            raise RuntimeError(f"PROOFCHAIN_SESSION_SECRET must be at least {MIN_SECRET_LENGTH} characters; "
                               "unset it to have one generated")
        return configured.encode("utf-8")
    path = Path(db_path).parent / SECRET_FILE
    if path.exists():
        secret = path.read_text(encoding="ascii").strip()
        if len(secret) < MIN_SECRET_LENGTH:
            raise RuntimeError(f"{path} does not hold a usable session secret; delete it to have one generated")
        return secret.encode("ascii")
    secret = secrets.token_hex(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret + "\n", encoding="ascii")
    try:
        path.chmod(0o600)
    except OSError:
        pass  # not every file system has owner-only permissions
    return secret.encode("ascii")


def _signature(payload: str, secret: bytes) -> str:
    return hmac.new(secret, payload.encode("ascii"), hashlib.sha256).hexdigest()


def issue(username: str, secret: bytes, now: float | None = None) -> str:
    """A cookie value saying that username signed in, valid for MAX_AGE seconds."""
    expires = int(time.time() if now is None else now) + MAX_AGE
    body = json.dumps({"u": username, "exp": expires}, separators=(",", ":")).encode("utf-8")
    payload = base64.urlsafe_b64encode(body).decode("ascii")
    return f"{payload}.{_signature(payload, secret)}"


def read(cookie, secret: bytes, now: float | None = None) -> str | None:
    """The username in a cookie this registry issued and that has not expired, otherwise None."""
    if not isinstance(cookie, str) or cookie.count(".") != 1:
        return None
    payload, signature = cookie.split(".")
    try:
        if not hmac.compare_digest(signature.encode("ascii"), _signature(payload, secret).encode("ascii")):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        username, expires = data["u"], data["exp"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(username, str) or not isinstance(expires, int) or isinstance(expires, bool):
        return None
    if expires <= (time.time() if now is None else now):
        return None
    return username
