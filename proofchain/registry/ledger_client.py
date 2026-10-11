"""The registry's only route to the ledger: its public HTTP endpoints.

The registry never opens the ledger file and never sees the ledger key. Tests
pass in any object with these four methods instead of this class.

Appending needs the shared secret in PROOFCHAIN_LEDGER_TOKEN, which is sent as
a bearer token with that one request. Reading the ledger sends no credential.
"""

import json
import os
import urllib.error
import urllib.request

DEFAULT_LEDGER_URL = "http://localhost:8001"


class LedgerError(Exception):
    """The ledger answered, but not in a way the registry can use."""


class LedgerUnavailable(LedgerError):
    """The ledger could not be reached."""


class LedgerConflict(LedgerError):
    """The ledger already holds a root for this batch."""


def default_url() -> str:
    return os.environ.get("PROOFCHAIN_LEDGER_URL", DEFAULT_LEDGER_URL)


def default_token() -> str | None:
    return os.environ.get("PROOFCHAIN_LEDGER_TOKEN") or None


class LedgerClient:
    def __init__(self, base_url: str | None = None, timeout: float = 10, token: str | None = None):
        self.base_url = (base_url or default_url()).rstrip("/")
        self.timeout = timeout
        self.token = token or default_token()

    def _request(self, method: str, path: str, body=None, authorise: bool = False):
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if authorise and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LedgerUnavailable(f"cannot reach the ledger at {self.base_url}: {exc}") from exc
        except ValueError as exc:
            raise LedgerError(f"the ledger at {self.base_url} did not return JSON") from exc

    def publish(self, batch_id: str, root: str, tree_size: int) -> dict:
        """Ask the ledger to append one root. Returns the signed entry."""
        status, entry = self._request("POST", "/entries",
                                      {"batch_id": batch_id, "root": root, "tree_size": tree_size}, authorise=True)
        if status == 409:
            raise LedgerConflict(batch_id)
        if status == 401:
            raise LedgerError(
                "the ledger rejected the registry's token; PROOFCHAIN_LEDGER_TOKEN must be the same for both"
                if self.token else
                "the ledger needs a token to accept a root, and PROOFCHAIN_LEDGER_TOKEN is not set for the registry")
        if status == 503:
            raise LedgerError("the ledger is not accepting new roots: it was started without PROOFCHAIN_LEDGER_TOKEN")
        if status != 201:
            raise LedgerError(f"the ledger refused the root for {batch_id} (HTTP {status})")
        return entry

    def entries(self) -> list:
        status, entries = self._request("GET", "/entries")
        if status != 200 or not isinstance(entries, list):
            raise LedgerError(f"the ledger did not return its entries (HTTP {status})")
        return entries

    def entry(self, batch_id: str) -> dict | None:
        status, entry = self._request("GET", f"/entries/{batch_id}")
        if status == 404:
            return None
        if status != 200:
            raise LedgerError(f"the ledger did not return the entry for {batch_id} (HTTP {status})")
        return entry

    def public_key(self) -> str:
        """The ledger's public key as 64 hex characters."""
        status, reply = self._request("GET", "/pubkey")
        if status != 200 or not isinstance(reply, dict) or not isinstance(reply.get("public_key"), str):
            raise LedgerError(f"the ledger did not return its public key (HTTP {status})")
        return reply["public_key"]
