"""The ledger's own Ed25519 key.

The private key lives in a file that only the ledger process reads. The
registry never sees it, which is why the registry cannot forge entries.

Signatures are over the 32 raw bytes of entry_hash and are stored as base64.
The public key is published as 64 hex characters.
"""

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load_or_create_key(path) -> Ed25519PrivateKey:
    """Read the key file, creating a new key the first time the ledger runs."""
    path = Path(path)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} does not hold an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return key


def public_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_hex(key: Ed25519PrivateKey) -> str:
    return public_key_bytes(key).hex()


def sign_entry_hash(key: Ed25519PrivateKey, entry_hash: str) -> str:
    return base64.b64encode(key.sign(bytes.fromhex(entry_hash))).decode("ascii")
