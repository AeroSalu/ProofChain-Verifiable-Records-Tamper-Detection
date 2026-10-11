"""The ledger service.

    uvicorn proofchain.ledger.app:app --port 8001

A separate process from the registry, with its own key and its own file. It
can append a root and it can be read. It has no endpoint that updates or
deletes an entry.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from .keys import load_or_create_key, public_key_hex
from .store import DuplicateBatch, LedgerStore

DEFAULT_LEDGER_PATH = "data/ledger.jsonl"
DEFAULT_KEY_PATH = "data/ledger_key.pem"


class NewEntry(BaseModel):
    batch_id: str = Field(min_length=1)
    root: str = Field(pattern=r"^[0-9a-f]{64}$")
    tree_size: int = Field(ge=1, strict=True)


def create_app(ledger_path=None, key_path=None) -> FastAPI:
    """Build the service. The key and ledger file are opened at startup, and a
    ledger file that fails its own chain check stops the service from starting."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        key = load_or_create_key(key_path or os.environ.get("PROOFCHAIN_LEDGER_KEY_PATH", DEFAULT_KEY_PATH))
        app.state.public_key = public_key_hex(key)
        app.state.store = LedgerStore(
            ledger_path or os.environ.get("PROOFCHAIN_LEDGER_PATH", DEFAULT_LEDGER_PATH), key
        )
        yield

    app = FastAPI(title="ProofChain ledger", lifespan=lifespan)

    @app.post("/entries", status_code=201)
    def append_entry(new: NewEntry, request: Request) -> dict:
        try:
            return request.app.state.store.append(new.batch_id, new.root, new.tree_size)
        except DuplicateBatch:
            raise HTTPException(409, f"a root is already published for batch {new.batch_id}")

    @app.get("/entries")
    def list_entries(request: Request) -> list[dict]:
        return request.app.state.store.entries()

    @app.get("/entries/{batch_id}")
    def get_entry(batch_id: str, request: Request) -> dict:
        entry = request.app.state.store.get(batch_id)
        if entry is None:
            raise HTTPException(404, f"no entry for batch {batch_id}")
        return entry

    @app.get("/head")
    def head(request: Request) -> dict:
        entry = request.app.state.store.head()
        if entry is None:
            raise HTTPException(404, "the ledger is empty")
        return {"seq": entry["seq"], "entry_hash": entry["entry_hash"]}

    @app.get("/pubkey")
    def pubkey(request: Request) -> dict:
        return {"public_key": request.app.state.public_key}

    return app


app = create_app()
