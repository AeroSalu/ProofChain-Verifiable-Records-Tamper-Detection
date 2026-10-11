import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofchain.ledger import app as ledger_app
from proofchain.registry import app as registry_app

from .helpers import InProcessLedger

VECTORS = Path(__file__).parent / "vectors" / "examples.json"


@pytest.fixture(scope="session")
def vectors():
    """The worked examples from the project brief, as generated for it."""
    return json.loads(VECTORS.read_text(encoding="utf-8"))


@pytest.fixture
def ledger_paths(tmp_path):
    return tmp_path / "ledger.jsonl", tmp_path / "ledger_key.pem"


@pytest.fixture
def ledger(ledger_paths):
    """A real ledger service running in-process, behind the registry's client interface."""
    with TestClient(ledger_app.create_app(*ledger_paths)) as client:
        yield InProcessLedger(client)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "registry.db"


@pytest.fixture
def registry(db_path, ledger):
    """The registry service on a temporary database, publishing to the ledger above."""
    with TestClient(registry_app.create_app(db_path, ledger)) as client:
        yield client
