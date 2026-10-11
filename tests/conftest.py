import json
from pathlib import Path

import pytest

VECTORS = Path(__file__).parent / "vectors" / "examples.json"


@pytest.fixture(scope="session")
def vectors():
    """The worked examples from the project brief, as generated for it."""
    return json.loads(VECTORS.read_text(encoding="utf-8"))
