import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_path():
    def _path(name: str) -> str:
        return str(FIXTURES / name)

    return _path


@pytest.fixture
def payload(fixture_path):
    def _load(name: str) -> dict:
        with open(fixture_path(name), encoding="utf-8") as handle:
            return json.load(handle)

    return _load


@pytest.fixture
def one_domain(payload):
    """Return the single domain dict out of a one-domain fixture."""

    def _domain(name: str, index: int = 0) -> dict:
        return payload(name)["domains"][index]

    return _domain
