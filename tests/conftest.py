import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="session")
def make_fixtures() -> ModuleType:
    """The scripts/make_fixtures.py module (it is a script, not part of the package)."""
    spec = importlib.util.spec_from_file_location(
        "make_fixtures", ROOT / "scripts" / "make_fixtures.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def fixtures_root(make_fixtures: ModuleType) -> Path:
    """Regenerate the invisible-character fixtures once per session so they are always fresh."""
    make_fixtures.generate(FIXTURES)
    return FIXTURES
