import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def load_script(name: str) -> ModuleType:
    """Import scripts/NAME.py (scripts are not part of the package)."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def make_fixtures() -> ModuleType:
    """The scripts/make_fixtures.py module."""
    return load_script("make_fixtures")


@pytest.fixture(scope="session")
def make_demo() -> ModuleType:
    """The scripts/make_demo.py module."""
    return load_script("make_demo")


@pytest.fixture(scope="session")
def fixtures_root(make_fixtures: ModuleType) -> Path:
    """Regenerate the invisible-character fixtures once per session so they are always fresh."""
    make_fixtures.generate(FIXTURES)
    return FIXTURES


@pytest.fixture(scope="session")
def demo_root(make_demo: ModuleType, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Both demo repositories freshly generated into a temporary directory."""
    return make_demo.generate(tmp_path_factory.mktemp("demo"))
