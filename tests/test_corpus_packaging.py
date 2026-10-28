import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILD = "import sys, hatchling.build as b; b.build_wheel(sys.argv[1]); b.build_sdist(sys.argv[1])"


def test_corpus_is_not_in_the_wheel_or_sdist(tmp_path: Path) -> None:
    pytest.importorskip("hatchling")
    done = subprocess.run(
        [sys.executable, "-c", BUILD, str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert done.returncode == 0, done.stderr
    wheel = next(tmp_path.glob("*.whl"))
    sdist = next(tmp_path.glob("*.tar.gz"))
    with zipfile.ZipFile(wheel) as zf:
        wheel_names = zf.namelist()
    with tarfile.open(sdist) as tar:
        sdist_names = tar.getnames()
    assert any(n.startswith("ghostrules/") for n in wheel_names)
    assert not [n for n in wheel_names + sdist_names if "corpus" in n.split("/")]
    assert any(n.endswith("/pyproject.toml") for n in sdist_names)
