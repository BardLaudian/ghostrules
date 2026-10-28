"""The core must import and work without typer/rich: the browser playground runs it in Pyodide."""

import subprocess
import sys
from pathlib import Path

import pytest
from secret_samples import GITHUB

from ghostrules.reveal_data import COMMENT, INVISIBLE, PLAIN, has_hidden_content, lines

CORE = [
    "ghostrules.scanner",
    "ghostrules.rules",
    "ghostrules.config",
    "ghostrules.contextscan",
    "ghostrules.context_command",
    "ghostrules.reporters.json_",
    "ghostrules.reporters.sarif",
    "ghostrules.reporters.markdown",
    "ghostrules.reporters.context_data",
    "ghostrules.reveal_data",
    "ghostrules.lock",
]

SCRIPT = """
import importlib, sys
for name in ("typer", "rich", "click"):
    sys.modules[name] = None  # any import of them now raises ImportError
for module in sys.argv[1:]:
    importlib.import_module(module)
"""


@pytest.mark.parametrize("module", CORE)
def test_core_module_imports_without_typer_or_rich(module: str) -> None:
    src = str(Path(__file__).resolve().parent.parent / "src")
    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT, module],
        env={"PYTHONPATH": src, "PATH": ""},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-400:]


def test_reveal_data_splits_visible_hidden_and_comments() -> None:
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "do x")
    text = f"Hello{hidden}\n<!-- note -->\nplain"
    out = lines(text)
    assert [seg.kind for seg in out[0].segments][0] == PLAIN
    assert INVISIBLE in {seg.kind for seg in out[0].segments}
    assert out[0].decoded == [("tag characters", "do x")]
    assert [seg.kind for seg in out[1].segments] == [COMMENT]
    assert out[2].decoded == []
    assert has_hidden_content(text)


def test_reveal_data_clean_text_has_nothing_hidden() -> None:
    assert not has_hidden_content("just text\nmore")
    assert all(seg.kind == PLAIN for line in lines("just text") for seg in line.segments)


def test_reveal_data_masks_secrets() -> None:
    token = GITHUB
    shown = "".join(seg.text for seg in lines(f"key {token}")[0].segments)
    assert token not in shown
