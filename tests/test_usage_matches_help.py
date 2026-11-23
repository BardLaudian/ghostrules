"""``scan --help`` and the option table of docs/USAGE.md say the same thing (phase 8)."""

import re
from pathlib import Path

import pytest
from typer.main import get_command

from ghostrules.cli import app

ROOT = Path(__file__).resolve().parent.parent
USAGE = (ROOT / "docs" / "USAGE.md").read_text(encoding="utf-8")
SCAN = get_command(app).commands["scan"]  # type: ignore[attr-defined]


def documented_rows() -> dict[str, str]:
    """option name -> its default cell, from the ``scan`` option table in USAGE.md."""
    section = USAGE.split("| `scan` option | Default | Meaning |")[1].split("\n\n")[0]
    rows: dict[str, str] = {}
    for line in section.splitlines():
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
        if len(cells) < 3 or set(cells[0]) <= {"-"}:
            continue
        for name in re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", cells[0]):
            rows[name] = cells[1].strip("`")
    return rows


def help_options() -> dict[str, object]:
    return {
        opt: param
        for param in SCAN.params
        for opt in [*getattr(param, "opts", []), *getattr(param, "secondary_opts", [])]
        if opt.startswith("--") and opt != "--help"
    }


def test_the_documented_options_are_exactly_the_ones_in_help() -> None:
    documented, real = set(documented_rows()), set(help_options())
    assert real - documented == set(), (
        f"in --help, missing from USAGE.md: {sorted(real - documented)}"
    )
    assert documented - real == set(), f"in USAGE.md, not in --help: {sorted(documented - real)}"


@pytest.mark.parametrize(
    ("option", "shown"),
    [
        ("--format", "table"),
        ("--fail-on", "high"),
        ("--min-severity", "low"),
        ("--max-file-size", "1048576"),
    ],
)
def test_documented_defaults_are_the_real_ones(option: str, shown: str) -> None:
    assert documented_rows()[option] == shown
    param = help_options()[option]
    real = getattr(param, "default", None)
    if real is not None:  # options whose default lives in the config are checked by the line above
        assert str(getattr(real, "value", real)) == shown


def test_help_and_usage_agree_on_the_exit_codes() -> None:
    doc = SCAN.help or ""
    for code, words in {"0": "clean", "1": "findings", "2": "usage", "3": "internal"}.items():
        assert re.search(rf"\b{code}\b[^.]*{words}", doc.replace("\n", " ")), (code, doc)
    section = USAGE.split("#### Exit codes")[1].split("\n#")[0]
    for code in "0123":
        assert f"| `{code}` |" in section


def test_every_command_has_a_help_text_and_scan_help_runs() -> None:
    from typer.testing import CliRunner

    out = CliRunner().invoke(app, ["scan", "--help"])
    assert out.exit_code == 0 and "--max-file-size" in out.output
    for name, command in get_command(app).commands.items():  # type: ignore[attr-defined]
        assert (command.help or "").strip(), f"{name} has no help text"
