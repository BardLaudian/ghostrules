"""W8: the context engine is a documented, stable library API with a JSON schema."""

import json
from pathlib import Path

import pytest
from conftest import ROOT
from jsonschema import Draft7Validator

import ghostrules.context as api
from ghostrules.config import Config
from ghostrules.context_command import build_report
from ghostrules.reporters.context_data import render_json

DEMO = ROOT / "examples" / "import-chain-repo"


def test_the_schema_is_itself_valid_and_ships_with_the_package() -> None:
    Draft7Validator.check_schema(api.schema())
    assert (ROOT / "src/ghostrules/schemas/context.schema.json").is_file()


@pytest.mark.parametrize("agent", ["all", "claude-code", "codex", "gemini-cli"])
@pytest.mark.parametrize("scan", [True, False])
def test_resolve_returns_a_document_that_matches_the_schema(agent: str, scan: bool) -> None:
    report = api.resolve(DEMO, agent=agent, target="src/api/users.ts", scan=scan)
    errors = sorted(Draft7Validator(api.schema()).iter_errors(report), key=str)
    assert not errors, errors[:3]
    assert (report["findings"] is None) == (not scan)


def test_resolve_is_what_the_json_format_prints() -> None:
    expected = json.loads(render_json(build_report(DEMO, Config(), agent="claude-code")))
    assert api.resolve(DEMO, agent="claude-code") == expected


def test_resolve_shows_the_chain_to_the_payload() -> None:
    report = api.resolve(DEMO, agent="claude-code")
    chain = {e["path"]: e["via"] for e in report["agents"]["claude-code"]["entries"]}
    assert chain["shared/team-rules.md"] == ["CLAUDE.md:5", "docs/style.md:4"]
    assert any(f["rule_id"] == "GR001" for f in report["findings"])


def test_a_bad_root_or_agent_is_a_context_error(tmp_path: Path) -> None:
    with pytest.raises(api.ContextError):
        api.resolve(tmp_path / "missing")
    with pytest.raises(api.ContextError):
        api.resolve(DEMO, agent="vim")


def test_the_public_names_are_the_documented_ones() -> None:
    assert set(api.__all__) == {
        "AGENT_NAMES",
        "DEFAULT_AGENTS",
        "ContextError",
        "resolve",
        "schema",
    }
    assert "codex" in api.AGENT_NAMES and "codex" not in api.DEFAULT_AGENTS
