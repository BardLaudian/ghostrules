import json

from ghostrules.jsonloc import parse_located
from ghostrules.mcp_config import extract_servers, is_settings_file, settings_env_entries
from ghostrules.models import ScanTarget
from ghostrules.scanner import parse_structured


def target(text: str, path: str = ".mcp.json", kind: str = "config") -> ScanTarget:
    parsed, _ = parse_structured(path, text)
    return ScanTarget(path, kind, text, parsed=parsed)  # type: ignore[arg-type]


def line_of(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def test_parse_located_tracks_offsets() -> None:
    text = '{\n  "a": [1, "two"],\n  "b": {"c": true}\n}\n'
    root = parse_located(text)
    assert root is not None
    two = root.get("a").elements[1]  # type: ignore[union-attr]
    assert text[slice(*two.string_span())] == "two"
    assert root.get("b").get("c").value is True  # type: ignore[union-attr]
    assert parse_located("{bad") is None
    assert parse_located('{"a": 1} trailing') is None
    assert parse_located("") is None


def test_parse_located_handles_jsonc_bom_and_escapes() -> None:
    text = '\ufeff{\n  // comment\n  "a": "x\\"y", /* c */\n  "b": [1,],\n}\n'
    root = parse_located(text)
    assert root is not None
    assert root.get("a").value == 'x"y'  # type: ignore[union-attr]
    assert root.get("b").value == [1]  # type: ignore[union-attr]


def test_mcpservers_shape_and_spans() -> None:
    text = json.dumps(
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "pkg@1.0.0"],
                    "env": {"TOKEN": "abc"},
                },
                "remote": {"url": "https://example.com/mcp", "headers": {"X-Key": "v"}},
                "noise": {"description": "no command or url"},
            }
        },
        indent=2,
    )
    t = target(text)
    github, remote = extract_servers(t)
    assert (github.name, github.command, github.args) == ("github", "npx", ("-y", "pkg@1.0.0"))
    assert github.env == {"TOKEN": "abc"}
    assert (remote.url, dict(remote.headers)) == ("https://example.com/mcp", {"X-Key": "v"})
    assert text[slice(*github.span("command"))] == "npx"
    assert text[slice(*github.span("args.1"))] == "pkg@1.0.0"
    assert text[slice(*github.span("env.TOKEN"))] == "abc"
    assert text[slice(*remote.span("headers.X-Key"))] == "v"
    assert line_of(text, github.span("env.TOKEN")[0]) == line_of(text, text.index("abc"))
    assert text[slice(*github.span("name"))] == '"github"'
    assert github.span("missing") == github.span("name")
    assert t.servers is t.servers  # cached


def test_vscode_servers_and_nested_mcp_servers() -> None:
    vscode = target('{"servers": {"a": {"command": "node"}}}', ".vscode/mcp.json")
    assert [s.name for s in vscode.servers] == ["a"]
    nested = target('{"mcp": {"servers": {"b": {"url": "https://x.example"}}}}', "settings.json")
    assert [s.name for s in nested.servers] == ["b"]


def test_claude_json_project_servers() -> None:
    text = json.dumps(
        {
            "mcpServers": {"top": {"command": "a"}},
            "projects": {"/work/app": {"mcpServers": {"deep": {"command": "b"}}}},
        }
    )
    assert [s.name for s in target(text, "~/.claude.json").servers] == ["top", "deep"]


def test_url_key_variants_and_trust() -> None:
    text = json.dumps(
        {
            "mcpServers": {
                "w": {"serverUrl": "http://a.example"},
                "g": {"httpUrl": "https://b", "trust": True},
            }
        }
    )
    w, g = target(text).servers
    assert w.url == "http://a.example"
    assert (g.url, g.trust) == ("https://b", True)


def test_command_name_normalisation() -> None:
    text = json.dumps(
        {"mcpServers": {"a": {"command": "C:\\Tools\\NPX.CMD"}, "b": {"command": "/usr/bin/uvx"}}}
    )
    a, b = target(text).servers
    assert (a.command_name, b.command_name) == ("npx", "uvx")


def test_toml_servers_and_spans() -> None:
    text = (
        "[mcp_servers.github]\n"
        'command = "npx"\n'
        'args = ["-y", "pkg"]\n'
        'env = { GITHUB_TOKEN = "tok123" }\n'
        "\n"
        "[mcp_servers.remote]\n"
        'url = "https://example.com/mcp"\n'
        "\n"
        "[mcp_servers.remote.http_headers]\n"
        'X-Key = "headervalue"\n'
        "\n"
        "[other]\nx = 1\n"
    )
    github, remote = target(text, "~/.codex/config.toml").servers
    assert github.env == {"GITHUB_TOKEN": "tok123"}
    assert text[slice(*github.span("env.GITHUB_TOKEN"))] == "tok123"
    assert line_of(text, github.span("env.GITHUB_TOKEN")[0]) == 4
    assert remote.url == "https://example.com/mcp"
    assert line_of(text, remote.span("url")[0]) == 7
    assert dict(remote.headers) == {"X-Key": "headervalue"}
    assert line_of(text, remote.span("headers.X-Key")[0]) == 10


def test_non_config_or_unparsable_files_have_no_servers() -> None:
    assert (
        target('{"mcpServers": {"a": {"command": "x"}}}', "AGENTS.md", "instructions").servers == []
    )
    assert target("{broken", ".mcp.json").servers == []
    assert target("[1, 2]", ".mcp.json").servers == []
    assert target("", "aider.conf.yml").servers == []


def test_settings_env_entries() -> None:
    text = '{\n  "env": {"A": "1", "B": 2, "C": "three"}\n}\n'
    entries = settings_env_entries(target(text, ".claude/settings.json"))
    assert [(e.key, e.value) for e in entries] == [("A", "1"), ("C", "three")]
    assert text[slice(*entries[1].span)] == "three"
    assert settings_env_entries(target(text, ".mcp.json")) == []


def test_is_settings_file() -> None:
    for path in (".claude/settings.json", ".claude/settings.local.json", "~/.gemini/settings.json"):
        assert is_settings_file(path)
    assert is_settings_file(".claude\\settings.json")
    assert not is_settings_file(".mcp.json")
    assert not is_settings_file("mysettings.json")
