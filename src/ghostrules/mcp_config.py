"""Normalise MCP server definitions from agent config files, keeping source locations.

Supported shapes: ``mcpServers`` (Claude Code/Desktop, Cursor, Gemini, Roo, Windsurf, also nested
under ``projects.*`` in ``~/.claude.json``), ``servers`` (VS Code, optionally under ``mcp``) and
``[mcp_servers.*]`` tables in Codex TOML. Locations are character offsets into the file text, so
rules can point at the exact value (a secret, a URL, an argument) rather than at the file.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ghostrules.jsonloc import JNode, parse_located

if TYPE_CHECKING:
    from ghostrules.models import ScanTarget

Span = tuple[int, int]
_URL_KEYS = ("url", "serverUrl", "httpUrl")


@dataclass(frozen=True)
class ServerDef:
    """One MCP server. ``spans`` maps ``name``, ``command``, ``url``, ``trust``, ``args.<i>``,
    ``env.<KEY>`` and ``headers.<KEY>`` to the span of that value in the file text."""

    name: str
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    trust: bool = False
    spans: Mapping[str, Span] = field(default_factory=dict)

    def span(self, key: str) -> Span:
        """Span of a field, falling back to the server's own key."""
        return self.spans.get(key) or self.spans.get("name") or (0, 0)

    @property
    def command_name(self) -> str:
        """Executable name without its directory or Windows extension, lower-cased."""
        if not self.command:
            return ""
        base = re.split(r"[\\/]", self.command.strip())[-1].lower()
        return re.sub(r"\.(?:exe|cmd|bat|ps1)$", "", base)


@dataclass(frozen=True)
class EnvEntry:
    """A ``KEY=value`` pair from an ``env`` table, with the span of its value."""

    key: str
    value: str
    span: Span


def _str_map(node: JNode | None, prefix: str, spans: dict[str, Span]) -> dict[str, str]:
    out: dict[str, str] = {}
    if node is None or node.members is None:
        return out
    for key, (_key_start, child) in node.members.items():
        if isinstance(child.value, str):
            out[key] = child.value
            spans[f"{prefix}.{key}"] = child.string_span()
    return out


def _server_from_json(name: str, key_start: int, node: JNode) -> ServerDef | None:
    if node.members is None:
        return None
    spans: dict[str, Span] = {"name": (key_start, key_start + len(name) + 2)}
    command_node = node.get("command")
    command = command_node.value if command_node and isinstance(command_node.value, str) else None
    if command_node is not None and command is not None:
        spans["command"] = command_node.string_span()
    url: str | None = None
    for key in _URL_KEYS:
        url_node = node.get(key)
        if url_node is not None and isinstance(url_node.value, str):
            url = url_node.value
            spans["url"] = url_node.string_span()
            break
    if command is None and url is None:
        return None
    args: list[str] = []
    args_node = node.get("args")
    if args_node is not None and args_node.elements is not None:
        for element in args_node.elements:
            if isinstance(element.value, str):
                spans[f"args.{len(args)}"] = element.string_span()
                args.append(element.value)
    trust_node = node.get("trust")
    trust = bool(trust_node and trust_node.value is True)
    if trust_node is not None:
        spans["trust"] = trust_node.start, trust_node.end
    return ServerDef(
        name=name,
        command=command,
        args=tuple(args),
        env=_str_map(node.get("env"), "env", spans),
        url=url,
        headers=_str_map(node.get("headers"), "headers", spans),
        trust=trust,
        spans=spans,
    )


def _json_containers(root: JNode) -> list[JNode]:
    found: list[JNode] = []

    def add(parent: JNode | None, key: str) -> None:
        child = parent.get(key) if parent else None
        if child is not None and child.members is not None:
            found.append(child)

    add(root, "mcpServers")
    add(root, "servers")
    add(root.get("mcp"), "servers")
    projects = root.get("projects")
    if projects is not None and projects.members is not None:
        for _key_start, project in projects.members.values():
            add(project, "mcpServers")
    return found


def _servers_from_json(text: str) -> list[ServerDef]:
    root = parse_located(text)
    if root is None or root.members is None:
        return []
    servers: list[ServerDef] = []
    for container in _json_containers(root):
        assert container.members is not None
        for name, (key_start, node) in container.members.items():
            server = _server_from_json(name, key_start, node)
            if server is not None:
                servers.append(server)
    return servers


def _toml_region(text: str, name: str) -> Span:
    """Span from the ``[mcp_servers.NAME]`` header to the next unrelated table header."""
    quoted = re.escape(name)
    header = re.compile(
        rf"^[ \t]*\[\s*mcp_servers\s*\.\s*(?:\"{quoted}\"|'{quoted}'|{quoted})\s*[.\]]",
        re.MULTILINE,
    )
    first = header.search(text)
    if first is None:
        return 0, len(text)
    end = len(text)
    for other in re.finditer(r"^[ \t]*\[", text[first.end() :], re.MULTILINE):
        line_start = first.end() + other.start()
        if not header.match(text, line_start):
            end = line_start
            break
    return first.start(), end


def _toml_find(text: str, region: Span, needle: str, fallback: Span) -> Span:
    index = text.find(needle, region[0], region[1])
    return (index, index + len(needle)) if index != -1 and needle else fallback


def _servers_from_toml(text: str, parsed: dict[str, Any]) -> list[ServerDef]:
    table = parsed.get("mcp_servers")
    if not isinstance(table, dict):
        return []
    servers: list[ServerDef] = []
    for name, node in table.items():
        if not isinstance(node, dict):
            continue
        region = _toml_region(text, name)
        header = (region[0], region[0])
        spans: dict[str, Span] = {"name": header}
        command = node.get("command") if isinstance(node.get("command"), str) else None
        url = next((node[k] for k in _URL_KEYS if isinstance(node.get(k), str)), None)
        if command is None and url is None:
            continue
        if command:
            spans["command"] = _toml_find(text, region, command, header)
        if url:
            spans["url"] = _toml_find(text, region, url, header)
        args = tuple(a for a in node.get("args", []) if isinstance(a, str))
        for i, arg in enumerate(args):
            spans[f"args.{i}"] = _toml_find(text, region, arg, header)
        maps: dict[str, dict[str, str]] = {"env": {}, "headers": {}}
        for prefix, keys in (("env", ("env",)), ("headers", ("http_headers", "headers"))):
            for key in keys:
                raw = node.get(key)
                if isinstance(raw, dict):
                    for k, v in raw.items():
                        if isinstance(v, str):
                            maps[prefix][k] = v
                            spans[f"{prefix}.{k}"] = _toml_find(text, region, v, header)
        servers.append(
            ServerDef(
                name=name,
                command=command,
                args=args,
                env=maps["env"],
                url=url,
                headers=maps["headers"],
                trust=node.get("trust") is True,
                spans=spans,
            )
        )
    return servers


def extract_servers(target: ScanTarget) -> list[ServerDef]:
    """All MCP servers defined in a config target (empty for other file kinds)."""
    if target.kind != "config" or not isinstance(target.parsed, dict):
        return []
    if target.path.lower().endswith(".toml"):
        return _servers_from_toml(target.text, target.parsed)
    return _servers_from_json(target.text)


_SETTINGS_RE = re.compile(r"(?:^|/)settings(?:\.local)?\.json$", re.IGNORECASE)


def is_settings_file(path: str) -> bool:
    """Whether the path is an agent ``settings.json`` / ``settings.local.json``."""
    return _SETTINGS_RE.search(path.replace("\\", "/")) is not None


def settings_env_entries(target: ScanTarget) -> list[EnvEntry]:
    """Entries of the top-level ``env`` table of a settings file."""
    if target.kind != "config" or not is_settings_file(target.path):
        return []
    root = parse_located(target.text)
    env = root.get("env") if root else None
    if env is None or env.members is None:
        return []
    return [
        EnvEntry(key, node.value, node.string_span())
        for key, (_start, node) in env.members.items()
        if isinstance(node.value, str)
    ]
