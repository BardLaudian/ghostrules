"""Code and files that agents reach without an ``@`` import (REMEDIATION W5.1, W5.2, W5.4).

A hook names a script, a skill's ``SKILL.md`` tells the agent to run one. The command looks
harmless and the script is what runs, so the script is scanned as agent-reachable code, with the
chain that leads to it. Everything here is pure: the caller says which paths exist.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import tomllib

from ghostrules.jsonloc import strip_jsonc

Exists = Callable[[str], bool]
_BOM = chr(0xFEFF)

# Variables agents set to the project directory in hook commands.
_PROJECT_DIR_VARS = re.compile(
    r"\$\{?(?:CLAUDE_PROJECT_DIR|GEMINI_PROJECT_DIR|CODEX_PROJECT_DIR)\}?"
)
_SEGMENT = re.compile(r"\|\||&&|[|;&]")
# Flags that make the next argument code, per interpreter family (``-e`` is errexit for a shell).
_INLINE_FLAGS: dict[str, frozenset[str]] = {
    **dict.fromkeys(("sh", "bash", "zsh", "dash", "ksh"), frozenset({"-c"})),
    **dict.fromkeys(("python", "python3", "py"), frozenset({"-c"})),
    **dict.fromkeys(("node", "nodejs", "deno"), frozenset({"-e", "-p", "--eval", "--print"})),
    **dict.fromkeys(("ruby", "perl"), frozenset({"-e"})),
    **dict.fromkeys(
        ("pwsh", "powershell"), frozenset({"-c", "-command", "-encodedcommand", "-e", "-ec"})
    ),
}
_INTERPRETERS = frozenset(_INLINE_FLAGS) | {"tsx", "ts-node", "bun", "php", "uv", "npx", "env"}
SCRIPT_EXTENSIONS = frozenset(
    {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".ps1",
     ".bat", ".cmd", ".lua"}
)  # fmt: skip
HOOK_CONFIGS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    ".cursor/hooks.json",
    ".codex/hooks.json",
    ".codex/config.toml",
)


@dataclass(frozen=True)
class ScriptRef:
    """A repository script that something runs. ``via`` is ``"<config path>:<line>"``."""

    path: str
    via: str
    why: str


def _clean(path: str) -> str | None:
    """A repository-relative POSIX path, or ``None`` if it leaves the repository."""
    path = _PROJECT_DIR_VARS.sub(".", path).replace("\\", "/")
    if path.startswith(("~", "/")) or re.match(r"^[A-Za-z]:/", path) or "$" in path:
        return None
    normal = posixpath.normpath(path)
    if normal == ".." or normal.startswith("../") or normal == ".":
        return None
    return normal


def _segments(command: str) -> Iterator[list[str]]:
    for segment in _SEGMENT.split(command):
        try:
            tokens = shlex.split(_PROJECT_DIR_VARS.sub(".", segment), posix=True)
        except ValueError:
            tokens = segment.split()
        if tokens:
            yield tokens


def _interpreter(token: str) -> str:
    name = posixpath.basename(token.replace("\\", "/")).lower()
    return re.sub(r"[\d.]+$", "", name) if name.startswith("python") else name


def script_from_command(command: str, exists: Exists) -> str | None:
    """The repository file a hook or skill command runs, or ``None``.

    The first token (``./a.sh``) or a later token that is a repository script (``bash a.sh``,
    ``uv run a.py``) is the script: it has a script extension or follows an interpreter. Inline code
    (``bash -c``), paths that leave the repository (absolute, ``~``, ``..``) and files that do not
    exist resolve to nothing.
    """
    for tokens in _segments(command):
        interpreter = _interpreter(tokens[0])
        inline = _INLINE_FLAGS.get(interpreter, frozenset())
        if any(t.lower() in inline for t in tokens[1:4]):
            continue
        for position, token in enumerate(tokens):
            if token.startswith("-"):
                continue
            path = _clean(token)
            if path is None or not exists(path):
                continue
            after_interpreter = position > 0 and _interpreter(tokens[position - 1]) in _INTERPRETERS
            if (
                position == 0
                or after_interpreter
                or posixpath.splitext(path)[1] in SCRIPT_EXTENSIONS
            ):
                return path
    return None


def _commands(node: Any) -> Iterator[str]:
    """Every string ``command`` value in a parsed hooks table."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "command" and isinstance(value, str):
                yield value
            else:
                yield from _commands(value)
    elif isinstance(node, list):
        for item in node:
            yield from _commands(item)


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index != -1 else 1


def _parse(path: str, text: str) -> Any:
    try:
        if path.endswith(".toml"):
            return tomllib.loads(text.removeprefix(_BOM))
        return json.loads(strip_jsonc(text.removeprefix(_BOM)))
    except (ValueError, RecursionError):
        return None


_SCRIPT_MENTION = re.compile(r"[\w./-]+\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|php|ps1|lua)\b")


def skill_scripts(path: str, text: str, exists: Exists) -> list[ScriptRef]:
    """Scripts under a skill's directory that its ``SKILL.md`` names (``python scripts/a.py``).

    Only files below the skill directory count, and only when the text mentions them: a script
    nobody points to is not something the agent was told to run.
    """
    directory = posixpath.dirname(path)
    refs: dict[str, ScriptRef] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        for mention in _SCRIPT_MENTION.findall(line):
            joined = _clean(posixpath.join(directory, mention))
            if (
                joined is not None
                and (directory == "" or joined.startswith(directory + "/"))
                and exists(joined)
            ):
                refs.setdefault(joined, ScriptRef(joined, f"{path}:{number}", "skill script"))
    return list(refs.values())


def hook_scripts(path: str, text: str, exists: Exists) -> list[ScriptRef]:
    """The repository scripts that the hooks of a settings file run."""
    if os.path.basename(path) == "" or not any(path.endswith(c) for c in HOOK_CONFIGS):
        return []
    data = _parse(path, text)
    hooks = data.get("hooks") if isinstance(data, dict) else None
    refs: dict[str, ScriptRef] = {}
    for command in _commands(hooks):
        script = script_from_command(command, exists)
        if script is not None and script not in refs:
            refs[script] = ScriptRef(script, f"{path}:{_line_of(text, command)}", "hook command")
    return list(refs.values())
