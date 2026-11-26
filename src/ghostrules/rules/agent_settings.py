"""Agent settings rules GR107-GR108 (``.claude/settings*.json``, Gemini settings, MCP trust)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ghostrules.jsonloc import JNode, parse_located
from ghostrules.mcp_config import Span, is_settings_file, settings_env_entries
from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.helpers import build_finding, urls_allowed
from ghostrules.rules.patterns import COLLECTOR_PATTERNS, EXFIL_PATTERNS, INJECTION_PATTERNS
from ghostrules.rules.registry import rule

CONFIG: tuple[Kind, ...] = ("config",)

_SENSITIVE_PATH = (
    r"(?:(?<!\w)\.env\b(?!\.(?:example|sample|template|dist)\b)|~/\.ssh|id_rsa|id_ed25519"
    r"|\.aws/credentials|\.npmrc|\.netrc|\.pypirc|/etc/shadow)"
)
_SENDER = r"(?:curl|wget|nc|ncat|netcat)"
_HOOK_EXFIL_PATTERNS = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        rf"\b{_SENDER}\b[^\n|;&]{{0,200}}{_SENSITIVE_PATH}",
        rf"{_SENSITIVE_PATH}[^\n]{{0,200}}\|\s*{_SENDER}\b",
        rf"\b(?:env|printenv)\b[^\n]{{0,60}}\|\s*{_SENDER}\b",
    )
)
# a directory grant that is the whole home folder or the disk root (not a project subfolder)
_BROAD_DIR = re.compile(r"~/?|\$HOME/?|\$\{HOME\}/?|/|/home/?|/Users/?|/root/?")
_BROAD_ALLOW = re.compile(
    r"Bash(?:\(\s*\*{0,2}\s*\))?"
    r"|Bash\(\s*(?:curl|sudo|rm)\s*:\s*\*\s*\)"
    r"|WebFetch(?:\(\s*\*?\s*\))?",
    re.IGNORECASE,
)
# a sender that posts data it was given: -d, --data-binary, -F, -T, --upload-file, -X POST.
# Case-sensitive on purpose: -f (fail) and -t are not data flags.
_POSTS_DATA = re.compile(
    rf"\b{_SENDER}\b[^\n]*?(?:\s-[a-zA-Z]*[dFT]\b|\s--(?:data|form|upload-file|post-data|json)\b"
    r"|\s-X\s*(?:POST|PUT)\b)"
)
_REMOTE_URL = re.compile(
    r"https?://(?!(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])[:/])[^\s'\"]+", re.IGNORECASE
)
_TOOL_RULE = re.compile(r"(?:Read|Edit|Write|MultiEdit|Bash|Grep|Glob)\((.*)\)", re.DOTALL)
_SECRET_FILE = re.compile(_SENSITIVE_PATH, re.IGNORECASE)


def _finding(
    target: ScanTarget,
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    span: Span,
    fix_hint: str,
) -> Finding:
    return build_finding(
        target=target,
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        start=span[0],
        end=max(span[1], span[0]),
        fix_hint=fix_hint,
        limit=80,
    )


def _hook_commands(node: JNode | None) -> Iterator[JNode]:
    """Every string ``command`` value nested anywhere under ``hooks``."""
    if node is None:
        return
    if node.members is not None:
        for key, (_start, child) in node.members.items():
            if key == "command" and isinstance(child.value, str):
                yield child
            else:
                yield from _hook_commands(child)
    elif node.elements is not None:
        for element in node.elements:
            yield from _hook_commands(element)


def _hook_problem(command: str) -> str | None:
    if any(p.search(command) for p in INJECTION_PATTERNS["GR012"]):
        return "downloads and executes remote code"
    if any(
        p.search(command) for p in (*EXFIL_PATTERNS, *_HOOK_EXFIL_PATTERNS, *COLLECTOR_PATTERNS)
    ):
        return "sends sensitive data to a remote host"
    if _POSTS_DATA.search(command) and _REMOTE_URL.search(command):
        return "posts data to a remote host (a hook runs on every prompt or tool call)"
    return None


def _secret_grant(rule: str) -> bool:
    """A tool permission (``Read(...)``, ``Bash(...)``) whose argument names a secret file."""
    found = _TOOL_RULE.fullmatch(rule.strip())
    return found is not None and _SECRET_FILE.search(found.group(1)) is not None


_CODEX_SWITCHES = (
    (
        re.compile(r"^[ \t]*sandbox_mode[ \t]*=[ \t]*([\"'])danger-full-access\1", re.MULTILINE),
        'sandbox_mode is "danger-full-access": commands run with no filesystem or network limits.',
        'Use "workspace-write" (or "read-only").',
    ),
    (
        re.compile(r"^[ \t]*approval_policy[ \t]*=[ \t]*([\"'])never\1", re.MULTILINE),
        'approval_policy is "never": Codex runs commands without ever asking.',
        'Use "on-request", and "never" only inside a sandbox you control.',
    ),
)
_GEMINI_BARE_SHELL = re.compile(r"run_shell_command(?:\(\s*\*{0,2}\s*\))?", re.IGNORECASE)


def _codex_findings(target: ScanTarget) -> Iterator[Finding]:
    """The two ``config.toml`` switches that turn Codex's guards off."""
    for pattern, message, hint in _CODEX_SWITCHES:
        for match in pattern.finditer(target.text):
            line_start = target.text.rfind("\n", 0, match.start()) + 1
            if target.text[line_start : match.start()].strip().startswith("#"):
                continue
            yield _finding(
                target, "GR107", Severity.HIGH, "Over-permissive agent settings",
                message, (match.start(), match.end()), hint,
            )  # fmt: skip


def _gemini_findings(target: ScanTarget, root: JNode) -> Iterator[Finding]:
    """Gemini CLI settings that skip confirmation (names from its configuration reference)."""
    tools, security = root.get("tools"), root.get("security")
    allowed = tools.get("allowed") if tools else None
    for item in (allowed.elements or []) if allowed else []:
        if isinstance(item.value, str) and _GEMINI_BARE_SHELL.fullmatch(item.value.strip()):
            yield _finding(
                target, "GR107", Severity.HIGH, "Over-permissive agent settings",
                f"tools.allowed has '{item.value}': any shell command runs without confirmation.",
                item.string_span(),
                "Allow specific commands, for example run_shell_command(git status).",
            )  # fmt: skip
    permanent = security.get("enablePermanentToolApproval") if security else None
    if permanent is not None and permanent.value is True:
        yield _finding(
            target, "GR107", Severity.HIGH, "Over-permissive agent settings",
            "security.enablePermanentToolApproval is true: approvals are remembered for good.",
            (permanent.start, permanent.end), "Remove it so each tool needs approval.",
        )  # fmt: skip


# a model API endpoint at its vendor is the normal setting; anything else receives the API key
_OFFICIAL_API = re.compile(
    r"^https?://(?:[\w-]+\.)*(?:anthropic\.com|openai\.com|googleapis\.com)(?=[:/]|$)", re.I
)
_FETCHES_REMOTE = re.compile(r"\b(?:curl|wget)\b[^\n]*?" + _REMOTE_URL.pattern, re.IGNORECASE)


def _auto_run_findings(target: ScanTarget, root: JNode) -> Iterator[Finding]:
    """An API key helper or a status line runs on every request: fetching from a remote host
    there runs remote content, or hands the key to a host, on each request."""
    nodes = [root.get("apiKeyHelper")]
    status = root.get("statusLine")
    nodes.append(status.get("command") if status is not None else None)
    for node in nodes:
        if node is None or not isinstance(node.value, str):
            continue
        if _FETCHES_REMOTE.search(node.value) and not urls_allowed(
            node.value, target.allow_domains
        ):
            yield _finding(
                target, "GR107", Severity.HIGH, "Over-permissive agent settings",
                f"A command that runs on every request fetches from a remote host: "
                f"{node.value[:100]}",
                node.string_span(),
                "Point it at a local script or a reviewed tool; keep the key off the network.",
            )  # fmt: skip


def _base_url_findings(target: ScanTarget) -> Iterator[Finding]:
    """A ``*_BASE_URL`` in the project's env block sends every prompt and the API key to that
    host; only the vendor's own endpoints and allowed domains are the normal setting."""
    for entry in settings_env_entries(target):
        value = entry.value.strip()
        if not entry.key.endswith("_BASE_URL") or not _REMOTE_URL.match(value):
            continue
        if _OFFICIAL_API.match(value) or urls_allowed(value, target.allow_domains):
            continue
        yield _finding(
            target, "GR107", Severity.HIGH, "Over-permissive agent settings",
            f"{entry.key} points the model API at {value[:80]}: prompts and the API key go to "
            "that host.",
            entry.span,
            "Remove the override from the committed settings, or set it in your own environment.",
        )  # fmt: skip


@rule(
    "GR107",
    Severity.HIGH,
    "Over-permissive agent settings",
    "Agent settings that skip permission prompts, allow unrestricted tools, or run risky hooks.",
    CONFIG,
)
def gr107_permissive_settings(target: ScanTarget) -> Iterator[Finding]:
    """``bypassPermissions``, blanket ``Bash``/``WebFetch``/``curl``/``sudo``/``rm`` allows, Gemini
    ``yolo``; hooks that fetch-and-run code or send secrets are critical."""
    if target.path.replace("\\", "/").endswith(".codex/config.toml"):
        yield from _codex_findings(target)
        return
    if not is_settings_file(target.path):
        return
    root = parse_located(target.text)
    if root is None:
        return
    if ".gemini/" in target.path.replace("\\", "/"):
        yield from _gemini_findings(target, root)
    permissions = root.get("permissions")
    mode = permissions.get("defaultMode") if permissions else None
    if mode is not None and mode.value == "bypassPermissions":
        yield _finding(
            target, "GR107", Severity.HIGH, "Over-permissive agent settings",
            "defaultMode is bypassPermissions: the agent runs every tool without asking.",
            mode.string_span(), "Remove defaultMode or use a mode that asks for permission.",
        )  # fmt: skip
    allow = permissions.get("allow") if permissions else None
    for item in (allow.elements or []) if allow else []:
        if isinstance(item.value, str) and _BROAD_ALLOW.fullmatch(item.value.strip()):
            yield _finding(
                target, "GR107", Severity.HIGH, "Over-permissive agent settings",
                f"Permission rule '{item.value}' allows unrestricted use of a powerful tool.",
                item.string_span(),
                "Allow only specific commands or domains, for example Bash(npm run test:*).",
            )  # fmt: skip
        elif isinstance(item.value, str) and _secret_grant(item.value):
            yield _finding(
                target, "GR107", Severity.HIGH, "Over-permissive agent settings",
                f"Permission rule '{item.value}' lets the agent use a secret file without asking.",
                item.string_span(),
                "Remove the rule; allow only the project files the task needs.",
            )  # fmt: skip
    extra = permissions.get("additionalDirectories") if permissions else None
    for item in (extra.elements or []) if extra else []:
        if isinstance(item.value, str) and _BROAD_DIR.fullmatch(item.value.strip()):
            yield _finding(
                target, "GR107", Severity.HIGH, "Over-permissive agent settings",
                f"additionalDirectories grants '{item.value}': the whole home folder or disk.",
                item.string_span(),
                "List only the project folders the task needs in additionalDirectories.",
            )  # fmt: skip
    yolo = root.get("yolo")
    if yolo is not None and yolo.value is True and ".gemini/" in target.path.replace("\\", "/"):
        yield _finding(
            target, "GR107", Severity.HIGH, "Over-permissive agent settings",
            "yolo is enabled: Gemini CLI runs every tool call without confirmation.",
            (yolo.start, yolo.end), "Remove \"yolo\" so tool calls need confirmation.",
        )  # fmt: skip
    for command in _hook_commands(root.get("hooks")):
        problem = _hook_problem(command.value)
        if problem:
            yield _finding(
                target, "GR107", Severity.CRITICAL, "Over-permissive agent settings",
                f"A hook {problem}: {command.value[:100]}",
                command.string_span(), "Remove the hook; hooks run with your full privileges.",
            )  # fmt: skip
    yield from _auto_run_findings(target, root)
    yield from _base_url_findings(target)


@rule(
    "GR108",
    Severity.MEDIUM,
    "Auto-enabled project MCP servers",
    "Settings that start MCP servers from a cloned repository without review.",
    CONFIG,
)
def gr108_auto_trust(target: ScanTarget) -> Iterator[Finding]:
    """``enableAllProjectMcpServers: true`` and servers marked ``trust: true`` (Gemini)."""
    if is_settings_file(target.path):
        root = parse_located(target.text)
        flag = root.get("enableAllProjectMcpServers") if root else None
        if flag is not None and flag.value is True:
            yield _finding(
                target, "GR108", Severity.MEDIUM, "Auto-enabled project MCP servers",
                "enableAllProjectMcpServers is true: any cloned repo's .mcp.json starts its "
                "servers without review.",
                (flag.start, flag.end), "Remove it and approve project servers one by one.",
            )  # fmt: skip
    for server in target.servers:
        if server.trust:
            yield _finding(
                target, "GR108", Severity.MEDIUM, "Auto-trusted MCP server",
                f"Server '{server.name}' is marked trust: its tool calls skip confirmation.",
                server.span("trust"), "Remove \"trust\" so tool calls need confirmation.",
            )  # fmt: skip
