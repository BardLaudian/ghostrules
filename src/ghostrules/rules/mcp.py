"""MCP configuration rules GR101-GR106 (JSON/TOML agent config files)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from urllib.parse import parse_qsl, urlsplit

from ghostrules.mcp_config import ServerDef, Span, settings_env_entries
from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.helpers import build_finding
from ghostrules.rules.patterns import INJECTION_PATTERNS
from ghostrules.rules.registry import rule
from ghostrules.secrets import is_secret_key_name, known_secret, looks_like_secret_value, mask_value

CONFIG: tuple[Kind, ...] = ("config",)


def _finding(
    target: ScanTarget,
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    span: Span,
    fix_hint: str,
    secrets: tuple[str, ...] = (),
) -> Finding:
    start, end = span
    return build_finding(
        target=target,
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        start=start,
        end=max(end, start),
        fix_hint=fix_hint,
        limit=60,
        secrets=secrets,
    )


# --- GR101 ---------------------------------------------------------------------------------


def _candidate_values(server: ServerDef) -> Iterator[tuple[str, str, str | None, str]]:
    """Yield ``(span key, where, key name or None, value)`` for every place a secret may sit."""
    for key, value in server.env.items():
        yield f"env.{key}", f"env var {key}", key, value
    for key, value in server.headers.items():
        yield f"headers.{key}", f"header {key}", key, value
    for i, arg in enumerate(server.args):
        name: str | None = None
        value = arg
        if arg.startswith("-") and "=" in arg:
            name, value = arg.split("=", 1)
        elif i > 0 and server.args[i - 1].startswith("-") and "=" not in server.args[i - 1]:
            name = server.args[i - 1]
        yield f"args.{i}", f"argument {i + 1}", name, value
    if server.url:
        parts = urlsplit(server.url)
        if parts.password:
            yield "url", "URL password", "password", parts.password
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            yield "url", f"URL parameter {name}", name, value
        yield "url", "URL", None, server.url


def _detect_secret(key: str | None, value: str) -> tuple[str, str] | None:
    """Return ``(label, secret)`` if the value is a hardcoded secret, else ``None``."""
    found = known_secret(value)
    if found:
        return found
    if key and is_secret_key_name(key) and looks_like_secret_value(value):
        return "Secret value", value
    return None


def _secret_findings(
    target: ScanTarget,
    where_prefix: str,
    candidates: Iterator[tuple[str, str, str | None, str]],
    spans: dict[str, Span] | None,
    server: ServerDef | None,
) -> Iterator[Finding]:
    seen: set[tuple[str, str]] = set()
    for span_key, where, key, value in candidates:
        detected = _detect_secret(key, value)
        if detected is None or (span_key, detected[1]) in seen:
            continue
        seen.add((span_key, detected[1]))
        label, secret = detected
        span = server.span(span_key) if server else (spans or {}).get(span_key, (0, 0))
        yield _finding(
            target,
            "GR101",
            Severity.CRITICAL,
            "Hardcoded secret in agent config",
            f"{label} hardcoded in {where}{where_prefix}: {mask_value(secret)}",
            span,
            "Reference an environment variable (for example ${GITHUB_TOKEN}) instead, and rotate "
            "this secret: it is exposed to everyone with access to the repository.",
            secrets=(secret,),
        )


@rule(
    "GR101",
    Severity.CRITICAL,
    "Hardcoded secret in agent config",
    "API keys and tokens written into MCP server env/args/headers/URLs or agent settings env.",
    CONFIG,
)
def gr101_hardcoded_secret(target: ScanTarget) -> Iterator[Finding]:
    """Known token formats anywhere in a server definition, plus high-entropy values under
    secret-looking names. Placeholders (``${VAR}``, ``<token>``) are fine. Always masked."""
    for server in target.servers:
        yield from _secret_findings(
            target, f" of server '{server.name}'", _candidate_values(server), None, server
        )
    entries = settings_env_entries(target)
    spans = {f"env.{e.key}": e.span for e in entries}
    candidates = ((f"env.{e.key}", f"env var {e.key}", e.key, e.value) for e in entries)
    yield from _secret_findings(target, " of the settings", candidates, spans, None)


# --- GR102 ---------------------------------------------------------------------------------

_RunnerSpec = tuple[str | None, frozenset[str], frozenset[str], bool]
# (required subcommand, flags taking a value to skip, flags whose value is the package, python?)
_RUNNERS: dict[str, _RunnerSpec] = {
    "npx": (
        None,
        frozenset({"-c", "--call", "--registry", "--cache", "--userconfig", "--prefix", "-w"}),
        frozenset({"-p", "--package"}),
        False,
    ),
    "bunx": (None, frozenset({"--registry", "--cwd"}), frozenset({"-p", "--package"}), False),
    "pnpm": ("dlx", frozenset({"--registry"}), frozenset({"-p", "--package"}), False),
    "yarn": ("dlx", frozenset({"--registry"}), frozenset({"-p", "--package"}), False),
    "uvx": (
        None,
        frozenset({"--python", "-p", "--with", "--index", "--index-url", "-i", "--env-file"}),
        frozenset({"--from"}),
        True,
    ),
    "pipx": (
        "run",
        frozenset({"--python", "--pip-args", "--index-url", "-i"}),
        frozenset({"--spec"}),
        True,
    ),
}
_NPM_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?")
_PY_VERSION = re.compile(r"\d+(?:\.[0-9A-Za-z]+)*(?:[-+!][0-9A-Za-z.+-]+)?")
_GIT_SHA = re.compile(r"[@#][0-9a-fA-F]{7,40}$")
_VCS_PREFIXES = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "ssh:")


def _package_arg(server: ServerDef) -> tuple[int, str, bool] | None:
    """Locate the package a runner executes: ``(arg index, spec, is_python)``."""
    runner = _RUNNERS.get(server.command_name)
    if runner is None:
        return None
    subcommand, value_flags, spec_flags, python = runner
    args = server.args
    i = 0
    if subcommand is not None:
        if not args or args[0] != subcommand:
            return None
        i = 1
    while i < len(args):
        arg = args[i]
        flag, _, inline = arg.partition("=")
        if flag in spec_flags:
            if inline:
                return i, inline, python
            return (i + 1, args[i + 1], python) if i + 1 < len(args) else None
        if flag in value_flags and not inline:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return i, arg, python
    return None


def _is_pinned(spec: str, python: bool) -> bool:
    """Whether a package spec fixes an exact version (or commit, or is not fetched at all)."""
    if spec.startswith((".", "/", "~", "file:")) or re.match(r"[A-Za-z]:[\\/]", spec):
        return True  # local path
    if spec.startswith(_VCS_PREFIXES):
        return _GIT_SHA.search(spec) is not None
    if re.match(r"https?://", spec):
        return True  # direct archive URL: version cannot be judged from the spec
    if python and re.search(r"===?\s*[^*\s,<>!~]+$", spec):
        return True
    at = spec.rfind("@")
    if at <= 0:
        return False
    version = spec[at + 1 :]
    return bool((_PY_VERSION if python else _NPM_VERSION).fullmatch(version))


def _pin_hint(spec: str, python: bool) -> str:
    if spec.startswith(_VCS_PREFIXES):
        return "Pin to a full commit SHA, for example ...repo.git@<40-hex-sha>."
    name = spec[:1] + re.split(r"[=<>!~@]", spec[1:], maxsplit=1)[0]
    return f"Pin an exact version, for example {name}{'==' if python else '@'}1.2.3."


@rule(
    "GR102",
    Severity.MEDIUM,
    "Unpinned package execution",
    "MCP servers launched with npx/uvx/etc. without an exact version run whatever is latest.",
    CONFIG,
)
def gr102_unpinned_package(target: ScanTarget) -> Iterator[Finding]:
    """npx, bunx, pnpm/yarn dlx, uvx and pipx run with a package that has no exact version."""
    for server in target.servers:
        located = _package_arg(server)
        if located is None or _is_pinned(located[1], located[2]):
            continue
        index, spec, python = located
        yield _finding(
            target,
            "GR102",
            Severity.MEDIUM,
            "Unpinned package execution",
            f"Server '{server.name}' runs '{spec}' without an exact version: "
            "whatever is published latest will execute with your agent's access.",
            server.span(f"args.{index}"),
            _pin_hint(spec, python),
        )


# --- GR103 ---------------------------------------------------------------------------------


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@rule(
    "GR103",
    Severity.HIGH,
    "Insecure remote MCP transport",
    "Remote MCP servers reached over plain http:// expose traffic and credentials.",
    CONFIG,
)
def gr103_insecure_transport(target: ScanTarget) -> Iterator[Finding]:
    """``http://`` URLs to hosts other than localhost, 127.0.0.0/8 and ::1."""
    for server in target.servers:
        if not server.url:
            continue
        parts = urlsplit(server.url)
        host = parts.hostname
        if parts.scheme.lower() != "http" or not host or "$" in parts.netloc or "{" in parts.netloc:
            continue
        if _is_loopback(host):
            continue
        yield _finding(
            target,
            "GR103",
            Severity.HIGH,
            "Insecure remote MCP transport",
            f"Server '{server.name}' connects to '{host}' over plain http://.",
            server.span("url"),
            "Use https:// so traffic and credentials are encrypted.",
        )


# --- GR104 ---------------------------------------------------------------------------------

_FS_NAME_TOKENS = frozenset({"fs", "files"})
_HOME_VARS = frozenset({"$home", "${home}", "%userprofile%", "~"})
_BROAD_PATHS = frozenset({"/", "/users", "/home"}) | _HOME_VARS
_DRIVE_ROOT = re.compile(r"[A-Za-z]:[\\/]*")


def _is_filesystem_server(server: ServerDef, package: str | None) -> bool:
    text = " ".join(filter(None, [server.name, package])).lower()
    tokens = set(re.split(r"[^a-z0-9]+", text))
    return "filesystem" in text or bool(tokens & _FS_NAME_TOKENS)


def _is_broad_path(arg: str) -> bool:
    stripped = arg.strip()
    if _DRIVE_ROOT.fullmatch(stripped):
        return True
    normal = stripped.rstrip("/\\") or "/"
    return normal.lower() in _BROAD_PATHS


@rule(
    "GR104",
    Severity.MEDIUM,
    "Overly broad filesystem scope",
    "Filesystem MCP servers given the whole disk or the whole home directory.",
    CONFIG,
)
def gr104_broad_filesystem(target: ScanTarget) -> Iterator[Finding]:
    """Filesystem-like servers whose arguments include ``/``, ``~``, ``$HOME``, ``C:\\``..."""
    for server in target.servers:
        located = _package_arg(server)
        package = located[1] if located else None
        if not _is_filesystem_server(server, package):
            continue
        for i, arg in enumerate(server.args):
            if (located and i == located[0]) or not _is_broad_path(arg):
                continue
            yield _finding(
                target,
                "GR104",
                Severity.MEDIUM,
                "Overly broad filesystem scope",
                f"Filesystem server '{server.name}' can access '{arg}': the whole disk or home.",
                server.span(f"args.{i}"),
                "Restrict the server to the project directory, for example ${workspaceFolder}.",
            )


# --- GR105 ---------------------------------------------------------------------------------

_POSIX_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})
_POWERSHELLS = frozenset({"powershell", "pwsh"})
_POSIX_C_FLAG = re.compile(r"-[a-zA-Z]*c[a-zA-Z]*")
_POWERSHELL_FLAGS = frozenset({"-c", "-command", "-e", "-enc", "-encodedcommand"})


def _runs_command_string(server: ServerDef) -> bool:
    name = server.command_name
    args = [a.lower() for a in server.args]
    if name in _POSIX_SHELLS:
        return any(_POSIX_C_FLAG.fullmatch(a) for a in server.args)
    if name == "cmd":
        return "/c" in args
    if name in _POWERSHELLS:
        return any(a in _POWERSHELL_FLAGS for a in args)
    return False


@rule(
    "GR105",
    Severity.HIGH,
    "Shell wrapper in server command",
    "MCP servers started through a shell command string can run arbitrary commands.",
    CONFIG,
)
def gr105_shell_wrapper(target: ScanTarget) -> Iterator[Finding]:
    """``bash -c``, ``cmd /c``, ``powershell -Command``...; critical if it also downloads and
    executes code (GR012 patterns)."""
    for server in target.servers:
        if not _runs_command_string(server):
            continue
        command_line = " ".join([server.command or "", *server.args])
        remote = any(p.search(command_line) for p in INJECTION_PATTERNS["GR012"])
        yield _finding(
            target,
            "GR105",
            Severity.CRITICAL if remote else Severity.HIGH,
            "Shell wrapper in server command",
            f"Server '{server.name}' runs through a shell: {command_line[:120]}"
            + (" (downloads and executes remote code)" if remote else ""),
            server.span("command"),
            "Launch the server binary directly with arguments instead of a shell command string.",
        )


# --- GR106 ---------------------------------------------------------------------------------

_DOCKER_SOCK = "docker.sock"


_ROOT_MOUNT = re.compile(r"/(?::|$)")
_ROOT_VOLUME_FLAG = re.compile(r"(?:-v=?|--volume=)/(?::|$)")
_ROOT_BIND_MOUNT = re.compile(r"(?:^|,)(?:source|src)=/(?:,|$)")


def _mounts_host_root(args: tuple[str, ...], i: int) -> bool:
    low = args[i].lower()
    if low in ("-v", "--volume"):
        return i + 1 < len(args) and _ROOT_MOUNT.match(args[i + 1]) is not None
    return bool(_ROOT_VOLUME_FLAG.match(low) or _ROOT_BIND_MOUNT.search(low))


def _flag_value(args: tuple[str, ...], i: int, names: tuple[str, ...]) -> str | None:
    """Value of an option given as ``--flag value`` or ``--flag=value``, if the flag matches."""
    flag, eq, inline = args[i].lower().partition("=")
    if flag not in names:
        return None
    if eq:
        return inline
    return args[i + 1].lower() if i + 1 < len(args) else ""


def _docker_issues(args: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    """Yield ``(arg index, description)`` for each dangerous docker option."""
    for i, arg in enumerate(args):
        low = arg.lower()
        if low == "--privileged" or low.startswith("--privileged="):
            yield i, "runs with --privileged"
        elif _DOCKER_SOCK in low:
            yield i, "mounts the Docker socket"
        elif _mounts_host_root(args, i):
            yield i, "mounts the host root filesystem"
        elif _flag_value(args, i, ("--network", "--net")) == "host":
            yield i, "uses the host network"
        elif _flag_value(args, i, ("--pid",)) == "host":
            yield i, "shares the host PID namespace"
        elif "sys_admin" in (_flag_value(args, i, ("--cap-add",)) or ""):
            yield i, "adds the SYS_ADMIN capability"


@rule(
    "GR106",
    Severity.HIGH,
    "Dangerous Docker options",
    "Docker-based MCP servers started with options that break container isolation.",
    CONFIG,
)
def gr106_dangerous_docker(target: ScanTarget) -> Iterator[Finding]:
    """``--privileged``, ``-v /:/x``, the Docker socket, host network/PID, ``SYS_ADMIN``."""
    for server in target.servers:
        if server.command_name != "docker":
            continue
        for index, description in _docker_issues(server.args):
            yield _finding(
                target,
                "GR106",
                Severity.HIGH,
                "Dangerous Docker options",
                f"Server '{server.name}' {description}: the container can take over the host.",
                server.span(f"args.{index}"),
                "Remove the option and mount only the specific directories the server needs.",
            )
