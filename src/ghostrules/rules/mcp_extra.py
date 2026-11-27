"""MCP rules GR109 and GR114-GR116: registry, auto-approve, bind address and typosquat."""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from ghostrules.mcp_config import ServerDef
from ghostrules.models import Finding, ScanTarget, Severity
from ghostrules.rules.helpers import host_allowed
from ghostrules.rules.mcp import CONFIG, _finding, _package_arg
from ghostrules.rules.registry import rule

# --- GR109: a package registry that is not the public one ----------------------------------

_OFFICIAL_REGISTRIES = frozenset(
    {"registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "pypi.org"}
    | {"files.pythonhosted.org"}
)
_REGISTRY_FLAGS = frozenset(
    {"--registry", "--index-url", "--index", "--extra-index-url", "--default-index", "-i"}
)
_REGISTRY_ENV = frozenset(
    {"npm_config_registry", "uv_index_url", "uv_extra_index_url", "uv_default_index"}
    | {"pip_index_url", "pip_extra_index_url"}
)


def _registry_values(server: ServerDef) -> Iterator[tuple[str, str]]:
    """``(span key, url)`` for each registry the server's command or environment points at."""
    for i, arg in enumerate(server.args):
        flag, _, inline = arg.partition("=")
        if flag in _REGISTRY_FLAGS:
            if inline:
                yield f"args.{i}", inline
            elif i + 1 < len(server.args):
                yield f"args.{i + 1}", server.args[i + 1]
    for key, value in server.env.items():
        if key.lower() in _REGISTRY_ENV:
            yield f"env.{key}", value


@rule(
    "GR109",
    Severity.MEDIUM,
    "Non-standard package registry",
    "An MCP server fetches its package from a registry other than npm or PyPI.",
    CONFIG,
)
def gr109_registry(target: ScanTarget) -> Iterator[Finding]:
    """A private registry is normal in a company, so it is medium; over http it is high."""
    for server in target.servers:
        for key, url in _registry_values(server):
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            if not host or host in _OFFICIAL_REGISTRIES or host_allowed(host, target.allow_domains):
                continue
            insecure = parts.scheme == "http"
            yield _finding(
                target,
                "GR109",
                Severity.HIGH if insecure else Severity.MEDIUM,
                "Non-standard package registry",
                f"Server '{server.name}' fetches packages from {host}"
                + (" over plain http" if insecure else "")
                + ": whoever runs that registry chooses what executes.",
                server.span(key),
                "Use the public registry, or add the registry's domain to allow_domains.",
            )


# --- GR114: every tool of a server is pre-approved -----------------------------------------


@rule(
    "GR114",
    Severity.HIGH,
    "All tools of an MCP server auto-approved",
    'autoApprove or alwaysAllow set to true or "*" lets every tool run without a prompt.',
    CONFIG,
)
def gr114_auto_approve(target: ScanTarget) -> Iterator[Finding]:
    """A named list of tools is a decision; "*" or true also approves tools added later."""
    for server in target.servers:
        if server.auto_approve:
            yield _finding(
                target,
                "GR114",
                Severity.HIGH,
                "All tools of an MCP server auto-approved",
                f"Server '{server.name}' runs every tool without asking, including tools it adds"
                " later.",
                server.span("auto_approve"),
                "List the tools you accept by name, or remove the setting.",
            )


# --- GR115: a server listening on every network interface ----------------------------------

_ALL_INTERFACES = re.compile(r"(?<![\d.])0\.0\.0\.0(?![\d.])|(?<![\w:])\[?::\]?(?![\w:])")


@rule(
    "GR115",
    Severity.HIGH,
    "MCP server bound to all network interfaces",
    "A server told to listen on 0.0.0.0 or :: can be reached from the network.",
    CONFIG,
)
def gr115_bind_all(target: ScanTarget) -> Iterator[Finding]:
    """Anyone on the network can call the tools of a server that listens on every interface."""
    for server in target.servers:
        places = [(f"args.{i}", a) for i, a in enumerate(server.args)]
        places += [(f"env.{k}", v) for k, v in server.env.items()]
        places += [("url", server.url)] if server.url else []
        for key, value in places:
            if _ALL_INTERFACES.search(value):
                yield _finding(
                    target,
                    "GR115",
                    Severity.HIGH,
                    "MCP server bound to all network interfaces",
                    f"Server '{server.name}' listens on every interface: other machines on the"
                    " network can call its tools.",
                    server.span(key),
                    "Bind to 127.0.0.1; put an authenticated proxy in front if it must be shared.",
                )
                break


# --- GR116: a package name one typo away from a well-known server --------------------------

_KNOWN = frozenset(
    {
        f"@modelcontextprotocol/server-{n}"
        for n in (
            "filesystem",
            "github",
            "gitlab",
            "postgres",
            "sqlite",
            "puppeteer",
            "slack",
            "memory",
            "brave-search",
            "google-maps",
            "fetch",
            "everything",
            "sequential-thinking",
            "gdrive",
            "redis",
            "aws-kb-retrieval",
            "everart",
            "git",
            "time",
        )
    }
    | {f"mcp-server-{n}" for n in ("git", "fetch", "time", "sqlite", "postgres", "filesystem")}
    | {
        "@upstash/context7-mcp",
        "@playwright/mcp",
        "firecrawl-mcp",
        "mcp-remote",
        "@notionhq/notion-mcp-server",
        "@supabase/mcp-server-supabase",
        "@browsermcp/mcp",
        "figma-developer-mcp",
        "@executeautomation/playwright-mcp-server",
        "mcp-proxy",
    }
)


def _distance(a: str, b: str) -> int:
    """Edit distance where swapping two neighbouring letters counts as one edit."""
    rows = [list(range(len(b) + 1))]
    for i, ca in enumerate(a, 1):
        row = [i]
        for j, cb in enumerate(b, 1):
            best = min(rows[-1][j] + 1, row[j - 1] + 1, rows[-1][j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                best = min(best, rows[-2][j - 2] + 1)
            row.append(best)
        rows.append(row)
    return rows[-1][-1]


def _bare_name(spec: str) -> str:
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def _lookalike(name: str) -> str | None:
    """The known package ``name`` imitates: one edit away, or two for a long name."""
    name = name.lower()
    if name in _KNOWN:
        return None
    for known in _KNOWN:
        limit = 2 if len(known) >= 24 else 1
        if abs(len(name) - len(known)) <= limit and _distance(name, known) <= limit:
            return known
    return None


@rule(
    "GR116",
    Severity.HIGH,
    "Package name imitates a well-known MCP server",
    "A server package whose name is a typo of a popular one may be a typosquat.",
    CONFIG,
)
def gr116_typosquat(target: ScanTarget) -> Iterator[Finding]:
    """Typosquats are published to catch a mistyped name; the agent then runs the code."""
    for server in target.servers:
        located = _package_arg(server)
        if located is None:
            continue
        index, spec, _python = located
        known = _lookalike(_bare_name(spec))
        if known:
            yield _finding(
                target,
                "GR116",
                Severity.HIGH,
                "Package name imitates a well-known MCP server",
                f"Server '{server.name}' runs '{_bare_name(spec)}', one typo away from the popular"
                f" '{known}'.",
                server.span(f"args.{index}"),
                f"Check the spelling; the package you probably want is {known}.",
            )
