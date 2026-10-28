"""Well-known installer scripts that GR012 treats as documentation rather than an attack.

Matching is on the exact ``https`` host (never a suffix, so ``astral.sh.attacker.example`` does
not match) plus an optional path prefix. Extend ``KNOWN_INSTALLERS`` to trust another project.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class Installer(NamedTuple):
    """A trusted installer location: project name, exact host and optional path prefix."""

    project: str
    host: str
    path_prefix: str = ""


KNOWN_INSTALLERS: tuple[Installer, ...] = (
    Installer("Astral uv/ruff", "astral.sh"),
    Installer("Rust (rustup)", "sh.rustup.rs"),
    Installer("Bun", "bun.sh"),
    Installer("Deno", "deno.land"),
    Installer("pnpm", "get.pnpm.io"),
    Installer("Poetry", "install.python-poetry.org"),
    Installer("Homebrew", "raw.githubusercontent.com", "/Homebrew/install/"),
    Installer("nvm", "raw.githubusercontent.com", "/nvm-sh/nvm/"),
    Installer("SDKMAN", "get.sdkman.io"),
    Installer("Docker convenience script", "get.docker.com"),
    Installer("Ollama", "ollama.com", "/install.sh"),
    Installer("Volta", "get.volta.sh"),
    # https://code.claude.com/docs/en/setup (seen in anthropics/claude-agent-sdk-python)
    Installer("Claude Code", "claude.ai", "/install.sh"),
)

_URL_RE = re.compile(r"(https?)://([^/?#\s'\"`)\]>|]*)([^\s'\"`)\]>|]*)", re.IGNORECASE)
_COLLECTOR_HOSTS = re.compile(
    r"(?:^|\.)(?:webhook\.site|requestbin(?:\.\w+)?|pipedream\.net|ngrok(?:-free)?\.(?:io|app)"
    r"|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|burpcollaborator\.net"
    r"|beeceptor\.com|hookbin\.com|canarytokens(?:\.\w+)?)$",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])$", re.IGNORECASE)


class Url(NamedTuple):
    """A URL found in a command."""

    scheme: str
    host: str
    port: str
    path: str


def extract_urls(text: str) -> list[Url]:
    """Every ``http(s)://`` URL in ``text``, split into scheme, host, port and path."""
    urls: list[Url] = []
    for scheme, authority, path in _URL_RE.findall(text):
        hostport = authority.rsplit("@", 1)[-1].lower()
        if hostport.startswith("["):
            host, _, rest = hostport.partition("]")
            host, port = host + "]", rest.lstrip(":")
        else:
            host, _, port = hostport.partition(":")
        urls.append(Url(scheme.lower(), host.rstrip("."), port, path))
    return urls


def is_risky_url(url: Url) -> bool:
    """Plain http, an IP literal, a non-default port or a request-collector domain."""
    return (
        url.scheme != "https"
        or bool(_IP_RE.match(url.host))
        or url.port not in ("", "443")
        or bool(_COLLECTOR_HOSTS.search(url.host))
    )


def known_installer(url: Url) -> Installer | None:
    """The installer entry matching this URL exactly, or ``None``."""
    if url.scheme != "https" or url.port not in ("", "443"):
        return None
    for entry in KNOWN_INSTALLERS:
        if url.host == entry.host and url.path.startswith(entry.path_prefix):
            return entry
    return None
