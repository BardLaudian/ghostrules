"""Installer hosts that belong to the project being scanned (GR012 treats them as known).

A project's README says ``curl -fsSL https://raw.githubusercontent.com/acme/tool/main/install.sh
| sh`` and that is the project's own installer, not an attack. First-party means: the owner of the
GitHub ``origin`` remote (``raw.githubusercontent.com/<owner>/`` and ``<owner>.github.io``) and
the homepage declared in ``pyproject.toml`` or ``package.json``. The remote comes from
``.git/config``, which a change cannot edit; the manifests are read from the base ref when the scan
has one, so a pull request cannot declare its own domain first-party. Pure parsing, no I/O.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from ghostrules._compat import tomllib
from ghostrules.rules.known_installers import Installer

_GITHUB_REMOTE = re.compile(
    r"(?:https?://(?:[^/@\s]+@)?github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"([A-Za-z0-9][A-Za-z0-9-]*)/",
    re.IGNORECASE,
)
_HOMEPAGE_KEYS = ("homepage", "home")
_HOSTED_ELSEWHERE = frozenset(
    {"github.com", "gitlab.com", "bitbucket.org", "pypi.org", "www.npmjs.com", "npmjs.com"}
)
_HOST = re.compile(r"^https://([A-Za-z0-9.-]+)(?::443)?(?:/|$)", re.IGNORECASE)

ReadText = Callable[[str], "str | None"]


def owner_from_git_config(text: str) -> str | None:
    """The GitHub owner of the ``origin`` remote in a ``.git/config``, if it has one."""
    in_origin = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_origin = stripped.replace(" ", "").lower() == '[remote"origin"]'
        elif in_origin and stripped.lower().startswith("url"):
            match = _GITHUB_REMOTE.search(stripped.partition("=")[2].strip())
            return match.group(1).lower() if match else None
    return None


def _host_of(url: object) -> str | None:
    match = _HOST.match(url.strip()) if isinstance(url, str) else None
    return match.group(1).lower().rstrip(".") if match else None


def _homepages(read: ReadText) -> list[str]:
    urls: list[object] = []
    text = read("pyproject.toml")
    if text is not None:
        try:
            project_urls = tomllib.loads(text).get("project", {}).get("urls", {})
        except tomllib.TOMLDecodeError:
            project_urls = {}
        if isinstance(project_urls, dict):
            urls += [v for k, v in project_urls.items() if str(k).lower() in _HOMEPAGE_KEYS]
    text = read("package.json")
    if text is not None:
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        if isinstance(data, dict):
            urls.append(data.get("homepage"))
    return [h for h in map(_host_of, urls) if h and h not in _HOSTED_ELSEWHERE]


def first_party_installers(read: ReadText, git_config: str | None) -> tuple[Installer, ...]:
    """Installer entries for the project's own organisation and homepage."""
    found: list[Installer] = []
    owner = owner_from_git_config(git_config) if git_config else None
    if owner:
        found += [
            Installer(f"{owner} (first party)", "raw.githubusercontent.com", f"/{owner}/"),
            Installer(f"{owner} (first party)", f"{owner}.github.io"),
        ]
    found += [Installer(f"{host} (first party)", host) for host in _homepages(read)]
    return tuple(dict.fromkeys(found))
