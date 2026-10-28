"""Which paths hold secrets or credentials (shared by GR021 and the context engine).

The context engine must never read such a file even when an instruction file imports it, so this
check is on the *path* only.
"""

from __future__ import annotations

import re

_PLACEHOLDER = re.compile(
    r"(?:^|[._-])(?:example|sample|template|dist|default)(?:$|[._-])", re.IGNORECASE
)
_PRIVATE_KEY = re.compile(r"^id_(?:rsa|ed25519|ecdsa|dsa)(?:[._-].*)?$", re.IGNORECASE)
_EXACT_NAMES = frozenset(
    {
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".pgpass",
        ".git-credentials",
        "kubeconfig",
        "credentials.json",
    }
)


def is_template_path(path: str) -> bool:
    """Whether ``path`` names a template for a secrets file (``.env.example``, ``*.sample``,
    ``creds.template``, ``.env.ai-surfaces.example``): it holds placeholders, not secrets."""
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return bool(_PLACEHOLDER.search(name))


def is_sensitive_path(path: str) -> bool:
    """Whether ``path`` (as written in an import) names a secrets or credentials file.

    Covers ``.env`` and ``.env.*`` (not ``.env.example`` and friends), anything under ``.ssh``,
    private keys (``id_rsa*``, ``id_ed25519*``; public ``.pub`` keys are fine),
    ``.aws/credentials``, ``.npmrc``, ``.pypirc``, ``.netrc``, kubeconfig, ``*.pem``, ``*.key``,
    ``credentials.json`` and ``secrets.*``.
    """
    parts = [p for p in path.replace("\\", "/").split("/") if p and p != "."]
    if not parts:
        return False
    name = parts[-1].lower()
    if name.endswith(".pub") or _PLACEHOLDER.search(name):
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    if name in _EXACT_NAMES or _PRIVATE_KEY.match(name):
        return True
    if name.endswith((".pem", ".key")) or name.startswith("secrets."):
        return True
    lowered = [p.lower() for p in parts]
    if ".ssh" in lowered[:-1]:
        return True
    if len(lowered) >= 2 and lowered[-2] == ".aws" and name == "credentials":
        return True
    return len(lowered) >= 2 and lowered[-2] == ".kube" and name == "config"
