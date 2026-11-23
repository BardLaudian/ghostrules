"""The README says ghostrules never uses the network: no module of ``src`` may import a network
library (``urllib.parse`` only parses strings and is allowed)."""

import ast

from conftest import ROOT

FORBIDDEN = {"socket", "ssl", "http", "ftplib", "smtplib", "requests", "httpx", "aiohttp"}


def imported(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def test_no_module_of_src_imports_a_network_library() -> None:
    bad = []
    for path in (ROOT / "src" / "ghostrules").rglob("*.py"):
        for name in imported(path):
            top = name.split(".")[0]
            if top in FORBIDDEN or (name.startswith("urllib") and name != "urllib.parse"):
                bad.append((str(path.relative_to(ROOT)), name))
    assert bad == []
