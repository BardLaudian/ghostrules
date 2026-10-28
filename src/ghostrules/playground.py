"""Backend of the browser playground: scan a set of in-memory files and return plain data.

Runs in Pyodide (no ``typer``/``rich``). The page passes ``{path: text}``; the files are written
to a temporary directory, scanned like a repository and the directory is removed. Nothing here
touches the network and nothing a file says is executed.
"""

from __future__ import annotations

import json
import posixpath
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from ghostrules.config import Config
from ghostrules.context_command import build_report
from ghostrules.imports import find_imports
from ghostrules.reporters import json_, markdown, sarif
from ghostrules.reporters.context_data import Node, build_nodes
from ghostrules.reveal_data import has_hidden_content, lines
from ghostrules.scanner import scan_paths
from ghostrules.targets import classify_path

MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_FILES = 500
# Files the agent models read that are not in the default target list.
EXTRA_TARGETS = (".claude/rules/**/*.md",)


class PlaygroundError(ValueError):
    """The input cannot be analysed (too big, unsafe path...)."""


def clean_path(raw: str) -> str:
    """A safe repo-relative POSIX path, or ``PlaygroundError``."""
    path = posixpath.normpath(raw.replace("\\", "/").lstrip("/"))
    parts = PurePosixPath(path).parts
    if not parts or path == "." or ".." in parts or "\x00" in path:
        raise PlaygroundError(f"unsafe path: {raw[:80]!r}")
    return path


def agent_paths(all_paths: list[str]) -> list[str]:
    """Which of ``all_paths`` are agent files (instructions and configs), sorted."""
    return sorted(p for p in map(clean_path, all_paths) if classify_path(p, EXTRA_TARGETS))


def imported_paths(all_paths: list[str], loaded: Mapping[str, str]) -> list[str]:
    """Files in ``all_paths`` that the ``loaded`` texts import with ``@path`` and that are not
    loaded yet (paths relative to the importing file, ``~`` and absolute paths are ignored)."""
    known = set(map(clean_path, all_paths))
    wanted: set[str] = set()
    for path, text in loaded.items():
        folder = posixpath.dirname(path)
        for imp in find_imports(text):
            if imp.path.startswith(("~", "/")) or not imp.looks_like_path:
                continue
            target = posixpath.normpath(posixpath.join(folder, imp.path))
            if target in known and target not in loaded:
                wanted.add(target)
    return sorted(wanted)


def _node(node: Node) -> dict[str, Any]:
    return {
        "icon": node.icon,
        "state": node.state,
        "path": node.path,
        "details": node.details,
        "counts": dict(node.counts),
        "children": [_node(c) for c in node.children],
    }


def analyze(files: Mapping[str, str]) -> dict[str, Any]:
    """Scan ``files`` as a repository. Returns findings, the per-agent context tree, the
    revealed text of every file with hidden content and the three downloadable reports."""
    if len(files) > MAX_FILES:
        raise PlaygroundError(f"too many files ({len(files)}, limit {MAX_FILES})")
    if sum(len(t.encode("utf-8", "replace")) for t in files.values()) > MAX_TOTAL_BYTES:
        raise PlaygroundError("more than 5 MB of files")
    cleaned = {clean_path(p): t for p, t in files.items()}
    root = Path(tempfile.mkdtemp(prefix="ghostrules-playground-"))
    try:
        for path, text in cleaned.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.encode("utf-8", "surrogatepass"))
        config = Config()
        result = scan_paths([root], config)
        report = build_report(root, config)
        context = {
            agent: [_node(n) for n in build_nodes(graph, report)]
            for agent, graph in report.graphs.items()
        }
        data = json_.to_dict(result)
        flagged = {f["path"] for f in data["findings"]}
        revealed = {
            path: [
                {
                    "number": ln.number,
                    "segments": [[s.kind, s.text] for s in ln.segments],
                    "decoded": ln.decoded,
                }
                for ln in lines(text)
            ]
            for path, text in sorted(cleaned.items())
            if path in flagged or has_hidden_content(text)
        }
        return {
            "findings": data["findings"],
            "summary": data["summary"],
            "scanned_files": data["scanned_files"],
            "warnings": data["warnings"],
            "errors": data["errors"],
            "context": context,
            "revealed": revealed,
            "reports": {
                "json": json_.render(result),
                "markdown": markdown.render(result),
                "sarif": sarif.render(result),
            },
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def analyze_json(files_json: str) -> str:
    """``analyze`` with JSON in and out (the Pyodide bridge)."""
    try:
        files = json.loads(files_json)
        if not isinstance(files, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in files.items()
        ):
            raise PlaygroundError("expected an object of path -> text")
        return json.dumps(analyze(files), ensure_ascii=False)
    except PlaygroundError as exc:
        return json.dumps({"error": str(exc)})


def agent_paths_json(paths_json: str) -> str:
    """``agent_paths`` for the Pyodide bridge."""
    return json.dumps(agent_paths(json.loads(paths_json)))


def imported_paths_json(paths_json: str, loaded_json: str) -> str:
    """``imported_paths`` for the Pyodide bridge."""
    return json.dumps(imported_paths(json.loads(paths_json), json.loads(loaded_json)))
