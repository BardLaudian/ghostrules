"""A fake ``git`` / ``gh`` / ``ghostrules`` layer for the corpus tests (no network)."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "corpus"))

from common import Proc  # noqa: E402

CMD = ["ghostrules-fake"]
SCAN_OK = {"version": "0", "scanned_files": 3, "findings": [], "summary": {}}
CTX_OK: dict[str, Any] = {"agents": {}}


class FakeRunner:
    """Answers ``git clone``, ``git rev-parse``, ``<CMD> scan|context`` and ``gh api``.

    ``scans`` / ``contexts`` map a repo slug (``owner__repo``) to the JSON the command prints;
    ``clone_fail`` maps a slug to an exit code. The fake ``git clone`` writes ``files`` into the
    destination, like a real clone would.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.files: dict[str, str] = {"AGENTS.md": "hello\n"}
        self.scans: dict[str, Any] = {}
        self.contexts: dict[str, Any] = {}
        self.scan_exit: dict[str, int] = {}
        self.clone_fail: dict[str, int] = {}
        self.clone_dirs: list[Path] = []
        self.gh: list[Proc] = []

    @staticmethod
    def _slug(args: Sequence[str]) -> str:
        for a in args:
            if "github.com/" in a:
                return a.split("github.com/")[1].removesuffix(".git").replace("/", "__")
            if "__" in Path(a).parent.name:
                return Path(a).parent.name.rsplit("-", 1)[0]
        return ""

    def __call__(
        self,
        args: Sequence[str],
        *,
        timeout: float = 120,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Proc:
        call: dict[str, Any] = {"args": list(args), "cwd": cwd, "env": env}
        if "--config" in args:  # the file lives in a temp dir that is gone after the run
            call["config_text"] = Path(args[list(args).index("--config") + 1]).read_text()
        self.calls.append(call)
        if args[0] == "gh":
            return self.gh.pop(0) if self.gh else Proc(1, "", "no canned gh reply")
        if args[0] == "git" and args[1] == "clone":
            slug = self._slug(args)
            if slug in self.clone_fail:
                return Proc(self.clone_fail[slug], "", "fatal: repository not found")
            dest = Path(args[-1])
            self.clone_dirs.append(dest)
            dest.mkdir(parents=True)
            for rel, text in self.files.items():
                (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                (dest / rel).write_text(text, encoding="utf-8")
            return Proc(0)
        if args[0] == "git" and args[1] == "rev-parse":
            return Proc(0, "0123456789abcdef0123456789abcdef01234567\n")
        if list(args[: len(CMD)]) == CMD:
            slug = self._slug(args) or self._slug([str(cwd or "")])
            clone = next((a for a in args if "__" in Path(a).parent.name), "")
            slug = Path(clone).parent.name.rsplit("-", 1)[0] if clone else slug
            kind = args[len(CMD)]
            code = self.scan_exit.get(slug, 0)
            if code:
                return Proc(code, "", "boom")
            data = (self.scans if kind == "scan" else self.contexts).get(
                slug, SCAN_OK if kind == "scan" else CTX_OK
            )
            return Proc(0, json.dumps(data))
        return Proc(127, "", f"unexpected command {args[0]}")


def finding(rule: str = "GR011", severity: str = "high", **extra: Any) -> dict[str, Any]:
    """A finding as ``ghostrules scan --format json`` prints it."""
    base = {
        "rule_id": rule,
        "severity": severity,
        "title": "t",
        "message": "SECRET MESSAGE TEXT",
        "path": "AGENTS.md",
        "line": 3,
        "column": 1,
        "end_column": 5,
        "snippet": "do not tell the user",
        "fix_hint": "SECRET FIX HINT",
    }
    return {**base, **extra}
