"""Label the unlabelled findings of the latest run (>= medium) in ``labels.toml``.

    python corpus/triage.py [--min-severity medium] [--limit N]

For each finding it shows the snippet and, when it can, the lines around it (fetched with ``gh api``
for display only, sanitised, never stored). Answers: ``tp``, ``fp``, ``wontfix``, ``reported``,
``s`` (skip) or ``q`` (quit). A ``reported`` label stores only the fingerprint and the rule: the
repository is never named in a committed file. A ``tp`` label does not name it either.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from common import (
    CORPUS_DIR,
    LABELS,
    REPO_ROOT,
    SEVERITIES,
    CorpusError,
    Label,
    Runner,
    format_label,
    latest_results_dir,
    load_labels,
    read_json,
    safe_text,
    subprocess_runner,
    test_exists,
    valid_repo,
)

Ask = Callable[[str], str]
Fetch = Callable[[str, str, str, int], str]
CONTEXT_LINES = 3


def pending_findings(
    run_dir: Path, labels: dict[str, Label], min_severity: str
) -> list[dict[str, Any]]:
    """Unlabelled findings at or above ``min_severity``, most severe first, each with its repo."""
    wanted = SEVERITIES[: SEVERITIES.index(min_severity) + 1]
    found: list[dict[str, Any]] = []
    for path in sorted(run_dir.glob("*.json")):
        if path.name == "summary.json":
            continue
        record = read_json(path)
        for f in record.get("findings", []):
            if f["severity"] in wanted and f["fingerprint"] not in labels:
                found.append({**f, "repo": record["repo"], "sha": record.get("sha", "")})
    found.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["repo"], f["path"]))
    return found


def gh_fetch(runner: Runner) -> Fetch:
    """A ``Fetch`` that reads one file at a commit through ``gh api`` (display only)."""

    def fetch(repo: str, sha: str, path: str, line: int) -> str:
        if not valid_repo(repo) or not sha.isalnum():
            return ""
        proc = runner(
            ["gh", "api", f"repos/{repo}/contents/{path}?ref={sha}"],
            timeout=60,
        )
        if proc.returncode != 0:
            return ""
        try:
            raw = base64.b64decode(json.loads(proc.stdout).get("content", ""))
        except (ValueError, AttributeError):
            return ""
        lines = raw.decode("utf-8", "replace").splitlines()
        lo, hi = max(0, line - 1 - CONTEXT_LINES), line + CONTEXT_LINES
        return "\n".join(
            f"{n:>5}  {safe_text(text, 200)}" for n, text in enumerate(lines[lo:hi], lo + 1)
        )

    return fetch


def describe(f: dict[str, Any], context: str) -> str:
    """What the person sees for one finding. Every stored string is already sanitised."""
    parts = [
        f"\n[{f['severity']}] {f['rule_id']}  {f['repo']}  {f['path']}:{f.get('line')}",
        f"  snippet: {f['snippet']}",
    ]
    if f.get("decoded"):
        parts.append(f"  decoded: {f['decoded']}")
    if f.get("via"):
        parts.append(f"  via: {' / '.join(f['via'])}")
    if context:
        parts += ["  context:", context]
    return "\n".join(parts)


def make_label(f: dict[str, Any], kind: str, reason: str, test: str) -> Label:
    """The label to store. ``reported`` and ``tp`` never carry the repository name."""
    if kind == "reported":
        return Label(f["fingerprint"], kind, rule=f["rule_id"])
    repo = f["repo"] if kind in ("fp", "wontfix") else ""
    return Label(f["fingerprint"], kind, f["rule_id"], f["severity"], repo, reason, test)


def triage(
    findings: list[dict[str, Any]],
    labels_path: Path,
    ask: Ask,
    fetch: Fetch | None = None,
    echo: Callable[[str], None] = print,
    repo_root: Path = REPO_ROOT,
) -> int:
    """Walk ``findings``, appending a label per answer. Returns how many labels were written."""
    written = 0
    for f in findings:
        context = fetch(f["repo"], f["sha"], f["path"], int(f.get("line") or 1)) if fetch else ""
        echo(describe(f, context))
        kind = ask(f"label [{'/'.join(LABELS)}/s/q]: ").strip().lower()
        if kind == "q":
            break
        if kind not in LABELS:
            continue
        reason = test = ""
        if kind != "reported":
            reason = ask("one-line reason: ").strip()
        if kind == "fp":
            test = ask("test (tests/x.py::name): ").strip()
            if not test_exists(test, repo_root):
                echo("  no such test: write the synthetic test first; finding left unlabelled")
                continue
        block = format_label(make_label(f, kind, reason, test))
        with labels_path.open("a", encoding="utf-8") as handle:
            handle.write("\n" + block)
        written += 1
    return written


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Label corpus findings.")
    p.add_argument("--results", type=Path, default=CORPUS_DIR / "results")
    p.add_argument("--labels", type=Path, default=CORPUS_DIR / "labels.toml")
    p.add_argument("--min-severity", choices=SEVERITIES, default="medium")
    p.add_argument("--limit", type=int, default=0, help="stop after this many findings")
    p.add_argument("--no-context", action="store_true", help="do not fetch surrounding lines")
    args = p.parse_args(argv)
    try:
        run_dir = latest_results_dir(args.results)
        if run_dir is None:
            raise CorpusError(f"no run found in {args.results}")
        pending = pending_findings(run_dir, load_labels(args.labels), args.min_severity)
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.limit:
        pending = pending[: args.limit]
    print(f"{len(pending)} unlabelled findings")
    written = triage(
        pending, args.labels, input, None if args.no_context else gh_fetch(subprocess_runner)
    )
    print(f"{written} labels written to {args.labels}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
