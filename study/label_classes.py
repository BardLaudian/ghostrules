"""Label the study findings (>= medium) by class, never naming a repository.

    python study/label_classes.py RESULTS_DIR [RESULTS_DIR ...] [--write study/labels.toml]

Each class is a rule, a severity and a test on the (already masked) snippet, with the label and the
reason the human approved. A finding that matches no class is listed and left unlabelled for manual
triage. Labels carry the fingerprint, rule, severity and reason only (no repository, no path).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "corpus"))
from common import Label, format_label, load_labels  # noqa: E402

Test = Callable[[dict[str, Any]], bool]


def _re(pattern: str) -> Test:
    rx = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    return lambda f: bool(rx.search(f["snippet"]))


def _always(_f: dict[str, Any]) -> bool:
    return True


# (rule, severities, test, label, reason). The first matching class wins.
CLASSES: tuple[tuple[str, tuple[str, ...], Test, str, str], ...] = (
    ("GR011", ("high", "medium"), _re(r"silently\s+(?:execute|modify)|quietly\s+install"),
     "benign-context", "describes what code does (plural subject), it does not order concealment"),
    ("GR011", ("high", "medium"), _always,
     "tp", "tells the agent to withhold or not narrate something from the user (benign intent)"),
    ("GR012", ("critical",), _always,
     "benign-context", "offensive-security skill documents the attack with placeholder hosts"),
    ("GR012", ("high",), _always,
     "benign-context",
     "documented installer one-liner (curl | sh) or a placeholder in security docs"),
    ("GR013", ("critical",), _always,
     "benign-context", "cloud-metadata URL inside a vulnerability or exploit description"),
    ("GR013", ("high",), _always,
     "benign-context", "request-collector service named in penetration-testing documentation"),
    ("GR013", ("medium",), _always,
     "benign-context",
     "documents where a key is sent (a fixed host over HTTPS), not an exfiltration"),
    ("GR010", ("high", "medium"), _always,
     "benign-context", "quotes the phrase to teach, detect or forbid it"),
    ("GR014", ("high", "medium"), _re(r"^\s*\||\|\s*$|blocked"),
     "benign-context", "table or blocked-command list that documents the file"),
    ("GR014", ("high", "medium"), _always,
     "tp", "instruction to read or print an env or credentials file"),
    ("GR016", ("high", "medium"), _re(r"never\s+ask\s+(?:for\s+)?(?:permission|confirmation)"),
     "tp", "tells the agent never to ask for permission or confirmation"),
    ("GR016", ("high", "medium"), _always,
     "benign-context",
     "documents or names a permission-bypass flag or mode, it does not instruct it"),
    ("GR015", ("medium", "high"), _always,
     "benign-context", "shellcode hex inside a security skill"),
    ("GR020", ("high",), _always, "tp", "import outside the repository or into the home directory"),
    ("GR102", ("medium",), _always, "tp", "MCP server started with an unpinned package"),
    ("GR105", ("high",), _always, "tp", "shell wrapper as an MCP server command"),
    ("GR107", ("high",), _always, "tp", "over-permissive agent settings"),
    ("GR108", ("medium",), _always, "tp", "auto-enables project MCP servers"),
    ("GR003", ("medium", "high"), _always,
     "tp", "invisible character really present in the text"),
    ("GR005", ("medium", "high"), _always,
     "tp", "hidden HTML comment with instructions (benign: maintainer notes, licence-header rule)"),
)  # fmt: skip
GATED = ("critical", "high", "medium")


def classify(f: dict[str, Any]) -> tuple[str, str, str] | None:
    """``(class key, label, reason)`` of a finding, or ``None`` when no class matches."""
    for i, (rule, sevs, test, label, reason) in enumerate(CLASSES):
        if f["rule_id"] == rule and f["severity"] in sevs and test(f):
            return f"{i:02d} {rule} {'/'.join(sevs)}", label, reason
    return None


def label_findings(
    records: list[dict[str, Any]],
) -> tuple[list[Label], Counter[str], list[dict[str, Any]]]:
    """Labels for every ``GATED`` finding, per-class counts and the unmatched findings."""
    labels: list[Label] = []
    counts: Counter[str] = Counter()
    unmatched: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        for f in record.get("findings", []):
            if f["severity"] not in GATED:
                continue
            hit = classify(f)
            if hit is None:
                unmatched.append(f)
                continue
            key, label, reason = hit
            if f["fingerprint"] in seen:
                continue  # the same snippet twice in one file has one fingerprint
            seen.add(f["fingerprint"])
            counts[f"{key} -> {label}"] += 1
            labels.append(Label(f["fingerprint"], label, f["rule_id"], f["severity"], "", reason))
    return labels, counts, unmatched


def main(argv: Sequence[str] | None = None) -> int:
    from analyze import load_records

    p = argparse.ArgumentParser(description="Label study findings by class.")
    p.add_argument("results", nargs="+", type=Path)
    p.add_argument("--write", type=Path, help="write the labels here (study/labels.toml)")
    args = p.parse_args(argv)
    labels, counts, unmatched = label_findings(load_records(args.results))
    for key, n in sorted(counts.items()):
        print(f"{n:4}  {key}")
    print(f"{len(labels)} labelled, {len(unmatched)} unmatched")
    for f in unmatched:
        print("  unmatched:", f["rule_id"], f["severity"], f["fingerprint"])
    if args.write:
        known = load_labels(args.write)
        new = [lb for lb in labels if lb.fingerprint not in known]
        with args.write.open("a", encoding="utf-8") as handle:
            for lb in new:
                handle.write("\n" + format_label(lb))
        print(f"{len(new)} labels appended to {args.write}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
