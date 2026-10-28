"""Per-repository features for the study, extracted from ``corpus/run.py`` records.

A record holds findings, context entries per agent and per-file numbers (never text). Everything
here is a pure function of one record, so it is testable and the CSVs are reproducible.
"""

from __future__ import annotations

import posixpath
from typing import Any

# Order matters: the first match wins.
FAMILIES: tuple[tuple[str, str], ...] = (
    ("skills", "skill.md"),
    ("settings", ".claude/settings"),
    ("mcp", ".mcp.json"),
    ("mcp", "mcp.json"),
    ("cursor", ".cursorrules"),
    ("cursor", ".cursor/"),
    ("copilot", ".github/copilot-instructions.md"),
    ("copilot", ".github/instructions/"),
    ("windsurf", ".windsurf"),
    ("cline", ".clinerules"),
    ("cline", ".roo/"),
    ("gemini", "gemini.md"),
    ("claude", "claude.md"),
    ("claude", "claude.local.md"),
    ("agents_md", "agents.md"),
    ("claude_dir", ".claude/"),
)
# Families that are instructions for one tool (AGENTS.md is the shared, tool-neutral one).
TOOLS = ("agents_md", "claude", "gemini", "cursor", "copilot", "windsurf", "cline")
INSTRUCTION_FAMILIES = ("agents_md", "claude", "gemini", "cursor", "copilot", "windsurf", "cline")
FAMILY_NAMES = {
    "agents_md": "AGENTS.md",
    "skills": "Skills (SKILL.md)",
    "claude": "CLAUDE.md",
    "copilot": "GitHub Copilot",
    "claude_dir": ".claude/ (commands, agents, rules)",
    "settings": ".claude/settings*.json",
    "mcp": "MCP config",
    "cursor": "Cursor rules",
    "other": "Other agent files",
    "gemini": "GEMINI.md",
    "windsurf": "Windsurf",
    "cline": "Cline / Roo",
}
CLAUDE_LINE_LIMIT = 200
RISK_RULES = {
    "mcp": ("GR102", "GR103", "GR104", "GR105", "GR106"),
    "settings": ("GR107", "GR108"),
    "hidden_unicode": ("GR001", "GR002", "GR003", "GR004"),
    "injection": ("GR010", "GR011", "GR012", "GR013", "GR014", "GR015", "GR016"),
    "secrets": ("GR101",),
    "imports": ("GR020", "GR021", "GR022", "GR025"),
}


def family(path: str) -> str:
    """The family of an agent file, from its repo-relative path (``other`` if unknown)."""
    low = path.lower()
    base = posixpath.basename(low)
    for name, needle in FAMILIES:
        if needle.endswith("/") or (needle.startswith(".") and not needle.endswith(".json")):
            if needle in low and (low.startswith(needle) or "/" + needle in low):
                return name
        elif base == needle or low.endswith("/" + needle):
            return name
    return "other"


def _root(path: str) -> bool:
    return "/" not in path


def claude_agents_relation(files: list[dict[str, Any]], entries: list[dict[str, Any]]) -> str:
    """How a repository with both a root ``CLAUDE.md`` and ``AGENTS.md`` keeps them in step:
    ``symlink``, ``import`` (``@AGENTS.md``), ``duplicate`` (same content) or ``separate``.
    ``n/a`` when it does not have both."""
    by_path = {f["path"]: f for f in files}
    claude, agents = by_path.get("CLAUDE.md"), by_path.get("AGENTS.md")
    if not claude or not agents:
        return "n/a"
    for link, name in ((claude, "AGENTS.md"), (agents, "CLAUDE.md")):
        if link.get("symlink") and link.get("link_target") == name:
            return "symlink"
    if any(e["path"] == "AGENTS.md" and e["depth"] >= 1 for e in entries):
        return "import"
    if claude.get("sha") and claude.get("sha") == agents.get("sha"):
        return "duplicate"
    return "separate"


def repo_features(record: dict[str, Any]) -> dict[str, Any]:
    """The features of one successfully scanned repository."""
    files = record.get("files", [])
    context = record.get("context", {})
    claude_entries = context.get("claude-code", {}).get("entries", [])
    all_entries = [e for agent in context.values() for e in agent.get("entries", [])]
    agent_files = [f for f in files if f["kind"] == "agent"]
    fams = [family(f["path"]) for f in agent_files]
    tools = sorted({f for f in fams if f in TOOLS})
    instruction_lines = [
        f["lines"]
        for f, fam in zip(agent_files, fams, strict=True)
        if fam in INSTRUCTION_FAMILIES and "lines" in f
    ]
    claude_lines = [
        f["lines"]
        for f in agent_files
        if _root(f["path"]) and f["path"].lower() == "claude.md" and "lines" in f
    ]
    findings = record.get("findings", [])
    imported = [e for e in claude_entries if e["depth"] > 0]
    rules = {f["rule_id"] for f in findings}
    return {
        "tier": record.get("tier", ""),
        "agent_files": len(agent_files),
        "families": sorted(set(fams)),
        "family_files": {k: fams.count(k) for k in set(fams)},
        "tools": tools,
        "multi_tool": len(tools) >= 2,
        "relation": claude_agents_relation(files, claude_entries),
        "instruction_lines": instruction_lines,
        "claude_lines": claude_lines,
        "claude_over_limit": any(n > CLAUDE_LINE_LIMIT for n in claude_lines),
        "imports": len(imported),
        "max_import_depth": max((e["depth"] for e in claude_entries), default=0),
        "imported_non_agent_files": sum(1 for f in files if f["kind"] == "imported"),
        "entries": len(all_entries),
        "conditional_entries": sum(1 for e in all_entries if e["conditional"]),
        "claude_html_comments": any(
            f.get("html_comments", 0) > 0 for f in agent_files if family(f["path"]) == "claude"
        ),
        "rules": sorted(rules),
        "risk": {k: bool(rules & set(v)) for k, v in RISK_RULES.items()},
        "findings": len(findings),
    }
