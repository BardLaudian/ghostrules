"""Draw the study charts as SVG, in a light and a dark variant, from ``study/data/*.csv``.

    python study/charts.py [--data study/data] [--out study/charts]

One message per chart. Single-series charts use the accent colour for the point and gray for the
context; values are labelled directly and the same numbers are in the report's tables.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import FAMILY_NAMES  # noqa: E402

matplotlib.rcParams["svg.fonttype"] = "none"  # keep text as text: selectable and theme-neutral
matplotlib.rcParams["svg.hashsalt"] = "ghostrules"  # reproducible ids

THEMES = {
    "light": {
        "surface": "#fcfcfb",
        "ink": "#0b0b0b",
        "muted": "#52514e",
        "accent": "#2a78d6",
        "gray": "#c4c3bd",
        "second": "#eb6834",
        "grid": "#e4e3de",
    },
    "dark": {
        "surface": "#1a1a19",
        "ink": "#f0efec",
        "muted": "#c3c2b7",
        "accent": "#3987e5",
        "gray": "#6a6a65",
        "second": "#d95926",
        "grid": "#2c2c2a",
    },
}
SOURCE = "1,583 popular public repositories with at least one agent file · snapshot 2026-10-28"


def read(path: Path) -> list[dict[str, str]]:
    """A CSV as a list of dicts."""
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _frame(theme: dict[str, str], title: str, subtitle: str, height: float) -> tuple[Any, Any]:
    fig, ax = plt.subplots(figsize=(8.6, height), facecolor=theme["surface"])
    ax.set_facecolor(theme["surface"])
    for side in ("top", "right", "left", "bottom"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0, colors=theme["muted"], labelsize=10)
    fig.text(0.02, 0.965, title, color=theme["ink"], fontsize=14, fontweight="bold", va="top")
    fig.text(
        0.02, 0.965 - 0.075 * 4.6 / height, subtitle, color=theme["muted"], fontsize=10, va="top"
    )
    fig.text(0.02, 0.02, SOURCE, color=theme["muted"], fontsize=8, va="bottom")
    return fig, ax


def hbars(
    theme: dict[str, str],
    title: str,
    subtitle: str,
    labels: list[str],
    values: list[float],
    highlight: set[int],
    notes: list[str] | None = None,
    fmt: str = "{:.1f}%",
    xmax: float | None = None,
) -> Any:
    """Horizontal bars, largest first; ``highlight`` indexes use the accent, the rest gray."""
    height = 1.9 + 0.42 * len(labels)
    fig, ax = _frame(theme, title, subtitle, height)
    ys = list(range(len(labels)))[::-1]
    colors = [theme["accent"] if i in highlight else theme["gray"] for i in range(len(labels))]
    ax.barh(ys, values, color=colors, height=0.62)
    ax.set_yticks(ys, labels, color=theme["ink"])
    ax.set_xticks([])
    top = xmax or max(values) * 1.28 or 1
    ax.set_xlim(0, top)
    for y, v, i in zip(ys, values, range(len(labels)), strict=True):
        text = fmt.format(v) + (f"  {notes[i]}" if notes and notes[i] else "")
        ax.text(v + top * 0.012, y, text, va="center", color=theme["ink"], fontsize=10)
    fig.subplots_adjust(
        left=min(0.62, 0.04 + 0.0098 * max(map(len, labels))),
        right=0.97,
        top=1 - 0.2 * 4.6 / height * 0.9,
        bottom=0.12,
    )
    return fig


def save(fig: Any, out: Path, name: str, mode: str) -> None:
    """Write ``name-mode.svg`` (no timestamps, so the files are reproducible)."""
    out.mkdir(parents=True, exist_ok=True)
    fig.savefig(
        out / f"{name}-{mode}.svg",
        format="svg",
        facecolor=fig.get_facecolor(),
        metadata={"Date": None, "Creator": "ghostrules study/charts.py"},
    )
    plt.close(fig)


def build(data: Path, out: Path) -> list[str]:
    """Draw every chart in both themes; returns the chart names."""
    fam = read(data / "adoption_families.csv")
    tools = read(data / "tools_per_repo.csv")
    rel = read(data / "claude_agents_relation.csv")
    nums = {r["id"]: r for r in read(data / "numbers.csv")}
    prec = read(data / "precision_by_rule.csv")
    names = []
    for mode, t in THEMES.items():
        # 1. adoption
        rows = [r for r in fam if r["family"] != "other"]
        fig = hbars(
            t,
            "AGENTS.md is in 7 of 10 repos; CLAUDE.md and skills in half",
            "Share of repositories that contain each kind of agent file",
            [FAMILY_NAMES.get(r["family"], r["family"]) for r in rows],
            [float(r["pct_of_repos"]) for r in rows],
            {0},
            xmax=88,
        )
        save(fig, out, "01-adoption", mode)
        # 2. tools per repo
        groups = {"0": 0.0, "1": 0.0, "2": 0.0, "3": 0.0, "4+": 0.0}
        for r in tools:
            key = r["tools_targeted"] if int(r["tools_targeted"]) < 4 else "4+"
            groups[key] += float(r["pct_of_repos"])
        fig = hbars(
            t,
            "44% of repos write instructions for more than one agent",
            "Share of repositories by number of different tools their instruction files target",
            [f"{k} tool{'s' if k != '1' else ''}" for k in groups],
            [round(v, 1) for v in groups.values()],
            {2, 3, 4},
            xmax=62,
        )
        save(fig, out, "02-tools-per-repo", mode)
        # 3. CLAUDE.md and AGENTS.md
        labels = {
            "import": "CLAUDE.md imports @AGENTS.md",
            "symlink": "One is a symlink to the other",
            "separate": "Two separate files",
            "duplicate": "Same content, copied",
        }
        fig = hbars(
            t,
            "Two files, one truth: most repos link CLAUDE.md to AGENTS.md",
            f"How the {sum(int(r['repos']) for r in rel)} repos with both files keep them in step",
            [labels[r["relation"]] for r in rel],
            [float(r["pct_of_repos_with_both"]) for r in rel],
            {i for i, r in enumerate(rel) if r["relation"] in ("import", "symlink")},
            [f"({r['repos']})" for r in rel],
            xmax=58,
        )
        save(fig, out, "03-claude-agents", mode)
        # 4. what agents read
        order = [
            "conditional_rules",
            "at_imports",
            "claude_html_comments",
            "non_agent_import",
            "unloaded_import",
        ]
        short = {
            "conditional_rules": "Rules that apply only to some paths",
            "at_imports": "@ imports pull files in",
            "claude_html_comments": "CLAUDE.md with HTML comments Claude strips",
            "non_agent_import": "Imports a file that is not an agent file",
            "unloaded_import": "An import that silently does not load",
        }
        fig = hbars(
            t,
            "What the agent reads is not always what the path says",
            "Share of repositories; the highlighted files are invisible to a path-based scanner",
            [short[k] for k in order],
            [float(nums[k]["pct"]) for k in order],
            {3},
            [f"({int(nums[k]['repos']):,} of {int(nums[k]['of']):,})" for k in order],
            xmax=48,
        )
        save(fig, out, "04-what-agents-read", mode)
        # 5. risk
        order = ["mcp_unpinned", "risky_settings", "hidden_unicode", "secrets"]
        short = {
            "mcp_unpinned": "MCP configs that run an unpinned package",
            "risky_settings": "Over-permissive agent settings",
            "hidden_unicode": "Hidden Unicode characters",
            "secrets": "Hardcoded secrets in agent files",
        }
        fig = hbars(
            t,
            "One in three repos with an MCP config runs an unpinned package",
            "Share of repositories (MCP: of the repositories that have an MCP config)",
            [short[k] for k in order],
            [float(nums[k]["pct"]) for k in order],
            {0},
            [f"({int(nums[k]['repos']):,} of {int(nums[k]['of']):,})" for k in order],
            xmax=52,
        )
        save(fig, out, "05-risk", mode)
        # 6. precision
        fig = _precision(t, prec)
        save(fig, out, "06-precision", mode)
    names = [
        "01-adoption",
        "02-tools-per-repo",
        "03-claude-agents",
        "04-what-agents-read",
        "05-risk",
        "06-precision",
    ]
    return names


def _precision(t: dict[str, str], prec: list[dict[str, str]]) -> Any:
    rows = sorted(prec, key=lambda r: -int(r["findings_medium_plus"]))
    tp = sum(int(r["tp"]) for r in rows)
    wf = sum(int(r["wontfix"]) for r in rows)
    fp = sum(int(r["fp"]) for r in rows)
    height = 1.9 + 0.34 * len(rows)
    fig, ax = _frame(
        t,
        "Every finding of medium or above was triaged",
        f"{tp} true positives, {wf} accepted benign in context, {fp} false positives "
        "(rule bugs were fixed first)",
        height,
    )
    ys = list(range(len(rows)))[::-1]
    ax.barh(ys, [int(r["tp"]) for r in rows], color=t["accent"], height=0.62, label="True positive")
    ax.barh(
        ys,
        [int(r["wontfix"]) for r in rows],
        left=[int(r["tp"]) for r in rows],
        color=t["gray"],
        height=0.62,
        label="Correct match, benign context",
    )
    ax.set_yticks(ys, [r["rule"] for r in rows], color=t["ink"])
    ax.set_xticks([])
    for y, r in zip(ys, rows, strict=True):
        ax.text(
            int(r["findings_medium_plus"]) + 2,
            y,
            r["findings_medium_plus"],
            va="center",
            color=t["ink"],
            fontsize=9,
        )
    leg = ax.legend(frameon=False, loc="lower right", fontsize=9, labelcolor=t["ink"])
    for h in leg.legend_handles:
        h.set_edgecolor(t["surface"])
    fig.subplots_adjust(left=0.1, right=0.97, top=1 - 0.2 * 4.6 / height * 0.9, bottom=0.12)
    return fig


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Draw the study charts.")
    here = Path(__file__).resolve().parent
    p.add_argument("--data", type=Path, default=here / "data")
    p.add_argument("--out", type=Path, default=here / "charts")
    args = p.parse_args(argv)
    for name in build(args.data, args.out):
        print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
