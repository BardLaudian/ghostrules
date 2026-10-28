"""Reports for ``ghostrules lock --check``: what changed in what the agents read.

Added lines are shown with invisible characters revealed (``⟦U+E0041⟧``), because that is exactly
what a pull-request diff hides. Removed lines are only counted: the lock keeps fingerprints of
lines, not their text.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.text import Text

from ghostrules.lock import Change, ConfigChange, Hunk, LockDiff
from ghostrules.reporters.common import safe
from ghostrules.secrets import mask_secrets
from ghostrules.unicode_utils import (
    TAG,
    VARIATION_SELECTOR,
    classify,
    decode_tags,
    decode_variation_selectors,
    find_runs,
    render_char,
)

MAX_RUN = 4  # invisible characters shown before "…(+N more)"
MAX_LINE = 150
MAX_ADDED_LINES = 8  # per change
_SOFT_HYPHEN = chr(0xAD)
_ICON = {"added": ("✚", "green"), "changed": ("✎", "yellow"), "removed": ("✖", "red")}
_HIDDEN_ICON = ("✎", "grey62")


def reveal_line(line: str) -> str:
    """One line with invisible characters made visible; long runs are cut short."""
    out: list[str] = []
    run = skipped = 0
    for ch in mask_secrets(line):
        if classify(ch) is not None or ch == _SOFT_HYPHEN:
            if run < MAX_RUN:
                out.append(render_char(ch, with_name=False))
            else:
                skipped += 1
            run += 1
            continue
        if skipped:
            out.append(f"…(+{skipped} more)")
            skipped = 0
        run = 0
        out.append(ch)
    if skipped:
        out.append(f"…(+{skipped} more)")
    text = safe("".join(out))
    return text if len(text) <= MAX_LINE else text[:MAX_LINE] + "…"


def hidden_text(line: str) -> list[str]:
    """What the invisible characters of a line spell, for tag characters and variation selectors."""
    found: list[str] = []
    for run in find_runs(line, TAG):
        decoded = decode_tags(line[run.start : run.end])
        if decoded:
            found.append(mask_secrets(decoded))
    for run in find_runs(line, VARIATION_SELECTOR):
        if run.end - run.start >= 3:
            decoded_vs = decode_variation_selectors(line[run.start : run.end])
            if decoded_vs:
                found.append(mask_secrets(decoded_vs))
    return found


# --- rows ---------------------------------------------------------------------------------------


def _where(change: Change) -> str:
    """How the file is reached, in words."""
    if change.kind == "removed":
        old = change.old
        if old is not None and old.via:
            return f"was imported by {old.via[-1]}"
        return f"was loaded ({old.load})" if old is not None else ""
    entry = change.entry
    if entry is None:
        return ""
    if entry.via:
        return f"now imported by {entry.via[-1]}"
    return entry.reason


def _chain(change: Change) -> str:
    if change.entry is not None and change.entry.via:
        return " → ".join(change.entry.via)
    if change.old is not None and change.old.via:
        return " → ".join(change.old.via)
    return ""


def _head(change: Change) -> Text:
    icon, color = _HIDDEN_ICON if change.kind == "hidden" else _ICON[change.kind]
    label = "changed" if change.kind == "hidden" else change.kind
    head = Text()
    head.append(f"{icon} {label:<8} ", style=f"bold {color}")
    head.append(safe(change.path), style="bold")
    where = _where(change)
    if where and change.kind in ("added", "removed"):
        head.append(f"  {safe(where)}", style="grey62")
    return head


def _agents_line(change: Change) -> Text:
    who = ", ".join(change.agents)
    if change.kind == "hidden":
        text = f"not visible to {who}: it only changes text they strip before the model sees it"
    elif change.kind == "removed":
        text = f"no longer in the context of {who}"
    elif change.kind == "added":
        text = f"in the context of {who}"
    else:
        text = f"seen by {who}"
    chain = _chain(change)
    if chain and change.kind in ("changed", "hidden"):
        text += f" · via {chain}"
    return Text(safe(text), style="grey62")


def _hunk_rows(hunks: list[Hunk] | None) -> list[RenderableType]:
    """The diff body: new lines with invisible characters revealed, removals counted."""
    if hunks is None:
        return [Text("(too large to compare line by line)", style="grey62")]
    rows: list[RenderableType] = []
    shown = 0
    omitted = 0
    for hunk in hunks:
        if hunk.removed_count and hunk.removed_range:
            a, b = hunk.removed_range
            span = f"line {a}" if a == b else f"lines {a}-{b}"
            noun = "line" if hunk.removed_count == 1 else "lines"
            rows.append(
                Text.assemble(
                    ("  − ", "bold red"),
                    (f"{hunk.removed_count} {noun} removed (was {span} of the locked text)", "red"),
                )
            )
        for number, line in hunk.added:
            if shown >= MAX_ADDED_LINES:
                omitted += 1
                continue
            shown += 1
            rows.append(
                Text.assemble(
                    ("  + ", "bold green"),
                    (f"{number:>3} │ ", "grey62"),
                    (reveal_line(line), "green"),
                )
            )
            for hidden in hidden_text(line):
                rows.append(
                    Text.assemble(
                        ("        ↳ hidden text: ", "bold red"), (safe(hidden), "bold red")
                    )
                )
    if omitted:
        rows.append(Text(f"  … and {omitted} more added line(s)", style="grey62"))
    return rows


def _change_block(change: Change) -> RenderableType:
    rows: list[RenderableType] = [_head(change), Padding(_agents_line(change), (0, 0, 0, 2))]
    for detail in change.details:
        rows.append(Padding(Text(safe(detail), style="yellow"), (0, 0, 0, 2)))
    if change.hunks is not None or change.kind in ("added", "changed"):
        rows.extend(Padding(r, (0, 0, 0, 2)) for r in _hunk_rows(change.hunks))
    return Group(*rows)


def _config_block(change: ConfigChange) -> RenderableType:
    icon, color = _ICON[change.kind]
    head = Text.assemble(
        (f"{icon} {change.kind:<8} ", f"bold {color}"),
        (safe(change.path), "bold"),
        ("  agent settings / MCP config", "grey62"),
    )
    rows: list[RenderableType] = [head]
    if change.kind != "removed":
        rows.extend(Padding(r, (0, 0, 0, 2)) for r in _hunk_rows(change.hunks))
    return Group(*rows)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def build_report(diff: LockDiff, lockfile: str) -> RenderableType:
    """The check result as a rich renderable."""
    if diff.empty:
        return Text(
            f"✔ {lockfile} is up to date ({_count(diff.files, 'file')} in the contexts)",
            style="green",
        )
    blocks: list[RenderableType] = [
        Text.assemble(("ghostrules lock --check", "bold"), (f"  {lockfile}", "grey62")),
        Text(""),
    ]
    for change in diff.visible_changes:
        blocks += [_change_block(change), Text("")]
    for config_change in diff.configs:
        blocks += [_config_block(config_change), Text("")]
    if diff.hidden_changes:
        blocks.append(Text("Changed, but not visible to the agent", style="bold"))
        blocks.append(Text(""))
        for change in diff.hidden_changes:
            blocks += [_change_block(change), Text("")]
    for note in diff.notes:
        blocks.append(Text(f"note: {safe(note)}", style="yellow"))
    if diff.old_generator and diff.old_generator != diff.new_generator:
        blocks.append(
            Text(
                f"note: the lock was made by {safe(diff.old_generator)}; "
                f"{safe(diff.new_generator)} may model agents differently",
                style="grey62",
            )
        )
    total = len(diff.changes) + len(diff.configs)
    blocks.append(
        Text.assemble(
            (f"{_count(total, 'change')} to what your agents read. ", "bold"),
            ("If they are intended, record them with ", "grey62"),
            ("ghostrules lock --update", "bold"),
            (".", "grey62"),
        )
    )
    return Group(*blocks)


# --- markdown and json --------------------------------------------------------------------------


def _md(text: str) -> str:
    return " ".join(safe(text).replace("`", "'").replace("<", "&lt;").replace(">", "&gt;").split())


def _md_hunks(hunks: list[Hunk] | None) -> list[str]:
    if hunks is None:
        return ["  _(too large to compare line by line)_"]
    lines: list[str] = []
    shown = 0
    for hunk in hunks:
        if hunk.removed_count and hunk.removed_range:
            a, b = hunk.removed_range
            span = f"line {a}" if a == b else f"lines {a}-{b}"
            lines.append(f"- {hunk.removed_count} line(s) removed (locked {span})")
        for number, line in hunk.added:
            if shown >= MAX_ADDED_LINES:
                break
            shown += 1
            lines.append(f"+ {number:>3} | {reveal_line(line)}")
            lines.extend(f"+       hidden text: {_md(h)}" for h in hidden_text(line))
    if not lines:
        return []
    return ["", "  ```diff", *[f"  {ln}" for ln in lines], "  ```"]


def render_markdown(diff: LockDiff, lockfile: str) -> str:
    """The check result as Markdown, for a pull-request summary."""
    if diff.empty:
        files = _count(diff.files, "file")
        return f"✅ **`{_md(lockfile)}` is up to date** ({files} in the contexts).\n"
    total = len(diff.changes) + len(diff.configs)
    out = [f"**{_count(total, 'change')}** to what your agents read (`{_md(lockfile)}`).", ""]
    for change in diff.visible_changes:
        icon, _ = _ICON[change.kind]
        where = f" — {_md(_where(change))}" if change.kind in ("added", "removed") else ""
        out.append(f"- {icon} **{change.kind}** `{_md(change.path)}`{where}")
        out.append(f"  - {_md(_agents_line(change).plain)}")
        out.extend(f"  - {_md(d)}" for d in change.details)
        out.extend(_md_hunks(change.hunks))
    for cc in diff.configs:
        icon, _ = _ICON[cc.kind]
        out.append(f"- {icon} **{cc.kind}** `{_md(cc.path)}` — agent settings / MCP config")
        if cc.kind != "removed":
            out.extend(_md_hunks(cc.hunks))
    if diff.hidden_changes:
        out += ["", "### Changed, but not visible to the agent", ""]
        for change in diff.hidden_changes:
            out.append(f"- ✎ `{_md(change.path)}` — {_md(_agents_line(change).plain)}")
    out += ["", *[f"> **Note:** {_md(n)}" for n in diff.notes]]
    out.append("> If these changes are intended, record them with `ghostrules lock --update`.")
    return "\n".join(out).rstrip("\n") + "\n"


def _change_dict(change: Change) -> dict[str, Any]:
    return {
        "kind": change.kind,
        "path": change.path,
        "via": list(change.entry.via if change.entry else (change.old.via if change.old else ())),
        "agents": change.agents,
        "details": change.details,
        "added_lines": [
            {"line": n, "text": reveal_line(t)}
            for hunk in (change.hunks or [])
            for n, t in hunk.added
        ],
        "removed_lines": sum(h.removed_count for h in (change.hunks or [])),
    }


def render_json(diff: LockDiff, lockfile: str) -> str:
    """The check result as JSON."""
    data = {
        "lockfile": lockfile,
        "up_to_date": diff.empty,
        "changes": [_change_dict(c) for c in diff.visible_changes],
        "not_visible_to_the_agent": [_change_dict(c) for c in diff.hidden_changes],
        "configs": [
            {
                "kind": c.kind,
                "path": c.path,
                "added_lines": [
                    {"line": n, "text": reveal_line(t)} for h in (c.hunks or []) for n, t in h.added
                ],
            }
            for c in diff.configs
        ],
        "notes": diff.notes,
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
