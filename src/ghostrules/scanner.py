"""The scan pipeline: discover -> load -> run rules -> suppress -> decode pass -> filter -> sort."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from ghostrules._compat import tomllib
from ghostrules.config import Config
from ghostrules.models import Finding, ScanResult, ScanTarget
from ghostrules.rules import Rule, all_rules
from ghostrules.targets import Candidate, discover, home_targets

# Invisible-character findings must never be silenceable from inside the scanned file.
NEVER_SUPPRESS: frozenset[str] = frozenset({"GR001", "GR002"})

_IGNORE_RE = re.compile(r"ghostrules-ignore(?:\s*:\s*((?:GR\d{3}(?:\s*,\s*)?)+))?", re.IGNORECASE)
_RULE_ID_RE = re.compile(r"GR\d{3}", re.IGNORECASE)

# Maps a 1-based line number to the rule ids it ignores; ``None`` means every rule.
Suppressions = dict[int, "frozenset[str] | None"]


def strip_jsonc(text: str) -> str:
    """Blank out ``//`` and ``/* */`` comments and trailing commas, outside of strings.

    Characters are replaced by spaces (newlines kept) so offsets, lines and columns still match
    the original text.
    """
    out: list[str] = []
    pending_comma: int | None = None
    in_string = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            end = n if close == -1 else close + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:end]))
            i = end
        else:
            if ch in "}]" and pending_comma is not None:
                out[pending_comma] = " "
            if ch == ",":
                pending_comma = len(out)
            elif not ch.isspace():
                pending_comma = None
            in_string = ch == '"'
            out.append(ch)
            i += 1
    return "".join(out)


def parse_structured(path: str, text: str) -> tuple[Any, str | None]:
    """Parse JSON (tolerating JSONC) or TOML by extension. Returns ``(parsed, error)``."""
    lowered = path.lower()
    try:
        if lowered.endswith(".json"):
            body = text.removeprefix("\ufeff")
            try:
                return json.loads(body), None
            except json.JSONDecodeError:
                return json.loads(strip_jsonc(body)), None
        if lowered.endswith(".toml"):
            return tomllib.loads(text.removeprefix("\ufeff")), None
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        return None, str(exc)
    return None, None


def load_target(candidate: Candidate, label: str | None = None) -> ScanTarget:
    """Read a candidate as UTF-8 (``surrogateescape``, so bad bytes never crash) and parse it."""
    data = candidate.abs_path.read_bytes()
    text = data.decode("utf-8", errors="surrogateescape")
    path = label or candidate.rel
    parsed, error = (None, None) if candidate.kind == "other" else parse_structured(path, text)
    return ScanTarget(path=path, kind=candidate.kind, text=text, parsed=parsed, parse_error=error)


def parse_suppressions(lines: Iterable[str]) -> Suppressions:
    """Find ``ghostrules-ignore[: GR010,GR012]`` markers; each covers its line and the next."""
    table: Suppressions = {}
    for number, line in enumerate(lines, start=1):
        match = _IGNORE_RE.search(line)
        if not match:
            continue
        ids = match.group(1)
        scope = frozenset(m.upper() for m in _RULE_ID_RE.findall(ids)) if ids else None
        for covered in (number, number + 1):
            existing = table.get(covered, frozenset())
            if scope is None or existing is None:
                table[covered] = None
            else:
                table[covered] = existing | scope
    return table


def is_suppressed(finding: Finding, table: Suppressions) -> bool:
    """Whether an inline marker silences this finding (never GR001/GR002)."""
    if finding.rule_id in NEVER_SUPPRESS or finding.line not in table:
        return False
    scope = table[finding.line]
    return scope is None or finding.rule_id in scope


def _applicable(rules: Iterable[Rule], config: Config) -> list[Rule]:
    return [r for r in rules if r.id not in config.disable]


def _run_rules(target: ScanTarget, rules: Iterable[Rule], errors: list[str]) -> list[Finding]:
    """Run applicable rules; a crashing rule is recorded in ``errors`` rather than aborting."""
    found: list[Finding] = []
    for r in rules:
        if target.kind not in r.applies_to:
            continue
        try:
            found.extend(r.check(target))
        except Exception as exc:  # a buggy rule must not hide every other finding
            errors.append(f"rule {r.id} failed on {target.path}: {type(exc).__name__}: {exc}")
    return found


def _scan_decoded(
    target: ScanTarget, parents: Iterable[Finding], rules: Iterable[Rule], errors: list[str]
) -> list[Finding]:
    """Run ``scans_decoded`` rules over hidden text recovered by other rules.

    Results are attributed to the parent's location, carry the decoded text, and get +1 severity.
    """
    decoding_rules = [r for r in rules if r.scans_decoded]
    derived: list[Finding] = []
    for parent in parents:
        if not parent.decoded:
            continue
        virtual = ScanTarget(
            path=target.path, kind="instructions", text=parent.decoded, origin=parent.rule_id
        )
        for hit in _run_rules(virtual, decoding_rules, errors):
            derived.append(
                replace(
                    hit,
                    severity=hit.severity.bumped(),
                    line=parent.line,
                    column=parent.column,
                    end_column=parent.end_column,
                    snippet=parent.snippet,
                    decoded=parent.decoded,
                    message=f"{hit.message} (found in hidden text decoded by {parent.rule_id})",
                )
            )
    return derived


def scan_target(
    target: ScanTarget, config: Config, rules: Iterable[Rule]
) -> tuple[list[Finding], int, list[str]]:
    """Scan one target. Returns ``(findings, suppressed_count, errors)``.

    Findings derived from decoded hidden text are added after suppression is applied, so an
    inline ignore comment can never silence something that was hidden in invisible characters.
    """
    errors: list[str] = []
    active = _applicable(rules, config)
    table = parse_suppressions(target.lines)
    kept: list[Finding] = []
    suppressed = 0
    for finding in _run_rules(target, active, errors):
        if is_suppressed(finding, table):
            suppressed += 1
        else:
            kept.append(finding)
    kept.extend(_scan_decoded(target, kept, active, errors))
    return kept, suppressed, errors


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[object, ...], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.column, f.end_column, f.title, f.decoded)
        unique.setdefault(key, f)
    return list(unique.values())


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Order by severity (most severe first), then path, line, column and rule id."""
    return sorted(findings, key=lambda f: (-int(f.severity), f.path, f.line, f.column, f.rule_id))


def scan_paths(
    paths: Iterable[Path],
    config: Config,
    *,
    all_files: bool = False,
    include_home: bool = False,
    rules: Iterable[Rule] | None = None,
    home_dir: Path | None = None,
) -> ScanResult:
    """Scan one or more files/directories (plus user-level configs with ``include_home``).

    With a single root, reported paths are relative to it; with several, each path is prefixed
    by the root as given so entries stay unambiguous.
    """
    rule_list = list(all_rules() if rules is None else rules)
    roots = list(paths)
    result = ScanResult(config_source=config.source)

    candidates: list[tuple[Candidate, str]] = []
    for root in roots:
        if not root.exists():
            result.errors.append(f"path not found: {root}")
            continue
        for cand in discover(
            root, all_files=all_files, exclude=config.exclude, extra_targets=config.extra_targets
        ):
            label = cand.rel if len(roots) == 1 or root.is_file() else (root / cand.rel).as_posix()
            candidates.append((cand, label))
    if include_home:
        candidates.extend((cand, cand.rel) for cand in home_targets(home_dir))

    seen: set[Path] = set()
    findings: list[Finding] = []
    for cand, label in candidates:
        resolved = cand.abs_path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            target = load_target(cand, label)
        except OSError as exc:
            result.warnings.append(f"cannot read {label}: {exc.strerror or exc}")
            continue
        result.scanned_files += 1
        if target.parse_error:
            result.warnings.append(f"cannot parse {label}: {target.parse_error}")
        kept, suppressed, errors = scan_target(target, config, rule_list)
        findings.extend(kept)
        result.suppressed += suppressed
        result.errors.extend(errors)

    visible = [f for f in _dedupe(findings) if f.severity >= config.min_severity]
    result.findings = sort_findings(visible)
    return result
