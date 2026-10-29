"""The scan pipeline: discover -> load -> run rules -> suppress -> decode pass -> filter -> sort."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from ghostrules._compat import tomllib
from ghostrules.agents import Repo
from ghostrules.changeset import ChangeBase, ChangeContext
from ghostrules.config import Config
from ghostrules.contextscan import FileMeta, RootContext, build_context, collect_meta, relabel_via
from ghostrules.ignores import IGNORE_RE as _IGNORE_RE
from ghostrules.ignores import ReviewedMarks, normalise_line
from ghostrules.jsonloc import strip_jsonc
from ghostrules.models import Finding, ScanResult, ScanTarget
from ghostrules.reach import ScriptRef, hook_scripts, prose_references, skill_scripts
from ghostrules.rules import Rule, all_rules
from ghostrules.scancontext import ScanContext
from ghostrules.secrets import mask_secrets
from ghostrules.targets import Candidate, discover, home_targets, matches_any
from ghostrules.visibility import by_visibility

# Invisible-character findings must never be silenceable from inside the scanned file.
NEVER_SUPPRESS: frozenset[str] = frozenset({"GR001", "GR002", "GR030"})

_RULE_ID_RE = re.compile(r"GR\d{3}", re.IGNORECASE)

# Maps a 1-based line number to the rule ids it ignores; ``None`` means every rule.
Suppressions = dict[int, "frozenset[str] | None"]


@dataclass(frozen=True)
class SuppressionPolicy:
    """Which ``ghostrules-ignore`` comments are honoured. ``all`` (the default) honours every one;
    ``off`` honours none; ``base`` honours only those that already existed at a trusted ref, found
    through ``reviewed(path)``. The scanned change cannot add an ignore to silence itself."""

    mode: Literal["all", "off", "base"] = "all"
    reviewed: Callable[[str], ReviewedMarks] | None = None


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


def load_target(
    candidate: Candidate,
    label: str | None = None,
    allow_domains: tuple[str, ...] = (),
    trust_known_installers: bool = True,
    first_party: tuple[Any, ...] = (),
) -> ScanTarget:
    """Read a candidate as UTF-8 (``surrogateescape``, so bad bytes never crash) and parse it."""
    data = candidate.abs_path.read_bytes()
    text = data.decode("utf-8", errors="surrogateescape")
    path = label or candidate.rel
    parsed, error = (None, None) if candidate.kind == "other" else parse_structured(path, text)
    return ScanTarget(
        path=path,
        kind=candidate.kind,
        text=text,
        parsed=parsed,
        parse_error=error,
        allow_domains=allow_domains,
        trust_known_installers=trust_known_installers,
        first_party=first_party,
    )


_NO_IGNORES = SuppressionPolicy("off")


def parse_suppressions(lines: Sequence[str], honour: ReviewedMarks | None = None) -> Suppressions:
    """Find ``ghostrules-ignore[: GR010,GR012]`` markers; each covers its line and the next.

    With ``honour`` only reviewed ignores count: a marker covers its own line if that line existed
    with the marker at the trusted ref, and the next line only if that pair of lines did."""
    table: Suppressions = {}
    for number, line in enumerate(lines, start=1):
        match = _IGNORE_RE.search(line)
        if not match:
            continue
        ids = match.group(1)
        scope = frozenset(m.upper() for m in _RULE_ID_RE.findall(ids)) if ids else None
        marker = normalise_line(line)
        following = normalise_line(lines[number]) if number < len(lines) else ""
        for covered in (number, number + 1):
            if honour is not None:
                if covered == number and marker not in honour.marks:
                    continue
                if covered == number + 1 and (marker, following) not in honour.pairs:
                    continue
            existing = table.get(covered, frozenset())
            if scope is None or existing is None:
                table[covered] = None
            else:
                table[covered] = existing | scope
    return table


def suppressions_for(target: ScanTarget, policy: SuppressionPolicy | None = None) -> Suppressions:
    """The suppression table of a target under ``policy`` (``None`` honours every marker)."""
    if policy is None or policy.mode == "all":
        return parse_suppressions(target.lines)
    if policy.mode == "off" or policy.reviewed is None:
        return {}  # "base" without a lookup fails closed: nothing is reviewed
    return parse_suppressions(target.lines, policy.reviewed(target.path))


def unhonoured_markers(target: ScanTarget, policy: SuppressionPolicy | None) -> int:
    """How many ignore comments in ``target`` the policy did not honour (for the report)."""
    if policy is None or policy.mode == "all":
        return 0
    markers = [n for n, line in enumerate(target.lines, start=1) if _IGNORE_RE.search(line)]
    if not markers:
        return 0
    honoured = suppressions_for(target, policy)
    return sum(1 for n in markers if n not in honoured)


def is_suppressed(finding: Finding, table: Suppressions, target: ScanTarget | None = None) -> bool:
    """Whether an inline marker silences this finding.

    Never GR001, GR002 or GR030, and never a finding inside an HTML comment: the agent reads that
    text and a reviewer looking at the rendered file does not, so a marker next to it cannot be
    taken as the reviewer's approval."""
    if finding.rule_id in NEVER_SUPPRESS or finding.line not in table:
        return False
    if target is not None and target.in_html_comment(target.offset(finding.line, finding.column)):
        return False
    scope = table[finding.line]
    return scope is None or finding.rule_id in scope


def _applicable(rules: Iterable[Rule], config: Config) -> list[Rule]:
    return [r for r in rules if r.id not in config.disable]


def _run_rules(target: ScanTarget, rules: Iterable[Rule], errors: list[str]) -> list[Finding]:
    """Run applicable rules; a crashing rule is recorded in ``errors`` rather than aborting."""
    found: list[Finding] = []
    for r in rules:
        if r.scope != "file":
            continue
        # code that an agent runs gets the generic "any file" checks (hidden characters) as well
        if target.kind not in r.applies_to and not (
            target.kind == "script" and "other" in r.applies_to
        ):
            continue
        try:
            found.extend(r.check(target))
        except Exception as exc:  # a buggy rule must not hide every other finding
            detail = mask_secrets(f"{type(exc).__name__}: {exc}")
            errors.append(f"rule {r.id} failed on {target.path}: {detail}")
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
            path=target.path,
            kind="instructions",
            text=parent.decoded,
            origin=parent.rule_id,
            allow_domains=target.allow_domains,
            trust_known_installers=target.trust_known_installers,
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
    target: ScanTarget,
    config: Config,
    rules: Iterable[Rule],
    policy: SuppressionPolicy | None = None,
) -> tuple[list[Finding], int, list[str]]:
    """Scan one target. Returns ``(findings, suppressed_count, errors)``.

    Findings derived from decoded hidden text are added after suppression is applied, so an
    inline ignore comment can never silence something that was hidden in invisible characters.
    """
    errors: list[str] = []
    active = _applicable(rules, config)
    table = suppressions_for(target, policy)
    kept: list[Finding] = []
    suppressed = 0
    for finding in _run_rules(target, active, errors):
        if is_suppressed(finding, table, target):
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
    """Order by severity (most severe first), hidden-text findings first among equals, then
    files closer to the root, path, line, column and rule id."""
    return sorted(
        findings,
        key=lambda f: (
            -int(f.severity),
            not f.decoded,
            f.path.count("/"),
            f.path,
            f.line,
            f.column,
            f.rule_id,
        ),
    )


_INJECTION_TAG_RULES = re.compile(r"GR0(?:0\d|1[0-6])")
IMPORT_TAG = "reached-via-import"


def _is_agent_file(cand: Candidate) -> bool:
    return cand.kind != "other"


def _annotate(finding: Finding, meta: FileMeta | None, standalone: bool) -> Finding:
    """Mark findings in a file that only an import reaches with the chain and the agents, and
    findings in a file an agent reads through a symlink with the link's name."""
    if meta is None:
        return finding
    if meta.via and not standalone:
        tags = (IMPORT_TAG,) if _INJECTION_TAG_RULES.fullmatch(finding.rule_id) else ()
        return replace(finding, via=meta.via, agents=tuple(sorted(meta.agents)), tags=tags)
    if meta.aliases:
        via = tuple(f"{alias} (symlink)" for alias in sorted(meta.aliases))
        return replace(finding, via=via, agents=tuple(sorted(meta.agents)))
    return finding


def _label_for(root: Path, roots: list[Path]) -> Callable[[str], str]:
    """Maps a graph path (relative to the scan directory) to the path shown in reports."""
    base = root if root.is_dir() else root.parent
    if len(roots) == 1 or root.is_file():
        return lambda path: path
    return lambda path: path if path.startswith("~/") else (base / path).as_posix()


def _run_graph_rules(
    contexts: list[RootContext],
    by_label: dict[str, ScanTarget],
    config: Config,
    rule_list: list[Rule],
    result: ScanResult,
    policy: SuppressionPolicy | None = None,
    import_only: frozenset[str] = frozenset(),
) -> list[Finding]:
    """GR020-GR025: once per scan root, with suppression by the importing file's own markers."""
    graph_rules = [
        r
        for r in rule_list
        if r.scope == "graph" and r.check_graph is not None and r.id not in config.disable
    ]
    found: list[Finding] = []
    tables: dict[str, Suppressions] = {}
    for rc in contexts:
        ctx = ScanContext(
            rc.graphs,
            {
                e.path: by_label[rc.label_of(e.path)]
                for g in rc.graphs.values()
                for e in g.entries
                if rc.label_of(e.path) in by_label
            },
            rc.label_of,
            lambda path: matches_any(path, config.exclude),
            rc.base,
        )
        for r in graph_rules:
            assert r.check_graph is not None
            try:
                produced = list(r.check_graph(ctx))
            except Exception as exc:  # a buggy rule must not hide every other finding
                detail = mask_secrets(f"{type(exc).__name__}: {exc}")
                result.errors.append(f"rule {r.id} failed: {detail}")
                continue
            for f in produced:
                f = _relabel_finding(f, rc.label_of, ctx)
                target = by_label.get(f.path)
                if target is not None:
                    table = tables.setdefault(
                        f.path,
                        suppressions_for(target, _NO_IGNORES if f.path in import_only else policy),
                    )
                    if is_suppressed(f, table, target):
                        result.suppressed += 1
                        continue
                found.append(f)
    return found


def _run_change_rules(
    ctx: ChangeContext, config: Config, rule_list: list[Rule], result: ScanResult
) -> list[Finding]:
    """Rules that compare the scanned tree with a trusted base ref. Never suppressed inline."""
    found: list[Finding] = []
    for r in rule_list:
        if r.scope != "change" or r.check_change is None or r.id in config.disable:
            continue
        try:
            found.extend(r.check_change(ctx))
        except Exception as exc:  # a buggy rule must not hide every other finding
            detail = mask_secrets(f"{type(exc).__name__}: {exc}")
            result.errors.append(f"rule {r.id} failed: {detail}")
    return found


_REACH_TAGS = {
    "hook command": "reached-via-hook",
    "skill script": "reached-via-skill",
    "prose reference": "reached-via-reference",
}


def _scan_reached_scripts(
    base: Path,
    by_label: dict[str, ScanTarget],
    config: Config,
    rule_list: list[Rule],
    result: ScanResult,
) -> list[Finding]:
    """Scripts that hooks and skills run: read from inside the tree only, scanned as code, and
    reported with the chain that reaches them. Never read through a link that leaves the tree."""
    repo = Repo(base)
    refs: dict[str, ScriptRef] = {}
    for label, target in by_label.items():
        if target.kind == "config":
            for ref in hook_scripts(label, target.text, repo.is_file):
                refs.setdefault(ref.path, ref)
        elif target.path.endswith("SKILL.md"):
            for ref in skill_scripts(label, target.text, repo.is_file):
                refs.setdefault(ref.path, ref)
        if target.kind == "instructions":
            for ref in prose_references(label, target.text, repo.is_file):
                if ref.kind == "script" or ref.path not in by_label:
                    refs.setdefault(ref.path, ref)
    code_rules = [r for r in rule_list if "script" in r.applies_to]
    found: list[Finding] = []
    for ref in refs.values():
        data = repo.read(ref.path)
        if data is None:
            continue
        script = ScanTarget(ref.path, ref.kind, data.decode("utf-8", errors="surrogateescape"))  # type: ignore[arg-type]
        known = (
            ref.path in by_label and ref.kind == "script"
        )  # already read under --all-files: only the code rules are new
        if not known:
            result.scanned_files += 1
        kept, _, errors = scan_target(
            script, config, code_rules if known else rule_list, _NO_IGNORES
        )
        tag = _REACH_TAGS.get(ref.why, "reached-via-hook")
        found.extend(replace(f, via=(ref.via,), tags=(*f.tags, tag)) for f in kept)
        result.errors.extend(errors)
    return found


def _relabel_finding(finding: Finding, label_of: Callable[[str], str], ctx: ScanContext) -> Finding:
    """Rules work on graph paths; reports use the labels (they differ with several roots)."""
    if ctx.target(finding.path) is not None:
        return finding  # already built from a labelled ScanTarget
    return replace(
        finding,
        path=label_of(finding.path),
        via=tuple(relabel_via(v, label_of) for v in finding.via),
    )


def scan_paths(
    paths: Iterable[Path],
    config: Config,
    *,
    all_files: bool = False,
    include_home: bool = False,
    rules: Iterable[Rule] | None = None,
    home_dir: Path | None = None,
    suppressions: SuppressionPolicy | None = None,
    change_base: ChangeBase | None = None,
) -> ScanResult:
    """Scan one or more files/directories (plus user-level configs with ``include_home``).

    With a single root, reported paths are relative to it; with several, each path is prefixed
    by the root as given so entries stay unambiguous. Unless ``config.follow_imports`` is off, the
    files agents reach through ``@`` imports are scanned too, with the chain that reaches them.
    """
    rule_list = list(all_rules() if rules is None else rules)
    roots = list(paths)
    result = ScanResult(config_source=config.source)
    follow = config.follow_imports and "GR024" not in config.disable

    candidates: list[tuple[Candidate, str]] = []
    contexts: list[RootContext] = []
    home_repo = Repo(home_dir or Path.home(), "~/") if include_home else None
    for root in roots:
        if not root.exists():
            result.errors.append(f"path not found: {root}")
            continue
        for cand in discover(
            root, all_files=all_files, exclude=config.exclude, extra_targets=config.extra_targets
        ):
            label = cand.rel if len(roots) == 1 or root.is_file() else (root / cand.rel).as_posix()
            candidates.append((cand, label))
        try:
            contexts.append(
                build_context(
                    root if root.is_dir() else root.parent,
                    config,
                    _label_for(root, roots),
                    home=home_repo,
                    only=root.name if root.is_file() else None,
                )
            )
        except OSError as exc:
            result.errors.append(f"cannot resolve imports under {root}: {exc.strerror or exc}")
    if include_home:
        candidates.extend((cand, cand.rel) for cand in home_targets(home_dir))

    meta = collect_meta(contexts, config)
    standalone = {label for cand, label in candidates if _is_agent_file(cand)}
    known = {label: i for i, (_, label) in enumerate(candidates)}
    for label, item in meta.items():
        if item.via and not follow:
            continue
        cand = Candidate(item.abs_path, item.rel, "instructions")
        if label in known:
            if candidates[known[label]][0].kind == "other":
                candidates[known[label]] = (cand, label)
            continue
        known[label] = len(candidates)
        candidates.append((cand, label))

    seen: set[Path] = set()
    unhonoured = unhonoured_imported = 0
    import_only_labels: set[str] = set()
    findings: list[Finding] = []
    by_label: dict[str, ScanTarget] = {}
    for cand, label in candidates:
        resolved = cand.abs_path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            target = load_target(
                cand,
                label,
                config.allow_domains,
                config.trust_known_installers,
                config.first_party,
            )
        except OSError as exc:
            result.warnings.append(f"cannot read {label}: {exc.strerror or exc}")
            continue
        info = meta.get(label)
        if info is not None:
            target.agent_views = tuple(info.views)
        by_label[label] = target
        result.scanned_files += 1
        if target.parse_error:
            result.warnings.append(mask_secrets(f"cannot parse {label}: {target.parse_error}"))
        is_standalone = label in standalone or bool(info and info.rooted)
        # A file an agent reaches only through an import is not reviewed with the file that imports
        # it, so an ignore inside it is not an approval: no inline ignore counts there.
        import_only = bool(info and info.via and not is_standalone)
        policy = _NO_IGNORES if import_only else suppressions
        if import_only:
            import_only_labels.add(label)
        kept, suppressed, errors = scan_target(target, config, rule_list, policy)
        skipped = unhonoured_markers(target, policy)
        if import_only:
            unhonoured_imported += skipped
        else:
            unhonoured += skipped
        if config.profile != "strict":
            kept = [by_visibility(f, target, import_only=import_only) for f in kept]
        findings.extend(_annotate(f, info, is_standalone) for f in kept)
        result.suppressed += suppressed
        result.errors.extend(errors)

    if len(roots) == 1 and roots[0].is_dir():
        findings.extend(_scan_reached_scripts(roots[0], by_label, config, rule_list, result))
    findings.extend(
        _run_graph_rules(
            contexts,
            by_label,
            config,
            rule_list,
            result,
            suppressions,
            frozenset(import_only_labels),
        )
    )
    if change_base is not None and len(roots) == 1:
        root = roots[0] if roots[0].is_dir() else roots[0].parent
        findings.extend(
            _run_change_rules(
                ChangeContext(root, config.lockfile, change_base, by_label),
                config,
                rule_list,
                result,
            )
        )
    if unhonoured_imported:
        noun = "comment" if unhonoured_imported == 1 else "comments"
        result.warnings.append(
            f"{unhonoured_imported} ghostrules-ignore {noun} in files reached only through an "
            "import not honoured: nobody reviews them together with the file that imports them"
        )
    if unhonoured:
        noun = "comment" if unhonoured == 1 else "comments"
        result.warnings.append(
            f"{unhonoured} ghostrules-ignore {noun} not honoured: only ignores that were already "
            "reviewed are trusted in this mode"
        )
    visible = [f for f in _dedupe(findings) if f.severity >= config.min_severity]
    result.findings = sort_findings(visible)
    return result
