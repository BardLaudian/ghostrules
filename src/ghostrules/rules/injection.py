"""Malicious-instruction rules GR010-GR016 (natural language, English + Spanish).

Every rule matches the raw text and also a whitespace-normalised copy of the whole file, so a
phrase broken across lines still matches, then drops overlapping duplicates. All of them run on
instruction files and on hidden text decoded by other rules (``scans_decoded``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.helpers import build_finding, host_allowed, urls_allowed
from ghostrules.rules.patterns import (
    COLLECTOR_PATTERNS,
    EXFIL_PATTERNS,
    INJECTION_PATTERNS,
    SHELL_LANGS,
    find_encoded_runs,
)
from ghostrules.rules.registry import rule

INSTRUCTIONS: tuple[Kind, ...] = ("instructions",)
_EXCERPT_CHARS = 80
_LONG_SNIPPET = 200  # GR012 must show the whole command


def _spans(target: ScanTarget, patterns: Iterable[re.Pattern[str]]) -> list[tuple[int, int]]:
    """Original-text spans matched by any pattern, on raw and normalised text, deduplicated."""
    patterns = tuple(patterns)
    spans = [m.span() for p in patterns for m in p.finditer(target.text)]
    normalised, offsets = target.normalized
    for p in patterns:
        for m in p.finditer(normalised):
            if m.end() > m.start():
                spans.append((offsets[m.start()], offsets[m.end() - 1] + 1))
    kept: list[tuple[int, int]] = []
    for start, end in sorted(set(spans), key=lambda s: (s[0], -s[1])):
        if not kept or start >= kept[-1][1]:
            kept.append((start, end))
    return kept


def _excerpt(target: ScanTarget, start: int, end: int) -> str:
    text = " ".join(target.text[start:end].split())
    return text if len(text) <= _EXCERPT_CHARS else text[:_EXCERPT_CHARS] + "…"


def _finding(
    target: ScanTarget,
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    span: tuple[int, int],
    *,
    fix_hint: str,
    decoded: str | None = None,
    limit: int = 120,
) -> Finding:
    start, end = span
    return build_finding(
        target=target,
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=f"{message}: “{_excerpt(target, start, end)}”",
        start=start,
        end=end,
        decoded=decoded,
        fix_hint=fix_hint,
        limit=limit,
    )


# --- GR010 ---------------------------------------------------------------------------------


@rule(
    "GR010",
    Severity.HIGH,
    "Instruction override",
    "Text telling the agent to ignore, forget or override its previous or system instructions.",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr010_instruction_override(target: ScanTarget) -> Iterator[Finding]:
    """High; low when inside a fenced code block (likely documentation about prompt injection)."""
    for span in _spans(target, INJECTION_PATTERNS["GR010"]):
        in_block = target.code_block_at(span[0]) is not None
        yield _finding(
            target,
            "GR010",
            Severity.LOW if in_block else Severity.HIGH,
            "Instruction override",
            "Tries to override the agent's instructions"
            + (" (appears inside a code block)" if in_block else ""),
            span,
            fix_hint="Remove the instruction. If this is documentation, keep it in a code block.",
        )


# --- GR011 ---------------------------------------------------------------------------------


@rule(
    "GR011",
    Severity.HIGH,
    "Concealment from the user",
    "Text telling the agent to hide what it does from the user.",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr011_concealment(target: ScanTarget) -> Iterator[Finding]:
    """Instructions to act without telling, showing or asking the user."""
    for span in _spans(target, INJECTION_PATTERNS["GR011"]):
        yield _finding(
            target,
            "GR011",
            Severity.HIGH,
            "Concealment from the user",
            "Tells the agent to hide its actions from the user",
            span,
            fix_hint="Remove the instruction; agents should be transparent about their actions.",
        )


# --- GR012 ---------------------------------------------------------------------------------


@rule(
    "GR012",
    Severity.CRITICAL,
    "Remote code execution pattern",
    "Commands that download and execute remote code (curl | sh, iex, encoded PowerShell...).",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr012_remote_code_execution(target: ScanTarget) -> Iterator[Finding]:
    """Critical in instruction files; skipped when every URL in the command is allow-listed.

    The snippet shows the whole command. (The "high elsewhere" case of RULES.md is GR105/GR107,
    which reuse these patterns for MCP server commands and hooks.)
    """
    for span in _spans(target, INJECTION_PATTERNS["GR012"]):
        if urls_allowed(target.text[span[0] : span[1]], target.allow_domains):
            continue
        yield _finding(
            target,
            "GR012",
            Severity.CRITICAL,
            "Remote code execution pattern",
            "Downloads or decodes and executes code",
            span,
            fix_hint="Remove it, or download, review and pin the script instead of piping it.",
            limit=_LONG_SNIPPET,
        )


# --- GR013 ---------------------------------------------------------------------------------


def _lines_of(target: ScanTarget, span: tuple[int, int]) -> range:
    first = target.position(span[0])[0]
    last = target.position(max(span[1] - 1, span[0]))[0]
    return range(first, last + 1)


@rule(
    "GR013",
    Severity.CRITICAL,
    "Data exfiltration",
    "Instructions to send secrets to a URL, markdown-image exfiltration, collector domains.",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr013_exfiltration(target: ScanTarget) -> Iterator[Finding]:
    """Critical for exfiltration instructions; collector domains alone are high.

    A collector domain on the same line as an exfiltration instruction is critical. One inside
    the matched instruction is not reported again.
    """
    allow = target.allow_domains
    exfil: list[tuple[int, int]] = []
    for span in _spans(target, EXFIL_PATTERNS):
        if urls_allowed(target.text[span[0] : span[1]], allow):
            continue
        exfil.append(span)
        yield _finding(
            target,
            "GR013",
            Severity.CRITICAL,
            "Data exfiltration",
            "Tells the agent to send data or secrets to a URL",
            span,
            fix_hint="Remove the instruction; never send environment data to external URLs.",
        )
    exfil_lines = {n for span in exfil for n in _lines_of(target, span)}
    for span in _spans(target, COLLECTOR_PATTERNS):
        domain = target.text[span[0] : span[1]]
        if host_allowed(domain, allow) or any(s <= span[0] and span[1] <= e for s, e in exfil):
            continue
        combined = bool(exfil_lines & set(_lines_of(target, span)))
        yield _finding(
            target,
            "GR013",
            Severity.CRITICAL if combined else Severity.HIGH,
            "Data exfiltration",
            "References a request-collector domain"
            + (" next to an exfiltration instruction" if combined else ""),
            span,
            fix_hint="Remove the reference, or add the domain to allow_domains if it is yours.",
        )


# --- GR014 ---------------------------------------------------------------------------------

_NEGATION_BEFORE = re.compile(
    r"(?:never|do\s+not|don'?t|must\s+not|should\s+not|shouldn'?t|mustn'?t|avoid|not"
    r"|nunca|evita)\s+(?:[a-z']+\s+){0,2}$",
    re.IGNORECASE,
)


# "Copy .env.example to .env.local": the sensitive path is the destination, not what is read.
_COPY_TO_DESTINATION = re.compile(
    r"(?:copy|paste)\b.*\b(?:to|into|as)\b", re.IGNORECASE | re.DOTALL
)


@rule(
    "GR014",
    Severity.HIGH,
    "Sensitive file access",
    "Instructions to read, print or send credentials files (~/.ssh, .env, .npmrc...).",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr014_sensitive_files(target: ScanTarget) -> Iterator[Finding]:
    """A sensitive path near a read/print/send verb, unless the verb is negated ("never print")."""
    for span in _spans(target, INJECTION_PATTERNS["GR014"]):
        if _NEGATION_BEFORE.search(target.text[max(0, span[0] - 40) : span[0]]):
            continue
        if _COPY_TO_DESTINATION.match(target.text[span[0] : span[1]]):
            continue
        yield _finding(
            target,
            "GR014",
            Severity.HIGH,
            "Sensitive file access",
            "Tells the agent to access a credentials or secrets file",
            span,
            fix_hint="Remove the instruction; agents should not read or transmit credential files.",
        )


# --- GR015 ---------------------------------------------------------------------------------


@rule(
    "GR015",
    Severity.MEDIUM,
    "Encoded payload",
    "Long base64 or hex strings in instruction files, which hide their content from reviewers.",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr015_encoded_payloads(target: ScanTarget) -> Iterator[Finding]:
    """High when the run decodes to printable text (shown in ``decoded``), else medium.

    Fenced code blocks are skipped unless labelled as a shell language; unlabelled blocks count
    as non-shell. Hashes, ``data:`` URIs and path-like strings are filtered out by the finder.
    """
    for run in find_encoded_runs(target.text):
        block = target.code_block_at(run.start)
        if block is not None and block.lang not in SHELL_LANGS:
            continue
        readable = run.decoded is not None
        yield _finding(
            target,
            "GR015",
            Severity.HIGH if readable else Severity.MEDIUM,
            "Encoded payload",
            "Long encoded string that decodes to readable text"
            if readable
            else "Long encoded string of unknown content",
            (run.start, run.end),
            fix_hint="Replace the encoded text with its plain form, or remove it.",
            decoded=run.decoded,
            limit=40,
        )


# --- GR016 ---------------------------------------------------------------------------------


@rule(
    "GR016",
    Severity.HIGH,
    "Agent safety bypass",
    "Instructions to skip permission prompts, disable sandboxes or auto-approve everything.",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr016_safety_bypass(target: ScanTarget) -> Iterator[Finding]:
    """Flags that or instructions which switch off the agent's safety checks."""
    for span in _spans(target, INJECTION_PATTERNS["GR016"]):
        yield _finding(
            target,
            "GR016",
            Severity.HIGH,
            "Agent safety bypass",
            "Tells the agent to bypass its permission or safety checks",
            span,
            fix_hint="Remove it; keep the agent's permission prompts and sandbox enabled.",
        )
