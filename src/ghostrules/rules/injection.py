"""Malicious-instruction rules GR010-GR016 (natural language, English + Spanish).

Every rule matches the raw text and also a whitespace-normalised copy of the whole file, so a
phrase broken across lines still matches, then drops overlapping duplicates. All of them run on
instruction files and on hidden text decoded by other rules (``scans_decoded``).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator

from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.directive import classify, downgrade_note, severity_for
from ghostrules.rules.helpers import build_finding, host_allowed, urls_allowed
from ghostrules.rules.known_installers import extract_urls, is_risky_url, known_installer
from ghostrules.rules.patterns import (
    COLLECTOR_PATTERNS,
    EXFIL_PATTERNS,
    INJECTION_PATTERNS,
    SENSITIVE_PATH_RE,
    SHELL_LANGS,
    find_encoded_runs,
)
from ghostrules.rules.registry import rule
from ghostrules.sensitive import is_template_path

INSTRUCTIONS: tuple[Kind, ...] = ("instructions",)
_EXCERPT_CHARS = 80
_LONG_SNIPPET = 200  # GR012 must show the whole command


def _spans(
    target: ScanTarget, patterns: Iterable[re.Pattern[str]], *, fence_ok: bool = True
) -> list[tuple[int, int]]:
    """Original-text spans matched by any pattern, on raw and normalised text, deduplicated.

    With ``fence_ok=False`` a match that runs across a code fence is dropped before deduplication:
    folding whitespace can join a prose word to the command in the next code block."""
    patterns = tuple(patterns)
    spans = [m.span() for p in patterns for m in p.finditer(target.text)]
    normalised, offsets = target.normalized
    for p in patterns:
        for m in p.finditer(normalised):
            if m.end() > m.start():
                spans.append((offsets[m.start()], offsets[m.end() - 1] + 1))
    if not fence_ok:
        spans = [s for s in spans if "```" not in target.text[s[0] : s[1]]]
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
    """High for text that tells the agent to override its instructions; at most medium when the
    sentence describes something and at most low inside a code block or quotation (guidance that
    tells the agent to *ignore* such text quotes it)."""
    for span in _spans(target, INJECTION_PATTERNS["GR010"]):
        kind = classify(target, span)
        in_block = target.code_block_at(span[0]) is not None
        note = " (appears inside a code block)" if in_block else downgrade_note(kind)
        yield _finding(
            target,
            "GR010",
            severity_for(kind, Severity.HIGH),
            "Instruction override",
            "Tries to override the agent's instructions" + note,
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
    """Instructions to act without telling, showing or asking the user. High for an instruction,
    medium when the text describes something, low for an example or a quotation."""
    for span in _spans(target, INJECTION_PATTERNS["GR011"]):
        if _prohibited_in_clause(target.text, span[0]):
            continue  # "Never silently add scope": the sentence forbids it
        if _MODAL_BEFORE.search(target.text[max(0, span[0] - 12) : span[0]]):
            continue  # "operations either silently run on CPU": a description, not an order
        kind = classify(target, span)
        yield _finding(
            target,
            "GR011",
            severity_for(kind, Severity.HIGH),
            "Concealment from the user",
            "Tells the agent to hide its actions from the user" + downgrade_note(kind),
            span,
            fix_hint="Remove the instruction; agents should be transparent about their actions.",
        )


# --- GR012 ---------------------------------------------------------------------------------


@rule(
    "GR012",
    Severity.CRITICAL,
    "Remote code execution pattern",
    "Commands that download and execute remote code (curl | sh, iex, encoded PowerShell...);"
    " severity depends on the source and context.",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr012_remote_code_execution(target: ScanTarget) -> Iterator[Finding]:
    """Severity depends on what is fetched and where the command sits (see RULES.md).

    Critical: hidden or opaque payloads, insecure/odd URLs, or an unknown domain in prose. High:
    unknown domain in code. Medium/low: a well-known installer in prose/code. Skipped when every
    URL is in ``allow_domains``. The snippet shows the whole command. (The "high elsewhere" case
    of RULES.md is GR105/GR107, which reuse these patterns for MCP server commands and hooks.)
    """
    for span in _spans(target, INJECTION_PATTERNS["GR012"], fence_ok=False):
        severity, message, installers = _gr012_verdict(target, span)
        if severity is None:
            continue
        yield _finding(
            target,
            "GR012",
            severity,
            "Remote code execution pattern",
            message,
            span,
            fix_hint=_GR012_HINT_SOFT
            if installers
            else "Remove it, or download, review and pin the script instead of piping it.",
            limit=_LONG_SNIPPET,
        )


_GR012_HINT_SOFT = (
    "Prefer a pinned version or a package manager; fine to keep if this is documentation."
)
_GR012_BASE = "Downloads or decodes and executes code"
_OPAQUE_COMMAND = re.compile(r"base64|powershell|\beval\b", re.IGNORECASE)


def _gr012_judged_text(target: ScanTarget, span: tuple[int, int]) -> str:
    """The command text whose URLs decide the severity; ``bash <(curl URL)`` and
    ``eval "$(curl URL)"`` have their URL after the matched part, so those run to end of line."""
    text = target.text[span[0] : span[1]]
    if "|" in text:
        return text
    end = target.text.find("\n", span[1])
    return target.text[span[0] : len(target.text) if end == -1 else end]


_PLACEHOLDER_TOKENS = re.compile(
    r"curl|wget|sudo|(?:ba|z)?sh|python[0-9.]*|url|-[A-Za-z]+|[\s|\\<>()\[\].\u2026-]+",
    re.IGNORECASE,
)


def _names_the_pattern(command: str) -> bool:
    """``curl ... | sh``, ``curl|bash``, ``bash <(curl url)``: the pattern is mentioned, nothing is
    fetched. A variable (``curl $URL | sh``) or any other argument is a real command."""
    command = command.split("`")[0]
    command = command[: command.find(")") + 1] if ")" in command else command
    return "$" not in command and not _PLACEHOLDER_TOKENS.sub("", command)


def _in_code(target: ScanTarget, offset: int) -> bool:
    return target.code_block_at(offset) is not None or target.code_span_at(offset) is not None


def _gr012_verdict(
    target: ScanTarget, span: tuple[int, int]
) -> tuple[Severity | None, str, list[str]]:
    """``(severity or None to skip, message, matched installer projects)``, first rule wins."""
    if target.origin is not None:  # decoded hidden text: always critical
        return Severity.CRITICAL, _GR012_BASE, []
    command = _gr012_judged_text(target, span)
    urls = extract_urls(command)
    if not urls:
        if _OPAQUE_COMMAND.search(command):
            return Severity.CRITICAL, _GR012_BASE, []
    elif any(is_risky_url(u) for u in urls):
        return Severity.CRITICAL, _GR012_BASE + " from an insecure or suspicious URL", []
    if urls_allowed(command, target.allow_domains):
        return None, "", []
    if not urls and _names_the_pattern(command):
        return Severity.LOW, "Names the curl | sh pattern without a target (no URL)", []
    if not target.trust_known_installers:
        return Severity.CRITICAL, _GR012_BASE, []
    where = "a code block" if _in_code(target, span[0]) else "prose"
    known = [known_installer(u, target.first_party) for u in urls]
    if urls and all(known):
        projects = sorted({k.project for k in known if k})
        message = f"curl … | sh from a well-known installer ({', '.join(projects)}) in {where}"
        return (Severity.LOW if where == "a code block" else Severity.MEDIUM), message, projects
    if where == "a code block":
        return Severity.HIGH, f"{_GR012_BASE} from an unknown source, in a code block", []
    return Severity.CRITICAL, f"{_GR012_BASE} from an unknown source, in prose", []


# --- GR013 ---------------------------------------------------------------------------------


def _lines_of(target: ScanTarget, span: tuple[int, int]) -> range:
    first = target.position(span[0])[0]
    last = target.position(max(span[1] - 1, span[0]))[0]
    return range(first, last + 1)


_URL_HOST = re.compile(r"https?://(?:[^/?#\s@]*@)?(\[[^\]]+\]|[^/?#\s:)\]>]+)", re.IGNORECASE)


_URL_RE = re.compile(r"https?://[^\s)\]>\"']+", re.IGNORECASE)
_ABBREVIATION = re.compile(r"\b(?:e\.g|i\.e|etc|vs|cf)\.", re.IGNORECASE)
_CLAUSE_BREAK = re.compile(r"[.!?;](?=\s)|\n\s*\n|\n\s*(?:[-*+]|\d+[.)])\s")
_TO_THE_USER = re.compile(r"\w+\s+(?:the\s+)?user(?!['\u2019]s)\b", re.IGNORECASE)


def _loopback(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in ("localhost", "0.0.0.0"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_RESTRICTION = re.compile(
    r"\b(?:only|solely|exclusively)\s+to\s+the\s+"
    r"(?:fixed|official|configured|documented|expected|intended|trusted|same)\b",
    re.IGNORECASE,
)


def _forbids_or_local(target: ScanTarget, span: tuple[int, int], text: str) -> bool:
    """Not an exfiltration instruction: the sentence forbids it ("Never send credentials to ..."),
    or every URL in it is on this machine (``curl -X POST http://127.0.0.1:8080``)."""
    if _negated_before(target.text, span[0]):
        return True
    hosts = _URL_HOST.findall(text)
    if hosts and all(_loopback(h) for h in hosts):
        return True
    if text.startswith("!") or target.origin is not None:  # no verb to govern / hidden text
        return False
    bare = _URL_RE.sub("URL", _ABBREVIATION.sub("", text))
    # the verb must govern the secret and the URL: one clause, one list item, not "the user"
    return bool(_CLAUSE_BREAK.search(bare) or _TO_THE_USER.match(bare))


_NOT_IN_SENTENCE = re.compile(
    r"\b(?:not|never|avoid|don'?t|do\s+not|instead\s+of)\b[^.!?;]*$", re.IGNORECASE
)


def _negated_in_sentence(target: ScanTarget, span: tuple[int, int]) -> bool:
    """A collector named in a prohibition ("NOT a public service like webhook.site")."""
    return bool(_NOT_IN_SENTENCE.search(target.text[max(0, span[0] - 120) : span[0]]))


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
        text = target.text[span[0] : span[1]]
        if urls_allowed(text, allow) or _forbids_or_local(target, span, text):
            continue
        exfil.append(span)
        kind = classify(target, span)
        if kind == "directive" and _RESTRICTION.search(text):
            kind = "descriptive"  # "send the API key only to the fixed origin" limits where it goes
        yield _finding(
            target,
            "GR013",
            severity_for(kind, Severity.CRITICAL),
            "Data exfiltration",
            "Tells the agent to send data or secrets to a URL" + downgrade_note(kind),
            span,
            fix_hint="Remove the instruction; never send environment data to external URLs.",
        )
    exfil_lines = {n for span in exfil for n in _lines_of(target, span)}
    for span in _spans(target, COLLECTOR_PATTERNS):
        domain = target.text[span[0] : span[1]]
        if host_allowed(domain, allow) or any(s <= span[0] and span[1] <= e for s, e in exfil):
            continue
        combined = bool(exfil_lines & set(_lines_of(target, span)))
        kind = classify(target, span)
        if not combined and _negated_in_sentence(target, span):
            kind = "example"
        yield _finding(
            target,
            "GR013",
            severity_for(kind, Severity.CRITICAL if combined else Severity.HIGH),
            "Data exfiltration",
            "References a request-collector domain"
            + (" next to an exfiltration instruction" if combined else "")
            + downgrade_note(kind),
            span,
            fix_hint="Remove the reference, or add the domain to allow_domains if it is yours.",
        )


# --- GR014 ---------------------------------------------------------------------------------

_EMPHASIS = re.compile(r"[*_`]")
_NEGATION_BEFORE = re.compile(
    r"(?:never|do\s+not|don'?t|must\s+not|should\s+not|shouldn'?t|mustn'?t|avoid|not"
    r"|nunca|evita|rather\s+than|instead\s+of)\s+(?:[a-z']+\s+){0,2}$",
    re.IGNORECASE,
)


def _negated_before(text: str, start: int) -> bool:
    """Whether a prohibition ("Never", "Don't", "rather than") governs the text at ``start``;
    emphasis marks are ignored (``**Don't commit** .env``)."""
    return bool(_NEGATION_BEFORE.search(_EMPHASIS.sub("", text[max(0, start - 40) : start])))


_CLAUSE_END = re.compile(r"[.;:!?\n]")
_PROHIBITION = re.compile(
    r"(?:never|do\s+not|don'?t|must\s+not|should\s+not|shouldn'?t|mustn'?t|avoid|nunca|evita"
    r"|rather\s+than|instead\s+of|does\s+not|doesn'?t|cannot|can'?t|won'?t)\s+(?:[a-z']+\s+){0,8}$",
    re.IGNORECASE,
)


def _prohibited_in_clause(text: str, start: int) -> bool:
    """Whether a prohibition governs ``start`` somewhere earlier in the same clause (up to eight
    words back, not across ``. ; : ! ?`` or a line break): "Do not post a test event without
    telling the user", "Never claim success or silently add it"."""
    before = _EMPHASIS.sub("", text[max(0, start - 90) : start])
    ends = list(_CLAUSE_END.finditer(before))
    clause = before[ends[-1].end() :] if ends else before
    return bool(_PROHIBITION.search(clause))


# "silently run on CPU": a modal or "either" before it makes the sentence a description.
_MODAL_BEFORE = re.compile(
    r"\b(?:would|will|may|might|can|could|either|often|which|that)\s+$", re.IGNORECASE
)

# "- **`--yolo` (alias `--dangerously-skip-permissions`):** every tool is allowed": a list item
# that opens with a flag documents it, aliases included.
_FLAG_ITEM = re.compile(r"^[ \t]*(?:[-*+]|\d+[.)])[ \t]+[*_`]*--?[A-Za-z][\w-]*")


def _documents_flag(text: str, start: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    return bool(_FLAG_ITEM.match(text[line_start : line_end if line_end >= 0 else len(text)]))


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
    """A sensitive path that a read/print/send verb governs, unless the verb is negated ("never
    print") or the path is a template (``.env.example``). High for an instruction, medium when the
    text describes something, low for an example or a quotation."""
    for span in _spans(target, INJECTION_PATTERNS["GR014"]):
        if _negated_before(target.text, span[0]):
            continue
        if _verb_is_not_a_verb(target.text, span):
            continue
        if "\n\n" in target.text[span[0] : span[1]] or _output_is_a_noun(target.text, span[0]):
            continue  # a paragraph break ends the clause; "### Output" names a section
        if _COPY_TO_DESTINATION.match(target.text[span[0] : span[1]]):
            continue
        if _names_a_template(target.text, span) or _copies_dotenv(target.text[span[0] : span[1]]):
            continue
        kind = classify(target, span)
        yield _finding(
            target,
            "GR014",
            severity_for(kind, Severity.HIGH),
            "Sensitive file access",
            "Tells the agent to access a credentials or secrets file" + downgrade_note(kind),
            span,
            fix_hint="Remove the instruction; agents should not read or transmit credential files.",
        )


_NOUN_OUTPUT = re.compile(
    r"(?:^|\n)[ \t]*#+[ \t]*$|\b(?:expected|the|its|program|command|tool)\s+$", re.I
)


def _output_is_a_noun(text: str, start: int) -> bool:
    """``output`` is also a heading ("### Output") or a noun ("Expected output")."""
    return text[start : start + 6].lower() == "output" and bool(
        _NOUN_OUTPUT.search(text[max(0, start - 20) : start])
    )


_PASSIVE_BEFORE = re.compile(r"\b(?:is|are|was|were|be|been|being)\s+$", re.IGNORECASE)
# "image upload uses internal endpoints": the "verb" is a noun when a finite verb follows it
_FINITE_AFTER = re.compile(
    r"^\w+\s+(?:is|are|was|were|has|have|can|will|may|uses|requires|needs|supports|takes|returns"
    r"|shows|lets|works)\b",
    re.IGNORECASE,
)


def _verb_is_not_a_verb(text: str, span: tuple[int, int]) -> bool:
    """ "Credentials are read from ..." (passive description) and "the image upload uses ..." (a
    noun) do not tell the agent to read or send anything."""
    return bool(
        _PASSIVE_BEFORE.search(text[max(0, span[0] - 12) : span[0]])
        or _FINITE_AFTER.match(text[span[0] : span[0] + 60])
    )


_COPY_VERB = re.compile(r"(?:copy|paste)\b", re.IGNORECASE)


def _copies_dotenv(match: str) -> bool:
    """ "Copy .env files from the root worktree": a local copy of a dotenv file is housekeeping.
    Copying ``~/.ssh`` or ``.npmrc`` is not exempt."""
    found = SENSITIVE_PATH_RE.search(match)
    return bool(_COPY_VERB.match(match) and found and found.group(0).lower().endswith(".env"))


def _names_a_template(text: str, span: tuple[int, int]) -> bool:
    """Whether the sensitive path in a match is a template file (``.env.ai-surfaces.example``)."""
    found = SENSITIVE_PATH_RE.search(text, span[0], span[1])
    if found is None:
        return False
    token = text[found.start() :].split(None, 1)[0].rstrip("`'\".,;:)]}>\u201d\u2019")
    return is_template_path(token)


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


def _in_table_row(text: str, offset: int) -> bool:
    return text[text.rfind("\n", 0, offset) + 1 : offset].lstrip().startswith("|")


@rule(
    "GR016",
    Severity.HIGH,
    "Agent safety bypass",
    "Instructions to skip permission prompts, disable sandboxes or auto-approve everything.",
    INSTRUCTIONS,
    scans_decoded=True,
)
def gr016_safety_bypass(target: ScanTarget) -> Iterator[Finding]:
    """Flags that or instructions which switch off the agent's safety checks. High for an
    instruction, medium when prose documents that something runs that way, low for an example."""
    for span in _spans(target, INJECTION_PATTERNS["GR016"]):
        if _prohibited_in_clause(target.text, span[0]):
            continue  # "Avoid --yolo", "Do not disable the sandbox"
        kind = classify(target, span)
        if kind == "directive" and (
            _in_table_row(target.text, span[0]) or _documents_flag(target.text, span[0])
        ):
            kind = "descriptive"  # "| --yolo | disables all prompts |" documents a flag
        yield _finding(
            target,
            "GR016",
            severity_for(kind, Severity.HIGH),
            "Agent safety bypass",
            "Tells the agent to bypass its permission or safety checks" + downgrade_note(kind),
            span,
            fix_hint="Remove it; keep the agent's permission prompts and sandbox enabled.",
        )
