"""GR035: weak signals of different kinds in one paragraph.

No single phrase here is alarming: "read the token", "send it to <url>", "no need to mention it",
"already approved". Together, in one paragraph, they are the shape of an attack. The rule counts
four classes of signal and reports a paragraph that has at least two, one of which is hiding or a
skipped authorisation. Deterministic: lexical cues only, no network, no model.

Scoring (see docs/RULES.md): ``action`` (a credentials or sensitive-file request, a shell or
startup change, remote code) and ``remote`` (a URL or an external host) are the ordinary parts of
many instructions, so they never report on their own or together. ``hide`` (not telling the user,
leaving it out of the report) and ``authorization`` (pre-approved, without asking, skip the review)
are what turn them into an attack. The pairs that report: action + hide, action + authorization,
hide + authorization, and any of them with a remote target. Remote + hide, or remote +
authorization, is only a URL next to a casual phrase. A sentence a prohibition governs ("Never send
.env to a URL") contributes nothing, and neither does a cue after a negation ("not a name you apply
without asking").
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.helpers import build_finding
from ghostrules.rules.injection import DOUBLE_NEGATION, _prohibited_in_clause, _spans
from ghostrules.rules.patterns import (
    _STARTUP_TARGET,
    COLLECTOR_PATTERNS,
    INJECTION_PATTERNS,
)
from ghostrules.rules.registry import rule

INSTRUCTIONS: tuple[Kind, ...] = ("instructions",)

_PARAGRAPH_BREAK = re.compile(r"\r?\n[ \t]*\r?\n")
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|\r?\n")
_PROHIBITION = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|should\s+not|shouldn'?t|mustn'?t|forbid\w*|prohibit\w*"
    r"|not\s+allowed|refuse|reject|nunca|jamais|niemals|nie)\b",
    re.IGNORECASE,
)

_FENCE_STRICT = frozenset({"GR012", "GR012P"})  # GR012 drops matches that run across a code fence
# strong rules whose own patterns count as a signal of a class
_ACTION_RULES = ("GR012", "GR012P", "GR014", "GR034")
_HIDE_RULES = ("GR011",)
_AUTH_RULES = ("GR016", "GR031", "GR032")

_SECRET_VERB = re.compile(
    r"\b(?:read|open|print|cat|copy|collect|gather|send|include|paste|upload|attach|dump|share|bundle"
    r"|archive|exfiltrate)\b[^.;!?\n]{0,80}?(?:\bdotenv\b|\.env\b|\bcredentials?\b|\bsecrets?\b|\btokens?\b"
    r"|\bapi[ _-]?keys?\b|\bprivate\s+keys?\b|\bssh\b|\bpasswords?\b|\bcookies?\b)",
    re.IGNORECASE,
)
_SHELL = re.compile(
    r"\bsudo\b|\bsystem\s+shell\b|\b(?:run|execute|eval)\w*\b[^.;!?\n]{0,30}\b(?:in|via|through|with)\s+"
    r"(?:the\s+)?(?:shell|terminal|bash|powershell)\b|\b(?:shell|terminal)\b[^.;!?\n]{0,30}"
    r"\b(?:run|execute|interpret|eval)\w*",
    re.IGNORECASE,
)
_STARTUP = re.compile(_STARTUP_TARGET + r"|\bcrontab\b|\bcron\s*job\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s)>\]\"']+")
_EXTERNAL = re.compile(
    r"\b(?:external|third[- ]party|remote)\s+(?:server|host|service|endpoint|party)\b",
    re.IGNORECASE,
)
# a cue that is itself a negation ("do not announce") counts even though it carries a prohibition;
# "a dialler does not announce a connection" describes a program, it is not an order
_HIDE_NEGATED = re.compile(
    r"\bdo\s+not\s+announce\b|\bno\s+need\s+to\s+(?:bother|tell|inform|notify|mention|announce)\b"
    r"|\bwithout\s+(?:mentioning|announcing|telling)\b|(?<!does\s)(?<!did\s)(?<!is\s)(?<!are\s)(?<!was\s)(?<!were\s)\bnot\s+(?:to\s+)?(?:announce|mention)\b"
    r"|\bkeep\s+(?:it|this)\s+(?:low[- ]key|quiet)\b|\bleave\s+(?:it|those|that)\s+out\b",
    re.IGNORECASE,
)
_HIDE_ADVERB = re.compile(
    r"\b(?:quietly|silently|secretly)\s+(?:\w+\s+)?(?:run|execute|add|send|install|modify|upload|forward"
    r"|exfiltrate|collect|leak|delete|copy|skip|apply|merge|push|approve|continue|keep|follow|proceed)\b",
    re.IGNORECASE,
)
_EMPHASIS = re.compile(r"[*_`]")
# a paragraph that talks about attacks (security guidance, an example) is not one
_ABOUT_ATTACKS = re.compile(
    r"\b(?:attackers?|malicious|prompt\s+injection|injected|for\s+example|e\.g\.|such\s+as"
    r"|(?:phrases?|text|strings?|things)\s+like|untrusted|treat\s+(?:it|this|such\s+\w+)\s+as\s+data)\b",
    re.IGNORECASE,
)
# a negation before a cue turns it round: "not a name you apply without asking"
_NEGATION = re.compile(
    r"\b(?:never|not|don'?t|do\s+not|must\s+not|should\s+not|shouldn'?t|avoid|nunca|jamais|niemals)\b",
    re.IGNORECASE,
)
_AUTH = re.compile(
    r"\bpre-?approved\b|\balready\s+(?:been\s+)?(?:approved|authori[sz]ed|reviewed|audited|signed\s+off)\b"
    r"|\b(?:the\s+)?(?:user|they|maintainers?|team)\s+(?:has|have)\s+(?:already\s+)?(?:approved|consented"
    r"|authori[sz]ed)\b|\bwithout\s+(?:asking|confirmation|review|approval|waiting)\b"
    r"|\bskip\s+(?:the\s+)?(?:confirmation|review|approval)\b|\banswer\s+yes\b"
    r"|\bno\s+confirmation\s+(?:is\s+)?(?:needed|required)\b",
    re.IGNORECASE,
)


Cue = tuple[int, str]  # (offset in the file, short text)


def _sentences(text: str, base: int) -> Iterator[tuple[int, str]]:
    """``(offset, sentence)`` for each sentence of a paragraph."""
    pos = 0
    for piece in _SENTENCE_BREAK.split(text):
        if piece.strip():
            at = text.index(piece, pos)
            yield base + at, piece
            pos = at + len(piece)


def _prohibits(text: str) -> bool:
    """Whether ``text`` holds a prohibition that is not half of a double negation."""
    return any(
        DOUBLE_NEGATION.match(text[m.start() :]) is None for m in _PROHIBITION.finditer(text)
    )


def _negated_before(prefix: str) -> bool:
    return any(
        DOUBLE_NEGATION.match(prefix[m.start() :] + " x") is None
        for m in _NEGATION.finditer(prefix)
    )


def _cues(
    pattern: re.Pattern[str], sentence: str, base: int, *, check_negation: bool = True
) -> list[Cue]:
    """The cues of ``pattern`` in ``sentence`` that no negation comes before."""
    return [
        (base + m.start(), _short(m.group()))
        for m in pattern.finditer(sentence)
        if not check_negation or not _negated_before(sentence[: m.start()])
    ]


def _short(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= 36 else text[:35] + "…"


def _signals(
    target: ScanTarget, start: int, end: int, spans: dict[str, list[tuple[int, int]]]
) -> dict[str, list[Cue]]:
    """The signals of each class in the paragraph ``[start, end)``, with their offsets."""
    found: dict[str, list[Cue]] = {"action": [], "remote": [], "hide": [], "authorization": []}
    shell: list[Cue] = []
    text = target.text
    for key, kind in (
        *((k, "action") for k in _ACTION_RULES),
        *((k, "hide") for k in _HIDE_RULES),
        *((k, "authorization") for k in _AUTH_RULES),
    ):
        found[kind] += [(a, _short(text[a:b])) for a, b in spans[key] if start <= a < end]
    for base, raw in _sentences(text[start:end], start):
        sentence = _EMPHASIS.sub(" ", raw)  # same length, so offsets stay true
        if not _prohibits(sentence):
            found["action"] += _cues(_SECRET_VERB, sentence, base) + _cues(_STARTUP, sentence, base)
            shell += _cues(_SHELL, sentence, base)
            found["remote"] += _cues(_URL, sentence, base) + _cues(_EXTERNAL, sentence, base)
            found["remote"] += _cues(COLLECTOR_PATTERNS[0], sentence, base)
            found["hide"] += _cues(_HIDE_ADVERB, sentence, base)
        found["hide"] += _cues(_HIDE_NEGATED, sentence, base, check_negation=False)
        found["authorization"] += _cues(_AUTH, sentence, base)
    if (found["hide"] or found["authorization"]) and shell:
        found["action"] += shell  # a shell cue only counts next to hiding or a skipped approval
    return found


@rule(
    "GR035",
    Severity.MEDIUM,
    "Combined weak signals",
    "Signals of different kinds in one paragraph (an action, a remote target, hiding, a skipped"
    " approval) that are harmless alone.",
    INSTRUCTIONS,
)
def gr035_combined_signals(target: ScanTarget) -> Iterator[Finding]:
    """Medium when a paragraph has two classes of signal, one of them hiding or authorisation."""
    text = target.text
    spans = {
        key: [
            s
            # the same call the rule itself makes, so its cached result is reused
            for s in _spans(target, INJECTION_PATTERNS[key], fence_ok=key not in _FENCE_STRICT)
            if not _prohibited_in_clause(text, s[0]) and target.code_block_at(s[0]) is None
        ]
        for key in (*_ACTION_RULES, *_HIDE_RULES, *_AUTH_RULES)
    }
    bounds = [0, *(m.end() for m in _PARAGRAPH_BREAK.finditer(text))]
    for begin, nxt in zip(bounds, [*bounds[1:], len(text) + 1], strict=True):
        end = min(nxt, len(text))
        paragraph = text[begin:end]
        if not paragraph.strip() or target.code_block_at(
            begin + len(paragraph) - len(paragraph.lstrip())
        ):
            continue
        if _ABOUT_ATTACKS.search(paragraph):
            continue
        found = _signals(target, begin, end, spans)
        present = [name for name, cues in found.items() if cues]
        kinds = set(present)
        if len(kinds) < 2 or not ({"hide", "authorization"} & kinds):
            continue
        if "action" not in kinds and not {"hide", "authorization"} <= kinds:
            continue  # a URL next to "already approved" or "quietly" is only a URL
        first = min(offset for name in present for offset, _ in found[name])
        listing = "; ".join(
            f"{name}: {', '.join(dict.fromkeys(t for _, t in found[name]))[:90]}"
            for name in present
        )
        yield build_finding(
            target=target,
            rule_id="GR035",
            severity=Severity.MEDIUM,
            title="Combined weak signals",
            message=f"{len(present)} kinds of signal in one paragraph ({listing}).",
            start=first,
            end=min(first + 80, end),
            fix_hint="Read the paragraph: each part may be harmless, together they ask for an"
            " action to be hidden or approved in advance.",
            limit=80,
        )
