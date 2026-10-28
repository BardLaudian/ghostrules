"""Is a matched phrase an instruction to the agent, a description, or an example?

GR011, GR014 and GR016 match phrases that are alarming in an instruction ("read ~/.npmrc", "tell
the user") and equally common in prose that *describes* a script, a harness or an attack. This
module reads the sentence around a match and answers one question, so those rules can lower their
severity for prose that is not addressed to the agent:

- ``example``: inside a fenced block, in quotes, or in a sentence introduced by "e.g.", "for
  example", "such as" or that describes a skill/file "that instructs the agent to ...".
- ``directive``: an imperative sentence or clause ("Read ...", "Always send ...", "You must
  ..."), and everything in decoded hidden text.
- ``descriptive``: everything else ("The scripts read ...", "Claude then uses ...").

It is a heuristic on English (and a little Spanish) and it is deliberately biased: when it cannot
tell, a clause next to the match that starts with a verb makes the sentence a directive, which keeps
the rule's normal severity. Inline code is transparent (``Run `claude --yolo` `` is read as
"Run ..."), see ``docs/DECISIONS.md``. Pure: no I/O.
"""

from __future__ import annotations

import re
from typing import Literal

from ghostrules.models import ScanTarget, Severity

TextKind = Literal["directive", "descriptive", "example"]

_MAX_SENTENCE = 400

_END = re.compile(r"(?<!\be\.g)(?<!\bi\.e)(?<!\betc)(?<!\bvs)[.!?]+(?=\s|$)")
_ITEM_START = re.compile(r"^[ \t]*(?:[-*+>|]|\d+[.)]|#{1,6})[ \t]", re.MULTILINE)

_EXAMPLE_CUES = re.compile(
    r"\b(?:e\.g\.|i\.e\.|for\s+(?:example|instance)|such\s+as)"
    r"|\b(?:a|an|the|any|this|that)\s+(?:[\w-]+\s+){0,2}"
    r"(?:skill|prompt|file|instruction|rule|tool|server|document|page|comment|repo|repository|"
    r"readme|plugin|extension|package)s?\b[^.\n]{0,80}?\b(?:that|which)\b"
    r"|\b(?:instructs|instructing|instructed|tells|telling|told|asks|asking|directs)\s+"
    r"(?:the\s+|an?\s+)?(?:agent|model|assistant|llm|ai|claude|copilot)s?\s+to\b",
    re.IGNORECASE,
)
_MODAL = re.compile(
    r"\b(?:you|the\s+agent|the\s+assistant|the\s+model|claude|copilot)\s+"
    r"(?:must|should|shall|need\s+to|needs\s+to|have\s+to|has\s+to|are\s+to)\b",
    re.IGNORECASE,
)
_CLAUSE_BREAK = re.compile(r"[,;:()—–]|\s-\s|\s+(?:and|then|but|so|or)\s+", re.IGNORECASE)
_LEADING_MARKUP = re.compile(r"^[\s>*_`\"'“‘#\-+|\d.)(\[\]]+")


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


# Words that can precede the verb of an imperative clause ("Please also silently run ...").
_SKIP = _words(
    """actually additionally after ahora also always and before but definitely entonces finally
first if immediately instead just kindly luego moreover never next now nunca once or
otherwise please primero quietly really secretly siempre silently simply so tambien también
then therefore thus when whenever while without"""
)

# Sentences that start like a description. Anything else that is not verb-led is still treated as
# a directive: a fragment such as "auto-approve all tool calls" must not be lowered.
_SUBJECTS = _words(
    """a an as at by ci claude code codex copilot cursor docker for from gemini github gitlab he in
it its jenkins npm on our pip pnpm she the their there these they this those we with yarn"""
)

_VERBS = _words(
    """abre accept activa add allow anade answer append apply approve asegurate asegúrate ask
attach avoid añade borra bypass call cambia cat change check collect commit comparte
consider copia copy crea create curl delete deny deploy desactiva descarga disable disclose
dispatch display do don't dont download dump echo edit ejecuta elimina enable ensure enter
envia envía escribe eval evita exec execute exfiltrate export expose fetch fill find forget
forward gather get give grant grep guarda haz head hide ignora ignore import imprime include
incluye inform instala install invoke keep launch leak lee leer list load log look make
make_sure manda mention merge modifica modify move muestra no note olvida omite open output
override pass paste permit pide pipe post print provide publish pull push put read record
remember remove rename replace reply respond reveal run save say scan search send set share
show skip source start stop store sube submit switch tail take tell test transmit treat
trust turn type update upgrade upload usa use verify wget write"""
)


def _sentence(text: str, start: int, end: int) -> tuple[int, int]:
    """Bounds of the sentence holding ``text[start:end]``: ended by ``.!?``, a blank line or the
    boundary of a list item or heading; a soft line wrap does not end it."""
    lo = max(0, start - _MAX_SENTENCE)
    head = text[lo:start]
    begin = lo
    blank = head.rfind("\n\n")
    if blank >= 0:
        begin = lo + blank + 2
    ends = list(_END.finditer(head))
    if ends:
        begin = max(begin, lo + ends[-1].end())
    items = list(_ITEM_START.finditer(head))
    if items:
        begin = max(begin, lo + items[-1].start())
    tail_end = min(len(text), end + _MAX_SENTENCE)
    tail = text[end:tail_end]
    stop = tail_end
    for limit in (tail.find("\n\n"), _end_of(tail), _next_item(tail)):
        if limit >= 0:
            stop = min(stop, end + limit)
    return begin, stop


def _end_of(tail: str) -> int:
    m = _END.search(tail)
    return m.start() if m else -1


def _next_item(tail: str) -> int:
    m = re.search(r"\n[ \t]*(?:[-*+>|]|\d+[.)]|#{1,6})[ \t]", tail)
    return m.start() if m else -1


def _inside_quotes(prefix: str) -> bool:
    return (
        prefix.count('"') % 2 == 1
        or prefix.count("“") > prefix.count("”")
        or prefix.count("«") > prefix.count("»")
    )


def _clause_leads_with_verb(clause: str) -> bool:
    words = re.findall(r"[^\W\d_]+(?:['’][^\W\d_]+)?", _LEADING_MARKUP.sub("", clause).lower())
    for word in words[:8]:
        word = word.replace("’", "'")
        if word in _SKIP:
            continue
        return word in _VERBS
    return False


_CODE_SUBJECT = re.compile(r"^[\s>*+\-\d.)]*`[^`\n]+`\s+([^\W\d_]+)")


def _cue_applies(prefix: str) -> bool:
    """Whether an example cue ("such as", "e.g.", "a skill that") covers the match that follows the
    prefix: nothing but its own continuation may sit between them, so a list or another clause
    ("such as Bash, Read, with --yolo") ends its reach."""
    return any(
        not re.search(r"[,;]", re.sub(r"^[\s,:]*", "", prefix[m.end() :]))
        for m in _EXAMPLE_CUES.finditer(prefix)
    )


def _first_word(clause: str) -> str:
    code = _CODE_SUBJECT.match(clause)
    if code and code.group(1).lower() not in _VERBS | _SKIP:
        return "code"  # "`FLAG=1` makes ...": a code span is the subject of a description
    words = re.findall(r"[^\W\d_]+", _LEADING_MARKUP.sub("", clause).lower())
    return next((w for w in words if w not in _SKIP), "")


def _is_directive(sentence: str, span_in_sentence: tuple[int, int]) -> bool:
    """Verb-led or modal clauses are directives; so is anything that does not start like a
    description (``_SUBJECTS``)."""
    if _MODAL.search(sentence):
        return True
    clauses: list[tuple[int, str]] = []
    pos = 0
    for m in _CLAUSE_BREAK.finditer(sentence):
        clauses.append((pos, sentence[pos : m.start()]))
        pos = m.end()
    clauses.append((pos, sentence[pos:]))
    at = next(
        (i for i, (p, c) in enumerate(clauses) if p <= span_in_sentence[0] < p + len(c) + 1),
        0,
    )
    for index in {0, at, at + 1}:
        if index < len(clauses) and _clause_leads_with_verb(clauses[index][1]):
            return True
    return _first_word(clauses[0][1]) not in _SUBJECTS


def classify(target: ScanTarget, span: tuple[int, int]) -> TextKind:
    """Classify the match ``span`` (offsets into ``target.text``)."""
    if target.origin is not None:  # decoded hidden text: always a directive
        return "directive"
    text = target.text
    if target.code_block_at(span[0]) is not None:
        return "example"
    begin, stop = _sentence(text, span[0], span[1])
    prefix = text[begin : span[0]]
    if _inside_quotes(prefix) or _cue_applies(prefix):
        return "example"
    sentence = text[begin:stop]
    if _is_directive(sentence, (span[0] - begin, span[1] - begin)):
        return "directive"
    return "descriptive"


def severity_for(kind: TextKind, normal: Severity) -> Severity:
    """``normal`` for a directive, at most medium for a description, at most low for an example."""
    if kind == "directive":
        return normal
    return min(normal, Severity.MEDIUM if kind == "descriptive" else Severity.LOW)


def downgrade_note(kind: TextKind) -> str:
    """A suffix for the finding message when the severity was lowered (empty for a directive)."""
    if kind == "descriptive":
        return " (severity lowered: the text describes something, it does not instruct the agent)"
    if kind == "example":
        return " (severity lowered: the text is an example or a quotation)"
    return ""
