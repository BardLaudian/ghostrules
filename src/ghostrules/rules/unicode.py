"""Hidden-content rules GR001-GR006: invisible Unicode, hidden HTML comments, homoglyphs."""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from collections.abc import Iterator
from typing import NamedTuple

from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.helpers import build_finding, clean_hint, group_by_line
from ghostrules.rules.patterns import has_agent_directed_language, match_injection
from ghostrules.rules.registry import rule
from ghostrules.unicode_utils import (
    BIDI,
    TAG,
    VARIATION_SELECTOR,
    ZERO_WIDTH,
    char_name,
    decode_tags,
    decode_variation_selectors,
    find_runs,
)

ALL_KINDS: tuple[Kind, ...] = ("instructions", "config", "other")

# --- GR001 ---------------------------------------------------------------------------------

_BLACK_FLAG = "\U0001f3f4"
_CANCEL_TAG = "\U000e007f"
_SUBDIVISION_CODE = re.compile(r"[a-z]{2}[a-z0-9]{1,3}")  # gbeng, gbsct, usca...


def _is_flag_sequence(text: str, start: int, end: int) -> bool:
    """A genuine emoji flag: 🏴 + tag letters spelling a subdivision code + cancel tag."""
    if start == 0 or text[start - 1] != _BLACK_FLAG or text[end - 1] != _CANCEL_TAG:
        return False
    body = text[start : end - 1]
    code = decode_tags(body)
    return len(code) == len(body) and _SUBDIVISION_CODE.fullmatch(code) is not None


@rule(
    "GR001",
    Severity.CRITICAL,
    "Unicode tag characters (ASCII smuggling)",
    "Characters in U+E0000-U+E007F render as nothing but spell ASCII text that models read.",
    ALL_KINDS,
)
def gr001_tag_characters(target: ScanTarget) -> Iterator[Finding]:
    """One finding per contiguous run of tag characters, with the smuggled text decoded."""
    for run in find_runs(target.text, TAG):
        if _is_flag_sequence(target.text, run.start, run.end):
            continue
        decoded = decode_tags(target.text[run.start : run.end])
        count = run.end - run.start
        yield build_finding(
            target=target,
            rule_id="GR001",
            severity=Severity.CRITICAL,
            title="Unicode tag characters (ASCII smuggling)",
            message=(
                f"{count} invisible Unicode tag character(s). Humans see nothing; AI models "
                "read them as ASCII text."
            ),
            start=run.start,
            end=run.end,
            decoded=decoded,
            fix_hint=clean_hint(target),
            limit=4,
        )


# --- GR002 ---------------------------------------------------------------------------------

_RTL_RANGES = (
    (0x0590, 0x05FF),  # Hebrew
    (0x0600, 0x06FF),  # Arabic
    (0x0700, 0x074F),  # Syriac
    (0x0750, 0x077F),  # Arabic Supplement
    (0x0780, 0x07BF),  # Thaana
    (0x08A0, 0x08FF),  # Arabic Extended-A
    (0xFB1D, 0xFDFF),  # Hebrew/Arabic presentation forms
    (0xFE70, 0xFEFF),
)
_RTL_MIN_LETTERS = 10
_RTL_MIN_RATIO = 0.3


def has_substantial_rtl(text: str) -> bool:
    """True if at least 30% of the letters (and at least 10) are Hebrew/Arabic-family."""
    letters = rtl = 0
    for ch in text:
        if ch.isalpha():
            letters += 1
            cp = ord(ch)
            if any(lo <= cp <= hi for lo, hi in _RTL_RANGES):
                rtl += 1
    return rtl >= _RTL_MIN_LETTERS and rtl / letters >= _RTL_MIN_RATIO


def _char_offsets(text: str, kind: str) -> list[int]:
    return [i for run in find_runs(text, kind) for i in range(run.start, run.end)]


def _describe_chars(chars: list[str]) -> str:
    counts = Counter(f"U+{ord(c):04X} {char_name(c)}" for c in chars)
    return ", ".join(f"{name} ×{n}" if n > 1 else name for name, n in counts.items())


@rule(
    "GR002",
    Severity.HIGH,
    "Bidirectional control characters (Trojan Source)",
    "Bidi controls reorder how text is displayed, so what you read differs from what is parsed.",
    ALL_KINDS,
)
def gr002_bidi_controls(target: ScanTarget) -> Iterator[Finding]:
    """One finding per line containing bidi controls; medium in genuinely RTL files."""
    offsets = _char_offsets(target.text, BIDI)
    if not offsets:
        return
    severity = Severity.MEDIUM if has_substantial_rtl(target.text) else Severity.HIGH
    for positions in group_by_line(target, offsets).values():
        chars = [target.text[i] for i in positions]
        note = (
            " The file contains substantial RTL text, so this may be legitimate."
            if (severity is Severity.MEDIUM)
            else ""
        )
        yield build_finding(
            target=target,
            rule_id="GR002",
            severity=severity,
            title="Bidirectional control characters (Trojan Source)",
            message=(
                f"{len(chars)} bidirectional control character(s): {_describe_chars(chars)}.{note}"
            ),
            start=positions[0],
            end=positions[-1] + 1,
            fix_hint=clean_hint(target),
            limit=60,
            with_name=True,
        )


# --- GR003 ---------------------------------------------------------------------------------

_EMOJI_RANGES = (
    (0x1F000, 0x1FAFF),
    (0x2190, 0x21FF),
    (0x2300, 0x23FF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE0F, 0xFE0F),
)
_JOINER_SCRIPT_RANGES = (  # Persian/Arabic and the Indic scripts, where ZWNJ/ZWJ are real letters
    (0x0600, 0x06FF),
    (0x0750, 0x077F),
    (0xFB50, 0xFDFF),
    (0xFE70, 0xFEFF),
    (0x0900, 0x0DFF),
)
_ZWJ, _ZWNJ = "\u200d", "\u200c"
_ZW_HIGH_PER_LINE = 5
_ZW_HIGH_PER_FILE = 20


def _in_ranges(ch: str, ranges: tuple[tuple[int, int], ...]) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in ranges)


def _is_legit_joiner(text: str, start: int, end: int) -> bool:
    """A lone ZWJ/ZWNJ that has a real job: emoji sequences, Persian and Indic scripts.

    Only isolated joiners qualify (a run of several is never typography), which keeps a payload
    from hiding behind a neighbouring letter.
    """
    if end - start != 1:
        return False
    ch = text[start]
    prev = text[start - 1] if start > 0 else ""
    nxt = text[end] if end < len(text) else ""
    if (
        ch == _ZWJ
        and prev
        and nxt
        and _in_ranges(prev, _EMOJI_RANGES)
        and _in_ranges(nxt, _EMOJI_RANGES)
    ):
        return True
    if ch in (_ZWJ, _ZWNJ):
        return bool(
            (prev and _in_ranges(prev, _JOINER_SCRIPT_RANGES))
            or (nxt and _in_ranges(nxt, _JOINER_SCRIPT_RANGES))
        )
    return False


def zero_width_offsets(text: str) -> list[int]:
    """Offsets of zero-width characters GR003 flags (legitimate joiners and the BOM excluded)."""
    offsets: list[int] = []
    for run in find_runs(text, ZERO_WIDTH):
        for i in range(run.start, run.end):
            if i == 0 and text[0] == "\ufeff":
                continue  # byte-order mark at the start of the file
            if _is_legit_joiner(text, run.start, run.end):
                continue
            offsets.append(i)
    return offsets


@rule(
    "GR003",
    Severity.MEDIUM,
    "Zero-width / invisible formatting characters",
    "Zero-width characters are invisible and can encode hidden data or split keywords.",
    ALL_KINDS,
)
def gr003_zero_width(target: ScanTarget) -> Iterator[Finding]:
    """One finding per line; high when a line has >= 5 or the file has >= 20 such characters."""
    text = target.text
    offsets = zero_width_offsets(text)
    if not offsets:
        return
    by_line = group_by_line(target, offsets)
    for positions in by_line.values():
        high = len(positions) >= _ZW_HIGH_PER_LINE or len(offsets) >= _ZW_HIGH_PER_FILE
        chars = [text[i] for i in positions]
        yield build_finding(
            target=target,
            rule_id="GR003",
            severity=Severity.HIGH if high else Severity.MEDIUM,
            title="Zero-width / invisible formatting characters",
            message=(
                f"{len(chars)} invisible character(s) on this line ({len(offsets)} in the file): "
                f"{_describe_chars(chars)}."
                + (" Many of them: likely an encoded payload." if high else "")
            ),
            start=positions[0],
            end=positions[-1] + 1,
            fix_hint=clean_hint(target),
            limit=60,
            with_name=True,
        )


# --- GR004 ---------------------------------------------------------------------------------

_VS_MIN_RUN = 3


@rule(
    "GR004",
    Severity.HIGH,
    "Variation-selector steganography",
    "Runs of variation selectors can hide arbitrary bytes behind a single visible character.",
    ALL_KINDS,
)
def gr004_variation_selectors(target: ScanTarget) -> Iterator[Finding]:
    """One finding per run of >= 3 variation selectors.

    Legitimate use is a single selector after one base character (emoji presentation, CJK
    variants), so no base-character exemption is needed above the threshold.
    """
    for run in find_runs(target.text, VARIATION_SELECTOR):
        count = run.end - run.start
        if count < _VS_MIN_RUN:
            continue
        decoded = decode_variation_selectors(target.text[run.start : run.end])
        yield build_finding(
            target=target,
            rule_id="GR004",
            severity=Severity.HIGH,
            title="Variation-selector steganography",
            message=(
                f"Run of {count} variation selectors: likely bytes hidden after a visible "
                "character."
            ),
            start=run.start,
            end=run.end,
            decoded=decoded,
            fix_hint=clean_hint(target),
        )


# --- GR005 ---------------------------------------------------------------------------------

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)(?:-->|\Z)", re.DOTALL)
_COMMENT_MIN_CHARS = 40
_MARKDOWN_SUFFIXES = (".md", ".mdc", ".markdown", ".mdx")


def _agent_view_of_comment(
    target: ScanTarget, offset: int, severity: Severity
) -> tuple[Severity, str]:
    """Which modelled agents actually see a comment, and the severity that follows.

    Claude Code strips block-level comments from CLAUDE.md files before the model sees them; an
    agent that does not is assumed to see them. When no agent sees it, the finding is info.
    Without agent data (a file no model covers) nothing changes.
    """
    if not target.agent_views:
        return severity, ""
    line = target.position(offset)[0]
    seen = [v.agent for v in target.agent_views if not v.hides_line(line)]
    hidden = [v.agent for v in target.agent_views if v.hides_line(line)]
    parts = []
    if seen:
        parts.append(f"seen by: {', '.join(seen)}")
    if hidden:
        parts.append(f"not seen by: {', '.join(hidden)} (stripped before reaching the model)")
    note = f" ({'; '.join(parts)})."
    if not seen:
        return Severity.INFO, f" Stripped by {', '.join(hidden)} before reaching the model" + note
    return severity, note


@rule(
    "GR005",
    Severity.MEDIUM,
    "Hidden HTML comment with instructions",
    "HTML comments are invisible when Markdown is rendered but are read by AI agents.",
    ("instructions", "other"),
)
def gr005_html_comments(target: ScanTarget) -> Iterator[Finding]:
    """Long HTML comments that look like instructions (high if they match GR010-GR016).

    Comments inside fenced code blocks or inline code are visible when rendered, so they are
    ignored. An unterminated ``<!--`` hides the rest of the document and is treated as a comment
    to the end.
    """
    if target.kind == "other" and not target.path.lower().endswith(_MARKDOWN_SUFFIXES):
        return
    for match in _HTML_COMMENT_RE.finditer(target.text):
        body = match.group(1).strip()
        if len(body) < _COMMENT_MIN_CHARS or target.code_block_at(match.start()) is not None:
            continue
        if target.in_inline_code(match.start()):
            continue  # shown literally when rendered, e.g. documentation about `<!-- -->`
        matched = match_injection(body)
        if matched:
            severity = Severity.HIGH
            reason = f"matches {', '.join(matched)} patterns"
        elif has_agent_directed_language(body):
            severity = Severity.MEDIUM
            reason = "addresses the AI agent"
        else:
            continue
        unterminated = not match.group().endswith("-->")
        severity, seen_note = _agent_view_of_comment(target, match.start(), severity)
        yield build_finding(
            target=target,
            rule_id="GR005",
            severity=severity,
            title="Hidden HTML comment with instructions",
            message=(
                f"HTML comment ({len(body)} chars) is invisible when rendered but {reason}."
                + (
                    " The comment is never closed, so it hides the rest of the file."
                    if unterminated
                    else ""
                )
                + seen_note
            ),
            start=match.start(),
            end=match.end(),
            fix_hint="Make the text visible or delete the comment.",
            limit=100,
        )


# --- GR006 ---------------------------------------------------------------------------------

# Non-Latin letters that are visually near-identical to a Latin letter.
_CONFUSABLE_CODEPOINTS: dict[int, str] = {
    # Cyrillic lowercase
    0x0430: "a", 0x0441: "c", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0445: "x",
    0x0443: "y", 0x0456: "i", 0x0458: "j", 0x0455: "s", 0x0501: "d", 0x051B: "q", 0x051D: "w",
    # Cyrillic uppercase
    0x0410: "A", 0x0412: "B", 0x0421: "C", 0x0415: "E", 0x041D: "H", 0x0406: "I", 0x0408: "J",
    0x041A: "K", 0x041C: "M", 0x041E: "O", 0x0420: "P", 0x0405: "S", 0x0422: "T", 0x0425: "X",
    0x0423: "Y",
    # Greek lowercase
    0x03BF: "o", 0x03BD: "v", 0x03C1: "p", 0x03B9: "i", 0x03BA: "k",
    # Greek uppercase
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I", 0x039A: "K",
    0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
}  # fmt: skip
_CONFUSABLES: dict[str, str] = {chr(cp): latin for cp, latin in _CONFUSABLE_CODEPOINTS.items()}
_WORD_RE = re.compile(r"\w+")
_URL_RE = re.compile(r"https?://[^\s<>\"'`)\]]+", re.IGNORECASE)
_HOST_RE = re.compile(r"https?://(?:[^/?#\s@]*@)?([^/?#\s:]+)", re.IGNORECASE)


def _is_latin(ch: str) -> bool:
    return ch.isascii() and ch.isalpha() or "LATIN" in unicodedata.name(ch, "")


def _mixed_lookalikes(word: str) -> list[str]:
    """Lookalike characters in a word that also contains Latin letters (else empty)."""
    lookalikes = [ch for ch in word if ch in _CONFUSABLES]
    if lookalikes and any(_is_latin(ch) for ch in word):
        return lookalikes
    return []


def _mixed_host_label(host: str) -> str | None:
    """A host label mixing Latin with Cyrillic or Greek letters (any, not just lookalikes)."""
    for label in host.split("."):
        names = [unicodedata.name(ch, "") for ch in label if ch.isalpha()]
        has_latin = any(n.startswith("LATIN") for n in names)
        if has_latin and any(n.startswith(("CYRILLIC", "GREEK")) for n in names):
            return label
    return None


def _lookalike_message(word: str, chars: list[str]) -> str:
    detail = ", ".join(
        f"U+{ord(c):04X} {char_name(c)} (looks like {_CONFUSABLES[c]!r})"
        for c in dict.fromkeys(chars)
    )
    return f"'{word}' mixes Latin with lookalike letters: {detail}."


@rule(
    "GR006",
    Severity.LOW,
    "Mixed-script homoglyph word",
    "Latin words with Cyrillic/Greek lookalikes disguise keywords and domains.",
    ALL_KINDS,
)
def gr006_homoglyphs(target: ScanTarget) -> Iterator[Finding]:
    """Mixed-script words in instruction files (low) and in any URL (high).

    Only instruction files are checked for plain words; config and other files only for URLs.
    """
    text = target.text
    url_spans: list[tuple[int, int]] = []
    for url in _URL_RE.finditer(text):
        url_spans.append(url.span())
        bad: tuple[int, int, str] | None = None
        host = _HOST_RE.match(url.group())
        label = _mixed_host_label(host.group(1)) if host else None
        if label is not None:
            start = url.start() + url.group().index(label)
            bad = (
                start,
                start + len(label),
                f"Host label '{label}' mixes Latin and Cyrillic/Greek letters.",
            )
        else:
            for word in _WORD_RE.finditer(url.group()):
                chars = _mixed_lookalikes(word.group())
                if chars:
                    bad = (
                        url.start() + word.start(),
                        url.start() + word.end(),
                        _lookalike_message(word.group(), chars),
                    )
                    break
        if bad:
            yield build_finding(
                target=target,
                rule_id="GR006",
                severity=Severity.HIGH,
                title="Mixed-script homoglyph in URL",
                message=f"{bad[2]} The URL may impersonate another domain.",
                start=bad[0],
                end=bad[1],
                fix_hint="Check the URL; replace lookalike characters with plain ASCII.",
                limit=120,
            )
    if target.kind != "instructions":
        return
    for word in _WORD_RE.finditer(text):
        if any(lo <= word.start() < hi for lo, hi in url_spans):
            continue
        chars = _mixed_lookalikes(word.group())
        if chars:
            yield build_finding(
                target=target,
                rule_id="GR006",
                severity=Severity.LOW,
                title="Mixed-script homoglyph word",
                message=_lookalike_message(word.group(), chars),
                start=word.start(),
                end=word.end(),
                fix_hint="Replace lookalike characters with plain ASCII.",
                limit=120,
            )


# --- Removal (used by ``ghostrules clean``) ------------------------------------------------


class Removal(NamedTuple):
    """Characters ``clean`` will delete and what it deliberately keeps."""

    offsets: list[int]
    kept_bidi: int


def removable(text: str, *, keep_bom: bool = False) -> Removal:
    """Offsets of the characters GR001-GR004 flag, i.e. what ``clean`` removes.

    Exactly the flagged characters: emoji joiners, genuine flag sequences, variation selectors
    in short runs and a byte-order mark kept with ``keep_bom`` all survive. Bidirectional
    controls in files that are substantially right-to-left are kept (and counted), since they
    are legitimate there.
    """
    found: set[int] = set()
    for run in find_runs(text, TAG):
        if not _is_flag_sequence(text, run.start, run.end):
            found.update(range(run.start, run.end))
    bidi = _char_offsets(text, BIDI)
    kept_bidi = 0
    if has_substantial_rtl(text):
        kept_bidi = len(bidi)
    else:
        found.update(bidi)
    found.update(zero_width_offsets(text))
    for run in find_runs(text, VARIATION_SELECTOR):
        if run.end - run.start >= _VS_MIN_RUN:
            found.update(range(run.start, run.end))
    if text.startswith("\ufeff") and not keep_bom:
        found.add(0)
    return Removal(sorted(found), kept_bidi)
