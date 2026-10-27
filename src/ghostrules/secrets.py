"""Secret detection and masking. Every piece of output goes through this module.

Masking rule: a secret of at least 20 characters is shown as its first 4 and last 4 characters
around ``****…`` (``ghp_****…a1b2``); shorter ones as ``****``. ``mask_secrets`` finds secrets in
arbitrary text (known token formats, bearer tokens, URL passwords, and ``key=value`` pairs whose
key name looks secret and whose value looks like one). It is idempotent. ``Finding`` applies it to
all of its text fields, so no reporter can print an unmasked secret.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from typing import NamedTuple

_MASK_MIN_LENGTH = 20
_MIN_GENERIC_LENGTH = 16
_MIN_GENERIC_ENTROPY = 3.5

# (label, pattern). The named group ``s`` is the secret part; no group means the whole match.
_KNOWN_SOURCES: tuple[tuple[str, str], ...] = (
    ("GitHub token", r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}"),
    ("GitHub fine-grained token", r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,255}"),
    ("Anthropic API key", r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI API key", r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    ("AWS access key", r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("Slack token", r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("Google API key", r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}"),
    ("GitLab token", r"(?<![A-Za-z0-9])glpat-[0-9A-Za-z_-]{20,}"),
    ("Hugging Face token", r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}"),
    ("npm token", r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36,}"),
    (
        "Slack webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/(?P<s>[A-Za-z0-9*…]+)",
    ),
    (
        "Discord webhook",
        r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/"
        r"(?P<s>[A-Za-z0-9_*…-]+)",
    ),
    ("Bearer token", r"Bearer\s+(?P<s>[A-Za-z0-9._~+/-]{20,}={0,2})"),
)
_BOUNDARY = r"(?<![A-Za-z0-9])"
KNOWN_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern)) for label, pattern in _KNOWN_SOURCES
)
# For masking, secrets glued to other letters ("xghp_...") must still be hidden, so the
# word-boundary guard used for *detection* is dropped. The ambiguous OpenAI prefix ("sk-" also ends
# words like "task-") then needs a digit and some entropy to count.
_MASK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern.replace(_BOUNDARY, ""))) for label, pattern in _KNOWN_SOURCES
)

_NAME_WORDS = r"(?:token|secret|key|password|passwd|auth)"
_SECRET_NAME_RE = re.compile(_NAME_WORDS, re.IGNORECASE)
_VALUE_CHARS = r"[^\s\"'`,;&)}\]]"
_KEY_VALUE_RES = (
    # key = value / "key": "value" / key: value
    re.compile(
        rf"(?<![\w.-])(?P<k>[\"']?[\w.-]*{_NAME_WORDS}[\w.-]*[\"']?\s*[:=]\s*[\"']?)"
        rf"(?P<s>{_VALUE_CHARS}{{16,}})",
        re.IGNORECASE,
    ),
    # --api-token VALUE
    re.compile(
        rf"(?<![\w.-])(?P<k>--[\w-]*{_NAME_WORDS}[\w-]*\s+[\"']?)(?P<s>{_VALUE_CHARS}{{16,}})",
        re.IGNORECASE,
    ),
)
_URL_PASSWORD_RE = re.compile(r"://[^/\s:@]+:(?P<s>[^@\s/]{3,})@")
_PLACEHOLDER_WORDS_RE = re.compile(
    r"(?:your|my)[-_ ].*(?:here|key|token|secret|password)"
    r"|x{4,}|\*{4,}|\.{3,}|changeme|placeholder|redacted|example-?token|todo",
    re.IGNORECASE,
)


class Replacement(NamedTuple):
    """Replace ``text[start:end]`` by ``text``."""

    start: int
    end: int
    text: str


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def mask_value(value: str) -> str:
    """Mask one secret: ``ghp_****…a1b2`` for long values, ``****`` for short ones."""
    if len(value) < _MASK_MIN_LENGTH:
        return "****"
    return f"{value[:4]}****…{value[-4:]}"


def is_placeholder(value: str) -> bool:
    """True for variable references (``${VAR}``, ``<token>``) and dummy values."""
    s = value.strip()
    return (
        not s
        or "${" in s
        or "{{" in s
        or s.startswith(("$", "<"))
        or (s.startswith("%") and s.endswith("%"))
        or len(set(s)) == 1
        or "****" in s
        or _PLACEHOLDER_WORDS_RE.fullmatch(s) is not None
    )


def is_secret_key_name(name: str) -> bool:
    """Whether a key/flag/variable name suggests it holds a secret."""
    return _SECRET_NAME_RE.search(name) is not None


def looks_like_secret_value(value: str) -> bool:
    """Heuristic for a generic secret: long, high-entropy, no spaces, not a placeholder/URL/path."""
    if (
        len(value) < _MIN_GENERIC_LENGTH
        or any(c.isspace() for c in value)
        or is_placeholder(value)
        or value.startswith(("/", "~", "./", "../"))
        or re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", value)
        or re.match(r"[A-Za-z]:[\\/]", value)
    ):
        return False
    return shannon_entropy(value) >= _MIN_GENERIC_ENTROPY


def known_secret(text: str) -> tuple[str, str] | None:
    """The first known-format secret in ``text`` as ``(label, secret)``, or ``None``."""
    for label, pattern in KNOWN_SECRET_PATTERNS:
        group = "s" if "s" in pattern.groupindex else 0
        for m in pattern.finditer(text):
            if not is_placeholder(m.group(group)):
                return label, m.group(group)
    return None


def _plausible_glued_key(value: str) -> bool:
    return any(c.isdigit() for c in value) and shannon_entropy(value) >= _MIN_GENERIC_ENTROPY


def _candidates(text: str, extra: Iterable[str]) -> list[Replacement]:
    found: list[Replacement] = []
    for label, pattern in _MASK_PATTERNS:
        for m in pattern.finditer(text):
            group = "s" if "s" in pattern.groupindex else 0
            value = m.group(group)
            if is_placeholder(value):
                continue
            glued = m.start(group) > 0 and text[m.start(group) - 1].isalnum()
            if label == "OpenAI API key" and glued and not _plausible_glued_key(value):
                continue
            found.append(Replacement(m.start(group), m.end(group), mask_value(value)))
    for m in _URL_PASSWORD_RE.finditer(text):
        found.append(Replacement(m.start("s"), m.end("s"), "****"))
    for pattern in _KEY_VALUE_RES:
        for m in pattern.finditer(text):
            if looks_like_secret_value(m.group("s")):
                found.append(Replacement(m.start("s"), m.end("s"), mask_value(m.group("s"))))
    for secret in extra:
        if secret:
            for m in re.finditer(re.escape(secret), text):
                found.append(Replacement(m.start(), m.end(), mask_value(secret)))
    return found


def mask_spans(text: str, extra: Iterable[str] = ()) -> list[Replacement]:
    """Non-overlapping replacements masking every secret in ``text``.

    ``extra`` lists exact secret values the caller already knows (for example a generic secret
    found by a rule) that must be masked wherever they occur.
    """
    kept: list[Replacement] = []
    for rep in sorted(_candidates(text, tuple(extra)), key=lambda r: (r.start, -r.end)):
        if not kept or rep.start >= kept[-1].end:
            kept.append(rep)
    return kept


def apply_spans(text: str, spans: Iterable[Replacement]) -> str:
    """Apply replacements produced by ``mask_spans``."""
    out: list[str] = []
    pos = 0
    for rep in spans:
        out.append(text[pos : rep.start])
        out.append(rep.text)
        pos = rep.end
    out.append(text[pos:])
    return "".join(out)


def map_offset(spans: Iterable[Replacement], offset: int, *, end: bool = False) -> int:
    """Translate an offset in the original text to the masked text.

    An offset inside a replaced secret snaps to the start of its replacement (or to its end when
    ``end`` is true), so a span covering a secret still covers its mask.
    """
    shift = 0
    for rep in spans:
        if offset <= rep.start:
            break
        if offset < rep.end:
            return rep.start + shift + (len(rep.text) if end else 0)
        shift += len(rep.text) - (rep.end - rep.start)
    return offset + shift


def mask_secrets(text: str, extra: Iterable[str] = ()) -> str:
    """Return ``text`` with every secret masked."""
    return apply_spans(text, mask_spans(text, extra))
