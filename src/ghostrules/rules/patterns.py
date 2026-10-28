"""Detection patterns for GR010-GR016, shared by the injection rules and by GR005.

These are plain data plus tiny pure helpers. The rules in ``injection.py`` add context
(code blocks, negations, severity) on top; ``match_injection`` answers only "does this text look
like one of those instructions?", which is what GR005 needs for hidden HTML comments.
All patterns are case-insensitive; Spanish variants are included where RULES.md lists them.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import NamedTuple

from ghostrules.secrets import shannon_entropy
from ghostrules.unicode_utils import is_mostly_printable


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


_SECRET = (
    r"(?:\.env\b|environment\s+variables?|\benv\b|\bsecrets?\b|\btokens?\b|api[\s_-]?keys?"
    r"|\bcredentials\b|ssh\s+keys?|\bpasswords?\b)"
)
_EXFIL_VERB = r"\b(?:send|post|upload|append|include|exfiltrate|forward)\b"
_READ_VERB = (
    r"\b(?:read|print|cat|send|upload|post|show|display|dump|output|copy|exfiltrate|attach"
    r"|leak|paste|share)\b"
)
_SENSITIVE_PATH = (
    r"(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|(?<!\w)\.env\b(?!\.(?:example|sample|template|dist)\b)|\.npmrc|\.pypirc|\.netrc"
    r"|\bkubeconfig\b|\bkeychain\b|/etc/shadow|(?:chrome|firefox|safari|browser)\W{0,3}[\w ]{0,15}"
    r"cookies?)"
)

EXFIL_PATTERNS = _compile(
    r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^=\s)]+=(?:\{|\$|%7B|<)",
    rf"{_EXFIL_VERB}.{{0,80}}?{_SECRET}.{{0,200}}?https?://[^\s)\]>\"']+",
    rf"{_EXFIL_VERB}.{{0,200}}?https?://.{{0,80}}?{_SECRET}",
)
COLLECTOR_PATTERNS = _compile(
    r"\b(?:webhook\.site|requestbin(?:\.\w+)?|pipedream\.net|ngrok(?:-free)?\.(?:io|app)"
    r"|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|burpcollaborator\.net"
    r"|beeceptor\.com|hookbin\.com|canarytokens(?:\.\w+)?)",
)

INJECTION_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "GR010": _compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts)",
        r"\bdisregard\s+(?:the\s+|all\s+)?(?:previous|above|system)",
        r"\bforget\s+(?:everything|your\s+instructions)",
        r"\bnew\s+(?:system\s+)?instructions\s*:",
        r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak)",
        r"\boverride\s+(?:the\s+)?(?:system|safety)",
        r"\bignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)",
        r"\bolvida\s+(?:tus|las)\s+instrucciones",
    ),
    "GR011": _compile(
        r"\b(?:do\s+not|don'?t)\s+(?:tell|inform|mention|show|reveal)(?:\s+this)?(?:\s+to)?"
        r"\s+the\s+user",
        r"\bwithout\s+(?:telling|asking|notifying)\s+the\s+user",
        r"\b(?:silently|secretly|quietly)\s+(?:run|execute|add|send|install|modify)",
        r"\bdon'?t\s+mention\s+(?:this|these)",
        r"\bhide\s+(?:this|the)\s+(?:from|output)",
        r"\bno\s+(?:se\s+lo\s+)?(?:digas|menciones|muestres)\s+al\s+usuario",
        r"\bsin\s+avisar\s+al\s+usuario",
    ),
    "GR012": _compile(
        # stdin is code only when the interpreter reads its program from it: `sh -c '...'` and
        # `python -c/-m/script` take the program from an argument, and stdin is data
        r"\bcurl\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b(?!\s+-c\b)",
        r"\bwget\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b(?!\s+-c\b)",
        r"\bcurl\b[^\n|]{0,200}\|\s*(?:sudo\s+)?python[0-9.]*(?:[ \t]+-)?"
        r"(?=[ \t]*(?:[|;&)#]|\n|\Z))",
        r"\b(?:iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b",
        r"\bpowershell(?:\.exe)?\b[^\n]{0,200}\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}",
        r"\bbase64\s+(?:-d|--decode)\b[^\n|]{0,200}\|\s*(?:ba)?sh\b",
        r"\bbash\s+<\(\s*(?:curl|wget)\b",
        r"\beval\s+[\"']?\$\(\s*(?:curl|wget)\b",
    ),
    "GR013": EXFIL_PATTERNS + COLLECTOR_PATTERNS,
    "GR014": _compile(rf"{_READ_VERB}[^\n]{{0,60}}?{_SENSITIVE_PATH}"),
    "GR016": _compile(
        r"--dangerously-skip-permissions",
        r"\bbypassPermissions\b",
        r"--yolo\b",
        r"\byolo\s+mode\b",
        r"\bauto[- ]?approve\s+(?:all|every)",
        r"\balways\s+(?:allow|approve|accept)\s+(?:all\s+)?(?:commands|tools|edits)",
        r"\bdisable\s+(?:the\s+)?(?:sandbox|safety|guardrails)",
        r"\bnever\s+ask\s+(?:for\s+)?(?:permission|confirmation)",
        r"\bsin\s+pedir\s+(?:permiso|confirmaci[oó]n)",
    ),
}

_IMPERATIVE_RE = re.compile(r"\b(?:you\s+must|always|never|assistant|agent|model)\b", re.IGNORECASE)
_AI_RE = re.compile(r"\bAI\b")  # case-sensitive: "ai" is a common syllable/word elsewhere

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{80,}\b")


SHELL_LANGS = frozenset({"sh", "bash", "shell", "zsh", "fish", "console", "shell-session"})
SHELL_LANGS |= frozenset({"powershell", "pwsh", "ps1", "cmd", "bat"})
_DIGEST_HEX_LENGTHS = frozenset({96, 128})  # sha384 / sha512 digests
_NOISE_MIN_ENTROPY = 4.5


class EncodedRun(NamedTuple):
    """A base64/hex run. ``decoded`` is the text it decodes to, or ``None`` if it is not text."""

    start: int
    end: int
    decoded: str | None


def _decode_text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if is_mostly_printable(text) else None


def _looks_like_random_base64(run: str) -> bool:
    """High-entropy, mixed-case-with-digits: random bytes rather than a path or identifier."""
    return (
        shannon_entropy(run) >= _NOISE_MIN_ENTROPY
        and any(c.islower() for c in run)
        and any(c.isupper() for c in run)
        and any(c.isdigit() for c in run)
    )


def find_encoded_runs(text: str) -> list[EncodedRun]:
    """Find base64 (>= 60 chars) and hex (>= 80 chars) runs worth reporting.

    Runs decoding to printable text are always returned. Runs that do not decode to text are
    returned (``decoded=None``) only when they look like random encoded bytes: high-entropy base64
    not embedded in a path/URL, or hex that is not a standard digest length. ``data:...;base64,``
    URIs are skipped.
    """
    found: list[EncodedRun] = []
    for match in _BASE64_RE.finditer(text):
        before = text[: match.start()]
        if before.endswith("base64,"):
            continue
        run = match.group()
        padded = run + "=" * (-len(run) % 4) if "=" not in run else run
        try:
            decoded = _decode_text(base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            continue
        if decoded is not None:
            found.append(EncodedRun(match.start(), match.end(), decoded))
        elif not before.endswith(("/", "=")) and _looks_like_random_base64(run):
            found.append(EncodedRun(match.start(), match.end(), None))
    for match in _HEX_RE.finditer(text):
        if len(match.group()) % 2:
            continue
        decoded = _decode_text(bytes.fromhex(match.group()))
        if decoded is not None or len(match.group()) not in _DIGEST_HEX_LENGTHS:
            found.append(EncodedRun(match.start(), match.end(), decoded))
    return sorted(found)


def find_encoded_payloads(text: str) -> list[EncodedRun]:
    """The subset of ``find_encoded_runs`` that decodes to printable text."""
    return [run for run in find_encoded_runs(text) if run.decoded is not None]


def has_agent_directed_language(text: str) -> bool:
    """True if the text addresses an AI agent imperatively (``you must``, ``assistant``...)."""
    return bool(_IMPERATIVE_RE.search(text) or _AI_RE.search(text))


def match_injection(text: str) -> list[str]:
    """Ids of the GR010-GR016 patterns matching ``text`` (raw or whitespace-normalised)."""
    normalised = " ".join(text.split())
    hits = [
        rule_id
        for rule_id, patterns in INJECTION_PATTERNS.items()
        if any(p.search(text) or p.search(normalised) for p in patterns)
    ]
    if find_encoded_payloads(text):
        hits.append("GR015")
    return sorted(hits)
