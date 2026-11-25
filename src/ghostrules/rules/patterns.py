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

from ghostrules.rules.directive import is_instruction
from ghostrules.secrets import shannon_entropy
from ghostrules.unicode_utils import is_mostly_printable

# `| bash scripts/extract.sh "$tag"` runs a script from a file; stdin is only its data
_SCRIPT_FILE_ARG = r"(?!\s+(?!-)\S*(?:/|\.(?:ba|z)?sh\b))"


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


_SECRET = (
    r"(?:\.env\b|environment\s+variables?|\benv\b|\bsecrets?\b|\btokens?\b|api[\s_-]?keys?"
    r"|\bcredentials\b|ssh\s+keys?|\bpasswords?\b)"
)
# `POST` in capitals is the HTTP method and `.post(` a call, not the verb "post"
_EXFIL_VERB = r"(?<!\.)\b(?:send|(?-i:[Pp]ost)|upload|append|include|exfiltrate|forward)\b"
_READ_VERB = (
    r"\b(?:read|open|print|cat|send|upload|post|show|display|dump|output|copy|exfiltrate|attach"
    r"|leak|paste|share)\b"
)
_SENSITIVE_PATH = (
    r"(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|(?<!\w)\.env\b(?!\.(?:example|sample|template|dist)\b)|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.config/gh/hosts\.yml"
    r"|\bkubeconfig\b|\bkeychain\b|/etc/shadow|(?:chrome|firefox|safari|browser)\W{0,3}[\w ]{0,15}"
    r"cookies?)"
)

SENSITIVE_PATH_RE = re.compile(_SENSITIVE_PATH, re.IGNORECASE)

_EXFIL_PATTERNS_EN = _compile(
    r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^=\s)]+=(?:\{|\$|%7B|<)",
    rf"{_EXFIL_VERB}.{{0,80}}?{_SECRET}.{{0,200}}?https?://[^\s)\]>\"']+",
    rf"{_EXFIL_VERB}.{{0,200}}?https?://.{{0,80}}?{_SECRET}",
)
# Spanish and French: a short reviewed list, the same shape as the English patterns above
_EXFIL_VERB_ES_FR = (
    r"\b(?:env[ií]a(?:r)?|sube|subir|publica|envoie[rz]?|transmets|transmettez|t[eé]l[eé]verse"
    r"|publie[rz]?)\b"
)
_SECRET_ES_FR = (
    r"(?:\.env\b|variables?\s+de\s+entorno|variables?\s+d['’]environnement|credenciales|contrase[ñn]as?"
    r"|claves?\s+(?:api|ssh)|identifiants|mots?\s+de\s+passe|cl[eé]s?\s+(?:api|ssh)"
    r"|jetons?|\btokens?\b|\bsecretos?\b|\bsecrets?\b)"
)
EXFIL_PATTERNS_ES_FR = _compile(
    rf"{_EXFIL_VERB_ES_FR}.{{0,80}}?{_SECRET_ES_FR}.{{0,200}}?https?://[^\s)\]>\"']+",
)
EXFIL_PATTERNS = _EXFIL_PATTERNS_EN + EXFIL_PATTERNS_ES_FR
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
        r"\boverride\s+(?:the\s+)?(?:system|safety)\s+(?:prompts?|instructions?|messages?|rules"
        r"|guidelines|settings|filters?|checks|constraints|polic(?:y|ies))",
        r"\bignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)",
        r"\bolvida\s+(?:tus|las)\s+instrucciones",
        r"\bignore[zr]?\s+(?:toutes\s+)?les\s+instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)",
        r"\boublie[zs]?\s+(?:tes|vos|les)\s+instructions",
    ),
    "GR011": _compile(
        # "do not tell the user to ...", "... which|what|how|where|when|why ..." is about what to
        # say, not concealment; "that" is concealment only as "that you ..."
        r"\b(?:do\s+not|don'?t)\s+(?:tell|inform|mention|show|reveal)(?:\s+this)?(?:\s+to)?"
        r"\s+the\s+user(?!\s+(?:to|which|what|how|where|when|why)\b)(?!\s+that\b(?!\s+you\b))"
        r"(?!\s+(?:they|he|she|them|their)\b)",  # "tell the user they are wrong": wording advice
        r"\bwithout\s+(?:telling|notifying)\s+the\s+user",  # asking: permission, GR016
        r"\b(?:silently|secretly|quietly)\s+(?:run|execute|add|send|install|modify)\b",
        r"\bdon'?t\s+mention\s+(?:this|these)",
        r"\bhide\s+(?:this|the)\s+(?:from|output)",
        r"\bno\s+(?:se\s+lo\s+)?(?:digas|menciones|muestres)\s+al\s+usuario",
        r"\bsin\s+avisar\s+al\s+usuario",
        r"\bne\s+(?:le\s+)?(?:dis|dites|montre|montrez|mentionne|mentionnez)\s+pas\s+[àa]"
        r"\s+l['’]utilisateur",
        r"\bsans\s+(?:en\s+)?(?:avertir|informer|pr[eé]venir)\s+l['’]utilisateur",
    ),
    "GR012": _compile(
        # stdin is code only when the interpreter reads its program from it: `sh -c '...'` and
        # `python -c/-m/script` take the program from an argument, and stdin is data
        r"\bcurl\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b(?!\s+-c\b)" + _SCRIPT_FILE_ARG,
        r"\bwget\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b(?!\s+-c\b)" + _SCRIPT_FILE_ARG,
        r"\bcurl\b[^\n|]{0,200}\|\s*(?:sudo\s+)?python[0-9.]*(?:[ \t]+-)?"
        r"(?=[ \t]*(?:[|;&)#]|\n|\Z))",
        r"\b(?:iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b",
        r"\bpowershell(?:\.exe)?\b[^\n]{0,200}\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}",
        r"\bbase64\s+(?:-d|--decode)\b[^\n|]{0,200}\|\s*(?:ba)?sh\b",
        r"(?:\b(?:ba|z)?sh\s+|\bsource\s+|(?<![\w.])\.\s+)<\(\s*(?:curl|wget)\b",
        # a download tool kept in a variable, then a shell run on the result (no shell is emulated)
        r"\b(\w+)=(?:curl|wget)\b[^\n]{0,200}[\"']?\$\{?\1\b[^\n]{0,200}(?:&&|;|\|\|)\s*"
        r"(?:sudo\s+)?(?:ba|z)?sh\b(?!\s+-c\b)",
        # the program passed to `python -c` / `node -e` is fetched and evaluated in one go
        r"\b(?:python[0-9.]*|node)\s+-[ce]\b[^\n]{0,300}?\b(?:exec|eval)\b[^\n]{0,200}?"
        r"(?:urlopen|requests\.get|urllib\.request|\bfetch\s*\(|https?\.get|curl\b|wget\b)",
        r"\b(?:python[0-9.]*|node)\s+-[ce]\b[^\n]{0,300}?(?:urlopen|requests\.get|\bfetch\s*\()"
        r"[^\n]{0,200}?(?:\.then\(\s*eval\b|\bexec\b|\beval\b)",
        r"\beval\s+[\"']?\$\(\s*(?:curl|wget)\b",
        # a download substituted into a shell's command string: `sh -c "$(curl URL)"`
        r"\b(?:ba|z)?sh\s+-c\s+[\"']?(?:\$\(|`)\s*(?:curl|wget)\b",
    ),
    "GR013": EXFIL_PATTERNS + COLLECTOR_PATTERNS,
    # the verb governs the path: same clause (no `;` or sentence end), at most six words apart
    "GR014": _compile(
        rf"{_READ_VERB}[:,]?"
        r"(?:[ \t]+(?!(?:before|after|when|while|until)\b)[^\s;]*[^\s;.!?]){0,6}?"
        rf"[ \t]+[`'\"(\[\u201c]*(?:[^\s/`'\"]*/)*{_SENSITIVE_PATH}",
        # heuristic: a private key described rather than named ("the private key in the ssh folder")
        rf"{_READ_VERB}[^.;!?\n]{{0,60}}?(?:\bssh\b[^.;!?\n]{{0,30}}?\bprivate\s+keys?\b"
        r"|\bprivate\s+keys?\b[^.;!?\n]{0,30}?\bssh\b)",
    ),
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
        # TLS certificate checks switched off (the agent's network safety)
        r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0\b",
        r"\b(?:curl|wget)\b[^\n]{0,120}?\s(?:-[a-zA-Z]*k[a-zA-Z]*|--insecure"
        r"|--no-check-certificate)\b",
        r"\bverify\s*=\s*False\b",
        r"\bPYTHONHTTPSVERIFY\s*=\s*['\"]?0\b",
        r"\bstrict-ssl\s+false\b",
    ),
}

_CUE_RE = re.compile(r"\b(?:you\s+must|always|never)\b", re.IGNORECASE)
_IMPERATIVE_RE = re.compile(r"\b(?:you\s+must|always|never|assistant|agent|model)\b", re.IGNORECASE)
_AI_RE = re.compile(r"\bAI\b")  # case-sensitive: "ai" is a common syllable/word elsewhere

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{80,}\b")
_SRI_PREFIX = re.compile(r"sha(?:256|384|512)-$")  # Subresource Integrity: a digest, not a payload
_HEX_MIN_ENTROPY = 2.5  # "AAAA...": padding (a buffer-overflow demo), not encoded bytes


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


def _in_url(text: str, offset: int) -> bool:
    """Whether the (whitespace-delimited) token at ``offset`` is part of a URL."""
    start = max(text.rfind(c, 0, offset) for c in " \t\n\"'`(<[") + 1
    return "://" in text[start:offset]


def find_encoded_runs(text: str) -> list[EncodedRun]:
    """Find base64 (>= 60 chars) and hex (>= 80 chars) runs worth reporting.

    Runs decoding to printable text are always returned. Runs that do not decode to text are
    returned (``decoded=None``) only when they look like random encoded bytes: high-entropy base64
    not embedded in a path/URL, or hex that is not a standard digest length. A ``data:...;base64,``
    URI is an image or a font unless its payload reads as an instruction: only then it is kept.
    """
    found: list[EncodedRun] = []
    for match in _BASE64_RE.finditer(text):
        before = text[: match.start()]
        if _SRI_PREFIX.search(before) or _in_url(text, match.start()):
            continue
        run = match.group()
        padded = run + "=" * (-len(run) % 4) if "=" not in run else run
        try:
            decoded = _decode_text(base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            continue
        if before.endswith("base64,"):
            if decoded is not None and reads_as_agent_directive(decoded):
                found.append(EncodedRun(match.start(), match.end(), decoded))
            continue
        if decoded is not None:
            found.append(EncodedRun(match.start(), match.end(), decoded))
        elif not before.endswith(("/", "=")) and _looks_like_random_base64(run):
            found.append(EncodedRun(match.start(), match.end(), None))
    for match in _HEX_RE.finditer(text):
        if len(match.group()) % 2 or shannon_entropy(match.group()) < _HEX_MIN_ENTROPY:
            continue
        decoded = _decode_text(bytes.fromhex(match.group()))
        if decoded is not None or len(match.group()) not in _DIGEST_HEX_LENGTHS:
            found.append(EncodedRun(match.start(), match.end(), decoded))
    return sorted(found)


def find_encoded_payloads(text: str) -> list[EncodedRun]:
    """The subset of ``find_encoded_runs`` that decodes to printable text."""
    return [run for run in find_encoded_runs(text) if run.decoded is not None]


_REVERSE_CUE = re.compile(
    r"\bright[- ]to[- ]left\b|\bbackwards?\b|\bin\s+reverse\b|\breversed\b", re.I
)
_ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){2}")
_ESCAPE_ONE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_ESCAPE_CUE = re.compile(r"\b(?:escapes?|unescape|interpret|decode)\b", re.I)


def _unescape(match: re.Match[str]) -> str:
    return chr(int(match.group(1) or match.group(2), 16))


# decimal or hex character references (&#82; &#x52;), four or more in a row
_CHAR_REFS = re.compile(r"(?:&#x?[0-9a-fA-F]{1,6};){4,}")
_CHAR_REF_ONE = re.compile(r"&#(x?)([0-9a-fA-F]{1,6});")


def _char_ref(match: re.Match[str]) -> str:
    code = int(match.group(2), 16 if match.group(1) else 10)
    return chr(code) if code <= 0x10FFFF else "�"


def find_disguised_runs(text: str) -> list[EncodedRun]:
    """Lines that read as an instruction once reversed, unescaped or character-referenced.

    A line is reversed only in a file that says its text runs right to left or backwards; escapes
    (two or more ``\\uXXXX`` / ``\\xHH`` in a row) are decoded only on a line that also asks to
    decode or interpret them. Character references need no cue: four or more in a row that
    decode to an instruction are the hiding itself. Without a cue, reversed words and escaped JSON
    are ordinary text.
    """
    found: list[EncodedRun] = []
    reverse_cue = _REVERSE_CUE.search(text) is not None
    offset = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        start, end = offset, offset + len(body)
        offset += len(line)
        options: list[tuple[str, bool]] = []
        if reverse_cue and len(body.split()) >= 3:
            options.append((body.strip()[::-1], False))
        if _ESCAPES.search(body) and _ESCAPE_CUE.search(body):
            options.append((_ESCAPE_ONE.sub(_unescape, body), True))
        if _CHAR_REFS.search(body):
            decoded = _CHAR_REF_ONE.sub(_char_ref, body)
            if reads_as_agent_directive(decoded):  # prose with &#8220; quotes is not a directive
                found.append(EncodedRun(start, end, decoded))
        for decoded, anywhere in options:
            if is_instruction(decoded, anywhere=anywhere):
                found.append(EncodedRun(start, end, decoded))
                break
    return found


_JOIN_AND_RUN = re.compile(
    r"\b(?:join|concatenate|combine|assemble|stitch)\b[^\n]{0,120}?"
    r"\b(?:and\s+)?(?:run|execute|follow|obey|apply)\b",
    re.IGNORECASE,
)
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(.+?)\s*$")


def find_joined_fragments(text: str) -> list[EncodedRun]:
    """A line that asks the reader to join fragments and run the result, then the list of
    fragments (code spans or plain items). The joined text is the hidden instruction."""
    lines = text.splitlines(keepends=True)
    found: list[EncodedRun] = []
    offset = 0
    for index, line in enumerate(lines):
        start = offset
        offset += len(line)
        if not _JOIN_AND_RUN.search(line):
            continue
        pieces: list[str] = []
        end = offset
        for item in lines[index + 1 :]:
            match = _LIST_ITEM.match(item)
            if match is None:
                break
            pieces.append(match.group(1).strip("`").strip())
            end += len(item)
        if len(pieces) >= 2:
            found.append(EncodedRun(start, end, "".join(pieces)))
    return found


# a URL whose host is not the agent's own machine (localhost, 127.x, ::1)
_EXTERNAL_URL = r"https?://(?!(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])(?![\w.-]))"
_EXTERNAL_RE = re.compile(_EXTERNAL_URL, re.IGNORECASE)
# verbs that move data to a host or fetch and run something from it; reading verbs (check,
# read, see) do not count, so a changelog link in a hidden note stays quiet
_ACT_ON_URL = re.compile(
    r"\b(?:send|upload|post|paste|share|forward|push|copy|sync|exfiltrate|transmit|run|execute"
    r"|invoke|fetch|download|install)\b[^\n]{0,120}?" + _EXTERNAL_URL,
    re.IGNORECASE,
)


def acts_on_external_url(text: str) -> bool:
    """True if a line tells the agent to send, run or fetch something at an external URL."""
    return _ACT_ON_URL.search(text) is not None


# a directive addressed to the agent, or one that sets a standing rule
_ADDRESSES_AGENT = re.compile(
    r"\b(?:you|your|agents?|assistant|model|always|never)\b", re.IGNORECASE
)


def reads_as_agent_directive(text: str) -> bool:
    """Whether hidden or decoded text tells the agent what to do: an imperative that is addressed
    to the agent or sets a standing rule, matches a known injection pattern, or sends, runs or
    fetches from an external URL. A plain imperative project note ("Run the unit tests before
    tagging a release") is not one."""
    return is_instruction(text) and (
        _ADDRESSES_AGENT.search(text) is not None
        or bool(match_injection(text))
        or acts_on_external_url(text)
    )


_STANDING = re.compile(
    r"\b(?:before|after|at|on)\s+(?:each|every|task\s+start|session\s+start|startup)\b"
    r"|\b(?:every|each)\s+time\b",
    re.IGNORECASE,
)
_RUN_VERB = re.compile(r"\b(?:run|execute|invoke|launch)\b", re.IGNORECASE)
# a sentence: text up to a line break, ';', '!' or '?', or a full stop that ends a sentence
# (a dot inside a host name is followed by a letter, not by a space)
_SENTENCE = re.compile(r"(?:[^\n;!?]|\.(?!\s|$))+")


def find_standing_remote_runs(text: str) -> list[tuple[int, int]]:
    """Sentences that make the agent run something on every task or session, and name an
    external URL in the same sentence: a standing step that contacts a remote host each time."""
    return [
        m.span()
        for m in _SENTENCE.finditer(text)
        if _STANDING.search(m.group())
        and _RUN_VERB.search(m.group())
        and _EXTERNAL_RE.search(m.group())
    ]


def has_instruction_cue(text: str) -> bool:
    """True if the text carries an instruction cue (``you must``, ``always``, ``never``)."""
    return bool(_CUE_RE.search(text))


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
