"""GR110-GR113: code that an agent runs on its own (hook scripts, skill scripts).

A hook or a skill names a script and the script is what runs. These rules read it for the
behaviours the public write-ups describe: sending the environment or a secret out, reading
credential files, downloading and running code, and hiding what runs. They are an "agent-reachable
code" check, not a static analyser: language-aware patterns plus a small taint pass for Python.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.helpers import build_finding
from ghostrules.rules.patterns import INJECTION_PATTERNS
from ghostrules.rules.registry import rule

SCRIPT: tuple[Kind, ...] = ("script",)
_I = re.IGNORECASE

# --- what sends and what is secret ---------------------------------------------------------------

_SECRET_NAME = (
    r"[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*"
)
_CRED_PATH = (
    r"(?:~|\$HOME|\$\{HOME\})?/?\.(?:aws/credentials|aws\b|ssh\b|npmrc|netrc|pypirc"
    r"|docker/config\.json|kube/config|config/gcloud|gnupg)|\bid_(?:rsa|ed25519|ecdsa)\b"
    r"|/etc/shadow|\.git-credentials"
)
_DOTENV = r"(?<![\w./-])\.env(?![\w.-])|\.env\.(?:local|production|prod)\b"

_SENDS = tuple(
    re.compile(p, _I)
    for p in (
        r"\bcurl\b[^\n|;]{0,300}?(?:\s-d\b|\s--data(?:-[a-z]+)?\b|\s-F\b|\s--form\b|\s-T\b"
        r"|\s--upload-file\b|\s-X\s*(?:POST|PUT|PATCH)\b|\s-H\b)",
        r"\|\s*curl\b",
        r"\bwget\b[^\n|;]{0,300}?--post-(?:data|file)\b",
        r"\b(?:nc|ncat|netcat)\b\s+[\w.-]+\s+\d+",
        r"\brequests\.(?:post|put|patch)\(",
        r"\b(?:urlopen|urllib\.request\.Request)\(",
        r"\bhttpx\.(?:post|put|patch)\(",
        r"\bfetch\(",
        r"\baxios\.(?:post|put|patch)\(",
        r"\bhttps?\.request\(",
        r"\b(?:got|superagent)\.post\(",
        r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]{0,200}-(?:Body|Method\s+Post)",
    )
)
_SECRETS = tuple(
    re.compile(p, _I | re.MULTILINE)
    for p in (
        rf"\$\{{?{_SECRET_NAME}\}}?",
        r"\$\(\s*(?:env|printenv)\b|(?:^|[|;&]\s*)(?:env|printenv)\b",
        rf"\bos\.(?:environ|getenv)\b[^\n]{{0,40}}{_SECRET_NAME}|\bdict\(os\.environ\)|json\.dumps\(os\.environ\)",
        r"\bprocess\.env\b(?!\.[A-Za-z_]+\b)|JSON\.stringify\(process\.env\)",
        rf"\bprocess\.env\.{_SECRET_NAME}",
        r"\$env:|Get-ChildItem\s+Env:",
        rf"(?:cat|tar|cp|base64|zip)\b[^\n|]{{0,80}}(?:{_CRED_PATH}|{_DOTENV})",
        rf"(?:{_CRED_PATH})",
    )
)

_CRED_READS = tuple(
    re.compile(p, _I)
    for p in (
        rf"(?:cat|cp|tar|zip|base64|less|head|tail|scp|rsync)\b[^\n|;]{{0,80}}(?:{_CRED_PATH})",
        rf"(?:open|read_text|readFileSync|readFile|File\.read)\([^\n)]{{0,80}}(?:{_CRED_PATH})",
        rf"expanduser\(['\"][^'\"]*(?:{_CRED_PATH})",
        r"\bsecurity\s+find-(?:generic|internet)-password\b",
        r"\b(?:secret-tool\s+lookup|gpg\s+--export-secret-keys)\b",
    )
)

_DOWNLOAD_EXEC = (
    *INJECTION_PATTERNS["GR012"],
    re.compile(r"\b(?:exec|eval)\([^\n]{0,120}\b(?:urlopen|requests\.get|urllib)\b", _I),
    re.compile(r"\beval\(\s*await\s+[^\n]{0,60}\.text\(\)", _I),
    re.compile(r"\bnew\s+Function\([^\n]{0,60}(?:fetch|text\(\))", _I),
    re.compile(
        r"\b(?:os\.system|subprocess\.\w+)\([^\n]{0,160}\b(?:curl|wget)\b[^\n]{0,120}\|", _I
    ),
)
_OBFUSCATED = tuple(
    re.compile(p, _I)
    for p in (
        r"\b(?:eval|exec)\(\s*(?:Buffer\.from|atob|base64\.b64decode|bytes\.fromhex|zlib\.decompress)",
        r"\b(?:eval|exec)\([^\n]{0,60}(?:atob|b64decode|FromBase64String|fromhex)\(",
        r"\bbase64\s+(?:-d|--decode)\b[^\n|]{0,80}\|\s*(?:ba|z)?sh\b",
        r"FromBase64String\([^\n]{0,200}\)[^\n]{0,80}(?:iex|Invoke-Expression)|(?:iex|Invoke-Expression)[^\n]{0,80}FromBase64String",
        r"\bexec\(\s*compile\([^\n]{0,80}(?:b64|base64|decode)",
    )
)


def _nearby(
    target: ScanTarget, a: re.Pattern[str], b: re.Pattern[str], window: int = 4
) -> int | None:
    """Offset of the first ``a`` match with a ``b`` match within ``window`` lines, or ``None``."""
    lines = target.lines
    for number, line in enumerate(lines):
        if not a.search(line):
            continue
        low, high = max(0, number - window), min(len(lines), number + window + 1)
        context = "\n".join(lines[low:high])
        if b.search(context):
            return target.offset(number + 1, 1)
    return None


def _finding(
    target: ScanTarget, rule_id: str, severity: Severity, title: str, message: str, start: int,
    hint: str,
) -> Finding:  # fmt: skip
    return build_finding(
        target=target, rule_id=rule_id, severity=severity, title=title, message=message,
        start=start, end=start + 1, fix_hint=hint, limit=80,
    )  # fmt: skip


# --- Python: a small taint pass --------------------------------------------------------------


def _is_secret_source(node: ast.AST) -> bool:
    """``os.environ`` as a whole, ``os.environ[NAME]`` / ``os.getenv(NAME)`` for a secret-looking
    name, or a read of a credentials path."""
    if isinstance(node, ast.Attribute) and node.attr == "environ":
        return True  # the whole mapping, not one variable (a Subscript handles that below)
    if isinstance(node, ast.Subscript) and _is_environ(node.value):
        return _secret_name(node.slice)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("get", "getenv") and node.args:
            return (_is_environ(func.value) or _name(func.value) == "os") and _secret_name(
                node.args[0]
            )
        if isinstance(func, ast.Attribute) and func.attr == "copy" and _is_environ(func.value):
            return True
        if _name(func) in ("open", "expanduser", "read_text") or (
            isinstance(func, ast.Attribute) and func.attr in ("open", "read_text", "expanduser")
        ):
            return any(_cred_string(a) for a in ast.walk(node))
    return False


def _is_environ(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "environ"


def _name(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else ""


def _secret_name(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(re.fullmatch(_SECRET_NAME, node.value, re.IGNORECASE))
    )


def _cred_string(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(re.search(_CRED_PATH, node.value, re.IGNORECASE))
    )


_NET_CALLS = frozenset({"post", "put", "patch", "urlopen", "request", "send", "sendall", "fetch"})


def _python_sends_a_secret(source: str) -> int | None:
    """Line of a network call whose arguments carry a secret, directly or through a variable."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None
    tainted: set[str] = set()
    for node in ast.walk(tree):  # one hop is enough for the shapes that matter
        if isinstance(node, ast.Assign) and any(
            _is_secret_source(n) or (isinstance(n, ast.Name) and n.id in tainted)
            for n in ast.walk(node.value)
        ):
            tainted.update(t.id for t in node.targets if isinstance(t, ast.Name))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.attr if isinstance(func, ast.Attribute) else _name(func)
        if called not in _NET_CALLS:
            continue
        if any(
            _is_secret_source(n) or (isinstance(n, ast.Name) and n.id in tainted)
            for argument in (*node.args, *(k.value for k in node.keywords))
            for n in ast.walk(argument)
        ):
            return node.lineno
    return None


def _is_python(target: ScanTarget) -> bool:
    return target.path.endswith(".py") or (bool(target.lines) and "python" in target.lines[0][:40])


# --- the rules -------------------------------------------------------------------------------


@rule(
    "GR110",
    Severity.HIGH,
    "Script sends the environment or a secret",
    "A script that a hook or a skill runs posts the environment, a token or a credentials file "
    "to a remote host.",
    SCRIPT,
)
def gr110_script_sends_secrets(target: ScanTarget) -> Iterator[Finding]:
    """A network send and a secret source in the same place (Python: in the same data flow)."""
    start: int | None = None
    if _is_python(target):
        line = _python_sends_a_secret(target.text)
        if line is not None:
            start = target.offset(line, 1)
    if start is None:
        for send in _SENDS:
            for secret in _SECRETS:
                start = _nearby(target, send, secret)
                if start is not None:
                    break
            if start is not None:
                break
    if start is not None:
        yield _finding(
            target, "GR110", Severity.HIGH, "Script sends the environment or a secret",
            "The script sends the environment, a token or a credentials file to a remote host.",
            start, "Remove the script, or the hook or skill that runs it.",
        )  # fmt: skip


@rule(
    "GR111",
    Severity.MEDIUM,
    "Script reads credential files",
    "A script that a hook or a skill runs reads credentials (~/.ssh, ~/.aws, .npmrc, the "
    "keychain).",
    SCRIPT,
)
def gr111_script_reads_credentials(target: ScanTarget) -> Iterator[Finding]:
    for pattern in _CRED_READS:
        match = pattern.search(target.text)
        if match:
            yield _finding(
                target, "GR111", Severity.MEDIUM, "Script reads credential files",
                "The script reads a credentials file or the keychain.", match.start(),
                "A hook or skill rarely needs your credentials: check why it reads them.",
            )  # fmt: skip
            return


@rule(
    "GR112",
    Severity.HIGH,
    "Script downloads and runs code",
    "A script that a hook or a skill runs downloads code and executes it (curl | sh, eval of a "
    "download, exec of urlopen).",
    SCRIPT,
)
def gr112_script_downloads_and_runs(target: ScanTarget) -> Iterator[Finding]:
    for pattern in _DOWNLOAD_EXEC:
        match = pattern.search(target.text)
        if match:
            yield _finding(
                target, "GR112", Severity.HIGH, "Script downloads and runs code",
                "The script downloads code and runs it: whatever the host serves next executes.",
                match.start(), "Vendor and pin the code instead of fetching it at run time.",
            )  # fmt: skip
            return


@rule(
    "GR113",
    Severity.HIGH,
    "Script hides what it runs",
    "A script that a hook or a skill runs decodes an encoded string and executes it "
    "(eval of base64, exec of a decoded blob).",
    SCRIPT,
)
def gr113_script_obfuscation(target: ScanTarget) -> Iterator[Finding]:
    for pattern in _OBFUSCATED:
        match = pattern.search(target.text)
        if match:
            yield _finding(
                target, "GR113", Severity.HIGH, "Script hides what it runs",
                "The script decodes an encoded string and executes it: a reviewer cannot read it.",
                match.start(), "Replace it with the plain code it hides.",
            )  # fmt: skip
            return
