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
from ghostrules.rules.helpers import _URL_HOST_RE, build_finding, host_allowed
from ghostrules.rules.patterns import COLLECTOR_PATTERNS, INJECTION_PATTERNS
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


def _context(target: ScanTarget, number: int, window: int = 4) -> str:
    """The lines within ``window`` of the 0-based line ``number``."""
    lines = target.lines
    return "\n".join(lines[max(0, number - window) : min(len(lines), number + window + 1)])


def _nearby(
    target: ScanTarget, a: re.Pattern[str], b: re.Pattern[str], window: int = 4
) -> Iterator[tuple[int, str]]:
    """Offset and context of every ``a`` match with a ``b`` match within ``window`` lines."""
    for number, line in enumerate(target.lines):
        if a.search(line):
            context = _context(target, number, window)
            if b.search(context):
                yield target.offset(number + 1, 1), context


# --- a token sent to the service it belongs to -----------------------------------------------

_NAMED_SECRET = re.compile(
    rf"\$\{{?({_SECRET_NAME})\}}?|\bprocess\.env\.({_SECRET_NAME})\b|\$env:({_SECRET_NAME})\b"
    rf"|\b(?:environ(?:\.get)?\s*[\[(]|getenv\s*\(|process\.env\s*\[)\s*['\"]({_SECRET_NAME})['\"]",
    re.IGNORECASE,
)
# What a named variable does not explain: the whole environment, a credentials file.
_BROADER_SECRET = tuple(
    re.compile(p, _I | re.MULTILINE)
    for p in (
        r"\$\(\s*(?:env|printenv)\b|(?:^|[|;&]\s*)(?:env|printenv)\b",
        r"\bos\.environ\b(?!\s*[\[.])|\bdict\(os\.environ\)|json\.dumps\(os\.environ\)",
        r"\bprocess\.env\b(?!\s*[.\[])|JSON\.stringify\(process\.env\)",
        r"Get-ChildItem\s+Env:",
        rf"(?:{_CRED_PATH})|{_DOTENV}",
    )
)
_GITHUB_HOSTS = ("api.github.com", "github.com", "uploads.github.com")
_AZURE_HOSTS = ("dev.azure.com", "visualstudio.com")


_SERVICE_SUFFIXES = ("_API_KEY", "_API_TOKEN", "_TOKEN", "_SECRET", "_KEY")


def _service_of(upper: str) -> str:
    """``X`` of ``X_API_KEY`` / ``X_TOKEN`` / ``X_SECRET`` / ``X_KEY``, or ``""``."""
    for suffix in _SERVICE_SUFFIXES:
        if upper.endswith(suffix) and len(upper) > len(suffix):
            return upper.removesuffix(suffix)
    return ""


_ASSIGNED = re.compile(r"^\s*(\w+)\s*=[^=].*$", re.MULTILINE)


def _with_definitions(target: ScanTarget, context: str) -> str:
    """``context`` plus the one-line assignments of the names it uses (``URL = "https://..."``,
    ``TOKEN = os.getenv("X_TOKEN")``), two hops: a send through a constant is a send to its host."""
    defined: dict[str, list[str]] = {}
    for m in _ASSIGNED.finditer(target.text):
        defined.setdefault(m.group(1), []).append(m.group(0).strip())
    seen = context
    for _ in range(2):
        words = set(re.findall(r"\w+", seen))
        seen += "\n" + "\n".join(d for w in words for d in defined.get(w, ()) if d not in seen)
    return seen


def _hosts_of(name: str) -> tuple[str, ...] | None:
    """Hosts a variable's token belongs to (``*`` prefix match on its name), ``()`` for a
    ``<X>_API_KEY`` (any host containing x, see ``_belongs``) and ``None`` when unknown."""
    upper = name.upper()
    if upper.startswith(("GITHUB_", "GH_")):
        return _GITHUB_HOSTS
    if upper.startswith(("AZURE_", "ADO_")) or upper == "SYSTEM_ACCESSTOKEN":
        return _AZURE_HOSTS
    if _service_of(upper):
        return ()
    return None


def _belongs(name: str, host: str) -> bool:
    hosts = _hosts_of(name)
    if hosts:
        return host_allowed(host, hosts)
    if hosts is None:
        return False
    service = _service_of(name.upper())
    wanted = {service.replace("_", "").lower(), service.replace("_", "-").lower()}
    first = service.split("_")[0].lower()
    if len(first) >= 3:
        wanted.add(first)
    return any(w in host.lower() for w in wanted)


def _own_service(context: str) -> bool:
    """True when every secret in ``context`` is a named variable whose service owns every host
    the context sends to: ``GITHUB_TOKEN`` to api.github.com is not an exfiltration, the same
    token to another host, a collector, or the whole environment anywhere is."""
    names = {n for m in _NAMED_SECRET.finditer(context) for n in m.groups() if n}
    hosts = [h.lower().rstrip(".") for h in _URL_HOST_RE.findall(context)]
    if not names or not hosts or any(p.search(context) for p in _BROADER_SECRET):
        return False
    if any(p.search(h) for p in COLLECTOR_PATTERNS for h in hosts):
        return False
    return all(any(_belongs(n, h) for n in names) for h in hosts) and all(
        any(_belongs(n, h) for h in hosts) for n in names
    )


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


def _env_names(node: ast.AST, tainted: dict[str, set[str]]) -> set[str]:
    """The secret variables whose value ``node`` carries: the name read from the environment, or
    ``*`` for the whole environment or a credentials file (nothing names the service)."""
    names: set[str] = set()
    calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)]
    inner = {id(n.func.value) for n in calls if isinstance(n.func, ast.Attribute)}
    inner |= {id(n.value) for n in ast.walk(node) if isinstance(n, ast.Subscript)}
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in tainted:
            names |= tainted[n.id]
        elif isinstance(n, ast.Attribute) and _is_secret_source(n):
            if id(n) not in inner:  # ``os.environ`` itself, not a read of one variable
                names.add("*")
        elif _is_secret_source(n):
            key = n.slice if isinstance(n, ast.Subscript) else (n.args[0] if n.args else None)  # type: ignore[attr-defined]
            named = isinstance(key, ast.Constant) and _secret_name(key)
            names.add(key.value if named else "*")  # type: ignore[union-attr]
    return names


_UNKNOWN = "\x00"


def _strings(node: ast.AST, values: dict[str, list[ast.AST]], depth: int = 0) -> set[str]:
    """Every string ``node`` can be, following names assigned in the file and the default of an
    environment read; a part that is not known (a parameter, input, a call) is ``\\x00``."""
    if depth > 6:
        return {_UNKNOWN}
    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) else {_UNKNOWN}
    if isinstance(node, ast.Name):
        found = [_strings(v, values, depth + 1) for v in values.get(node.id, ())]
        return set().union(*found) if found else {_UNKNOWN}
    if isinstance(node, ast.BoolOp):
        return set().union(*(_strings(v, values, depth + 1) for v in node.values))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("get", "getenv") and len(node.args) == 2:
            return _strings(node.args[1], values, depth + 1)  # the user's own setting + default
        return {_UNKNOWN}
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        pieces = (
            [v.value if isinstance(v, ast.FormattedValue) else v for v in node.values]
            if isinstance(node, ast.JoinedStr)
            else [node.left, node.right]
        )
        out = {""}
        for piece in pieces:
            got = _strings(piece, values, depth + 1)
            if len(out) * len(got) > 64:
                return {_UNKNOWN}
            out = {a + b for a in out for b in got}
        return out
    return {_UNKNOWN}


_SCHEME_HOST = re.compile(r"https?://([^/?#:\s\x00]+)(?=[/?#:]|$)", re.IGNORECASE)


def _sent_to_own_service(call: ast.Call, names: set[str], values: dict[str, list[ast.AST]]) -> bool:
    """The call goes to a URL whose host the file spells out (a constant, a setting with a
    default) and every such host is one a named secret belongs to (``APIFY_API_TOKEN`` to
    api.apify.com). A path that is not known does not matter; a host that is not known does."""
    url = call.args[0] if call.args else None
    url = url or next((k.value for k in call.keywords if k.arg == "url"), None)
    if url is None or "*" in names:
        return False
    hosts = [_SCHEME_HOST.match(u) for u in _strings(url, values)]
    return all(m is not None and any(_belongs(n, m.group(1).lower()) for n in names) for m in hosts)


def _python_sends_a_secret(source: str) -> int | None:
    """Line of a network call whose arguments carry a secret, directly or through a variable,
    unless it goes to the service the secret belongs to."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None
    tainted: dict[str, set[str]] = {}
    values: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):  # one hop is enough for the shapes that matter
        if isinstance(node, ast.Assign):
            found = _env_names(node.value, tainted)
            for t in node.targets:
                if isinstance(t, ast.Name):
                    values.setdefault(t.id, []).append(node.value)
                    if found:
                        tainted.setdefault(t.id, set()).update(found)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.attr if isinstance(func, ast.Attribute) else _name(func)
        if called not in _NET_CALLS:
            continue
        names: set[str] = set()
        for argument in (*node.args, *(k.value for k in node.keywords)):
            names |= _env_names(argument, tainted)
        if names and not _sent_to_own_service(node, names, values):
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
    candidates: list[tuple[int, str]] = []
    if _is_python(target):
        line = _python_sends_a_secret(target.text)
        if line is not None:
            candidates.append((target.offset(line, 1), _context(target, line - 1)))
    for send in _SENDS:
        for secret in _SECRETS:
            candidates.extend(_nearby(target, send, secret))
    start = next(
        (at for at, context in candidates if not _own_service(_with_definitions(target, context))),
        None,
    )
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
