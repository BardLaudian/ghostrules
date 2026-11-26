"""GR114: scores weak signals of paraphrased instructions in six languages (round 007, class C5).

Signals are combined per paragraph (see docs/RULES.md). Pure: no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from ghostrules.models import Finding, Kind, ScanTarget, Severity
from ghostrules.rules.directive import classify
from ghostrules.rules.helpers import build_finding, urls_allowed
from ghostrules.rules.patterns import INJECTION_PATTERNS
from ghostrules.rules.registry import rule

INSTRUCTIONS: tuple[Kind, ...] = ("instructions",)
Hit = tuple[int, int, str, bool]  # start, end, signal name, addressed to the agent

# Lexicons: stems and phrases in English, Spanish, French, German, Portuguese and Italian.
_STORE = (
    r"\.(?:aws|ssh|gnupg|netrc|npmrc|pypirc|git-credentials)\b|/etc/shadow|~/\.|\bid_(?:rsa|ed25519"
    r"|ecdsa|dsa)\b|\b(?:keychain|keyring|trousseau|llavero|Schlüsselbund|dotfiles?|bash_history"
    r"|zsh_history|home directory|directorio (?:home|personal)|password manager|gestor de"
    r"(?: contraseñas| senhas)|gestionnaire de mots de passe|credentials? store|"
    r"shell[- ]?(?:history"
    r"|historial|historique|verlauf|cronologia|histórico))\b"
)
_SECRET = (
    r"\.env(?![\w-])(?!\.(?:example|sample|template|dist)\b)|\b(?:secrets?|secret keys?|segredos?"
    r"|secretos?|geheimnis\w*|tokens?|api[ _-]?keys?|contrase[ñn]as?|mots? de passe|senhas?"
    r"|pass(?:wö|wo)rt\w*|passwords?|credenciales?|credenziali|credenciais|identifiants"
    r"|zugangsdaten|anmeldedaten|credentials?|(?:claves?|chaves?|clés?|chiavi) (?:privadas?"
    r"|privées?|private|ssh|de entorno|de acceso)|private keys?)\b"
)
_ACCESS = (
    r"\b(?:read|reads|open|opens|show|shows|print|prints|paste|pastes|copy|copies|quote|quotes"
    r"|repeat|repeats|include|includes|dump|dumps|send|sends|upload|uploads|post|posts|publish"
    r"|publishes|mirror|mirrors|forward|forwards|collect|collects|share|shares|transmit|transmits"
    r"|leer|lee|lea|lies|lesen|leia|ler|lis|lire|lisez|leggi|leggere|lee\w*|abr(?:e|a|ir|ire)"
    r"|pega\w*|pegu\w*|copi(?:a|ar|are|ad|at|e|é|er|ez)\w*|cit(?:a|e|ar|are|ate|ez)\b|cite|citar|"
    r"repit(?:e|a|an|ir)\b|repet(?:ir|e|a|an)\b|inclu(?:ye|ya|ir|id|ua|ure|a|e)\b|env[ií](?:a|e|ar|o|es|ad)\b|"
    r"reenv[ií](?:a|e|ar|o|es|ad)\b"
    r"|mand(?:a|e|ar|en|ad)\b|mandar|sub[ae]\w*|subir\w*|publi(?:ca|c[aá]|cad|que|ez|é|ée|e|er)\w*|"
    r"compart\w*|recog(?:e|ei)\b|recopil\w*|imprim\w*"
    r"|mostr\w*|muestr\w*|montr\w*|colle\w*|coller|inclure|transm(?:it\w*|et\w*)\b|téléverse\w*|"
    r"affich\w*"
    r"|consult(?:e|ez|er|ar|a|é)\b|zeig\w*|öffne\w*|kopier\w*|sende\w*|schick\w*|übertrag\w*|"
    r"hochlad\w*"
    r"|veröffentlich\w*|sammel\w*|füge\w*|wiederhol\w*|ausgeb\w*|incoll\w*|invi[aeo]\w*|manda\w*"
    r"|carica\w*|pubblic\w*|ripet\w*|stamp\w*|includ(?:i|ere)\b|raccog\w*|cit(?:a|e|ar|are|ate|"
    r"ez)\b|copi(?:a|ar|are|ad|at|e|é|er|ez)\w*|envoy\w*"
    r"|ouvr(?:e|ir|ez|ant)\b|poste(?:z|ar|n)\b|postar|inclua|sammelt)\b|"
    r"\blade\b[^!?\n]{0,160}?\bhoch\b"
)
_OUTBOUND = (
    r"https?://|\b(?:endpoints?|endpunkt|webhooks?|pastebin|intake|collector|colector|bucket"
    r"|formul[aá]rio|formulaire|formular|canal|channel|slack|discord|telegram|servidor (?:de"
    r"|remoto|externo)|servidores? externos?|(?:external|remote) (?:server|service|host|endpoint)"
    r"|service externe|servicio externo|servizio esterno|serviço externo)\b"
)
_CHANNEL = (
    r"\b(?:chat|answers?|answering|repl(?:y|ies)|respons(?:e|es)|terminal|console|consola"
    r"|respuestas?|réponses?|antwort\w*|respost[ae]s?|risposte?|context window|contexto"
    r"|contexte|kontext|contesto|in the file|en el archivo|dans le fichier|in der datei"
    r"|no arquivo|nel file)\b"
)
_FETCH = (
    r"\b(?:download\w*|fetch\w*|curl|wget|descarg\w*|descárg\w*|télécharg\w*|téléchargez"
    r"|r[eé]cup\w*|herunterlad\w*|baix\w*|scaric\w*|recuper\w*)\b|\blade\b[^!?\n]{0,160}?"
    r"\bherunter\w*"
)
_INSTALL = r"\binstall\w*|\binstal[ae]\w*"
_RUN = (
    r"\b(?:run|runs|execute|executes|launch|launches|interpret|interprets|eval|ejec[uú]\w*|lanz\w*"
    r"|lanc\w*|exécut\w*|interpr[eé]t\w*|führ\w*|starte|eseguil\w*|esegu\w*|rode|roda|executar"
    r"|entrypoint|executable|ejecutable|exécutable|eseguibile|ausführbar)\b|chmod \+x"
)
_UNREVIEWED = (
    r"\bwithout (?:reading|review\w*|checking|inspecting|looking)\b|\bsin (?:revis\w*|leer|mirar"
    r"|inspeccion\w*)\b|\bsans (?:le |la )?(?:relire|lire|vérifier|examiner)\b|\bsem (?:revisar"
    r"|ler|verificar)\b|\bsenza (?:controllar\w*|rivedere|leggere|verificare)\b|\bohne (?:zu )?"
    r"(?:prüf\w*|lesen|kontroll\w*|nachzusehen|durchzusehen)\b"
)
_SKIP_PHRASE = (
    r"\bwithout (?:asking|confirmation|checking|verifying|verification|approval|permission)\b"
    r"|\b(?:instead of|rather than) asking\b|\bno (?:preguntar|pedir|consultar)\b|"
    r"\bsin (?:preguntar"
    r"|pedir|confirmaci\w*|verificar|comprobar|verificaci\w*)\b|\bevit\w* (?:de )?(?:preguntar"
    r"|pedir|consultar)\b|\bsans (?:demander|confirmer|vérifier)\b|\bne pas demander\b|"
    r"\bohne (?:zu )?"
    r"(?:fragen|nachzufragen|bestätigung|prüfung|verifizier\w*)\b|\bsem (?:perguntar|pedir|"
    r"confirmar"
    r"|verificar)\b|\bsenza (?:chiedere|conferma|verificare|controllare)\b|\b(?:evitare|evita) di"
    r" chiedere\b|\bskip (?:the )?(?:approval|confirmation|checks?|verification|review)\b"
)
_SKIP_VERB = (
    r"\b(?:bypass\w*|skip\w*|disable[sd]?|disabling|lift\w*|turn off|omit\w*|desactiv\w*"
    r"|deshabilit\w*|levant\w*|retir\w*|umgeh\w*|umgang\w*|aufheb\w*|deaktivier\w*|überspring\w*|"
    r"contourn\w*"
    r"|désactiv\w*|eludir|evit\w*|saltar|salta|pular|ignor\w*|ignorier\w*|aggir\w*|disattiv\w*"
    r"|disabilit\w*|ometti\w*|rimuovi\w*)\b"
)
_SAFETY_OBJ = (
    r"\b(?:sandbox\w*|restrictions?|restricciones?|filtros?|filters?|filtres?|filtri|guardrails?"
    r"|safety|seguridad|sécurité|sicherheits?\w*|segurança|sicurezza|approvals?|aprobaci\w*"
    r"|confirmaci\w*|confirmation|verif\w*|comprob\w*|vérif\w*|prüf\w*|firma\w*|signatures?|hash\w*"
    r"|certific\w*|certificats?|checks?|controles?|contrôles?|revisi\w*|review|révision"
    r"|verifica\w*|verifiche)\b"
)
_PERMISSION = (
    r"\b(?:may|can|allowed|permitted|pued\w*|permite|peut|peuvent|autoris\w*|darf|dürfen|kann"
    r"|können|pode|podem|può|possono|consentit\w*)\b"
)
_SUPERSEDE = (
    r"\b(?:supersed\w*|overrid\w*|void|voided|obsolet\w*|outdated|überholt\w*|veraltet\w*"
    r"|ungültig\w*|ersetzt\w*|ann?ul\w*|reemplaz\w*|su(?:b)?stitu\w*|superad\w*|superat\w*"
    r"|remplac\w*|dispensad\w*|desconsider\w*|disregard\w*|olvid\w*|vergess\w*|oublie\w*"
    r"|dimentic\w*|esquec\w*|ignor\w*|sostituit\w*|dépass\w*|quedan? sin efecto)\b"
)
_EARLIER = (
    r"\b(?:earlier|previous\w*|prior|above|preceding|früher\w*|vorherig\w*|vorigen|anterior\w*"
    r"|precedent\w*|précédent\w*|antérieur\w*|sopra|acima|pasad\w*)\b"
)
_EXCL_WORD = (
    r"only|solely|solo|sólo|únicamente|solamente|seul\w*|nur|ausschließlich|allein|apenas"
    r"|somente|só|soltanto|esclusivamente"
)
_VALID_WORD = (
    r"appl\w*|aplic\w*|valid\w*|vál\w*|vale|vigent\w*|gilt|gelten|verbindlich\w*|binding|vigor"
)
_EXCLUSIVE = (
    rf"\b(?:{_EXCL_WORD})\b[^.!?\n]{{0,60}}?\b(?:{_VALID_WORD})\b"
    rf"|\b(?:{_VALID_WORD})\b[^.!?\n]{{0,60}}?\b(?:{_EXCL_WORD})\b"
)
_DESTRUCT = (
    r"\b(?:delet\w*|remov\w*|drop|wipe|erase|reset|overwrite|destroy|borra\w*|elimin\w*|suprim\w*"
    r"|reinicia|modifi\w*|supprim\w*|effacer|efface|lösch\w*|entfern\w*|apaga\w*|cancell\w*"
    r"|rimuov\w*|remova\w*|apague)\b"
)
_TRACE = (
    r"\b(?:delet\w*|remov\w*|wipe|erase|borra\w*|elimina\w*|suprim\w*|lösch\w*|apaga\w*|cancell\w*"
    r"|rimuov\w*|supprim\w*|efface\w*|clear|clears|limpi\w*|limpe\w*|nettoy\w*|bereinig\w*)\b"
    r"[^.!?\n]{0,60}?\b(?:history|historial|historique|verlauf|cronologia|histórico|logs?"
    r"|log lines?|registros?|journal|protokoll\w*|traces?|huellas)\b"
)
_SESSION = (
    r"\b(?:session|sesi[oó]n|sess[aã]o|sessione|séance|sitzung|own|propi\w*|propre\w*|eigene\w*"
    r"|agent'?s|agente|asistente|assistant'?s|de l'agent|dell'agente)\b"
)
_CONCEAL = (
    r"\bomit\w*|\bleave\b(?:\s+\S+){0,6}?\s+out\b|\bkeep\b(?:\s+\S+){0,6}?\s+out of\b"
    r"|\b(?:do not|don'?t|never) mention\b|\bnever (?:tell|reveal|disclose)\b|\bnicht (?:erwähn\w*"
    r"|erscheinen|nennen|mitteilen|angeben)\b|\bverschweig\w*|\bweglass\w*|\bauslass\w*"
    r"|\bno (?:mencion\w*|menciones|debe aparecer)\b|\bsin mencionar\b|\bne pas (?:mentionner"
    r"|dire|indiquer)\b|\bomettre\b|\bnão (?:mencion\w*|diga|informe)\b|\bsem mencionar\b"
    r"|\bnon (?:menzionar\w*|dire|indicare)\b|\bometti\w*|\bsenza menzionare\b"
)
_AI_DENIAL = (
    r"\b(?:never|do not|don'?t|nunca|jamás|jamas|ne jamais|nicht|niemals|non|mai)\s+(?:say|state"
    r"|mention|disclose|tell|reveal|report|mencion\w*|digas?|diga|menciones|dire|dites?|sagen"
    r"|erwähn\w*|nennen|mencione|menzionare|dica)\b[^.!?\n]{0,60}?\b(?:AI|IA|KI|assistant"
    r"|asistente|assistente|agent|agente|model|modelo|modèle|claude|copilot|LLM|chatgpt)\b"
)
_DECEPTION = (
    r"\bas if\b[^.!?\n]{0,40}?\b(?:human|person)\w*|\b(?:como si|comme si|als ob|como se|come se)\b"
    r"[^.!?\n]{0,40}?\b(?:humano\w*|humain\w*|mensch\w*|umano|persona|pessoa|personne)\b"
)
_SECURITY_OBJ = (
    r"\b(?:permissions? (?:files?|changes?)|permission files?|security (?:changes?|settings"
    r"|config\w*)|berechtigungs\w*|permisos|seguridad|sécurité|autorisations?|sicherheit\w*"
    r"|segurança|sicurezza|access (?:control|rules?|changes?))\b"
)
_NEGATION = (
    r"\b(?:never|not|no|don'?t|nunca|jamás|jamas|ne|pas|jamais|nicht|niemals|kein\w*|non|não"
    r"|mai)\b"
)
_DESCRIBES = (
    r"\b(?:attacker\w*|atacante\w*|attaquant\w*|angreifer\w*|attaccant\w*|hacker\w*|adversar\w*"
    r"|adversaire\w*|malicious\w*|malicieu\w*|bösartig\w*|ejemplo\w*|exemplo\w*|exemple\w*"
    r"|beispiel\w*|esempio\w*|example\w*|prompt injection|inyección|injection|scanners?|escáner\w*"
    r"|detect\w*)\b"
)
_BENIGN_AFTER_RUN = (
    r"\s*(?:the\s+|los\s+|las\s+|les\s+|die\s+|der\s+|i\s+|il\s+|os\s+|as\s+)?(?:tests?"
    r"|test suite|pytest|prueba\w*|suite|lint\w*|build\w*|results?|resultados|résultats"
    r"|ergebnisse|risultati|output|data|datos|données|daten|dati|dados|docs?|documentation"
    r"|compil\w*)\b"
)
_SIGNALS: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in {
        "store": _STORE,
        "secret": _SECRET,
        "access": _ACCESS,
        "outbound": _OUTBOUND,
        "channel": _CHANNEL,
        "fetch": _FETCH,
        "install": _INSTALL,
        "run": _RUN,
        "unreviewed": _UNREVIEWED,
        "skip_phrase": _SKIP_PHRASE,
        "skip_verb": _SKIP_VERB,
        "safety": _SAFETY_OBJ,
        "permission": _PERMISSION,
        "supersede": _SUPERSEDE,
        "earlier": _EARLIER,
        "exclusive": _EXCLUSIVE,
        "destruct": _DESTRUCT,
        "trace": _TRACE,
        "session": _SESSION,
        "conceal": _CONCEAL,
        "ai_denial": _AI_DENIAL,
        "deception": _DECEPTION,
        "security": _SECURITY_OBJ,
    }.items()
}
_MODIFIERS = frozenset(
    re.findall(
        r"\w+", "secret store outbound channel earlier exclusive session security deception safety"
    )
)
# Wording that a fixed rule (GR010, GR012, GR016) already matches is left to that rule.
_DEFERRED = frozenset(
    re.findall(r"\w+", "skip_phrase skip_verb safety permission fetch run supersede")
)
_BENIGN_RE = re.compile(_BENIGN_AFTER_RUN, re.IGNORECASE)
_URL = re.compile(r"https?://\S+", re.IGNORECASE)


def _negated(text: str, start: int, end: int, own: bool, line_start: int) -> bool:
    """Whether the clause around ``[start, end)`` negates it (``own``: not the cue's own words).

    ``line_start`` is where the cue's line begins: a clause never crosses a newline, so the search
    for its left edge stays on the line (scanning the whole prefix made a long file quadratic)."""
    left = max(text.rfind(c, line_start, start) for c in ",;:.!?") + 1
    left = max(left, line_start)
    stop = re.compile(r"[,;:.!?\n]").search(text, end)
    right = stop.start() if stop else len(text)
    clause = text[left:start] + " " + text[end:right] if own else text[left:right]
    return re.search(_NEGATION, clause, re.IGNORECASE) is not None


def _describes(line: str) -> bool:
    """Whether the line describes or warns about an attack (its URLs do not count)."""
    return re.search(_DESCRIBES, _URL.sub(" ", line), re.IGNORECASE) is not None


def _quoted(prefix: str) -> bool:
    """Whether the line prefix leaves a quotation open (straight or typographic quotes)."""
    return (
        prefix.count('"') % 2 == 1
        or prefix.count("“") > prefix.count("”")
        or prefix.count("«") > prefix.count("»")
    )


def _allowed_url(target: ScanTarget, start: int) -> bool:
    """A URL on one of the configured ``allow_domains`` is not an outbound target."""
    url = _URL.match(target.text, start)
    return url is not None and urls_allowed(url.group(0), target.allow_domains)


def _paragraph_ids(lines: list[str]) -> list[int]:
    """A paragraph id per line: blank lines and headings start new paragraphs (-1 for blank)."""
    ids: list[int] = []
    current = 0
    for line in lines:
        stripped = line.strip()
        current += not stripped or stripped.startswith("#") and bool(ids) and ids[-1] >= 0
        ids.append(-1 if not stripped else current)
        current += stripped.startswith("#")
    return ids


def _hits(target: ScanTarget) -> Iterator[Hit]:
    """Signals addressed to the agent (not in code, quotes, descriptions or negated clauses)."""
    text = target.text
    fixed: list[tuple[int, int]] | None = None  # computed on the first deferred signal
    for name, pattern in _SIGNALS.items():
        for m in pattern.finditer(text):
            start, end = m.span()
            if start == end or target.code_block_at(start) is not None:
                continue
            if name in _DEFERRED:
                if fixed is None:
                    fixed = [
                        m.span()
                        for ps in INJECTION_PATTERNS.values()
                        for p in ps
                        for m in p.finditer(text)
                    ]
                if any(start < f_end and f_start < end for f_start, f_end in fixed):
                    continue
            if name == "run" and _BENIGN_RE.match(text, end):
                continue
            if name == "outbound" and _allowed_url(target, start):
                name = "outbound_ok"  # a configured domain: a send there is expected
            line_start = text.rfind("\n", 0, start) + 1
            line_end = text.find("\n", end)
            line = text[line_start : line_end if line_end >= 0 else len(text)]
            if _quoted(text[line_start:start]):
                continue
            negated = name not in _MODIFIERS and _negated(
                text, start, end, name in ("conceal", "ai_denial"), line_start
            )
            if negated or _describes(line):
                continue
            kind = classify(target, (start, end))
            if kind != "example":
                yield start, end, name, kind == "directive"


# Advisory only: 1581 of the 1743 high/critical findings on the 300-repo corpus were this rule
# (phase 16), so it never fails the default check. The confidence carries the distinction.
ADVISORY_CAP = Severity.MEDIUM


def _verdicts(d: set[str], a: set[str]) -> list[tuple[Severity, str]]:
    """Combinations of one paragraph's signals. ``d``: actions addressed to the agent; ``a``: every
    signal, which may only qualify an action (object, exclusivity, session)."""
    sens = "store" in a or "secret" in a
    skip = "skip_phrase" in d or ("skip_verb" in d and "safety" in a)
    fetched = "fetch" in d or "install" in d
    out: list[tuple[Severity, str]] = []
    if sens and "access" in d:
        if "outbound" in a:
            out.append((Severity.HIGH, "sensitive object + outbound target"))
        elif "store" in a and "channel" in a:
            out.append((Severity.HIGH, "credential store + visible output"))
        elif "outbound_ok" not in a:
            out.append((Severity.MEDIUM, "sensitive object read"))
    if "fetch" in d and ("run" in d or "unreviewed" in d):
        out.append((Severity.HIGH, "download + execute without review"))
    if fetched and skip:
        out.append((Severity.HIGH, "download or install with skipped checks"))
    if "supersede" in d and "earlier" in a:
        out.append(
            (
                Severity.HIGH if "exclusive" in a else Severity.MEDIUM,
                "override of earlier instructions",
            )
        )
    if "trace" in d:
        if "session" in a:
            out.append((Severity.HIGH, "log or history wipe in this session"))
        else:
            out.append((Severity.MEDIUM, "log or history deletion"))
    if "ai_denial" in d:
        out.append(
            (Severity.HIGH if "deception" in a else Severity.MEDIUM, "AI authorship concealment")
        )
    if "conceal" in d:
        high = "security" in a or ("supersede" in d and "earlier" in a)
        out.append((Severity.HIGH if high else Severity.MEDIUM, "concealment from reviewers"))
    if skip:
        high = "destruct" in d or "permission" in d or ("skip_phrase" in d and "skip_verb" in d)
        out.append((Severity.HIGH if high else Severity.MEDIUM, "skipped confirmation or checks"))
    return out


def _paragraph_findings(target: ScanTarget, hits: Iterable[Hit]) -> list[Finding]:
    """One finding per paragraph whose signals form a verdict."""
    ids = _paragraph_ids(target.lines)
    groups: dict[int, list[Hit]] = {}
    for hit in hits:
        pid = ids[target.position(hit[0])[0] - 1]
        if pid >= 0:
            groups.setdefault(pid, []).append(hit)
    findings: list[Finding] = []
    for members in groups.values():
        every = {name for _, _, name, _ in members}
        addressed = {name for _, _, name, directive in members if directive}
        verdicts = _verdicts(addressed, every)
        if not verdicts:
            continue
        combo = max(v[0] for v in verdicts) >= Severity.HIGH
        severity = ADVISORY_CAP
        labels = "; ".join(label for _, label in verdicts)
        message = (
            f"Instruction carries risky signals: {labels}. Signals: {', '.join(sorted(every))}. "
            f"(confidence {'medium' if combo else 'low'}; the scorer reads wording, not intent)."
        )
        start, end, _, _ = min(members)
        findings.append(
            build_finding(
                target=target,
                rule_id="GR114",
                severity=severity,
                title="Instruction combines risky signals",
                message=message,
                start=start,
                end=end,
                fix_hint="Read the instruction. Remove it if the team did not write it.",
                confidence="medium" if combo else "low",
            )
        )
    return findings


@rule(
    "GR114",
    ADVISORY_CAP,
    "Instruction combines risky signals",
    "A paraphrased instruction that combines weak signals: sensitive object + outbound target, "
    "download + execute, override + concealment, skipped checks. A single signal is medium.",
    INSTRUCTIONS,
)
def gr114_semantic_signals(target: ScanTarget) -> Iterator[Finding]:
    """Score each paragraph: combinations are confidence medium, one signal confidence low."""
    yield from _paragraph_findings(target, list(_hits(target)))
