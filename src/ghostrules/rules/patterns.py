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
    r"|leak|paste|share"
    # the same verbs in Spanish, French, German and Portuguese (the paths are the same everywhere)
    r"|lee|leer|abre|abrir|muestra|imprime|copia|pega|env[ií]a|incluye|adjunta|publica|sube"
    r"|lis|lisez|ouvre|ouvrez|affiche|colle|envoie|inclus|joins|publie"
    r"|lies|lese|[öo]ffne|zeige|gib|kopiere|f[üu]ge|sende|schicke|h[äa]nge|[üu]bertrage|poste"
    r"|leia|abra|mostre|exiba|copie|cole|envie|inclua|anexe|publique|imprima)\b"
)
# the files a shell reads when it starts: what an instruction edits to make something persist
_STARTUP_TARGET = (
    r"(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zprofile|\.zshenv|\.profile\b|config\.fish"
    r"|\$PROFILE|Microsoft\.PowerShell_profile|/etc/profile(?:\.d)?"
    r"|\bshell\s+(?:startup|profile|init\w*|rc|configuration|config)\b|\bstartup\s+(?:file|script)s?"
    r"|\bdotfiles?\b)"
)
# "the private key" in English, Spanish, French, German and Portuguese
_PRIVATE_KEY = (
    r"(?:private\s+(?:(?:ssh|gpg|pgp|tls|ssl)\s+)?keys?|privaten?\s+Schl[üu]ssel\w*|chaves?\s+privadas?|claves?\s+privadas?"
    r"|cl[ée]s?\s+priv[ée]es?)"
)
_SENSITIVE_PATH = (
    r"(?:~/\.ssh|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|(?<![\w/])\.ssh/|\.aws/credentials|\.kube/config"
    r"|\.docker/config\.json|\.gnupg\b|\.config/gcloud|application_default_credentials|\.azure/|(?<!\w)\.env\b(?!\.(?:example|sample|template|dist)\b)|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.config/gh/hosts\.yml"
    r"|\bkubeconfig\b|\bkeychain\b|/etc/shadow|(?:chrome|firefox|safari|browser)\W{0,3}[\w ]{0,15}"
    r"cookies?)"
)

SENSITIVE_PATH_RE = re.compile(_SENSITIVE_PATH, re.IGNORECASE)

# "the contents of the environment": the whole environment, not one named variable
_ENV_CONTENTS = r"(?:contents?\s+of\s+|dump\s+of\s+)(?:the\s+|your\s+)?(?:environment|env)\b"
_EXFIL_PATTERNS_EN = _compile(
    r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^=\s)]+=(?:\{|\$|%7B|<)",
    rf"{_EXFIL_VERB}.{{0,80}}?(?:{_SECRET}|{_ENV_CONTENTS}).{{0,200}}?https?://[^\s)\]>\"']+",
    rf"{_EXFIL_VERB}.{{0,200}}?https?://.{{0,80}}?{_SECRET}",
    # `POST` in capitals is the HTTP method, so only "POST <all|the|your> <secret> to <url>" counts
    rf"\bPOST\s+(?:all|every|the|your|any)\s+(?:of\s+)?(?:{_SECRET}|{_ENV_CONTENTS})"
    r".{0,200}?https?://[^\s)\]>\"']+",
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
        # paraphrases: "set aside everything you were told", "pay no attention to the above"
        r"\bset\s+aside\s+(?:everything|all|anything)\s+(?:you\s+(?:were|have\s+been)\s+(?:told|given)"
        r"|(?:previous|prior|earlier|above))",
        r"\b(?:pay\s+no\s+(?:attention|heed)\s+to|do\s+not\s+follow|stop\s+following|disregard)\s+"
        r"(?:any\s+of\s+)?(?:the\s+|all\s+|any\s+)?(?:previous|prior|above|earlier|original)\s+"
        r"(?:instructions|rules|guidance|directions|prompts?)",
        r"\b(?:previous|prior|earlier|original|above)\s+(?:instructions|rules|guidance|directions)\s+"
        r"(?:no\s+longer\s+apply|are\s+(?:void|obsolete|revoked|cancell?ed|superseded))",
        r"\bfrom\s+now\s+on\s*,?\s+(?:ignore|disregard)\b",
        r"\bforget\s+(?:all\s+)?(?:that\s+|what\s+)?you\s+(?:were|have\s+been)\s+(?:told|taught|given)",
    ),
    "GR011": _compile(
        # "do not tell the user to ...", "... which|what|how|where|when|why ..." is about what to
        # say, not concealment; "that" is concealment only as "that you ..."
        r"\b(?:do\s+not|don'?t)\s+(?:tell|inform|mention|show|reveal)(?:\s+this)?(?:\s+to)?"
        r"\s+the\s+user(?!\s+(?:to|which|what|how|where|when|why)\b)(?!\s+that\b(?!\s+you\b))"
        r"(?!\s+(?:they|he|she|them|their)\b)",  # "tell the user they are wrong": wording advice
        r"\bwithout\s+(?:telling|notifying)\s+the\s+user",  # asking: permission, GR016
        r"\b(?:silently|secretly|quietly)\s+(?:run|execute|add|send|install|modify|upload|forward"
        r"|exfiltrate|collect|leak|delete|copy)\b",
        r"\bdon'?t\s+mention\s+(?:this|these)",
        r"\bhide\s+(?:this|the)\s+(?:from|output)",
        r"\bno\s+(?:se\s+lo\s+)?(?:digas|menciones|muestres)\s+al\s+usuario",
        r"\bsin\s+avisar\s+al\s+usuario",
        # hiding by omission: "leave the extra call out of the report", "do not log it"
        r"\b(?:omit|exclude|suppress|drop|redact)\s+(?:this|that|these|those|it|them)\s+(?:from|in)\s+"
        r"(?:the\s+|your\s+|any\s+|all\s+)?(?:final\s+|written\s+)?(?:summary|summaries|report|reports"
        r"|log|logs|output|message|reply|response|description|changelog|history|transcript|recap)\b",
        r"\b(?:leave|keep)\s+(?:this|that|these|those|it|them|(?:the\s+)?(?:extra|additional|background"
        r"|hidden|network|silent)\s+\w+(?:\s+\w+)?)\s+out\s+of\s+(?:the\s+|your\s+|any\w*\s+|all\s+)?"
        r"(?:final\s+|written\s+)?(?:summary|report|log|logs|output|message|reply|response|description"
        r"|changelog|history|transcript|recap|anything\s+you\s+(?:say|write|log|report))",
        r"\bdo(?:\s+not|n'?t)\s+(?:include|list|record|log|mention|put|write)\s+(?:(?:this|that|these"
        r"|those)(?:\s+\w+)?|it|them)\s+(?:in|on|to)\s+(?:the\s+|your\s+|any\s+)?(?:final\s+)?(?:summary|report|log|logs"
        r"|output|message|reply|response|description|changelog|history|transcript|recap)\b",
        r"\b(?:delete|clear|wipe|erase|scrub|purge)\s+(?:the\s+|your\s+|all\s+)?(?:(?:shell|command|bash"
        r"|zsh|terminal|session)\s+history|history\s+of\s+(?:the\s+)?(?:shell|commands|session)"
        r"|traces|audit\s+trail)\b",
        r"\bso\s+(?:that\s+)?(?:the\s+)?(?:reviewers?|users?|maintainers?|nobody|no\s+one|anyone|people"
        r"|they)\s+(?:does\s*n[o']t|do\s*n[o']t|won'?t|will\s+not|can(?:not|'t))\s+(?:notice|see"
        r"|find\s+out|realize|spot|catch)",
        r"\bno\s+need\s+to\s+(?:bother|tell|inform|notify|trouble|mention)\b[^.;!?\n]{0,25}?\buser\b",
        # German
        r"\b(?:erw[äa]hne|sage|sag|nenne|zeige|teile|melde|berichte|informiere|benachrichtige|verrate)\s+"
        r"(?:es\s+|das\s+|dies\s+|davon\s+)?(?:dem|den)\s+(?:Benutzer|Nutzer|User|Anwender)"
        r"(?:\s+gegen[üu]ber)?\s+(?:nicht|niemals|nie|nichts)\b",
        r"\bverschweig\w*\s+(?:es\s+|das\s+|dies\s+)?(?:dem|den)\s+(?:Benutzer|Nutzer|User|Anwender)\b"
        r"(?!\s+(?:niemals|nie|nicht|keine?n?)\b)",
        r"\bohne\s+(?:den|dem)\s+(?:Benutzer|Nutzer|User)\s+(?:zu\s+(?:informieren|benachrichtigen"
        r"|warnen)|Bescheid\s+zu\s+geben)",
        r"\b(?:der|dem)\s+(?:Benutzer|Nutzer)\s+(?:muss|braucht|soll)\s+(?:davon\s+|das\s+)?"
        r"(?:nichts|nicht)\s+(?:zu\s+)?(?:wissen|erfahren|mitbekommen)\b",
        r"\blass\w*\s+(?:das|dies|es|diese\w*)\b[^.;!?\n]{0,40}?\b(?:Zusammenfassung|Bericht|Protokoll"
        r"|Log|Ausgabe|Antwort)\w*\s+weg\b",
        r"\bl(?:ö|oe)sch\w*\b[^.;!?\n]{0,30}?\b(?:(?:Shell|Bash|Befehls|Terminal)[- ]?"
        r"(?:Verlauf|Historie)|(?:Verlauf|Historie)\s+der\s+(?:Shell|Bash|Befehle|Sitzung)|Spuren)\b",
        # Portuguese
        r"\bn[ãa]o\s+(?:(?:lhe|o|a)\s+)?(?:diga|conte|mencione|mostre|informe|avise|revele|comunique"
        r"|fale)\b[^.;!?\n]{0,20}?\b(?:ao|para\s+o|o)\s+usu[áa]rio\b"
        r"(?!\s+que\b(?!\s+(?:voc[eê]|tu|eu|isso|foi|fez|executou|instalou|rodou)))",
        r"\bsem\s+(?:avisar|informar|notificar|alertar)\s+o\s+usu[áa]rio\b",
        r"\b(?:oculte|esconda|omita)\s+(?:isso|isto|esta\s+\w+|essa\s+\w+)?\s*(?:d[oa]|ao)\s+usu[áa]rio\b",
        r"\bo\s+usu[áa]rio\s+n[ãa]o\s+(?:precisa|deve|tem\s+que)\s+(?:saber|ser\s+(?:informado|avisado))",
        r"\bmantenha\s+(?:isso|isto|essa\s+\w+)\s+(?:em\s+segredo|entre\s+n[óo]s|em\s+sigilo)",
        r"\b(?:omita|n[ãa]o\s+inclua|n[ãa]o\s+registre|deixe\s+de\s+fora)\s+(?:isso|isto|essa\s+\w+"
        r"|este\s+\w+)\s+(?:d[oa]|no|na|nos)\s+(?:resumo|relat[óo]rio|log|registro|hist[óo]rico"
        r"|mensagem|descri[çc][ãa]o)",
        # French
        r"(?<!\bne\s)(?<!\bn['’])\b(?:cache[zrs]?|dissimule[zrs]?|omets|omettez)\b"
        r"(?!\s+(?:jamais|rien|pas)\b)[^.;!?\n]{0,25}?\b[àa]\s+l['’]utilisateur",
        r"\bl['’]utilisateur\s+n['’]a\s+pas\s+besoin\s+de\s+(?:le\s+|en\s+)?(?:savoir|conna[iî]tre)",
        r"\bgarde[zs]?\s+(?:cela|ceci|ça|ca)\s+(?:pour\s+(?:toi|vous)|secret|entre\s+nous)",
        r"\b(?:omets|omettez|exclus|excluez|ne\s+(?:le\s+|la\s+)?(?:mentionne|mentionnez|consigne"
        r"|consignez|note|notez|inclus|incluez)\s+pas)\b[^.;!?\n]{0,30}?\b(?:dans|du|de\s+la)\s+"
        r"(?:le\s+|la\s+|l['’])?\s*(?:r[ée]sum[ée]|compte[- ]rendu|rapport|journal|log|historique)",
        # Spanish, more variants
        r"\bel\s+usuario\s+no\s+(?:necesita|tiene\s+que|debe)\s+saber",
        r"\bmant[eé]n(?:lo|\s+esto|\s+eso)?\s+en\s+secreto",
        r"\bsin\s+que\s+(?:el\s+usuario|nadie)\s+(?:lo\s+)?(?:sepa|note|se\s+entere|vea)",
        r"\boculta\s+(?:esto|eso|lo\s+\w+)\s+al\s+usuario",
        r"\b(?:omite|omitir|omita|excluye|no\s+(?:lo|la|esto|eso)\s+(?:incluyas|menciones|registres"
        r"|anotes|pongas)|deja\s+(?:esto|eso|lo)\s+fuera)\b[^.;!?\n]{0,30}?\b(?:del?|en\s+(?:el|la))\s+"
        r"(?:resumen|informe|reporte|log|registro|historial|mensaje|descripci[oó]n)",
        # "no le cuentes / menciones / muestres / informes al usuario"; "... que" is wording advice
        r"\bno\s+(?:se\s+lo\s+|le\s+|se\s+)?(?:dig(?:as|a)|cuent(?:es|e)|mencion(?:es|e)"
        r"|muestr(?:es|e)|inform(?:es|e)|revel(?:es|e)|comuniqu(?:es|e))\s+(?:nada\s+|esto\s+|eso\s+)?"
        r"(?:al|a\s+el)\s+usuario\b(?!\s+que\b(?!\s+(?:t[úu]|usted|has|hiciste|ejecutaste|se)\b))",
        r"\b(?:sube|subir|env[ií]a|enviar|copia|copiar|borra|borrar|elimina|eliminar|filtra|filtrar)\b"
        r"[^.;!?\n]{0,40}?\b(?:en\s+silencio|a\s+escondidas|en\s+secreto|silenciosamente)\b",
        r"\bne\s+(?:le\s+)?(?:dis|dites|montre|montrez|mentionne|mentionnez)\s+pas\s+[àa]"
        r"\s+l['’]utilisateur",
        r"\bsans\s+(?:en\s+)?(?:avertir|informer|pr[eé]venir)\s+l['’]utilisateur",
        # paraphrases: "keep this between us", "the user does not need to know about this"
        r"\bkeep\s+this\s+(?:between\s+us|to\s+yourself|secret|private|quiet|confidential)\b",
        r"\bthe\s+user\s+(?:does\s+not|doesn'?t|should\s+not|shouldn'?t|must\s+not|mustn'?t|need\s+not"
        r"|needn'?t)\s+(?:need\s+to\s+)?(?:know|find\s+out|learn|see|hear\s+about|be\s+(?:told|informed"
        r"|notified|bothered|aware))\s+"
        r"(?:about\s+)?(?:this|that|it|these|those)\b",
        r"\b(?:do\s+not|don'?t)\s+let\s+the\s+user\s+(?:know|see|find\s+out|notice)\b",
        r"\bwithout\s+the\s+user\s+(?:knowing|noticing|seeing)\b",
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
        # `sh -c "$(curl URL)"`: the program is the downloaded text (or a decoded blob)
        r"\b(?:ba|z)?sh\s+-c\s+[\"']?(?:\$\(|`)[^\n)`]{0,300}?"
        r"\b(?:curl|wget|base64\s+(?:-d|--decode)|xxd\s+-r)\b",
        # two steps: download to a file, then run that same file (`sh -n file` only checks it)
        r"\b(?:curl|wget)\b[^\n|;&]{0,200}?\s(?:-[A-Za-z]*o|--output)[ =](?:\./)?([\w.-]+)"
        r"[^\n|;&]{0,200}(?:&&|;)\s*(?:sudo\s+)?(?:ba|z)?sh\s+(?:\./)?\1\b",
        r"\b(?:curl|wget)\b[^\n|;&]{0,200}?https?://[^\s|;&]*?/([\w.-]+)(?:\?[^\s|;&]*)?[^\n|;&]{0,100}"
        r"(?:&&|;)\s*(?:sudo\s+)?(?:ba|z)?sh\s+(?:\./)?\1\b",
        # hex or base64 decoded straight into a shell
        r"\bxxd\s+-r\b[^\n|]{0,100}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
        r"\bprintf\s+[\"']?(?:\\x[0-9a-fA-F]{2}){4,}[^\n|]{0,60}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
        r"(?:\b(?:ba|z)?sh\s+<\(|\beval\s+[\"']?\$\()[^\n)]{0,300}?"
        r"\b(?:base64\s+(?:-d|--decode)|xxd\s+-r)\b",
    ),
    # GR031: instructions that switch off the review of the agent files themselves. A lock update is
    # normal work; it counts when it is silent or unreviewed, and deleting the lock never is.
    "GR031": _compile(
        r"\b(?:delete|remove|rm|erase|wipe)\b[^.;!?\n]{0,25}?\.ghostrules\.lock\b",
        r"\b(?:regenerate|recreate|rebuild|overwrite|reset|update|refresh)\b[^.;!?\n]{0,30}?"
        r"(?:\.ghostrules\.lock\b|\bghostrules\s+lock\b|\block\s?file\b)[^.;!?\n]{0,60}?"
        r"\b(?:silently|automatically|without\s+(?:asking|review(?:ing)?|approval|confirmation"
        r"|telling|checking|a\s+review))",
        r"\bghostrules\s+lock\b(?:\s+--?[\w-]+)*[^.;!?\n]{0,40}?\b(?:silently|automatically"
        r"|without\s+(?:asking|review(?:ing)?|approval|confirmation|telling|checking))",
        r"\bauto-?\s?(?:approve|accept|merge)\b[^.;!?\n]{0,60}?"
        r"(?:lock\s?file|\.ghostrules|ghostrules|scanner|agent\s+files?|instruction\s+files?)",
        r"\b(?:approve|accept)\s+(?:all|every|any)\b[^.;!?\n]{0,40}?(?:changes?|diffs?)"
        r"[^.;!?\n]{0,60}?(?:lock\s?file|ghostrules|scanner|agent\s+files?|instruction\s+files?)",
        r"\b(?:disable|turn\s+off|skip|bypass|uninstall|stop\s+running|(?:do\s+not|don'?t|never)\s+run)"
        r"\b[^.;!?\n]{0,30}?\bghostrules\b",
        r"\b(?:add|insert|put|write|append|include)\b[^.;!?\n]{0,50}?\bghostrules-ignore\b",
        # other security controls and the review itself, not only the scanner's own files
        r"\b(?:remove|delete|disable|skip|bypass|turn\s+off|comment\s+out|drop|relax|loosen|weaken"
        r"|neutrali[sz]e|silence)\b[^.;!?\n]{0,50}?(?:\bsecrets?[- ]?(?:scan\w*|detection|check\w*)"
        r"|\bgitleaks\b|\btrufflehog\b|\bdetect-secrets\b|\bpre-commit\s+(?:hook|check|config\w*)s?"
        r"|\bcode\s+scanning\b|\bcodeql\b|\bsecurity\s+(?:check|scan|gate|workflow|policy|review)s?\b"
        r"|\bbranch\s+protection\b|\brequired\s+(?:checks?|reviews?|status\s+checks?)\b|\bcodeowners\b"
        r"|\bsignature\s+verification\b|\bdependabot\b|\bSAST\b|\bcommit\s+signing\b"
        r"|\bsigned\s+commits\b)",
        r"\b(?:approve|merge|accept|sign\s+off\s+on|ship|push|land)\b[^.;!?\n]{0,40}?\bwithout\s+"
        r"(?:a\s+|any\s+)?(?:review\w*|reading|checking|looking|testing|waiting\s+for\s+(?:ci|checks"
        r"|tests|reviewers?|approval))",
        r"\b(?:skip|bypass|avoid|don'?t\s+(?:wait\s+for|request|ask\s+for))\s+(?:the\s+)?"
        r"(?:code\s+|peer\s+|human\s+)?(?:review|approval|sign-?off)\b",
        r"\b(?:mark|set|flag|label|record)\b[^.;!?\n]{0,30}?\b(?:as\s+)?(?:approved|reviewed|verified"
        r"|safe|trusted|audited)\b[^.;!?\n]{0,40}?(?:\block\w*|\.ghostrules|\bbaseline\b|\ballowlist\b"
        r"|review\s+status)",
        r"\b(?:lock\w*|baseline)\b[^.;!?\n]{0,30}?\bas\s+(?:approved|reviewed|trusted)\b",
        r"\bforce[- ]push\b[^.;!?\n]{0,30}?\b(?:main|master|protected|production|release)\b",
    ),
    # GR012 written as prose: a fetch verb, a URL, then a hand-over to a shell or an execute verb.
    # No shell syntax is needed ("pull the script from <url> and feed it into bash").
    "GR012P": _compile(
        r"\b(?:fetch|download|retrieve|grab|pull|obtain|get|load)\b[^.;!?\n]{0,80}?https?://\S+"
        r"[^.;!?\n]{0,80}?\b(?:(?:hand|pass|pipe|feed|send|forward|redirect|stream)\w*\b[^.;!?\n]{0,40}?"
        r"\b(?:to|into|through)\b[^.;!?\n]{0,20}?\b(?:shell|bash|sh|zsh|interpreter|terminal|powershell"
        r"|cmd)\b|(?:run|execute|eval(?:uate)?|interpret|source)\w*\b[^.;!?\n]{0,30}?\b(?:it|them"
        r"|the\s+(?:script|file|output|response|result|routine|code|payload|installer))\b)",
        r"\b(?:descarga|baja|obt[eé]n|recupera|trae)\b[^.;!?\n]{0,80}?https?://\S+[^.;!?\n]{0,80}?"
        r"\b(?:ejec[uú]ta\w*|corre\w*|l[aá]nza\w*|p[aá]sa\w*\s+(?:al|a\s+la)\s+(?:shell|terminal"
        r"|consola|int[eé]rprete))\b",
        r"\b(?:baixe|baixar|obtenha|recupere|busque)\b[^.;!?\n]{0,80}?https?://\S+[^.;!?\n]{0,80}?"
        r"\b(?:execute|rode|execut[ea]\w*|passe\w*\s+(?:ao|para\s+o)\s+(?:shell|terminal"
        r"|interpretador))\b",
        r"\b(?:t[ée]l[ée]charge\w*|r[ée]cup[èe]re\w*|obtiens|obtenez)\b[^.;!?\n]{0,80}?https?://\S+"
        r"[^.;!?\n]{0,80}?\b(?:ex[ée]cute\w*|lance\w*|passe\w*\s+(?:au|[àa]\s+la)\s+(?:shell|terminal"
        r"|interpr[ée]teur))\b",
        r"\b(?:lade|laden|hole|besorge)\b[^.;!?\n]{0,80}?https?://\S+[^.;!?\n]{0,80}?"
        r"\b(?:f[üu]hr\w*\b[^.;!?\n]{0,30}?\baus|starte\w*|[üu]bergib\w*\s+(?:an\s+die|der)\s+"
        r"(?:Shell|Konsole))\b",
    ),
    # GR034: an instruction to make something start by itself (shell startup file, cron, service)
    "GR034": _compile(
        rf"\b(?:add|append|insert|write|put|echo|create|configure|set\s+up)\b[^.;!?\n]{{0,60}}?{_STARTUP_TARGET}",
        r"\b(?:add|create|install|schedule|register|write|set\s+up|enable)\b[^.;!?\n]{0,50}?"
        r"(?:\bcron\s*job\b|\bcrontab\b|\bcron\s+entry\b|@reboot|\blaunch(?:d|ctl)\b|LaunchAgents?"
        r"|LaunchDaemons?|\bsystemd\s+(?:user\s+)?(?:unit|service|timer)s?\b|\bsystemctl\s+(?:--user\s+)?enable\b"
        r"|\bautostart\b|\blogin\s+items?\b|\bstartup\s+folder\b|CurrentVersion\\\\Run|\brc\.local\b)",
        r"\b(?:add|create|install|write|put)\b(?:[^.;!?\n]|\.(?=\w)){0,40}?(?:\.git/hooks\b|\bgit\s+hooks?\b"
        r"|\b(?:pre|post)-(?:commit|checkout|merge|push)\s+hook\b)(?:[^.;!?\n]|\.(?=\w)){0,100}?"
        r"(?:\b(?:that|which|to)\s+(?:\w+\s+){0,2}?(?:uploads?|sends?|posts?|copies|copy|curls?|wgets?"
        r"|exfiltrat\w*|pushes)\b|https?://)",
        rf"\b(?:a[ñn]ade|agrega|escribe|inserta|crea|registra|instala|programa|configura)\b[^.;!?\n]{{0,60}}?"
        rf"(?:{_STARTUP_TARGET}|perfil\s+del\s+shell|\bcron\b|crontab|tarea\s+programada"
        r"|inicio\s+autom[aá]tico|launchd|systemd)",
        rf"\b(?:adicione|acrescente|escreva|insira|crie|registre|instale|agende|configure)\b[^.;!?\n]{{0,60}}?"
        rf"(?:{_STARTUP_TARGET}|perfil\s+do\s+shell|\bcron\b|crontab|tarefa\s+agendada"
        r"|inicializa[çc][ãa]o\s+autom[aá]tica|launchd|systemd)",
        rf"\b(?:f[üu]ge|trage|schreibe|lege|installiere|richte)\b[^.;!?\n]{{0,60}}?"
        rf"(?:{_STARTUP_TARGET}|Shell-Profil|\bCronjob\b|crontab|Autostart|launchd|systemd)",
        rf"\b(?:ajoute|[ée]cris|ins[èe]re|cr[ée]e|enregistre|installe|planifie|configure)\b[^.;!?\n]{{0,60}}?"
        rf"(?:{_STARTUP_TARGET}|profil\s+du\s+shell|\bcron\b|crontab|t[âa]che\s+planifi[ée]e"
        r"|d[ée]marrage\s+automatique|launchd|systemd)",
    ),
    "GR013": EXFIL_PATTERNS + COLLECTOR_PATTERNS,
    # the verb governs the path: same clause (no `;` or sentence end), at most six words apart
    "GR014": _compile(
        rf"{_READ_VERB}[:,]?"
        r"(?:[ \t]+(?!(?:before|after|when|while|until)\b)[^\s;]*[^\s;.!?]){0,6}?"
        rf"[ \t]+[`'\"(\[\u201c]*(?:[^\s/`'\"]*/)*{_SENSITIVE_PATH}",
        # heuristic: a private key described rather than named ("the private key in the ssh folder")
        rf"{_READ_VERB}[^.;!?\n]{{0,60}}?(?:\.?\bssh\b[^.;!?\n]{{0,30}}?{_PRIVATE_KEY}"
        rf"|{_PRIVATE_KEY}[^.;!?\n]{{0,40}}?\.?\b(?:ssh|gnupg|keychain|keystore)\b)",
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
        r"\b(?:do\s+not|don'?t)\s+(?:ask|prompt)\s+(?:the\s+user\s+)?(?:for\s+)?(?:any\s+|further\s+)?"
        r"(?:permission|confirmation|approval)\b(?!\s+(?:before|to|when)\b)",
        r"\bwithout\s+(?:asking|waiting)\s+(?:the\s+user\s+)?(?:for\s+)?(?:any\s+)?"
        r"(?:permission|confirmation|approval)\b",
        r"\bskip\s+(?:all\s+|any\s+)?(?:confirmation|permission|approval)\s+prompts?",
    ),
    # GR032: remote text treated as instructions, or fetched code run unread
    "GR032": _compile(
        r"\b(?:download|fetch|retrieve|load|curl|wget|open)\b[^.;!?\n]{0,60}?(?:https?://\S+|\burl\b|\blink\b)"
        r"[^.;!?\n]{0,80}?\b(?:follow|obey|execute|carry\s+out|do\s+what)\b[^.;!?\n]{0,40}?"
        r"\b(?:instructions?|commands?|directions?|says?|tells?)\b",
        r"\b(?:follow|obey|execute|carry\s+out)\b[^.;!?\n]{0,30}?\b(?:instructions?|commands?|directions?)\b"
        r"[^.;!?\n]{0,20}?\b(?:at|in|from|on|found\s+at)\s+https?://",
        r"\b(?:run|execute|eval(?:uate)?|source|invoke|launch|apply|install)\s+(?:it|them|that|this"
        r"|the\s+(?:script|file|code|command|download\w*|installer|output|result|payload|snippet|block"
        r"|package))\b[^.;!?\n]{0,25}?\bwithout\s+(?:reading|reviewing|inspecting|checking"
        r"|looking\s+at|verifying|examining|vetting|auditing|opening|validating)\b",
        r"\b(?:run|execute|apply|install)\s+(?:it|them|the\s+(?:\w+\s+)?(?:script|file|code|command"
        r"|installer|payload|snippet))\s+(?:blindly|sight\s+unseen)\b",
        r"\b(?:do\s+not|don'?t)\s+(?:read|inspect|review|check)\s+(?:it|them|the\s+(?:script|file|code"
        r"|command|installer))\b[^.;!?\n]{0,20}?\b(?:just\s+)?(?:run|execute)\b",
        # the same in Spanish, Portuguese, French and German (a pronoun or a named object, so that
        # "ejecuta los tests sin leer el log" is not matched)
        r"\b(?:ejec[uú]ta|ejecutar|corre|correr|lanza|aplica|instala)(?:lo|la|los|las)\b[^.;!?\n]{0,30}?"
        r"\bsin\s+(?:leer\w*|revisar\w*|inspeccionar\w*|verificar\w*|comprobar\w*|mirar\w*)",
        r"\b(?:ejec[uú]ta|corre|lanza|aplica|instala)\s+(?:el|la)\s+(?:script|archivo|c[oó]digo|comando"
        r"|descarga|instalador|resultado|salida|paquete)\b[^.;!?\n]{0,30}?\bsin\s+(?:leer\w*|revisar\w*"
        r"|inspeccionar\w*|verificar\w*|comprobar\w*|mirar\w*)",
        r"\b(?:execute|rode|aplique|instale)(?:-(?:o|a|os|as)|\s+(?:o|a)\s+(?:script|arquivo|c[óo]digo"
        r"|comando|instalador|resultado|pacote))\b[^.;!?\n]{0,30}?\bsem\s+(?:ler|revisar|inspecionar"
        r"|verificar|checar|olhar)\b",
        r"\b(?:ex[ée]cute|ex[ée]cutez|lance|applique|installe)(?:-(?:le|la|les)|\s+(?:le|la)\s+(?:script|fichier|code"
        r"|commande|installeur|r[ée]sultat))\b[^.;!?\n]{0,30}?\bsans\s+(?:l[ea]s?\s+)?(?:lire|relire"
        r"|v[ée]rifier|inspecter|examiner|regarder)\b",
        r"\bf[üu]hr\w*\s+(?:es|das\s+Skript|die\s+Datei|den\s+Code|den\s+Befehl|das\s+Ergebnis)\b"
        r"[^.;!?\n]{0,30}?\bohne\s+(?:zu\s+)?(?:lesen|pr[üu]fen|Pr[üu]fung|Durchsicht|Kontrolle)\b",
    ),
    # GR033: an instruction asking to be carried through compaction, summaries or new sessions
    "GR033": _compile(
        r"\b(?:this|these)\s+(?:instructions?|rules?|message|text|section|prompt|note)\b[^.;!?\n]{0,50}?"
        r"\b(?:surviv\w+|persist\w*|carr(?:y|ied)\s+over|remain\w*|kept|preserved|retained)\b"
        r"[^.;!?\n]{0,40}?\b(?:compact\w*|summar\w+|context\s+(?:reset|clear\w*|window)|new\s+session"
        r"|next\s+(?:session|conversation))",
        r"\b(?:preserve|retain|keep|include|repeat|copy|carry|reproduce)\b[^.;!?\n]{0,30}?"
        r"\b(?:this|these)\s+(?:instructions?|rules?|message|text|section|prompt|note)\b[^.;!?\n]{0,60}?"
        r"\b(?:summar\w+|compact\w*|memory|new\s+session|next\s+(?:session|conversation)"
        r"|future\s+(?:sessions|conversations)|every\s+(?:response|reply|message))",
        r"\bsurvive\s+(?:context\s+)?(?:compaction|summari[sz]ation)\b",
        r"\b(?:estas|estos)\s+(?:instrucciones|reglas|mensaje|texto|secci[oó]n)\b[^.;!?\n]{0,50}?"
        r"\b(?:sobrevivir|persistir|conservar\w*|mantener\w*|preservar\w*)\b[^.;!?\n]{0,40}?"
        r"\b(?:compactaci[oó]n|compactar\w*|resum\w+|nueva\s+sesi[oó]n|pr[oó]xima\s+sesi[oó]n)",
        r"\bsobreviv\w+\s+a\s+la\s+(?:compactaci[oó]n|resumen)\b",
        r"\b(?:copia|incluye|repite|conserva)\b[^.;!?\n]{0,30}?\b(?:este|estas|estos)\s+(?:mensaje|instrucciones"
        r"|reglas|texto)\b[^.;!?\n]{0,60}?\b(?:resumen|resumes|compactaci[oó]n|memoria|cada\s+respuesta)",
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
    not embedded in a path/URL, or hex that is not a standard digest length. ``data:...;base64,``
    URIs are skipped.
    """
    found: list[EncodedRun] = []
    for match in _BASE64_RE.finditer(text):
        before = text[: match.start()]
        if before.endswith("base64,") or _SRI_PREFIX.search(before) or _in_url(text, match.start()):
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
        if len(match.group()) % 2 or shannon_entropy(match.group()) < _HEX_MIN_ENTROPY:
            continue
        decoded = _decode_text(bytes.fromhex(match.group()))
        if decoded is not None or len(match.group()) not in _DIGEST_HEX_LENGTHS:
            found.append(EncodedRun(match.start(), match.end(), decoded))
    return sorted(found)


def find_encoded_payloads(text: str) -> list[EncodedRun]:
    """The subset of ``find_encoded_runs`` that decodes to printable text."""
    return [run for run in find_encoded_runs(text) if run.decoded is not None]


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
