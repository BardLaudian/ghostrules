"""Core data models: severities, findings, scan targets and scan results."""

from __future__ import annotations

import enum
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from ghostrules.markdown_utils import FencedBlock, fenced_blocks, inline_code_spans
from ghostrules.secrets import mask_secrets

_HTML_COMMENT_RE = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)

if TYPE_CHECKING:
    from ghostrules.mcp_config import ServerDef

Kind = Literal["instructions", "config", "other", "script"]
"""What a scanned file is: agent instructions, agent/MCP config, or any other text file."""


class Severity(enum.IntEnum):
    """Finding severity. Ordered: ``CRITICAL > HIGH > MEDIUM > LOW > INFO``."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity name, raising ``ValueError`` if unknown."""
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    @property
    def label(self) -> str:
        """Lower-case name, as used in CLI flags, config and reports."""
        return self.name.lower()

    def bumped(self) -> Severity:
        """One level more severe, capped at ``CRITICAL``."""
        return Severity(min(int(self) + 1, int(Severity.CRITICAL)))


@dataclass(frozen=True)
class Finding:
    """A single issue reported by a rule. Line/column are 1-based, in Unicode code points."""

    rule_id: str
    severity: Severity
    title: str
    message: str
    path: str
    line: int
    column: int
    end_column: int
    snippet: str
    decoded: str | None = None
    fix_hint: str = ""
    via: tuple[str, ...] = ()
    agents: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    confidence: str = ""

    def __post_init__(self) -> None:
        # Single choke point: whatever built this finding, no secret survives in its text, so no
        # reporter can print one.
        for name in ("title", "message", "snippet", "decoded", "fix_hint"):
            value = getattr(self, name)
            if value:
                object.__setattr__(self, name, mask_secrets(value))

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form; ``via``, ``agents`` and ``tags`` appear only when set."""
        data = self._base_dict()
        for name in ("via", "agents", "tags"):
            value = getattr(self, name)
            if value:
                data[name] = list(value)
        if self.confidence:
            data["confidence"] = self.confidence
        return data

    def _base_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_column": self.end_column,
            "snippet": self.snippet,
            "decoded": self.decoded,
            "fix_hint": self.fix_hint,
        }


class AgentView(NamedTuple):
    """How one agent sees a file: the line ranges of block-level HTML comments it strips before
    the text reaches the model, and whether that is uncertain."""

    agent: str
    stripped: tuple[tuple[int, int], ...] = ()
    unverified: bool = False

    def hides_line(self, line: int) -> bool:
        """Whether ``line`` lies in a comment this agent strips."""
        return any(a <= line <= b for a, b in self.stripped)


@dataclass
class ScanTarget:
    """A file (or derived text) handed to rules. Rules must treat it as read-only.

    ``origin`` is ``None`` for real files; for text derived from a finding (e.g. decoded hidden
    text) it holds the id of the rule that produced it. ``allow_domains`` is the configured
    allow-list and ``trust_known_installers`` the matching switch, handed to rules as read-only
    input so they stay pure.
    """

    path: str
    kind: Kind
    text: str
    parsed: Any = None
    parse_error: str | None = None
    origin: str | None = None
    allow_domains: tuple[str, ...] = ()
    trust_known_installers: bool = True
    first_party: tuple[Any, ...] = ()
    agent_views: tuple[AgentView, ...] = ()
    lines: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.lines = [line.removesuffix("\r") for line in self.text.split("\n")]

    @cached_property
    def _line_starts(self) -> list[int]:
        starts = [0]
        for i, ch in enumerate(self.text):
            if ch == "\n":
                starts.append(i + 1)
        return starts

    @cached_property
    def normalized(self) -> tuple[str, list[int]]:
        """Whitespace-normalised text plus, for each of its characters, the original offset.

        Every run of whitespace becomes one space, so phrases broken across lines still match.
        """
        chars: list[str] = []
        offsets: list[int] = []
        in_space = False
        for i, ch in enumerate(self.text):
            if ch.isspace():
                if not in_space:
                    chars.append(" ")
                    offsets.append(i)
                in_space = True
            else:
                chars.append(ch)
                offsets.append(i)
                in_space = False
        return "".join(chars), offsets

    @cached_property
    def servers(self) -> list[ServerDef]:
        """MCP servers defined in this config file (computed once)."""
        from ghostrules.mcp_config import extract_servers

        return extract_servers(self)

    @cached_property
    def code_blocks(self) -> list[FencedBlock]:
        """Fenced Markdown code blocks in the text (computed once)."""
        return fenced_blocks(self.text)

    @cached_property
    def inline_code(self) -> list[tuple[int, int]]:
        """Spans of inline code (backticks) in the text (computed once)."""
        return inline_code_spans(self.text)

    def code_span_at(self, offset: int) -> tuple[int, int] | None:
        """The inline code span containing ``offset``, if any."""
        for start, end in self.inline_code:
            if start <= offset < end:
                return start, end
        return None

    def in_inline_code(self, offset: int) -> bool:
        """Whether ``offset`` is inside an inline code span."""
        return self.code_span_at(offset) is not None

    def code_block_at(self, offset: int) -> FencedBlock | None:
        """The fenced code block containing ``offset``, if any."""
        for block in self.code_blocks:
            if block.start <= offset < block.end:
                return block
        return None

    @cached_property
    def html_comments(self) -> list[tuple[int, int]]:
        """Spans of HTML comments a renderer hides but an agent may read (computed once).

        Empty for config files. Comments in fenced code or inline code render as written, so they
        are not hidden. An unterminated ``<!--`` hides the rest of the document.
        """
        if self.kind == "config":
            return []
        spans = []
        for match in _HTML_COMMENT_RE.finditer(self.text):
            if self.code_block_at(match.start()) is None and not self.in_inline_code(match.start()):
                spans.append((match.start(), match.end()))
        return spans

    def in_html_comment(self, offset: int) -> bool:
        """Whether ``offset`` is inside a hidden HTML comment."""
        return any(start <= offset < end for start, end in self.html_comments)

    def offset(self, line: int, column: int) -> int:
        """Character offset of a 1-based ``(line, column)`` (clamped to the text)."""
        index = min(max(line, 1), len(self._line_starts)) - 1
        return min(self._line_starts[index] + max(column, 1) - 1, len(self.text))

    def position(self, offset: int) -> tuple[int, int]:
        """Convert a character offset into a 1-based ``(line, column)`` pair."""
        index = bisect_right(self._line_starts, offset) - 1
        return index + 1, offset - self._line_starts[index] + 1


@dataclass
class ScanResult:
    """Everything a scan produced.

    ``suppressed`` counts findings hidden by inline ``ghostrules-ignore`` comments, so reports can
    surface it. ``warnings`` are non-fatal (unreadable file, unparsable JSON); ``errors`` are rule
    crashes, which callers should treat as a failed scan.
    """

    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    suppressed: int = 0
    baselined: int = 0
    config_source: str | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
