"""Agent models: how each supported agent loads instructions (``docs/AGENT_MODELS.md``)."""

from __future__ import annotations

from ghostrules.agents.base import (
    AgentModel,
    ContextEntry,
    ContextGraph,
    ImportEdge,
    Load,
)
from ghostrules.agents.claude_code import DEFAULT_MODE, MODES, ClaudeCode
from ghostrules.agents.codex import Codex
from ghostrules.agents.copilot_cli import CopilotCli
from ghostrules.agents.cursor import Cursor
from ghostrules.agents.gemini_cli import GeminiCli
from ghostrules.agents.generic import Generic
from ghostrules.agents.repo import Repo

DEFAULT_AGENTS: tuple[str, ...] = ("claude-code", "copilot-cli", "cursor", "generic")
AGENT_NAMES: tuple[str, ...] = (*DEFAULT_AGENTS, "codex", "gemini-cli")


def get_model(name: str, *, instructions_mode: str = DEFAULT_MODE) -> AgentModel:
    """The model for an agent name; ``ValueError`` for an unknown one."""
    if name == "claude-code":
        return ClaudeCode(instructions_mode)
    if name == "copilot-cli":
        return CopilotCli()
    if name == "cursor":
        return Cursor()
    if name == "generic":
        return Generic()
    if name == "codex":
        return Codex()
    if name == "gemini-cli":
        return GeminiCli()
    raise ValueError(f"unknown agent {name!r} (expected one of: {', '.join(AGENT_NAMES)})")


__all__ = [
    "AGENT_NAMES",
    "DEFAULT_AGENTS",
    "DEFAULT_MODE",
    "MODES",
    "AgentModel",
    "ClaudeCode",
    "Codex",
    "ContextEntry",
    "ContextGraph",
    "CopilotCli",
    "Cursor",
    "Generic",
    "GeminiCli",
    "ImportEdge",
    "Load",
    "Repo",
    "get_model",
]
