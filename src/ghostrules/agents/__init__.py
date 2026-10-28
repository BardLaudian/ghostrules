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
from ghostrules.agents.copilot_cli import CopilotCli
from ghostrules.agents.cursor import Cursor
from ghostrules.agents.generic import Generic
from ghostrules.agents.repo import Repo

AGENT_NAMES: tuple[str, ...] = ("claude-code", "copilot-cli", "cursor", "generic")


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
    raise ValueError(f"unknown agent {name!r} (expected one of: {', '.join(AGENT_NAMES)})")


__all__ = [
    "AGENT_NAMES",
    "DEFAULT_MODE",
    "MODES",
    "AgentModel",
    "ClaudeCode",
    "ContextEntry",
    "ContextGraph",
    "CopilotCli",
    "Cursor",
    "Generic",
    "ImportEdge",
    "Load",
    "Repo",
    "get_model",
]
