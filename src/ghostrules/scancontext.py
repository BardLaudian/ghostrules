"""What the graph rules (GR020-GR025) get: every agent's import graph and the scanned files."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ghostrules.agents.base import ContextGraph
from ghostrules.models import ScanTarget


@dataclass
class ScanContext:
    """One scan root's view for graph rules.

    ``graphs`` maps an agent name to its context graph (session started at the root).
    ``targets`` holds the files that were actually loaded for scanning, keyed by graph path;
    findings can only be placed in those. ``label`` maps a graph path to the path reported to the
    user (they differ when several roots are scanned).
    """

    graphs: dict[str, ContextGraph]
    targets: dict[str, ScanTarget] = field(default_factory=dict)
    label: Callable[[str], str] = lambda path: path
    excluded: Callable[[str], bool] = lambda path: False

    def target(self, path: str) -> ScanTarget | None:
        """The scanned file for a graph path, if there is one."""
        return self.targets.get(path)
