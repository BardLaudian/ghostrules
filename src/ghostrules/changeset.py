"""What a scan needs to compare the working tree with a trusted base ref (``change`` rules)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ghostrules.models import ScanTarget

# Text of a file at the base ref, addressed relative to the scanned directory; ``None`` when the
# file did not exist there.
ReadBase = Callable[[str], "str | None"]


@dataclass(frozen=True)
class ChangeBase:
    """Where the base versions come from: ``config`` for the scanner configuration and the lockfile,
    ``ignores`` for ``ghostrules-ignore`` comments. They are the same ref unless the caller gave
    two different ones."""

    config: ReadBase
    ignores: ReadBase
    config_ref: str
    ignores_ref: str


@dataclass(frozen=True)
class ChangeContext:
    """The scanned directory, the targets that were scanned and the base to compare them with."""

    root: Path
    lockfile: str
    base: ChangeBase
    targets: Mapping[str, ScanTarget]
