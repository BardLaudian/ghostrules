"""Test helper: scan a dict of {path: text} as a repository and return the JSON report data."""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ghostrules.config import Config
from ghostrules.models import Severity
from ghostrules.reporters import json_
from ghostrules.scanner import scan_paths


def analyze(
    files: Mapping[str, str], *, strict: bool = False, min_severity: str = "low"
) -> dict[str, Any]:
    """Write ``files`` to a temp directory, scan it and return ``json_.to_dict(result)``."""
    with tempfile.TemporaryDirectory(prefix="ghostrules-test-") as tmp:
        root = Path(tmp)
        for path, text in files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.encode("utf-8", "surrogatepass"))
        config = Config(
            profile="strict" if strict else "default", min_severity=Severity.parse(min_severity)
        )
        return json_.to_dict(scan_paths([root], config))
