"""JSON report: ``{"version", "scanned_files", "findings", "summary", ...}``."""

from __future__ import annotations

import json
from typing import Any

from ghostrules import __version__
from ghostrules.models import ScanResult
from ghostrules.reporters.common import safe, severity_counts


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return safe(value)
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def to_dict(result: ScanResult) -> dict[str, Any]:
    """The report as plain data."""
    return _clean(
        {
            "version": __version__,
            "scanned_files": result.scanned_files,
            "findings": [f.to_dict() for f in result.findings],
            "summary": {
                "total": len(result.findings),
                "by_severity": severity_counts(result.findings),
                "files_with_findings": len({f.path for f in result.findings}),
                "suppressed": result.suppressed,
                "baselined": result.baselined,
                "config_source": result.config_source,
            },
            "warnings": result.warnings,
            "errors": result.errors,
        }
    )


def render(result: ScanResult, **_options: Any) -> str:
    """Render the JSON report."""
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"
