"""Phase 16: at least 100 benign documentation and policy twins must pass the default check."""

from pathlib import Path

import pytest
from benign_twins import TWINS

from ghostrules.config import load_config
from ghostrules.models import Severity
from ghostrules.scanner import scan_paths


def test_there_are_at_least_a_hundred_twins() -> None:
    assert len(TWINS) >= 100


@pytest.mark.parametrize("name", sorted(TWINS))
def test_benign_twin_passes_the_default_check(tmp_path: Path, name: str) -> None:
    file_name, text = TWINS[name]
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    findings = scan_paths([tmp_path], load_config(tmp_path)).findings
    failing = [f for f in findings if f.severity >= Severity.HIGH]
    assert not failing, [(f.rule_id, f.severity.label, f.snippet) for f in failing]
