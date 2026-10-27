import pytest

from ghostrules.models import Finding, ScanTarget, Severity


def test_severity_ordering() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_severity_parse_and_label() -> None:
    assert Severity.parse(" High ") is Severity.HIGH
    assert Severity.HIGH.label == "high"
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("urgent")


def test_severity_bump_is_capped_at_critical() -> None:
    assert Severity.MEDIUM.bumped() is Severity.HIGH
    assert Severity.CRITICAL.bumped() is Severity.CRITICAL


def test_finding_to_dict_uses_severity_label() -> None:
    finding = Finding("GR001", Severity.CRITICAL, "t", "m", "a.md", 1, 2, 3, "s")
    data = finding.to_dict()
    assert data["severity"] == "critical"
    assert data["decoded"] is None


def test_target_lines_strip_carriage_returns() -> None:
    target = ScanTarget("a.md", "instructions", "one\r\ntwo\nthree")
    assert target.lines == ["one", "two", "three"]


def test_target_position_is_one_based() -> None:
    target = ScanTarget("a.md", "instructions", "ab\ncde\n")
    assert target.position(0) == (1, 1)
    assert target.position(1) == (1, 2)
    assert target.position(3) == (2, 1)
    assert target.position(5) == (2, 3)
