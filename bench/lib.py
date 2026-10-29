"""The attack set (recall) and the held-out benign set (precision) of docs/design/v0.4, W6.

Attack cases live in ``bench/attacks/*.toml``. They are written from public descriptions of real
techniques, defanged (``.example`` hosts, fake tokens) and free of invisible characters: the
committed files carry placeholders, which :func:`expand` turns into the characters when a case is
run. Nothing here executes what a case contains; a case is written to a temporary directory and
read by the scanner like any repository.

Placeholders: ``{tags:TEXT}`` (Unicode tag characters), ``{vs:TEXT}`` (variation selectors, one per
byte, as in the emoji-smuggling write-up), ``{b64:TEXT}``, ``{hex:TEXT}`` and ``{u+200B}`` (any
code point).
"""

from __future__ import annotations

import base64
import re
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomllib

from ghostrules.config import Config, load_config
from ghostrules.models import Severity
from ghostrules.scanner import scan_paths

HERE = Path(__file__).resolve().parent
ATTACKS = HERE / "attacks"
STATUSES = ("detected", "known-miss")
ORIGINS = ("public", "review", "ours")

_TOKEN = re.compile(r"\{(tags|vs|b64|hex):([^{}]*)\}|\{u\+([0-9A-Fa-f]{4,6})\}")


def _vs(data: bytes) -> str:
    """Each byte as one variation selector: 0-15 -> U+FE00.., 16-255 -> U+E0100.. (Butler)."""
    return "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in data)


def expand(text: str) -> str:
    """Replace the placeholders of a case with the characters they stand for."""

    def one(match: re.Match[str]) -> str:
        kind, body, codepoint = match.groups()
        if codepoint:
            return chr(int(codepoint, 16))
        if kind == "tags":
            return "".join(chr(0xE0000 + ord(c)) for c in body)
        if kind == "vs":
            return _vs(body.encode("utf-8"))
        if kind == "b64":
            return base64.b64encode(body.encode("utf-8")).decode("ascii")
        return body.encode("utf-8").hex()

    return _TOKEN.sub(one, text)


@dataclass(frozen=True)
class Case:
    id: str
    technique: str
    origin: str
    source: str
    description: str
    expected: tuple[str, ...]
    status: str
    files: dict[str, str]
    symlinks: dict[str, str] = field(default_factory=dict)
    note: str = ""


def load_cases(directory: Path = ATTACKS) -> list[Case]:
    cases: list[Case] = []
    for path in sorted(directory.glob("*.toml")):
        if path.name == "sources.toml":
            continue
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for raw in data.get("case", []):
            cases.append(
                Case(
                    id=raw["id"],
                    technique=raw["technique"],
                    origin=raw["origin"],
                    source=raw["source"],
                    description=raw["description"],
                    expected=tuple(raw["expected"]),
                    status=raw["status"],
                    files=dict(raw["files"]),
                    symlinks=dict(raw.get("symlinks", {})),
                    note=raw.get("note", ""),
                )
            )
    return cases


def load_sources(directory: Path = ATTACKS) -> dict[str, dict[str, str]]:
    data = tomllib.loads((directory / "sources.toml").read_text(encoding="utf-8"))
    return {k: dict(v) for k, v in data["source"].items()}


@dataclass(frozen=True)
class Outcome:
    case: Case
    rules: tuple[str, ...]  # every rule that fired, whatever its severity
    reported: bool  # an expected rule fired at the default profile (shown findings)
    fails_ci: bool  # ... at high or critical, so the default `--fail-on high` fails


def run_case(case: Case, config: Config | None = None) -> Outcome:
    """Write the case to a temporary directory and scan it with the default settings."""
    with tempfile.TemporaryDirectory(prefix="ghostrules-bench-") as tmp:
        root = Path(tmp)
        for name, text in case.files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(expand(text).encode("utf-8"))
        for name, destination in case.symlinks.items():
            link = root / name
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(destination)
        # like `ghostrules scan DIR`: the directory's own .ghostrules.toml applies
        result = scan_paths([root], config or load_config(root))
    hits = [f for f in result.findings if f.rule_id in case.expected]
    return Outcome(
        case,
        tuple(sorted({f.rule_id for f in result.findings})),
        bool(hits),
        any(f.severity >= Severity.HIGH for f in hits),
    )


def run_attacks(cases: Iterable[Case], config: Config | None = None) -> list[Outcome]:
    return [run_case(c, config) for c in cases]


def recall_by_rule(outcomes: list[Outcome]) -> list[dict[str, Any]]:
    """Per expected rule: the cases that name it, how many it caught, how many fail the check."""
    rows: dict[str, dict[str, Any]] = {}
    for o in outcomes:
        for rule in o.case.expected:
            row = rows.setdefault(rule, {"rule": rule, "cases": 0, "reported": 0, "fails_ci": 0})
            row["cases"] += 1
            row["reported"] += o.reported
            row["fails_ci"] += o.fails_ci
    return sorted(rows.values(), key=lambda r: r["rule"])


def recall_table(outcomes: list[Outcome]) -> list[dict[str, Any]]:
    """Per technique: cases, reported, failing the default check. Misses stay in the base."""
    rows: dict[str, dict[str, Any]] = {}
    for o in outcomes:
        row = rows.setdefault(
            o.case.technique,
            {"technique": o.case.technique, "cases": 0, "reported": 0, "fails_ci": 0},
        )
        row["cases"] += 1
        row["reported"] += o.reported
        row["fails_ci"] += o.fails_ci
    return sorted(rows.values(), key=lambda r: r["technique"])


# --- precision on the held-out set --------------------------------------------------------------

LABELS = ("tp", "benign-context", "fp")


def precision_for_a_user(tp: int, benign: int, fp: int) -> float | None:
    """tp / (tp + benign-context + fp): a benign-context match is noise for a user."""
    total = tp + benign + fp
    return tp / total if total else None


def precision_table(
    findings: list[dict[str, Any]], labels: dict[str, str]
) -> tuple[list[dict[str, Any]], int]:
    """Per rule: findings, tp, benign-context, fp and unlabelled. Returns the rows and how many
    findings have no label; an unlabelled finding is never counted as correct."""
    rows: dict[str, dict[str, Any]] = {}
    unlabelled = 0
    for f in findings:
        row = rows.setdefault(
            f["rule_id"],
            {
                "rule": f["rule_id"],
                "findings": 0,
                "tp": 0,
                "benign-context": 0,
                "fp": 0,
                "unlabelled": 0,
            },
        )
        row["findings"] += 1
        label = labels.get(f["fingerprint"])
        if label in LABELS:
            row[label] += 1
        else:
            row["unlabelled"] += 1
            unlabelled += 1
    for row in rows.values():
        row["precision"] = precision_for_a_user(row["tp"], row["benign-context"], row["fp"])
    return sorted(rows.values(), key=lambda r: r["rule"]), unlabelled
