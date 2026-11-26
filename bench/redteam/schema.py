"""Validate red-team cases against bench/redteam/case_schema.toml and turn them into bench Cases."""

from __future__ import annotations

from typing import Any

from redteam_common import CLASSES, ORIGIN, Case, valid_id

MAX_FILES = 8
PAYLOAD_RANGE = (10, 400)
LITERAL_CLASSES = ("C3", "C4")


def _bad_path(path: object) -> bool:
    return (
        not isinstance(path, str)
        or not path
        or path.startswith(("/", "\\"))
        or ".." in path.replace("\\", "/").split("/")
    )


def validate(raw: dict[str, Any]) -> list[str]:
    """Return the problems of one case (empty when it is valid)."""
    problems: list[str] = []
    if not valid_id(raw.get("id")):
        problems.append("id: lowercase letters, digits and hyphens, 3 to 60 characters")
    if raw.get("class") not in CLASSES:
        problems.append(f"class: one of {', '.join(CLASSES)}")
    for key in ("technique", "description", "round"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            problems.append(f"{key}: a non-empty string")
    payload = raw.get("declared_payload")
    lo, hi = PAYLOAD_RANGE
    if not isinstance(payload, str) or not lo <= len(payload.strip()) <= hi:
        problems.append(f"declared_payload: a string of {lo} to {hi} characters")
    literal = raw.get("declared_literal")
    if raw.get("class") in LITERAL_CLASSES and (
        not isinstance(literal, str) or not 3 <= len(literal.strip()) <= 400
    ):
        problems.append("declared_literal: required for C3 and C4, 3 to 400 characters")
    if literal is not None and not isinstance(literal, str):
        problems.append("declared_literal: a string")
    if raw.get("origin") != ORIGIN:
        problems.append(f"origin: must be '{ORIGIN}'")
    files = raw.get("files")
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        problems.append(f"files: a table of 1 to {MAX_FILES} files")
    else:
        problems += [f"files: bad path {p!r}" for p in files if _bad_path(p)]
        problems += [
            f"files: {p!r} is not text" for p, t in files.items() if not isinstance(t, str)
        ]
    links = raw.get("symlinks", {})
    if not isinstance(links, dict):
        problems.append("symlinks: a table")
    else:
        problems += [f"symlinks: bad path {p!r}" for p in links if _bad_path(p)]
    return problems


def validate_round(cases: list[dict[str, Any]]) -> list[str]:
    """Validate every case and the uniqueness of ids."""
    problems: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(cases):
        label = str(raw.get("id", f"#{index}"))
        problems += [f"{label}: {p}" for p in validate(raw)]
        if label in seen:
            problems.append(f"{label}: duplicate id")
        seen.add(label)
    return problems


def to_case(raw: dict[str, Any]) -> Case:
    """The bench Case for a valid red-team case. The oracle never fills `expected`."""
    return Case(
        id=raw["id"],
        technique=raw["technique"],
        origin=raw["origin"],
        source="redteam-" + str(raw["round"]),
        description=raw["description"],
        expected=(),
        status="detected",
        files=dict(raw["files"]),
        symlinks=dict(raw.get("symlinks", {})),
    )
