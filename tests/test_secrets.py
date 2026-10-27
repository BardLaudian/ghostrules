import pytest
from secret_samples import GENERIC, GITHUB, KNOWN

from ghostrules.models import Finding, Severity
from ghostrules.secrets import (
    apply_spans,
    is_placeholder,
    known_secret,
    looks_like_secret_value,
    map_offset,
    mask_secrets,
    mask_spans,
    mask_value,
)


def test_mask_value_format() -> None:
    assert mask_value(GITHUB) == "ghp_****…PLE0"
    assert mask_value("short") == "****"
    assert mask_value("x" * 19) == "****"
    assert mask_value("a" * 20) == "aaaa****…aaaa"


@pytest.mark.parametrize(("label", "value", "secret"), KNOWN)
def test_known_formats_are_detected_and_masked(label: str, value: str, secret: str) -> None:
    assert known_secret(f"prefix {value} suffix") == (label, secret)
    masked = mask_secrets(f"prefix {value} suffix")
    assert secret not in masked
    assert masked.startswith("prefix ")
    assert masked.endswith(" suffix")
    assert "****" in masked


@pytest.mark.parametrize(("label", "value", "secret"), KNOWN)
def test_masking_is_idempotent(label: str, value: str, secret: str) -> None:
    once = mask_secrets(value)
    assert mask_secrets(once) == once


def test_openai_pattern_does_not_swallow_anthropic_label() -> None:
    label, _ = known_secret("sk-ant-api03-EXAMPLEexampleEXAMPLE0123") or ("", "")
    assert label == "Anthropic API key"


@pytest.mark.parametrize(
    "text",
    [
        "token: ${GITHUB_TOKEN}",
        "Authorization: Bearer ${GITHUB_TOKEN}",
        "--token $TOKEN_VALUE_FROM_ENV",
        'API_KEY="<your-api-key>"',
        "api_key=your-api-key-here",
        "secret=xxxxxxxxxxxxxxxxxxxxxxxx",
        "password=%DB_PASSWORD_VARIABLE%",
        "just prose about a token and a key without values",
        "see https://example.com/some/long/path/with/key/in/it",
    ],
)
def test_placeholders_and_prose_are_left_alone(text: str) -> None:
    assert mask_secrets(text) == text


@pytest.mark.parametrize(
    "text",
    [
        f"GITHUB_TOKEN={GENERIC}",
        f'"api_key": "{GENERIC}"',
        f"export SECRET_KEY: {GENERIC}",
        f"run --api-token {GENERIC} --verbose",
        f"curl 'https://x.example/a?auth={GENERIC}&b=1'",
        f"db://user:{GENERIC}@host/db",
    ],
)
def test_generic_secrets_in_key_value_contexts_are_masked(text: str) -> None:
    masked = mask_secrets(text)
    assert GENERIC not in masked
    assert "****" in masked


def test_value_heuristics() -> None:
    assert looks_like_secret_value(GENERIC)
    assert not looks_like_secret_value("short")
    assert not looks_like_secret_value("a" * 40)  # low entropy
    assert not looks_like_secret_value("/usr/local/lib/python3.12/site-packages/x")
    assert not looks_like_secret_value("https://example.com/Zx9fQ2mK7pL4vR8tY1nB6cD3")
    assert not looks_like_secret_value("two words that are long enough though")
    assert is_placeholder("${A}")
    assert is_placeholder("<token>")
    assert not is_placeholder(GENERIC)


def test_spans_and_offset_mapping() -> None:
    text = f"a={GITHUB};b"
    spans = mask_spans(text)
    masked = apply_spans(text, spans)
    assert masked == "a=ghp_****…PLE0;b"
    start = text.index(GITHUB)
    assert map_offset(spans, 0) == 0
    assert map_offset(spans, start) == start
    assert map_offset(spans, start + 10) == start  # inside a secret: snaps to its start
    assert map_offset(spans, start + 10, end=True) == start + len("ghp_****…PLE0")
    assert map_offset(spans, len(text)) == len(masked)


def test_extra_secrets_are_masked_wherever_they_appear() -> None:
    masked = mask_secrets(f"{GENERIC} and again {GENERIC}", extra=[GENERIC])
    assert GENERIC not in masked
    assert masked.count("****") == 2


def test_finding_masks_every_text_field() -> None:
    finding = Finding(
        "GR900", Severity.HIGH, f"t {GITHUB}", f"m {GITHUB}", "a.md", 1, 1, 2,
        f"s {GITHUB}", decoded=f"d {GITHUB}", fix_hint=f"h {GITHUB}",
    )  # fmt: skip
    for text in (
        finding.title,
        finding.message,
        finding.snippet,
        finding.decoded,
        finding.fix_hint,
    ):
        assert text is not None
        assert GITHUB not in text
        assert "ghp_****…PLE0" in text
    assert GITHUB not in repr(finding)
    assert GITHUB not in str(finding.to_dict())


def test_secrets_glued_to_other_letters_are_still_masked() -> None:
    masked = mask_secrets("A" * 10 + GITHUB + "B" * 10)
    assert GITHUB[10:30] not in masked
    assert "****" in masked
    # ... but ordinary words ending in "sk-" are not mangled
    prose = "see task-management-system-design-overview for details"
    assert mask_secrets(prose) == prose
    # and detection (for GR101) still requires a proper boundary
    assert known_secret("A" * 10 + GITHUB) is None
