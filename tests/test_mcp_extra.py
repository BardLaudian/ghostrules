"""GR102 (ranges, tags, -y), GR109, GR114, GR115 and GR116: a bad and a good config for each."""

from __future__ import annotations

import json

import pytest
from _analyze import analyze


def rules(server: dict) -> dict[str, list[dict]]:
    config = json.dumps({"mcpServers": {"s": server}}, indent=2)
    found: dict[str, list[dict]] = {}
    for f in analyze({".mcp.json": config}, strict=True)["findings"]:
        found.setdefault(f["rule_id"], []).append(f)
    return found


def npx(*args: str, **extra: object) -> dict:
    return {"command": "npx", "args": list(args), **extra}


@pytest.mark.parametrize(
    "spec", ["pkg@^1.2.0", "pkg@~1.2.0", "pkg@*", "pkg@latest", "pkg@next", "pkg@>=1", "pkg"]
)
def test_gr102_catches_ranges_tags_and_no_version(spec: str) -> None:
    assert "GR102" in rules(npx("-y", spec))


def test_gr102_accepts_an_exact_version_even_with_y() -> None:
    assert "GR102" not in rules(npx("-y", "pkg@1.2.3"))


def test_gr102_says_when_y_skips_the_install_prompt() -> None:
    (hit,) = rules(npx("-y", "pkg@latest"))["GR102"]
    assert "-y" in hit["message"]


# GR109 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "severity"),
    [
        (npx("--registry", "https://npm.attacker.example/", "pkg@1.0.0"), "medium"),
        (npx("--registry=http://npm.attacker.example", "pkg@1.0.0"), "high"),
        (
            {
                "command": "uvx",
                "args": ["--index-url", "https://pypi.attacker.example/s", "p==1.0"],
            },
            "medium",
        ),
        (npx("pkg@1.0.0", env={"NPM_CONFIG_REGISTRY": "https://npm.attacker.example"}), "medium"),
    ],
)
def test_gr109_flags_a_registry_that_is_not_public(server: dict, severity: str) -> None:
    (hit,) = rules(server)["GR109"]
    assert hit["severity"] == severity


def test_gr109_accepts_the_public_registries() -> None:
    assert "GR109" not in rules(npx("--registry", "https://registry.npmjs.org/", "pkg@1.0.0"))
    assert "GR109" not in rules(
        {"command": "uvx", "args": ["--index-url", "https://pypi.org/simple", "p==1"]}
    )


# GR114 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", [True, "*", ["*"]])
def test_gr114_flags_approve_all(value: object) -> None:
    assert "GR114" in rules(npx("pkg@1.0.0", autoApprove=value))
    assert "GR114" in rules(npx("pkg@1.0.0", alwaysAllow=value))


@pytest.mark.parametrize("value", [False, [], ["read_file", "list_directory"]])
def test_gr114_accepts_a_named_list_or_nothing(value: object) -> None:
    assert "GR114" not in rules(npx("pkg@1.0.0", autoApprove=value))


# GR115 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "server",
    [
        npx("pkg@1.0.0", "--host", "0.0.0.0"),
        npx("pkg@1.0.0", "--bind=0.0.0.0:8080"),
        npx("pkg@1.0.0", env={"HOST": "0.0.0.0"}),
        {"command": "docker", "args": ["run", "-p", "0.0.0.0:8080:80", "img"]},
        npx("pkg@1.0.0", "--host", "::"),
    ],
)
def test_gr115_flags_listening_on_every_interface(server: dict) -> None:
    assert "GR115" in rules(server)


@pytest.mark.parametrize(
    "server",
    [
        npx("pkg@1.0.0", "--host", "127.0.0.1"),
        npx("pkg@1.0.0", "--host=localhost", "--port", "8080"),
        npx("pkg@1.0.0", "--ip", "10.10.0.0.1"),
        npx("pkg@1.0.0", "--range", "10.0.0.0/8"),
    ],
)
def test_gr115_accepts_loopback_and_other_addresses(server: dict) -> None:
    assert "GR115" not in rules(server)


# GR116 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "@modelcontextprotocol/server-filesytem",
        "@modelcontextprotocol/server-githubb",
        "@modelcontextprotoco1/server-github",
        "mcp-server-fecth",
        "@upstash/context7-mpc",
    ],
)
def test_gr116_flags_a_name_one_typo_from_a_popular_server(name: str) -> None:
    assert "GR116" in rules(npx("-y", f"{name}@1.0.0"))


@pytest.mark.parametrize(
    "name",
    [
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "mcp-server-fetch",
        "my-company-mcp-tools",
        "@acme/mcp-server-orders",
    ],
)
def test_gr116_accepts_exact_and_unrelated_names(name: str) -> None:
    assert "GR116" not in rules(npx("-y", f"{name}@1.0.0"))
