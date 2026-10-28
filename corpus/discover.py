"""Find popular public repositories that contain AI agent files (candidates for the corpus).

    python corpus/discover.py --min-stars 2000 --language python,typescript --months 6
    python corpus/discover.py --propose regression:300

Uses the ``gh`` CLI (your token, never stored). Responses are cached in ``corpus/.cache/`` so a run
can be resumed. It prints candidates as JSON to ``--out`` and, with ``--propose tier:N``, a TOML
block to paste into ``repos.toml``; it never writes ``repos.toml`` itself (the human picks
the tiers).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

from common import (
    CORPUS_DIR,
    TIERS,
    CorpusError,
    Proc,
    Runner,
    load_repos,
    read_json,
    subprocess_runner,
    valid_repo,
    write_json,
)

from ghostrules.targets import classify_path

CACHE_DIR = CORPUS_DIR / ".cache"
EXTRA_TARGETS = (".claude/rules/**/*.md",)
SEARCH_PAGES = 10  # the search API returns at most 1,000 results per query
PER_PAGE = 100


class GhClient:
    """``gh api`` with cache and rate-limit handling. ``sleep`` and ``now`` are injectable."""

    def __init__(
        self,
        runner: Runner = subprocess_runner,
        cache_dir: Path = CACHE_DIR,
        *,
        refresh: bool = False,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.runner, self.cache_dir, self.refresh = runner, cache_dir, refresh
        self.sleep, self.now = sleep, now
        self.remaining: int | None = None

    def get(self, endpoint: str) -> tuple[int, Any]:
        """``(status, parsed JSON body)``. Responses with status 200 and 404/409/451 are cached."""
        key = hashlib.sha256(endpoint.encode()).hexdigest()[:24]
        cached = self.cache_dir / f"{key}.json"
        if cached.is_file() and not self.refresh:
            data = read_json(cached)
            return data["status"], data["body"]
        while True:
            proc = self.runner(["gh", "api", "-i", "--", endpoint], timeout=120)
            if proc.returncode == 127:
                raise CorpusError("the gh CLI is not installed or not on PATH")
            status, headers, body = parse_response(proc)
            self.remaining = _int(headers.get("x-ratelimit-remaining"), self.remaining)
            reset = _int(headers.get("x-ratelimit-reset"), 0) or 0
            limited = status in (403, 429) and (self.remaining == 0 or "retry-after" in headers)
            if limited:
                wait = _int(headers.get("retry-after"), None)
                delay = wait if wait is not None else max(1.0, reset - self.now() + 1)
                self.sleep(min(delay, 3700))
                continue
            break
        if status == 0:
            raise CorpusError(f"gh api failed: {proc.stderr.strip()[:200]}")
        if self.remaining == 0 and reset:  # next call would fail: wait now
            self.sleep(min(max(1.0, reset - self.now() + 1), 3700))
        if status in (200, 404, 409, 451):
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            write_json(cached, {"status": status, "body": body})
        return status, body


def _int(value: str | None, default: int | None) -> int | None:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def parse_response(proc: Proc) -> tuple[int, dict[str, str], Any]:
    """Split ``gh api -i`` output into status, lower-cased headers and the JSON body."""
    head, _, body = proc.stdout.replace("\r\n", "\n").partition("\n\n")
    lines = head.splitlines()
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return 0, {}, None
    headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
    try:
        return status, headers, json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        return status, headers, None


def search_query(
    min_stars: int, language: str, months: int, today: dt.date, max_stars: int = 0
) -> str:
    """The repository search query (not archived, not a fork, pushed recently). With
    ``max_stars`` the star range is closed."""
    since = (today - dt.timedelta(days=30 * months)).isoformat()
    stars = f"stars:{min_stars}..{max_stars}" if max_stars else f"stars:>={min_stars}"
    parts = [stars, "archived:false", "fork:false", f"pushed:>{since}"]
    if language:
        parts.append(f"language:{language}")
    return " ".join(parts)


def search_repos(client: GhClient, query: str, pages: int = SEARCH_PAGES) -> list[dict[str, Any]]:
    """Repositories matching ``query``, most starred first."""
    found: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        endpoint = (
            f"search/repositories?q={quote(query)}&sort=stars&order=desc"
            f"&per_page={PER_PAGE}&page={page}"
        )
        status, body = client.get(endpoint)
        if status != 200 or not isinstance(body, dict):
            raise CorpusError(f"search failed with HTTP {status}")
        items = body.get("items", [])
        found += items
        if len(items) < PER_PAGE:
            break
    return found


def agent_files(client: GhClient, repo: str, branch: str) -> list[str] | None:
    """Agent files of ``repo`` from one Git trees call; ``None`` (unknown) when the tree is
    truncated or unavailable. Nothing is guessed."""
    status, body = client.get(f"repos/{repo}/git/trees/{quote(branch, safe='')}?recursive=1")
    if status != 200 or not isinstance(body, dict) or body.get("truncated"):
        return None
    files = []
    for node in body.get("tree", []):
        path = node.get("path", "")
        if node.get("type") == "blob" and classify_path(path, EXTRA_TARGETS):
            files.append(path)
    return sorted(files)


def discover(
    client: GhClient, queries: list[str], limit: int = 0, per_query: int = 0
) -> list[dict[str, Any]]:
    """Candidates with stars, language and agent files (``None`` = unknown). ``per_query`` keeps
    only the most starred results of each query."""
    seen: dict[str, dict[str, Any]] = {}
    for query in queries:
        pages = -(-per_query // PER_PAGE) if per_query else SEARCH_PAGES
        for item in search_repos(client, query, pages)[: per_query or None]:
            name = item.get("full_name", "")
            if valid_repo(name) and name not in seen and not item.get("fork"):
                seen[name] = item
    candidates = []
    for name, item in seen.items():
        files = agent_files(client, name, item.get("default_branch") or "HEAD")
        candidates.append(
            {
                "name": name,
                "stars": item.get("stargazers_count", 0),
                "language": item.get("language") or "",
                "agent_files": files,
            }
        )
        if limit and len(candidates) >= limit:
            break
    return candidates


def propose(candidates: list[dict[str, Any]], tier: str, count: int) -> str:
    """A TOML block of up to ``count`` repos that have agent files, taken round-robin across
    languages (most starred first within each), for the human to review and paste."""
    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in sorted(candidates, key=lambda c: -c["stars"]):
        if c["agent_files"]:
            by_language[c["language"] or "other"].append(c)
    chosen: list[dict[str, Any]] = []
    queues = sorted(by_language.values(), key=lambda q: -q[0]["stars"])
    while len(chosen) < count and any(queues):
        for queue in queues:
            if queue and len(chosen) < count:
                chosen.append(queue.pop(0))
    lines = [f"# proposed: {len(chosen)} repos, tier {tier}, {dt.date.today().isoformat()}"]
    for c in sorted(chosen, key=lambda c: c["name"].lower()):
        lines += ["[[repo]]", f'name = "{c["name"]}"', f'tier = "{tier}"', ""]
    return "\n".join(lines)


def parse_strata(spec: str) -> list[tuple[int, int]]:
    """``"500-1999,2000-9999,10000-"`` -> ``[(500, 1999), (2000, 9999), (10000, 0)]``."""
    out = []
    for part in spec.split(","):
        lo, _, hi = part.strip().partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            raise CorpusError(f"bad stratum {part!r}: expected LOW-HIGH or LOW-")
        out.append((int(lo), int(hi) if hi else 0))
    return out


def stratum_name(lo: int, hi: int) -> str:
    """A label such as ``500-1999`` or ``10000+``."""
    return f"{lo}-{hi}" if hi else f"{lo}+"


def discover_strata(
    client: GhClient,
    strata: list[tuple[int, int]],
    languages: list[str],
    months: int,
    per_cell: int,
    today: dt.date,
) -> list[dict[str, Any]]:
    """Candidates of every (stars range x language) cell, each tagged with its ``stratum``."""
    out: list[dict[str, Any]] = []
    for lo, hi in strata:
        for lang in languages:
            query = search_query(lo, lang, months, today, hi)
            for c in discover(client, [query], per_query=per_cell):
                out.append({**c, "stratum": stratum_name(lo, hi)})
    return out


def propose_strata(
    candidates: list[dict[str, Any]], tier: str, per_stratum: int, exclude: set[str]
) -> str:
    """Like ``propose`` but ``per_stratum`` repos from each stars stratum (round-robin across
    languages), skipping ``exclude`` (repos already in another tier)."""
    chosen: list[dict[str, Any]] = []
    for stratum in dict.fromkeys(c["stratum"] for c in candidates):
        pool = [
            c
            for c in candidates
            if c["stratum"] == stratum and c["name"] not in exclude and c["agent_files"]
        ]
        chosen += _round_robin(pool, per_stratum)
    lines = [f"# proposed: {len(chosen)} repos, tier {tier}, {dt.date.today().isoformat()}"]
    for c in sorted(chosen, key=lambda c: c["name"].lower()):
        lines += ["[[repo]]", f'name = "{c["name"]}"', f'tier = "{tier}"', ""]
    return "\n".join(lines)


def _round_robin(pool: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in sorted(pool, key=lambda c: -c["stars"]):
        by_language[c["language"] or "other"].append(c)
    queues = sorted(by_language.values(), key=lambda q: -q[0]["stars"])
    chosen: list[dict[str, Any]] = []
    while len(chosen) < count and any(queues):
        for queue in queues:
            if queue and len(chosen) < count:
                chosen.append(queue.pop(0))
    return chosen


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Discover corpus candidates with the gh CLI.")
    p.add_argument("--min-stars", type=int, default=2000)
    p.add_argument("--language", default="", help="comma-separated; empty = any")
    p.add_argument("--months", type=int, default=6, help="pushed within this many months")
    p.add_argument("--limit", type=int, default=0, help="stop after this many candidates")
    p.add_argument("--out", type=Path, default=CACHE_DIR / "candidates.json")
    p.add_argument("--refresh", action="store_true", help="ignore the cache")
    p.add_argument("--propose", metavar="TIER:N", help="print a TOML block, e.g. regression:300")
    p.add_argument("--strata", help='stars strata, e.g. "500-1999,2000-9999,10000-"')
    p.add_argument("--per-cell", type=int, default=150, help="candidates per stratum x language")
    p.add_argument("--per-stratum", type=int, default=500, help="repos proposed per stratum")
    p.add_argument("--exclude-tier", help="skip repos of this tier in repos.toml")
    p.add_argument("--from-file", type=Path, help="propose from an earlier --out file")
    args = p.parse_args(argv)
    try:
        if args.from_file:
            candidates = read_json(args.from_file)
        else:
            languages = [lang.strip() for lang in args.language.split(",")] or [""]
            today = dt.date.today()
            client = GhClient(refresh=args.refresh)
            if args.strata:
                candidates = discover_strata(
                    client, parse_strata(args.strata), languages, args.months, args.per_cell, today
                )
            else:
                queries = [
                    search_query(args.min_stars, lang, args.months, today) for lang in languages
                ]
                candidates = discover(client, queries, args.limit)
            write_json(args.out, candidates)
            known = sum(1 for c in candidates if c["agent_files"])
            unknown = sum(1 for c in candidates if c["agent_files"] is None)
            print(f"{len(candidates)} candidates, {known} with agent files, {unknown} unknown")
        if args.propose:
            tier, _, count = args.propose.partition(":")
            if tier not in TIERS or not count.isdigit():
                raise CorpusError(f"--propose expects TIER:N with TIER in {', '.join(TIERS)}")
            if args.strata or any("stratum" in c for c in candidates):
                skip = {
                    e.name
                    for e in load_repos(CORPUS_DIR / "repos.toml")
                    if e.tier == args.exclude_tier
                }
                print(propose_strata(candidates, tier, args.per_stratum, skip))
            else:
                print(propose(candidates, tier, int(count)))
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
