"""Clone each corpus repository shallowly, scan it, write results without file contents.

    python corpus/run.py --tier regression
    python corpus/run.py --repos owner/a,owner/b

Output: ``results/<date>/<owner>__<repo>.json`` per repository, ``results/<date>/summary.json``
and a copy at ``results/latest-summary.json``. Nothing a scanned file contains is stored except
what the findings already show (masked snippets), plus the decoded text of GR001/GR004 for triage.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import filestats
from common import (
    CORPUS_DIR,
    STORE_DECODED_FOR,
    CorpusError,
    Proc,
    RepoEntry,
    Runner,
    fingerprint,
    git_env,
    load_repos,
    repo_slug,
    safe_text,
    subprocess_runner,
    valid_repo,
    write_json,
)

from ghostrules import __version__
from ghostrules.secrets import mask_secrets

DEFAULT_COMMAND = (sys.executable, "-I", "-c", "from ghostrules.cli import app; app()")
OK, CLONE_FAILED, SCAN_FAILED, CONTEXT_FAILED, TIMEOUT = (
    "ok",
    "clone_failed",
    "scan_failed",
    "context_failed",
    "timeout",
)
TIMEOUT_CODE = 124


def sanitize_finding(repo: str, finding: dict[str, Any]) -> dict[str, Any]:
    """The part of a finding that is stored: no message or fix hint, secrets masked again, and the
    decoded text only for the rules whose triage needs it."""
    rule, path = str(finding.get("rule_id", "")), safe_text(str(finding.get("path", "")))
    snippet = safe_text(mask_secrets(str(finding.get("snippet", ""))))
    out: dict[str, Any] = {
        "fingerprint": fingerprint(repo, path, rule, snippet),
        "rule_id": rule,
        "severity": str(finding.get("severity", "")),
        "path": path,
        "line": finding.get("line"),
        "snippet": snippet,
    }
    if rule in STORE_DECODED_FOR and finding.get("decoded"):
        out["decoded"] = safe_text(mask_secrets(str(finding["decoded"])), limit=400)
    for key in ("via", "tags"):
        if finding.get(key):
            out[key] = [safe_text(str(v)) for v in finding[key]]
    return out


def summarize_context(context: dict[str, Any]) -> dict[str, Any]:
    """Counts and readable paths only, per agent."""
    agents: dict[str, Any] = {}
    for name, model in (context.get("agents") or {}).items():
        entries = model.get("entries") or []
        agents[name] = {
            "loads": dict(Counter(str(e.get("load", "")) for e in entries)),
            "entries": [
                {
                    "path": safe_text(str(e.get("path", ""))),
                    "load": str(e.get("load", "")),
                    "depth": len(e.get("via") or []),
                    "conditional": bool(e.get("condition")),
                    "transforms": [str(t) for t in e.get("transforms") or []],
                    "readable": bool(e.get("readable")),
                }
                for e in entries
            ],
            "imported": sum(1 for e in entries if e.get("via")),
            "edges": len(model.get("edges") or []),
            "cycles": len(model.get("cycles") or []),
            "paths": sorted(
                safe_text(str(e.get("path", ""))) for e in entries if e.get("readable")
            ),
        }
    return agents


def _json(proc: Proc) -> dict[str, Any] | None:
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def process_repo(
    entry: RepoEntry,
    runner: Runner,
    command: Sequence[str],
    workdir: Path,
    empty_config: Path,
    timeout: float,
) -> dict[str, Any]:
    """Clone, scan and build the stored record for one repository. Never raises."""
    name = entry.name
    result: dict[str, Any] = {"repo": name, "tier": entry.tier, "status": OK}
    started = time.monotonic()
    clone = Path(tempfile.mkdtemp(prefix=repo_slug(name) + "-", dir=workdir)) / "repo"
    try:
        url = f"https://github.com/{name}.git"
        proc = runner(
            ["git", "clone", "--depth", "1", "--filter=blob:limit=2m", "--no-tags",
             "--single-branch", "--quiet", "--", url, str(clone)],
            timeout=timeout,
            env=git_env(),
        )  # fmt: skip
        if proc.returncode != 0:
            result["status"] = TIMEOUT if proc.returncode == TIMEOUT_CODE else CLONE_FAILED
            result["error"] = safe_text(proc.stderr.strip().splitlines()[-1] if proc.stderr else "")
            return result
        sha = runner(["git", "rev-parse", "HEAD"], timeout=30, cwd=clone, env=git_env())
        result["sha"] = sha.stdout.strip() if sha.returncode == 0 else ""

        common = ["--config", str(empty_config)]
        scan = runner(
            [*command, "scan", str(clone), "--format", "json", "--fail-on", "none",
             "--min-severity", "info", *common],
            timeout=timeout,
            cwd=workdir,
        )  # fmt: skip
        scan_data = _json(scan)
        if scan.returncode != 0 or scan_data is None:
            result["status"] = TIMEOUT if scan.returncode == TIMEOUT_CODE else SCAN_FAILED
            result["error"] = safe_text(scan.stderr.strip()[-200:])
            return result
        ctx = runner(
            [*command, "context", "--format", "json", "--agent", "all", "--no-scan",
             "--root", str(clone), *common],
            timeout=timeout,
            cwd=workdir,
        )  # fmt: skip
        ctx_data = _json(ctx)
        if ctx.returncode != 0 or ctx_data is None:
            result["status"] = TIMEOUT if ctx.returncode == TIMEOUT_CODE else CONTEXT_FAILED
            result["error"] = safe_text(ctx.stderr.strip()[-200:])
            return result

        result["scanned_files"] = scan_data.get("scanned_files", 0)
        result["findings"] = [sanitize_finding(name, f) for f in scan_data.get("findings", [])]
        result["context"] = summarize_context(ctx_data)
        context_paths = {e["path"] for a in result["context"].values() for e in a["entries"]}
        result["files"] = filestats.collect(clone, context_paths)
        return result
    finally:
        result["seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(clone.parent, ignore_errors=True)


def build_summary(results: list[dict[str, Any]], tier: str, date: str) -> dict[str, Any]:
    """Counts per rule and severity, failures and timings for one run."""
    by_rule: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    for r in results:
        for f in r.get("findings", []):
            by_rule[f["rule_id"]] += 1
            by_severity[f["severity"]] += 1
    return {
        "date": date,
        "tier": tier,
        "ghostrules_version": __version__,
        "repos": len(results),
        "status": dict(Counter(r["status"] for r in results)),
        "failures": sorted(
            ({"repo": r["repo"], "status": r["status"]} for r in results if r["status"] != OK),
            key=lambda d: d["repo"],
        ),
        "findings": sum(by_rule.values()),
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(by_severity),
        "seconds": {r["repo"]: r["seconds"] for r in sorted(results, key=lambda r: r["repo"])},
    }


def run_corpus(
    entries: list[RepoEntry],
    results_root: Path,
    *,
    runner: Runner = subprocess_runner,
    command: Sequence[str] = DEFAULT_COMMAND,
    workers: int = 4,
    timeout: float = 300,
    date: str | None = None,
    tier: str = "",
) -> dict[str, Any]:
    """Process ``entries`` and write the results. Returns the summary."""
    date = date or dt.date.today().isoformat()
    out_dir = results_root / date
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ghostrules-corpus-", ignore_cleanup_errors=True
    ) as tmp:
        workdir = Path(tmp)
        empty_config = workdir / "empty.toml"
        empty_config.write_text("", encoding="utf-8")
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(
                pool.map(
                    lambda e: process_repo(e, runner, command, workdir, empty_config, timeout),
                    entries,
                )
            )
    for r in results:
        write_json(out_dir / f"{repo_slug(r['repo'])}.json", r)
    summary = build_summary(results, tier, date)
    write_json(out_dir / "summary.json", summary)
    write_json(results_root / "latest-summary.json", summary)
    return summary


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Scan the corpus repositories.")
    p.add_argument("--tier", help="scan every repository of this tier in repos.toml")
    p.add_argument("--repos", help="comma-separated owner/repo list (ignores repos.toml)")
    p.add_argument("--repos-file", type=Path, default=CORPUS_DIR / "repos.toml")
    p.add_argument("--results", type=Path, default=CORPUS_DIR / "results")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--timeout", type=float, default=300, help="seconds per command")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.repos:
            names = [n.strip() for n in args.repos.split(",") if n.strip()]
            bad = [n for n in names if not valid_repo(n)]
            if bad:
                raise CorpusError(f"invalid repository name: {safe_text(bad[0], 80)}")
            entries = [RepoEntry(n, "adhoc") for n in dict.fromkeys(names)]
        elif args.tier:
            entries = [e for e in load_repos(args.repos_file) if e.tier == args.tier]
        else:
            raise CorpusError("give --tier or --repos")
        if not entries:
            raise CorpusError("no repositories selected")
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    summary = run_corpus(
        entries,
        args.results,
        workers=args.workers,
        timeout=args.timeout,
        tier=args.tier or "adhoc",
    )
    print(
        f"{summary['repos']} repos, {summary['findings']} findings, "
        f"status {summary['status']} -> {args.results / summary['date']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
