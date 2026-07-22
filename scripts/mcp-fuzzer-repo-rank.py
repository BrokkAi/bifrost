#!/usr/bin/env python3
"""Per-language repository ranking for the MCP property fuzzer campaign.

Ranks corpus repositories by task count, as pinned in
`.agents/plans/mcp_property_fuzzer.md` (Decision Log, 2026-07-21): the primary
key is `tasks.sft_count_for_repo` (candidate commits passing `SFT_PREDICATES`),
the tiebreaker is the raw scan-record count, then slug ascending. Languages
whose `sft_count` is zero across the board (testsome never bound there) fall
back to the raw scan-record count so "prioritize by task count" stays
meaningful.

All `sft-tools-commits`/`sfttasks` access goes through `tasks.py` per its
"Thou Shalt Not Read Tasks Manually" policy; the fuzzer's Rust runner shells
out to this script and never parses corpus metadata itself.

Usage:
    scripts/mcp-fuzzer-repo-rank.py --commits-root PATH [--languages scala,ts]

Emits one JSON object on stdout:
    {"<language>": [{"slug": "owner__repo", "sft_count": N, "scan_records": M,
                     "rank_key": "sft" | "scan"}, ...], ...}
sorted by the language's effective ranking key.
"""

import argparse
import json
import os
import sys
from pathlib import Path

BROKK_BENCH_DIR = Path(
    os.environ.get("BROKK_BENCH_DIR", "/home/jonathan/Projects/brokkbench")
).resolve()
sys.path.insert(0, str(BROKK_BENCH_DIR))

import tasks  # noqa: E402  (path set above)

CORPUS_LANGUAGES = ["c", "cpp", "csharp", "go", "java", "js", "php", "py", "rust", "scala", "ts"]


def rank_language(commits_root: Path, language: str, large_repos, build_time_map) -> list[dict]:
    language_dir = commits_root / language
    repos = sorted(path.stem for path in language_dir.glob("*.jsonl")) if language_dir.is_dir() else []
    rows = []
    for slug in repos:
        sft_count = tasks.sft_count_for_repo(
            commits_root,
            tasks.DEFAULT_SFTTASKS_DIR,
            language,
            slug,
            large_repos=large_repos,
            build_time_map=build_time_map,
        )
        scan_records = len(tasks.repo_scan_records(commits_root, language, slug))
        rows.append({"slug": slug, "sft_count": sft_count, "scan_records": scan_records})
    # All-zero sft languages (testsome never bound there) rank by raw scan
    # records instead; see the plan's Decision Log.
    rank_key = "sft" if any(row["sft_count"] for row in rows) else "scan"
    for row in rows:
        row["rank_key"] = rank_key
    if rank_key == "sft":
        rows.sort(key=lambda row: (-row["sft_count"], -row["scan_records"], row["slug"]))
    else:
        rows.sort(key=lambda row: (-row["scan_records"], row["slug"]))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commits-root", type=Path, required=True)
    parser.add_argument("--languages", default=None, help="comma-separated subset")
    args = parser.parse_args()
    commits_root = args.commits_root.resolve()
    languages = args.languages.split(",") if args.languages else CORPUS_LANGUAGES
    large_repos = tasks.large_repo_set(commits_root)
    build_time_map = tasks.build_times(commits_root)
    ranking = {
        language: rank_language(commits_root, language, large_repos, build_time_map)
        for language in languages
    }
    json.dump(ranking, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
