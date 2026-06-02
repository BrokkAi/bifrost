from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, is_dataclass
import hashlib
import json
from pathlib import Path
import random
import sys
import time
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bifrost_searchtools import SearchToolsClient, SymbolKindFilter


ResultFn = Callable[[SearchToolsClient], Any]


class Query:
    def __init__(self, name: str, run: ResultFn) -> None:
        self.name = name
        self.run = run


def query_fingerprint(result: Any) -> str:
    if is_dataclass(result):
        payload = asdict(result)
    else:
        payload = result
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def build_queries() -> list[Query]:
    return [
        Query(
            "search:SearchToolsService",
            lambda client: client.search_symbols(["SearchToolsService"], limit=20),
        ),
        Query(
            "search:WorkspaceAnalyzer",
            lambda client: client.search_symbols(["WorkspaceAnalyzer"], limit=20),
        ),
        Query(
            "search:ProjectChangeWatcher",
            lambda client: client.search_symbols(["ProjectChangeWatcher"], limit=20),
        ),
        Query(
            "search:call_tool_json",
            lambda client: client.search_symbols(["call_tool_json"], include_tests=True, limit=20),
        ),
        Query(
            "search:Analyzer",
            lambda client: client.search_symbols(["Analyzer"], include_tests=True, limit=25),
        ),
        Query(
            "locations:SearchToolsService",
            lambda client: client.get_symbol_locations(["SearchToolsService"]),
        ),
        Query(
            "locations:WorkspaceAnalyzer",
            lambda client: client.get_symbol_locations(["WorkspaceAnalyzer"]),
        ),
        Query(
            "sources:SearchToolsService",
            lambda client: client.get_symbol_sources(["SearchToolsService"]),
        ),
        Query(
            "sources:WorkspaceAnalyzer",
            lambda client: client.get_symbol_sources(["WorkspaceAnalyzer"]),
        ),
        Query(
            "sources:call_tool_json",
            lambda client: client.get_symbol_sources(
                ["SearchToolsService.call_tool_json"],
                kind_filter=SymbolKindFilter.FUNCTION,
            ),
        ),
        Query(
            "summaries:service",
            lambda client: client.get_summaries(["src/searchtools_service.rs"]),
        ),
        Query(
            "summaries:python-module",
            lambda client: client.get_summaries(["src/python_module.rs"]),
        ),
        Query(
            "summaries:client",
            lambda client: client.get_summaries(["bifrost_searchtools/client.py"]),
        ),
        Query(
            "summaries:service-tests",
            lambda client: client.get_summaries(["tests/searchtools_service.rs"]),
        ),
        Query(
            "list:service",
            lambda client: client.list_symbols(["src/searchtools_service.rs"]),
        ),
        Query(
            "list:python-module",
            lambda client: client.list_symbols(["src/python_module.rs"]),
        ),
        Query(
            "list:client",
            lambda client: client.list_symbols(["bifrost_searchtools/client.py"]),
        ),
        Query(
            "relevant:service",
            lambda client: client.most_relevant_files(["src/searchtools_service.rs"], limit=20),
        ),
        Query(
            "relevant:client",
            lambda client: client.most_relevant_files(["bifrost_searchtools/client.py"], limit=20),
        ),
    ]


def build_baseline(client: SearchToolsClient, queries: list[Query]) -> dict[str, str]:
    baseline = {}
    for query in queries:
        baseline[query.name] = query_fingerprint(query.run(client))
    return baseline


def run_worker(
    worker_id: int,
    calls_per_thread: int,
    seed: int,
    root: Path,
    query_names: list[str],
    baseline: dict[str, str],
) -> tuple[Counter[str], list[str]]:
    rng = random.Random(seed + worker_id)
    queries_by_name = {query.name: query for query in build_queries()}
    counts: Counter[str] = Counter()
    failures: list[str] = []

    with SearchToolsClient(root=root) as client:
        for call_index in range(calls_per_thread):
            query_name = rng.choice(query_names)
            query = queries_by_name[query_name]
            try:
                observed = query_fingerprint(query.run(client))
            except Exception as exc:  # noqa: BLE001 - fuzz harness records any failure.
                counts["errors"] += 1
                if len(failures) < 5:
                    failures.append(
                        f"worker={worker_id} call={call_index} query={query_name} error={exc}"
                    )
                continue

            counts[f"query:{query_name}"] += 1
            if observed != baseline[query_name]:
                counts["mismatches"] += 1
                if len(failures) < 5:
                    failures.append(
                        "worker={} call={} query={} expected={} observed={}".format(
                            worker_id,
                            call_index,
                            query_name,
                            baseline[query_name],
                            observed,
                        )
                    )

    return counts, failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stress one bifrost_searchtools client per thread against the bifrost repo."
    )
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--calls-per-thread", type=int, default=100)
    parser.add_argument("--seed", type=int, default=0xB1F4057)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()

    queries = build_queries()
    started = time.perf_counter()
    with SearchToolsClient(root=args.root) as client:
        baseline = build_baseline(client, queries)

    query_names = [query.name for query in queries]
    total_counts: Counter[str] = Counter()
    failure_samples: list[str] = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                run_worker,
                worker_id,
                args.calls_per_thread,
                args.seed,
                args.root,
                query_names,
                baseline,
            )
            for worker_id in range(args.threads)
        ]
        for future in as_completed(futures):
            counts, failures = future.result()
            total_counts.update(counts)
            remaining = 20 - len(failure_samples)
            if remaining > 0:
                failure_samples.extend(failures[:remaining])

    total_calls = args.threads * args.calls_per_thread
    observed_calls = sum(
        count for key, count in total_counts.items() if key.startswith("query:")
    )
    elapsed = time.perf_counter() - started

    print(
        json.dumps(
            {
                "threads": args.threads,
                "calls_per_thread": args.calls_per_thread,
                "total_calls": total_calls,
                "observed_successes": observed_calls,
                "errors": total_counts["errors"],
                "mismatches": total_counts["mismatches"],
                "elapsed_seconds": round(elapsed, 3),
                "query_counts": {
                    key.removeprefix("query:"): value
                    for key, value in sorted(total_counts.items())
                    if key.startswith("query:")
                },
                "failure_samples": failure_samples,
            },
            indent=2,
            sort_keys=True,
        )
    )

    if observed_calls != total_calls:
        return 1
    if total_counts["errors"] or total_counts["mismatches"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
