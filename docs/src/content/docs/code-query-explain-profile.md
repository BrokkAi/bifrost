---
title: Explain and Profile CodeQuery
description: Inspect Bifrost's logical and physical query plans, then measure an executed query with structured operator telemetry.
---

`query_code` has three root execution modes. `results` is the default and returns the existing query-result object. `explain` lowers and selects a plan without accessing analyzer data during that phase; a host such as the one-shot CLI may still initialize and index its workspace before the request runs. `profile` executes the query and returns the ordinary result together with opt-in measurements. The mode is an output control: it is excluded from query-plan identity, cannot appear inside a set branch, and is not available to static-analysis policy selectors.

## Request an explanation

Set `execution_mode` on a JSON query:

<!-- code-query-test:json:explain-mode -->
```json
{
  "schema_version": 2,
  "execution_mode": "explain",
  "union": [
    {"match": {"kind": "class", "name": "Legacy"}},
    {"match": {"kind": "class", "name": "Replacement"}}
  ]
}
```

Or wrap an RQL query:

<!-- code-query-test:rql:profile-mode -->
```lisp
(profile
  (references-of :proof proven
    (enclosing-decl (method :name "handle"))))
```

Use `(explain QUERY)` for the planning-only form. `explain` and `profile` are mutually exclusive because both lower to the same root enum. A saved `.json` or `.rql` query may contain the mode directly, so `--query-file` and MCP `query_file` calls use the same contract.

## Explain response

An explanation has format `bifrost_code_query_explain/v1` and four distinct stages:

- `query_schema_version` identifies the parsed CodeQuery language version. It is independent of the report contract version carried by `format`.
- `parsed_query` is canonical schema-v2 JSON, including resolved defaults.
- `logical_plan` is a dependency-first directed acyclic graph. Stable, plan-local node IDs and ordered dependency arrays expose shared work; a dependency ID may appear more than once when authored branches share the same logical seed.
- `physical_plan` maps each physical node to its logical node, selected operator, output kind, and ordered physical dependencies. Logical and physical IDs are separate contracts even where the current planner selects them one-to-one.
- `scheduling` records the production policy, selected strategy, and maximum concurrency for the selected plan.

The explanation deliberately omits internal cache fingerprints, storage generations, representation versions, and executor-only suffix flags. Those values are implementation details, not a stable public planning contract.

## Profile response

A profile has format `bifrost_code_query_profile/v2`. Its `result` field is the exact ordinary `CodeQueryResult`; result ordering, diagnostics, provenance, truncation, and completion semantics do not change. The remaining fields are observations from that same execution:

- `explain` contains the selected public plan described above.
- `timings_ns` separates planning, execution, result rendering, and the execution-core total elapsed wall time.
- `work` reports budget-accounted files, source bytes, fact nodes, pipeline rows, references, provenance steps, and resolved import files and edges.
- `cache_layers` reports deterministic, completeness-sensitive outcomes for request-local seed results, seed-path structural facts, reference and call relations, and forward/reverse import relations.
- `access_path` separates compatibility-budget work from physical structural access. It reports the selected positive posting terms and their pre-intersection candidate cardinalities, provider/scoped/candidate facts, compatibility-admitted fact nodes, whether exact source-anchor verification remained necessary, cache readiness, materialization and source inspection, index lifecycle/build cost, fallback, and uniquely retained bytes. `scoped_fact_nodes` is exact when indexed metadata is available and zero for scan-only execution; `admitted_fact_nodes` is comparable on both paths. A narrow scope may reuse a ready snapshot index, but production `Auto` will not construct a whole-provider index when the scoped files are fewer than eight or less than one quarter of that provider. For a viable scope, the first use scans and records reuse interest; a later use builds the snapshot index, avoiding whole-workspace construction for one-shot queries.
- `scheduling` reports peak concurrency and, when bounded dispatch actually occurred, queue, coordinator, budget-wait, and dispatch observations.
- `operators` reports authored invocation identity, disposition and termination reasons, cardinalities, elapsed/wait/merge/scheduling time, work/cache deltas, truncation, cancellation, and a lower-bound temporary container-capacity estimate.

Times are monotonic elapsed wall time. `timings_ns.total` covers the executor request core through ordinary result construction; it excludes analyzer query-scope setup and cleanup, public-report projection, serialization, transport, and host workspace initialization, so it is not end-to-end tool latency. Operator-inclusive intervals can overlap and must not be summed as CPU time. Temporary memory excludes allocator metadata and heap payloads owned by strings, paths, traces, and nested vectors, so it is a lower bound rather than RSS or retained heap.

Cancellation fields are observable through the public Rust `execute_request_with_cancellation` API, which returns a profiled cancellation-safe partial result. LSP cancellation follows normal protocol semantics instead: it returns `RequestCancelled` and does not deliver the partially built profile.

Profiling is opt-in: an ordinary `results` query does not allocate the plan explanation, operator observation vector, or per-operator timers. A profiled request may warm analyzer caches, so compare cold and warm profiles using separate, deliberately controlled analyzer/storage lifecycles.

## Current scheduling policy

Production `Auto` deliberately selects the sequential union operator. Bifrost retains a bounded two-worker `ParallelUnion` implementation and parity/benchmark harness, but it does not expose a force-parallel request flag.

The final M4 release experiment used TypeScript workspaces of 257, 513, and 1,001 files on an Apple M4 with ten logical processors. Exact unions scanned one file per branch; broad unions scanned 128, 256, or 500 files per branch. Each warm cell used eight paired measurements, and the second round reversed stable candidate order. Representative absolute elapsed times were:

| Workspace | Shape | Round 12 cold sequential / parallel | Round 13 cold sequential / parallel | Round 12 warm median sequential / parallel | Round 13 warm median sequential / parallel |
| ---: | --- | ---: | ---: | ---: | ---: |
| 257 | exact | 4.597 / 9.001 ms | 10.558 / 10.252 ms | 5.361 / 9.459 ms | 5.952 / 8.559 ms |
| 513 | exact | 16.612 / 16.946 ms | 36.146 / 22.976 ms | 15.684 / 25.430 ms | 31.705 / 19.476 ms |
| 1,001 | exact | 16.647 / 31.457 ms | 142.964 / 38.171 ms | 22.798 / 35.798 ms | 26.796 / 50.630 ms |
| 257 | broad | 47.622 / 44.388 ms | 329.183 / 69.796 ms | 34.340 / 37.236 ms | 233.110 / 112.244 ms |
| 513 | broad | 104.182 / 91.845 ms | 513.850 / 297.272 ms | 80.580 / 83.848 ms | 386.303 / 151.409 ms |
| 1,001 | broad | 841.686 / 428.313 ms | 877.218 / 619.713 ms | 222.465 / 402.767 ms | 782.926 / 329.696 ms |

Exact cold results changed sign at every scale after candidate order reversed. Broad warm medians favored sequential at every scale in round 12 and parallel at every scale in round 13. Absolute times varied by several multiples under system load even though results, work, cache contracts, and source fingerprints stayed equal. Bifrost therefore has no stable, observable pre-execution signal for a production threshold. This is a measured negative policy, not a claim that parallel unions can never win.

Three adjacent alternatives stopped at different evidence gates:

- bitmap-backed sets were ineligible because no stable dense identity domain was established;
- the normalized SQL edge-table negative control was discarded after it returned a non-equivalent consumer result and lacked an exact publishable snapshot identity;
- arbitrary recursive graph splitting remained a safety and ownership non-goal because current branch-local caches, resolver state, fair budgets, and derived dependencies do not yet have a safe general concurrent model.

A future selector must demonstrate a stable cold-and-warm crossover, an observable pre-execution cache/cardinality signal, exact result and budget parity, and behavior under concurrent request load before `Auto` can select parallel execution.
