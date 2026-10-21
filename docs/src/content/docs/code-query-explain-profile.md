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
  "schema_version": "1",
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

An explanation has format `bifrost_code_query_explain/v1` and these fields:

- `query_schema_version` identifies the parsed CodeQuery language version. It is independent of the report contract version carried by `format`.
- `parsed_query` is canonical JSON for the resolved query schema version, including defaults.
- `logical_plan` is a dependency-first directed acyclic graph. Stable, plan-local node IDs and ordered dependency arrays expose shared work; a dependency ID may appear more than once when authored branches share the same logical seed.
- `physical_plan` maps each physical node to its logical node, selected operator, output kind, and ordered physical dependencies. A semantic step also carries `semantic_request`, which states with eight booleans which semantic facets the step would need. Explain publishes that demand without resolving a host registration or materializing semantic artifacts. Logical and physical IDs are separate contracts even where the current planner selects them one-to-one.
- `scheduling` records the scheduling policy, the selected strategy, and the maximum concurrency for the selected plan.

The explanation omits internal cache fingerprints, storage generations, representation versions, and executor-only suffix flags. Those values are implementation details, not a stable public planning contract. [Explain fields](#explain-fields) lists every field.

## Profile response

A profile has format `bifrost_code_query_profile/v2`. Its `result` field is the exact ordinary `CodeQueryResult`; result ordering, diagnostics, provenance, truncation, and completion semantics do not change. The remaining fields are observations from that same execution:

- `explain` contains the selected public plan described above.
- `timings_ns` separates planning, execution, result rendering, and the execution-core total elapsed wall time.
- `request_timings_ns` measures the whole tool request around the query: transport queueing, workspace readiness, analyzer admission, preparation, input decoding, query execution, and rendering. The MCP server fills every field. `bifrost --tool query_code`, `bifrost --query-file`, and the Rust `SearchToolsService::query_code_result` method also fill them, but report zero for the three transport wait fields; `query_code_result` also reports zero for `rendering_serialization`. Lower-level Rust execution functions such as `execute_workspace` leave every field at zero.
- `work` reports budget-accounted files, source bytes, fact nodes, pipeline rows, references, provenance steps, resolved import files and edges, and semantic work. Its nested `semantic` object reports materialization, semantic IR element counts, cumulative work and resident and per-root work peaks across the semantic lanes, retained bytes, traversal steps, and whether the separate semantic budget was exhausted. When typestate, value-flow, or class-set type-flow analysis runs, `semantic.typestate`, `semantic.value_flow`, or `semantic.type_flow` adds that solver's counters. A pure `witness` projection adds no solve work.
- `cache_layers` reports deterministic, completeness-sensitive outcomes for request-local seed results, seed-path structural facts, reference and call relations, forward and reverse import relations, and the snapshot-local complete direct-import topology. The topology layer includes build files, edges, elapsed time, retained bytes, cancellation and unavailability, and request-local fallbacks. Only complete immutable topology values are reused; unsupported reverse domains and failed or bounded builds fall back to the request-local resolver.
- `access_path` separates compatibility-budget work from physical structural access. It reports the selected positive posting terms and their pre-intersection candidate counts, provider, scoped, and candidate facts, compatibility-admitted fact nodes, whether exact source-anchor verification remained necessary, cache readiness, materialization and source inspection, index lifecycle and build cost, fallback, and uniquely retained bytes. `scoped_fact_nodes` is exact when indexed metadata is available and zero for scan-only execution; `admitted_fact_nodes` is comparable on both paths. A narrow scope may reuse a ready snapshot index. Bifrost does not build a whole-provider index for a query on its own when the scoped files are fewer than eight or less than one quarter of that provider. For a viable scope, the first use scans and records reuse interest; a later use builds the snapshot index. This avoids whole-workspace index construction for one-shot queries.
- `scheduling` reports peak concurrency and, when bounded dispatch actually occurred, queue, coordinator, budget-wait, and dispatch observations.
- `operators` reports authored invocation identity, disposition and termination reasons, row counts, elapsed, wait, merge, and scheduling time, work and cache deltas, truncation, cancellation, and a lower-bound temporary container-capacity estimate.

Times are monotonic elapsed wall time in nanoseconds. `timings_ns.total` covers the executor request core through ordinary result construction. It excludes analyzer query-scope setup and cleanup, public-report projection, serialization, transport, and host workspace initialization, so it is not end-to-end tool latency; use `request_timings_ns.total` for that. Operator-inclusive intervals can overlap and must not be summed as CPU time. Temporary memory excludes allocator metadata and heap payloads owned by strings, paths, traces, and nested vectors, so it is a lower bound rather than RSS or retained heap.

Cancellation fields are observable through the public Rust `execute_request_with_cancellation` API, which returns a profiled cancellation-safe partial result.

Profiling is opt-in: an ordinary `results` query does not allocate the plan explanation, operator observation vector, or per-operator timers. A profiled request may warm analyzer caches, so compare cold and warm profiles using separate, deliberately controlled analyzer and storage lifecycles. [Profile fields](#profile-fields) lists every field.

## Current scheduling policy

The `auto` scheduling policy always selects the `sequential_union` operator. Bifrost keeps a bounded two-worker `parallel_union` implementation and a parity and benchmark harness, but it has no request option that forces parallel execution.

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

A future selector must demonstrate a stable cold-and-warm crossover, an observable pre-execution cache/cardinality signal, exact result and budget parity, and behavior under concurrent request load before the `auto` policy can select parallel execution.

## Explain fields

Every count is a non-negative integer. IDs are plan-local integers that are meaningful only inside one report.

### Explain object

| Field | Type | Meaning |
| --- | --- | --- |
| `format` | string | Always `bifrost_code_query_explain/v1`. |
| `query_schema_version` | integer | CodeQuery schema version of the parsed query. The only version is `1`. |
| `parsed_query` | object | Canonical JSON for the query, with defaults filled in. |
| `logical_plan` | object | The logical plan. See [Logical plan](#logical-plan). |
| `physical_plan` | object | The selected physical plan. See [Physical plan](#physical-plan). |
| `scheduling` | object | The scheduling decision. See [Explain scheduling](#explain-scheduling). |

### Logical plan

| Field | Type | Meaning |
| --- | --- | --- |
| `logical_plan.root` | integer | ID of the node whose output is the query result. |
| `logical_plan.nodes` | array | Logical nodes in dependency-first order. |
| `nodes[].id` | integer | Logical node ID. |
| `nodes[].operation` | object | What the node computes. `operation.kind` selects the shape below. |
| `nodes[].output_kind` | string | The row domain the node produces, such as `structural_match`, `declaration`, `file`, or `procedure`. |
| `nodes[].dependencies` | array of integers | Ordered input node IDs. An ID repeats when two authored branches share one logical node. |

`operation.kind` values:

| `kind` | Extra field | Meaning |
| --- | --- | --- |
| `seed` | `seed`: object | A structural `match` seed, as canonical JSON. |
| `occurrence_seed` | `seed`: object | An occurrence seed, as canonical JSON. |
| `scope_seed` | `seed`: object | A lexical-scope seed, as canonical JSON. |
| `binding_seed` | `seed`: object | A binding seed, as canonical JSON. |
| `generation_site_seed` | `seed`: object | A generation-site seed, as canonical JSON. |
| `export_seed` | `seed`: object | An export seed, as canonical JSON. |
| `path_seed` | `seed`: object | A path seed, as canonical JSON. |
| `dependency_evidence_seed` | `seed`: object | Stored static dependency evidence filters, as canonical JSON. |
| `configuration_facts_seed` | `seed`: object | A configuration-facts seed, as canonical JSON. |
| `step` | `step`: object | One pipeline step, as canonical JSON, for example `{"op": "procedure_of"}`. |
| `set` | `op`: string | A set operation: `union`, `intersect`, or `except`. |
| `limit` | `count`: integer | The public result limit. |

For the seeds and steps themselves, see [Code Query Vocabulary](/reference/code-query/).

### Physical plan

| Field | Type | Meaning |
| --- | --- | --- |
| `physical_plan.root` | integer | ID of the physical node whose output is the query result. |
| `physical_plan.nodes` | array | Physical nodes in dependency-first order. |
| `nodes[].id` | integer | Physical node ID. |
| `nodes[].logical_node` | integer | ID of the logical node this physical node implements. |
| `nodes[].operator` | string | The selected operator. See the table below. |
| `nodes[].output_kind` | string | The row domain the node produces. |
| `nodes[].dependencies` | array of integers | Ordered input physical node IDs. |
| `nodes[].semantic_request` | object, optional | Present only on a step that needs semantic facts. See the table below. |

`operator` values:

| Operator | Meaning |
| --- | --- |
| `seed_scan` | Evaluates a structural `match` seed. |
| `occurrence_scan` | Evaluates an occurrence seed. |
| `scope_scan` | Evaluates a lexical-scope seed. |
| `binding_scan` | Evaluates a binding seed. |
| `generation_site_scan` | Evaluates a generation-site seed. |
| `export_scan` | Evaluates an export seed. |
| `path_scan` | Evaluates a path seed. |
| `dependency_evidence_scan` | Reads the selected durable static dependency publication. |
| `configuration_facts_scan` | Evaluates a configuration-facts seed. |
| `pipeline_step` | Runs one step over its input rows. |
| `sequential_union` | Computes a union, one branch at a time. |
| `parallel_union` | Computes a union on bounded parallel workers. The `auto` policy does not select it today. |
| `sequential_intersection` | Computes an intersection. |
| `sequential_except` | Computes a set difference. |
| `limit` | Applies the public result limit. |

`semantic_request` has exactly these eight booleans. Each one is `true` when the step needs that facet:

| Field | Meaning when `true` | Steps that set it |
| --- | --- | --- |
| `procedures` | The step resolves or reads source-backed procedures. | Every step that has a `semantic_request`. |
| `dispatch` | The step resolves call dispatch targets. | For example `call_bindings`, `dispatch_outcome`, `dispatch_targets`, `class_set`, `absent_member`, `nilness_operations`, and the result-contract steps. |
| `program_points` | The step reads control-flow program points. | For example `cfg_entry`, `cfg_exits`, `state_events_of`, `statement_reachability`, `guards_of`. |
| `control_edges` | The step reads control-flow edges. | For example `cfg_successor_edges`, `cfg_predecessor_edges`, `control_relations`, `loop_relations`, `switch_coverage`. |
| `switch_facts` | The step reads switch facts. | `switch_coverage`. |
| `typestate` | The step runs a registered typestate protocol. | `typestate`. |
| `value_flow` | The step runs value-flow propagation. | `value_flow`, `class_set`, `absent_member`, `keyed_read_value`. |
| `taint` | The step projects a registered taint result. | `taint`. |

### Explain scheduling

| Field | Type | Meaning |
| --- | --- | --- |
| `scheduling.policy` | string | Always `auto`. |
| `scheduling.selected` | string | `sequential` or `parallel`. It is `parallel` only when the plan contains a `parallel_union` node. |
| `scheduling.max_concurrency` | integer | `1` for a sequential plan. For a parallel plan, the smaller of the scheduler worker count and the parallel union's branch count. |

## Profile fields

The profile object has these top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `format` | string | Always `bifrost_code_query_profile/v2`. |
| `result` | object | The ordinary query result, unchanged. |
| `explain` | object | The [explain object](#explain-object) for the executed plan. |
| `timings_ns` | object | Execution-core times. See [Timings](#timings). |
| `request_timings_ns` | object | Whole-request times. See [Request timings](#request-timings). |
| `work` | object | Budget-accounted work for the whole request. See [Work](#work). |
| `cache_layers` | array | Cache outcomes for the whole request. See [Cache layers](#cache-layers). |
| `access_path` | object | Structural index and scan use. See [Access path](#access-path). |
| `scheduling` | object | Observed concurrency. See [Profile scheduling](#profile-scheduling). |
| `operators` | array | One observation per operator invocation. See [Operators](#operators). |

Counters are unsigned 64-bit integers that saturate at their maximum instead of wrapping. Every time is in nanoseconds of monotonic wall time.

### Timings

| Field | Meaning |
| --- | --- |
| `timings_ns.planning` | Time to build the plan. |
| `timings_ns.execution` | Time to execute the physical plan. |
| `timings_ns.rendering` | Time to build the ordinary result rows. |
| `timings_ns.total` | Executor request-core time through ordinary result construction. It is not end-to-end tool latency. |

### Request timings

| Field | Meaning |
| --- | --- |
| `request_timings_ns.transport_queue_wait` | Time from MCP request acceptance until analyzer execution starts. |
| `request_timings_ns.workspace_readiness_wait` | Time from MCP request acceptance until a deferred workspace is ready. Part of `transport_queue_wait`. |
| `request_timings_ns.analyzer_admission_wait` | Time spent waiting for an analyzer execution slot after the workspace is ready. Part of `transport_queue_wait`. |
| `request_timings_ns.workspace_ready` | Snapshot acquisition, including any wait for a deferred workspace build. |
| `request_timings_ns.preparation` | Remaining request setup before input decoding. |
| `request_timings_ns.input_decode` | Decoding the query JSON or query file. |
| `request_timings_ns.query_execution` | Running the query, including the execution core measured in `timings_ns`. |
| `request_timings_ns.rendering_serialization` | Rendering and serializing the tool response. |
| `request_timings_ns.total` | The whole request, including `transport_queue_wait`. |

### Work

`work` covers the whole request. Each `operators[].work` has the same fields and covers one operator invocation.

| Field | Meaning |
| --- | --- |
| `scanned_files` | Source files scanned. |
| `scanned_source_bytes` | Source bytes scanned. |
| `fact_nodes` | Structural fact nodes charged to the execution budget. |
| `pipeline_rows` | Rows produced by pipeline steps. |
| `examined_references` | Reference candidates examined. |
| `provenance_steps` | Provenance steps recorded. |
| `import_files_resolved` | Files whose imports were resolved. |
| `import_edges_resolved` | Import edges resolved. |
| `semantic` | Semantic work. See below. |

`work.semantic` fields:

| Field | Meaning |
| --- | --- |
| `materialization_attempts` | Attempts to materialize a semantic artifact for a file. |
| `unique_materialized_files` | Distinct files materialized. |
| `request_cache_hits` | Semantic artifacts reused from the request-local cache. |
| `source_bytes` | Source bytes read for semantic materialization. |
| `procedures` | Procedures materialized. |
| `blocks` | Basic blocks materialized. |
| `program_points` | Program points materialized. |
| `values` | Values materialized. |
| `allocations` | Allocation sites materialized. |
| `call_sites` | Call sites materialized. |
| `memory_locations` | Memory locations materialized. |
| `captures` | Closure captures materialized. |
| `source_mappings` | Source mappings materialized. |
| `evidence` | Evidence records materialized. |
| `gaps` | Recorded gaps (facts the lowering could not model). |
| `events` | State events materialized. |
| `control_edges` | Control-flow edges materialized. |
| `nested_entries` | Nested entries materialized. |
| `retained_bytes` | Bytes retained by materialized semantic artifacts. |
| `cumulative` | Object. Cumulative semantic work per lane: retained admissions plus performed work. Holding and scanning the same bytes can count them twice, so this telemetry is not a bound. |
| `resident_peaks` | Object. Largest live resident census per lane. |
| `root_work_peaks` | Object. Largest work balance of any one root or prepass per lane. |
| `resident_nested_entries_peak` | Largest resident nested-entry count. |
| `resident_retained_bytes_peak` | Largest resident retained-artifact byte count. |
| `traversal_steps` | Semantic traversal steps taken. |
| `budget_exhausted` | Boolean. `true` when the separate semantic budget ran out. |
| `typestate` | Object, present only when typestate work happened. |
| `value_flow` | Object, present only when value-flow work happened. |
| `type_flow` | Object, present only when class-set type-flow work happened. |

`cumulative`, `resident_peaks`, and `root_work_peaks` each carry the same sixteen
lane keys: `source_bytes`, `procedures`, `blocks`, `program_points`, `values`,
`allocations`, `call_sites`, `memory_locations`, `captures`, `source_mappings`,
`evidence`, `gaps`, `events`, `control_edges`, `nested_entries`, and
`owned_text_bytes`. In these objects, `source_bytes` counts admitted or scanned
source bytes rather than the materialization reads in the top-level
`source_bytes` field, and `owned_text_bytes` counts artifact-owned text bytes.
`resident_nested_entries_peak` is the `nested_entries` lane of `resident_peaks`,
and `resident_retained_bytes_peak` repeats the retained-artifact peak that
`retained_bytes` reports.

`work.semantic.typestate` fields:

| Field | Meaning |
| --- | --- |
| `solves` | Typestate solves run. |
| `cache_hits` | Solves answered from cache. |
| `summary_hits`, `summary_misses` | Procedure summary lookups that hit or missed. |
| `summary_rejections` | Summaries found but rejected. |
| `summary_evictions` | Summaries evicted from the bounded cache. |
| `summary_recomputations` | Summaries computed again. |
| `reached_rows` | Rows the solver reached. |
| `findings`, `omitted_findings` | Findings retained and findings omitted by the finding budget. |
| `witnesses`, `omitted_witnesses` | Witnesses retained and witnesses omitted. |
| `witness_steps`, `witness_bytes` | Size of the retained witnesses. |
| `fixed_point_solves` | Solves that reached a fixed point. |
| `cancelled_solves` | Solves stopped by cancellation. |
| `budget_exhausted_solves` | Solves stopped by the solver budget. |
| `failed_solves` | Solves that failed. |
| `finding_budget_exhausted` | Boolean. `true` when the finding budget ran out. |

`work.semantic.value_flow` fields:

| Field | Meaning |
| --- | --- |
| `solves` | Value-flow solves run. |
| `cache_hits` | Solves answered from cache. |
| `reached_rows` | Rows the solver reached. |
| `meetings` | Origin-to-observation meetings found. |
| `sink_outcomes` | Observation (sink) outcomes produced. |
| `omitted_endpoints` | Endpoints omitted by the endpoint cap. |
| `witnesses`, `omitted_witnesses` | Witnesses retained and witnesses omitted. |
| `witness_expansions` | Witness expansion steps taken. |
| `witness_steps`, `witness_bytes` | Size of the retained witnesses. |
| `fixed_point_solves` | Solves that reached a fixed point. |
| `cancelled_solves` | Solves stopped by cancellation. |
| `budget_exhausted_solves` | Solves stopped by the solver budget. |
| `failed_solves` | Solves that failed. |
| `endpoint_truncated` | Boolean. `true` when endpoints were omitted. |
| `witness_truncated` | Boolean. `true` when witnesses were omitted. |

`work.semantic.type_flow` fields (the `class_set` and `absent_member` steps):

| Field | Meaning |
| --- | --- |
| `field_slot_builds` | Fresh whole-workspace field-slot indexes built. |
| `field_slot_memory_hits` | Ready field-slot indexes reused from memory. |
| `field_slot_persistence_hits` | Complete stored field-slot indexes loaded and accepted. |
| `field_slot_persistence_misses` | Stored field-slot lookups that found no matching index. |
| `field_slot_persistence_rejections` | Stored field-slot rows found but rejected by validation. |
| `field_slot_publications` | Fresh field-slot indexes written to storage. |
| `root_result_persistence_hits` | Stored finding-free root results loaded and accepted. |
| `root_result_persistence_misses` | Stored root-result lookups with no exact key. |
| `root_result_persistence_rejections` | Stored root results found but rejected. |
| `root_result_store_failures` | Failures while reading or writing stored root results. |
| `root_result_publications` | Fresh finding-free root results written to storage. |
| `solves` | Distinct root transactions solved. |
| `cache_hits` | Solves answered from cache. |
| `snapshot_cache_hits`, `snapshot_cache_misses` | Snapshot cache lookups. |
| `dispatch_cache_hits`, `dispatch_cache_misses` | Dispatch cache lookups. |
| `binding_cache_hits`, `binding_cache_misses` | Binding cache lookups. |
| `summary_cache_hits`, `summary_cache_misses` | Summary cache lookups. |
| `root_summary_cache_hits` | Root relations restored from reusable summaries. |
| `root_summary_observation_rejections` | Restored root relations rejected because they lacked a meeting for a current sink. |
| `published_summaries` | Summaries published for reuse. |
| `solver_attempts` | Bounded solver runs. One root can need more than one. |
| `summary_profile` | Object, present only when nonzero. Counts reasons a reusable summary could not be prepared, looked up, or published: `preparation_call_contract`, `preparation_dependency`, `preparation_source_limit`, `preparation_recursive_dependency`, `preparation_repository_failure`, `preparation_surface`, `lookup_procedure`, `lookup_source_behavior`, `lookup_source_partition`, `lookup_entry`, `lookup_relation`, `lookup_live_remap`, `publication_incomplete_result`, `publication_projection`, `publication_entry`, `publication_relation_shape`, `publication_dispatch_reads`, `publication_reused_conflict`, `publication_transfer`, `publication_dependency`. |
| `class_set_rows` | `class_set` rows produced. |
| `finding_rows` | Finding rows produced. |
| `witnesses`, `omitted_witnesses` | Witnesses retained and witnesses omitted. |
| `witness_expansions` | Witness expansion steps taken. |
| `witness_steps`, `witness_bytes` | Size of the retained witnesses. |
| `witness_truncated` | Boolean. `true` when witnesses were omitted. |
| `incomplete_roots` | Roots whose analysis did not complete. |
| `failed_solves` | Solves that failed. |

### Cache layers

`cache_layers` always has nine entries, in this order. Each entry is `{"layer": <name>, "metrics": {...}}`. `operators[].cache_layers` has the same shape for one operator invocation.

| `layer` | What it caches | `metrics.kind` |
| --- | --- | --- |
| `seed_result` | Request-local seed results. | `complete_value` |
| `seed_structural_facts` | Structural facts read by seed scans. | `structural_facts` |
| `inbound_reference` | Inbound reference relations. | `complete_value` |
| `outbound_reference` | Outbound reference relations. | `complete_value` |
| `incoming_call` | Incoming call relations. | `complete_value` |
| `outgoing_call` | Outgoing call relations. | `complete_value` |
| `import_forward` | Forward import relations. | `complete_value` |
| `import_reverse` | Reverse import relations. | `complete_value` |
| `direct_import_topology` | The snapshot-local complete direct-import topology. | `complete_value` |

`complete_value` metrics:

| Field | Meaning |
| --- | --- |
| `lookups` | Cache lookups. |
| `hits`, `misses` | Lookups that found or did not find a value. |
| `builds` | Values built. |
| `waits`, `wait_ns` | Waits for another builder of the same key, and their total time. |
| `complete_hits`, `incomplete_hits` | Hits on complete and on incomplete values. |
| `complete_builds`, `incomplete_builds` | Builds that produced complete and incomplete values. |
| `unknown_outcomes` | Lookups whose completeness was unknown. |
| `replayed_items` | Cached items handed to the consumer before relation-specific filtering. This can exceed emitted rows. |

`direct_import_topology` adds these fields:

| Field | Meaning |
| --- | --- |
| `cancelled` | Builds stopped by cancellation. |
| `unavailable` | Lookups where the topology could not be built. |
| `over_budget` | Builds that exceeded their budget. |
| `fallbacks` | Requests that fell back to the request-local resolver. |
| `build_files`, `build_edges` | Files and edges in built topologies. |
| `build_ns` | Time spent building. |
| `retained_bytes` | Bytes retained by built topologies. |

`structural_facts` metrics:

| Field | Meaning |
| --- | --- |
| `lookups` | Structural-facts lookups by seed scans. |
| `memory_hits` | Lookups answered from memory. |
| `persisted_hydrations` | Lookups answered by loading stored facts. |
| `extractions` | Lookups that parsed and extracted facts. |
| `unavailable` | Lookups for which no facts were available. |
| `unknown_outcomes` | Lookups with an unknown outcome. |
| `replayed_files` | Files whose facts were replayed to the consumer. |

### Access path

| Field | Meaning |
| --- | --- |
| `selected` | `scan_only`, `posting:<terms>` (for example `posting:kind+name`), or `mixed` when seeds used different paths. Posting terms are `kind`, `name`, `role_name`, and `kwarg`. |
| `representation_version` | Version of the structural index representation that was used. `0` for scan-only execution. |
| `estimated_provider_files` | Files in the structural provider, as estimated for index selection. |
| `scoped_files` | Files inside the query's path and language scope. |
| `scoped_fact_nodes` | Total facts in the scoped files. Exact when an index supplies metadata; `0` for scan-only execution. |
| `admitted_fact_nodes` | Facts admitted by compatibility source filtering and charged to the execution budget. Comparable on both paths. |
| `candidate_files`, `candidate_facts` | Files and facts left after posting intersection. |
| `selected_terms` | Array of `{"label", "candidate_facts"}`: each posting term used and its candidate count before intersection. |
| `source_verification_required` | Boolean. `true` when candidates still needed exact source-anchor verification. |
| `cache_ready_lookups` | Lookups that found a ready index before they started. |
| `materialized_files`, `materialized_fact_nodes` | Files and fact nodes materialized. |
| `inspected_source_bytes` | Source bytes inspected. |
| `examined_fact_nodes` | Fact nodes examined by the matcher. |
| `index_lookups`, `index_hits`, `index_misses` | Structural index lookups and their outcomes. |
| `index_builds` | Structural index builds. |
| `index_waits`, `index_wait_ns` | Waits for an index build, and their total time. |
| `index_cancelled` | Index builds stopped by cancellation. |
| `index_unavailable` | Lookups where no index could be provided. |
| `index_over_budget` | Index builds that exceeded their budget. |
| `scan_fallbacks` | Seeds that fell back to scanning. |
| `index_build_files`, `index_build_source_bytes`, `index_build_fact_nodes`, `index_build_facts_bytes` | Size of the inputs to index builds. |
| `index_build_ns` | Time spent building indexes. |
| `retained_bytes` | Bytes uniquely retained by the access path. |

### Profile scheduling

| Field | Meaning |
| --- | --- |
| `scheduling.peak_concurrency` | Highest number of operators that ran at once. |
| `scheduling.bounded_dispatch` | Object, present only when bounded parallel dispatch enqueued tasks. |
| `bounded_dispatch.worker_limit` | Maximum workers allowed. |
| `bounded_dispatch.workers_spawned` | Workers started. |
| `bounded_dispatch.tasks_enqueued`, `tasks_started`, `tasks_completed` | Task counts. |
| `bounded_dispatch.tasks_observed_cancelled_before_start` | Tasks that saw cancellation before they started. |
| `bounded_dispatch.queue_wait_ns` | Time tasks waited in the queue. |
| `bounded_dispatch.budget_wait_ns` | Time tasks waited for budget. |
| `bounded_dispatch.coordinator_wait_ns` | Time the coordinator waited. |
| `bounded_dispatch.dispatch_overhead_ns` | Time spent dispatching. |
| `bounded_dispatch.peak_concurrency` | Highest number of tasks that ran at once. |

### Operators

Each entry in `operators` describes one operator invocation. A shared plan node that runs for several branches has one entry per invocation.

| Field | Type | Meaning |
| --- | --- | --- |
| `node` | integer | Physical node ID. |
| `branch` | array of integers | Zero-based set-branch slots from the root to this invocation. Empty outside set operations. |
| `operator` | string | The physical operator. See [Physical plan](#physical-plan). |
| `disposition` | string | `completed`; `skipped`, when the operator did no work of its own because cancellation arrived first or a dependency was cancelled or halted; or `cancelled`, when the operator saw cancellation during its own work. |
| `timings_ns.elapsed` | integer | Operator-local time, excluding inline dependency execution. |
| `timings_ns.total` | integer | Inclusive time from entry until the operator returned. |
| `timings_ns.dependency_execution` | integer | Time spent running dependency subtrees inline. |
| `timings_ns.dependency_wait` | integer | Idle time waiting for an already-running scheduled dependency. |
| `timings_ns.merge` | integer | Time spent attaching branch provenance and diagnostics and combining sets. |
| `timings_ns.scheduling_overhead` | integer | Ready-queue, enqueue, and dequeue overhead. |
| `input_rows` | integer | Rows received from dependencies. |
| `rows_visited` | integer | Input rows the operator actually visited. Can be smaller than `input_rows` after cancellation or an early cap. |
| `relation_expansions` | integer | Relation expansions after relation-specific filtering, before de-duplication. |
| `rows_discarded` | integer or `null` | Exact discarded-row count for row-to-row operators. `null` for expansion operators. |
| `output_rows` | integer | Rows passed to the parent. A skipped operator can pass on a dependency's partial rows. |
| `temporary_capacity_bytes_lower_bound` | integer | Lower bound of temporary container capacity. Excludes heap payloads owned by strings, paths, traces, and nested vectors. |
| `work` | object | Work charged to this invocation. See [Work](#work). |
| `cache_layers` | array | Cache outcomes for this invocation. See [Cache layers](#cache-layers). |
| `terminations` | array of strings | Reasons the operator did not consume all available work. See below. |
| `operator_truncated` | boolean | The operator clipped or did not fully produce its own output. |
| `result_truncated` | boolean | The result passed upward was incomplete. |
| `result_cancelled` | boolean | The result passed upward was cancelled. |

`terminations` values:

| Value | Meaning |
| --- | --- |
| `cancellation_before_work` | Cancellation arrived before the operator started its own work. |
| `cancellation_during_work` | Cancellation arrived during the operator's own work. |
| `dependency_cancelled` | A dependency was cancelled. |
| `dependency_pipeline_halted` | A dependency halted the pipeline. |
| `terminal_cap` | A seed stopped at the row cap derived from the query's terminal limit. |
| `result_limit` | The public result limit was reached. |
| `execution_budget` | The execution budget ran out. |
| `pipeline_budget` | The pipeline row budget ran out. |
| `import_graph_budget` | The import-graph budget ran out. |
| `analysis_limit` | An analysis cap or budget clipped the output, for example a reference, call-relation, semantic, typestate, value-flow, or taint limit. |
| `unsupported_analysis` | A language adapter or capability does not support the requested analysis. |
| `analysis_incomplete` | An analysis reported a partial or incomplete derivation. |
