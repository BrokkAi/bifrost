# Issue #918 Milestone 3: derived-layer lifecycle and SQL graph experiment

## Scope

Milestone 3 had two independent gates:

1. extract one reusable cancellation-aware complete-value single-flight
   lifecycle and define exact versioned identities for future derived layers;
2. select, measure, and either promote or discard one SQL-to-memory graph
   representation without introducing the Milestone 4 scheduler.

No parallel operator, ready queue, scheduling threshold, public profile surface,
or database migration belongs to this milestone.

## Candidate selection from Milestone 2

The optimized M2 runs measured the large shared-reference request at 57.101 ms
and 58.155 ms, but Bifrost does not persist a resolved reference or call edge
relation. Those traversals still depend on language-specific parsing and
resolution, so there are no stable identity/topology SQL columns to bulk-freeze.

The large shared-import request measured 4.537 ms and 4.576 ms while resolving
130 files and 256 edges. The store persists ordered `ImportInfo` payload blobs,
not resolved file-to-file topology. Resolution still depends on live paths,
language providers, package/include indexes, and JS/TS alias configuration.
Persisting a new resolved-edge schema would therefore be a separate storage
design, not a loader optimization justified by the M2 profile.

Structural facts were also rejected as a candidate because they are already a
versioned per-file packed snapshot containing dense node arenas and CSR role
rows. Repacking them as another SQL graph would duplicate an existing warm path.

`unit_children` was the only current normalized SQL edge table. It was used as
a negative control even though M2 did not identify member/owner traversal as an
expensive shared prerequisite.

## Complete-value lifecycle and exact keys

`CompleteSemanticArtifactCache` now delegates to a generic byte-weighted
`CompleteValueCache<K, V>`. The generic lifecycle owns ready values and the
same-key in-flight map together. A leader builds outside all locks and can only
publish an immutable `Arc<V>` through its completion permit. Dropping the
permit on error, cancellation, or an incomplete domain outcome removes the
exact flight, wakes followers, and lets one uncancelled follower retry.
Cancelled followers do not affect the leader. Oversize values can be handed to
current followers without being retained by the bounded ready cache.

Plan-known derived-layer requests contain the layer kind, exact
projection/filter identity, and representation version. The generic cache
documents that every concrete layer-owned runtime key must additionally bind:

- normalized workspace mount identity;
- a canonical sorted storage-language generation vector;
- an exact content/overlay fingerprint;
- a separate resolver/configuration fingerprint.

Keeping runtime configuration separate is necessary because physical plan
selection has no analyzer input. In particular, JS/TS import topology changes
with effective `tsconfig.json` or `jsconfig.json` path mappings.

An in-memory fake composite key covers every required dimension and proves
that a generation cutover cannot reuse a ready value. No production runtime
key type was retained: after the SQL candidate was discarded, no concrete
layer owned a valid snapshot/configuration constructor. Keeping an unbound key
abstraction would make exactness look stronger than it is. A future promoted
layer must define its typed key beside its materializer and instantiate
`CompleteValueCache<ThatKey, ThatSnapshot>`.

The physical plan annotates `ImportersOf` with a plan-known request for the
complete direct-import topology. It does not acquire or materialize a runtime
dependency in M3. `ImportsOf` remains unmarked because its projection is the
dynamic input frontier rather than the complete relation. The internal profile
format is version 2 now that physical explain nodes can carry this metadata.

## SQL-to-memory negative control

The experiment prototype selected ordered active `code_units` identities and
`unit_children(parent_key, child_key, ordinal)` rows, remapped the composite
persistent identities to typed dense IDs, stored each edge payload once, and
built outgoing and incoming edge-ID adjacency with degree counts, prefix sums,
and scatter. It validated endpoint bounds, row offsets, and exactly-once edge
coverage before constructing an `Arc`.

The optimized illustrative run used:

```sh
BIFROST_UNIT_CHILDREN_GRAPH_FILES=20 \
BIFROST_UNIT_CHILDREN_GRAPH_MEMBERS=4 \
BIFROST_UNIT_CHILDREN_GRAPH_ITERATIONS=3 \
cargo test --release --lib \
  analyzer::store::graph_experiment::unit_children_graph_negative_control_benchmark \
  --no-default-features -- --ignored --exact --nocapture
```

The exact versioned output was:

```json
{"format":"bifrost_unit_children_graph_experiment/v1","decision":"discard","decision_reason":"unit_children already hydrates into FileState::children; this dense-ID candidate omits the CodeUnit and range materialization required by Members, so lookup-only gains cannot establish an end-to-end win","comparison_equivalence":"closest existing IAnalyzer::direct_children traversal over all generated class declarations; candidate returns dense edge IDs and is not an equivalent Members pipeline","active_snapshot_filter":"caller-supplied live (language, blob_oid) keys intersected with current complete analyzer-generation rows","memory_accounting":"lower-bound allocation estimate from vector lengths, hash capacities, string bytes, and Arc headers; allocator metadata and SQLite buffers are excluded","timer":"std::time::Instant monotonic elapsed wall time","files":20,"configured_members_per_file":4,"iterations":3,"sql_scan_ms":1.252042,"remap_freeze_ms":0.034041999999999996,"vertices":140,"edges":120,"retained_bytes_estimate":16344,"temporary_bytes_estimate":26832,"current_direct_children_first_ms":4.3655,"current_direct_children_warm_median_ms":0.148792,"current_direct_children_results":100,"candidate_cold_lookup_ms":0.003708,"candidate_warm_reuse_median_ms":0.000959,"candidate_lookup_results":120,"result_counts_equal":false,"invalidation_analyzer_update_ms":2.8323340000000004,"invalidation_sql_scan_ms":1.345583,"invalidation_remap_freeze_ms":0.024875,"invalidation_rebuild_ms":1.370458,"invalidated_vertices":141,"invalidated_edges":121}
```

At this small synthetic scale, the SQL scan took 1.252 ms, remap/freeze
0.034 ms, and the measured invalidation rebuild 1.370 ms. The graph contained
140 vertices and 120 edges with a lower-bound retained estimate of 16,344
bytes. The nearest current traversal returned 100 results while the candidate
returned 120. The extra 20 were one synthetic file-scope-to-top-level-class
edge per file, confirming that the lookup timings compare different contracts.
The JSON field `candidate_warm_reuse_median_ms` measures repeated direct lookup
against the already-built prototype value. It is not `CompleteValueCache`
reuse, a same-key follower wait, or sibling-contention evidence.

This prototype was not eligible for promotion regardless of lookup timing:

- it did not carry an exact captured analyzer generation, snapshot identity,
  and representation version through publication;
- its SQL used the lightweight atomic-publication marker rather than the full
  persisted-row integrity condition and did not prove coverage of every
  requested active blob;
- its dense lookup returned edge IDs, whereas the current `Members` path
  returns rich `CodeUnit` values, so the measured inputs and outputs were not
  end-to-end equivalent;
- the first prototype used a global composite hash remap even though
  `unit_key` is dense within each blob, leaving a better grouped remap
  unmeasured;
- a single fixed measurement order and lookup-only candidate could not support
  a general latency conclusion.

The experiment-only module was removed after measurement. Retaining roughly one
thousand lines of non-equivalent test code would add normal lib-test compile and
schema maintenance cost without production reuse.

## Decision

Discard SQL-backed graph promotion for M3. No migration, resolved-edge table,
durable graph payload, or production `CompactDirectedGraph` cache is added.
The M3 evidence supports a narrower conclusion than “SQL graphs are slow”:
Bifrost currently has no profile-selected persisted resolved topology whose
identity and end-to-end consumer contract make this optimization valid.

The reusable outcome is the strict complete-value lifecycle, plan-known request
identity, and exact layer-owned key contract. Milestone 4 can use that boundary
when concurrent plan nodes request one actual derived dependency. A future SQL
graph candidate must first be nominated by real end-to-end profile evidence
and must compare equivalent typed results across cold build, warm reuse,
contention, retained memory, and exact generation invalidation.

## Validation

Passed:

- 7 generic complete-value lifecycle and fake exact-key tests;
- all 15 semantic-service cache/publication tests;
- 7 physical execution-plan tests, with the ignored M2 benchmark registered;
- all 40 structural-search tests;
- all 73 `code_query_pipelines` integration tests;
- the ignored optimized negative-control run shown above;
- `cargo fmt --all` and `git diff --check`;
- `rustup run 1.96.0 cargo-clippy --all-targets --all-features -- -D warnings`.

Adversarial review found and fixed one generic-cache bug: a caller-supplied
zero weight could bypass Moka's bounded-weight accounting. The cache now
clamps every retained value to at least weight one, with a discriminating
capacity-one regression. Review found no lost wakeup, publication race,
cancellation coupling, retry, oversize-handoff, plan-identity, schema, or M4
scope defect after the fix.
