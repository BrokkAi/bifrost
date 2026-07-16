# SQLite-backed compact graph applicability

This note records where Bifrost should use the hybrid tested by
`experiment-sqlite-backed-compact-graph-snapshots`: durable packed facts in the
existing SQLite cache, hydrated into CSR/CSC-style arrays for repeated reads.
It is intentionally not a proposal to query graph edges through SQL.

## Decision rule

Use the hybrid only when all of the following are true:

1. The graph is an immutable snapshot with a small, exact persisted identity.
2. Reconstructing it repeats expensive parsing, normalization, or resolution.
3. Consumers repeatedly scan complete adjacency rows, so contiguous memory is
   a better hot representation than SQLite rows.
4. The packed payload does not duplicate an already-cheap derived view of raw
   facts without a measured cold-start benefit.
5. Semantic-version and parent-lifecycle invalidation can be made explicit.

Mutable discovery state, query-budget state, diagnostics, rich resolver
catalogs, and tiny indexes should remain domain-owned and rebuildable.

## Applicability matrix

| Graph family | Stable persisted identity | Reconstruction and lifecycle | Hot representation | Decision |
| --- | --- | --- | --- | --- |
| Structural facts and semantic roles | Exact Git blob OID, exact storage-language key, analyzer generation, and explicit structural snapshot version | Tree-sitter parsing plus structural normalization repeats for every process lifetime and after hot-cache eviction. Each file is immutable at a blob identity; overlays get their own source-derived identity and are accepted only when a matching complete parsed parent exists. | Per-file preorder node arena plus `CompactRows<RoleTarget>` CSR rows | **Promote.** Store one checked packed BLOB per file and hydrate on a Moka miss. Keep SQLite as cold cache and CSR as the query format. |
| Import dependency graphs | Raw `import_details` are already keyed by blob/language/generation, but a derived workspace graph additionally depends on the workspace file set and import-resolution semantics. RQL traversal also depends on seed rows and execution limits. | Relevance constructs a seed-induced two-hop view. RQL discovers forward edges incrementally, retains unsupported-provider and truncation state, and freezes only when reverse traversal needs a complete view. Prior 1,000-file/17,982-edge measurements found compact in-memory rows valuable, but not a durable reconstruction bottleneck. | `CompactDirectedGraph<ProjectFile>` CSR plus CSC after domain-specific discovery | **Keep compact in memory; do not persist the derived graph.** Persisting would duplicate raw facts and require a workspace/semantic/query key. Reconsider only if a future whole-workspace resolver benchmark shows material repeated cold cost. |
| Common reverse type hierarchy | Raw per-file `unit_supertypes` and `unit_children` already live in SQLite. The shared reverse index is a workspace snapshot whose exact identities include declarations and language-specific resolution. | Lazily built once per analyzer/provider. At 800 types its measured first full-descendant construction/traversal was 0.219 ms and warm traversal 0.192 ms after compaction; end-to-end hierarchy/RQL paths stayed at parity. | Exact `CodeUnit` arena, hash lookup only for ancestors with rows, and one-way `CompactRows<u32>` | **Keep compact in memory; discard derived persistence.** The rebuild is too cheap to justify another versioned workspace payload and invalidation surface. Go/Rust specialized indexes remain separate. |
| Usage graph and PageRank input | A final graph depends on the complete declaration catalog, ecosystem-specific exact identity, resolver implementation, file-scoped JS/TS identity, filters, truncation, unproven inbound counts, and calibration semantics. | `WorkspaceUsageCatalog::build` and language resolvers dominate construction. The prior compact-final-adjacency candidate saved under 1 MiB at roughly 14,000 nodes/12,000 edges, did not improve end-to-end latency, and did not reduce RSS. There is no current incoming-CSC consumer. | Rich catalog/maps during resolution, then sorted dense `WorkspaceUsageEdge` values and a transient weighted PageRank adjacency | **Discard persistence of the final graph.** If future work identifies an expensive stable resolver intermediate, benchmark and persist that narrower fact layer rather than the calibrated/query-facing graph. |

## Structural pilot results

The checked snapshot stores explicit `u32` spans and IDs plus stable `u8`
kind/role codes. It omits source text and line starts, validates all decoded
boundaries and graph invariants, and is a cascading child of the complete
parsed blob. Snapshot failures are best-effort cache misses: normal extraction
continues and repairs the current row.

Representative optimized A/B medians:

| Fixture | Metric | Baseline | Hybrid | Delta |
| --- | --- | ---: | ---: | ---: |
| 200 files x 50 calls | cold materialization | 132.621 ms | 154.946 ms | +16.8% |
| 200 files x 50 calls | reopened materialization | 140.420 ms | 43.573 ms | -69.0% |
| 200 files x 50 calls | reopened role-heavy query | 33.407 ms | 33.831 ms | +1.3% |
| 200 files x 50 calls | retained structural facts | 22.60 MB | 18.10 MB | -19.9% |
| 400 files x 100 calls | cold materialization | 519.783 ms | 629.273 ms | +21.1% |
| 400 files x 100 calls | reopened materialization | 539.081 ms | 144.334 ms | -73.2% |
| 400 files x 100 calls | reopened role-heavy query | 104.570 ms | 111.590 ms | +6.7% |
| 400 files x 100 calls | retained structural facts | 90.36 MB | 72.01 MB | -20.3% |

The 400-file end-to-end query delta persisted under reverse run order, but a
representation-only scan of every CSR row and role was slightly faster after
hydration: 0.822 ms extracted versus 0.804 ms hydrated. The hot arrays are
therefore at parity; the end-to-end difference comes from surrounding
provider/source lifecycle and is not evidence for SQL-driven traversal.

Snapshot payloads were 3.67 MiB for 200 files and 15.50 MiB for 400 files.
Total database size increased by about 37-38%. Warm analyzers performed zero
structural extractions and reproduced exact file, fact, and role counts.
Hydration allocates exact vector capacities, explaining the approximately 20%
lower retained-size estimate relative to freshly extracted values.

Process peak RSS is not used as a promotion criterion here: the benchmark does
cold extraction and warm hydration in one process, and `getrusage` reports a
cumulative high-water mark that includes SQLite mmap and allocator history.
The retained-size metric and fresh-process timing are the interpretable
representation measurements.

## Operational conclusions

- Enable structural snapshots as rebuildable cache data, not authoritative
  analysis state.
- Acquire SQLite's writer slot before reading replacement/accounting state.
  A deferred read-to-write upgrade can lose to the concurrent cache writer and
  return `SQLITE_BUSY_SNAPSHOT`, leaving an avoidable one-file persistence gap.
- Keep one SQLite connection path. A separate low-mmap reader reduced the
  combined-process peak by roughly 15 MiB, but made cold and warm
  materialization 5-10% slower and did not improve hot queries.
- Generalize the checked packed-snapshot mechanism only after another graph
  crosses the same stable-identity and reconstruction-cost threshold. The
  reusable part is the boundary and validation discipline, not a universal
  persisted graph type.
