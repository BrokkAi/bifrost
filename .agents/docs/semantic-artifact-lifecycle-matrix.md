# Semantic artifact lifecycle matrix

This note is the current artifact inventory for Bifrost issue #817. It records implemented behavior and measured decisions, not a promise that every artifact will become persistent. Update it whenever an artifact's owner, identity, completeness rule, representation, or promotion evidence changes.

“Snapshot-local” means a dense ID is valid only inside one immutable artifact. “Generation-local” means an artifact is tied to one `WorkspaceAnalyzer` generation. “Request-local” means the value belongs to one bounded operation and must not be shared as a complete answer after cancellation, truncation, or a configuration change.

## Promotion policy

Persistence starts only after a concrete equivalent artifact exists. The baseline must rebuild that artifact; the candidate must serialize and hydrate the same semantic fields and reconstruct the same traversal behavior. Both paths must report exact identity, completeness, counts, elapsed time, retained bytes or RSS, serialized size, and invalidation behavior.

The default equivalent-artifact gates are all required:

| Gate | Requirement |
| --- | --- |
| Relative hydration | At least 30% faster than rebuild |
| Absolute hydration | At least 50 ms faster than rebuild |
| Hydration RSS | No more than 110% of rebuild RSS |
| Serialized size | No more than 2x estimated hydrated bytes |
| Relative cold write | Build plus write no more than 125% of rebuild |
| Absolute cold write | Build plus write overhead no more than 250 ms |

Missing or invalid measurements make a candidate ineligible. Stale, corrupt, incomplete, cancelled, or budget-truncated persisted values are misses. Overlay artifacts are memory-only unless a later plan explicitly changes that rule with new evidence.

## Current matrix

| Artifact | Owner and consumers | Lifetime and identity | Representation and admission | Reuse and observability | Decision |
| --- | --- | --- | --- | --- | --- |
| Structural file facts | `StructuralFactsCache`; structural search and snapshot index consumers | Cross-process disk cache. Keyed by blob OID, language, live analyzer-store generation, and `STRUCTURAL_FACTS_SNAPSHOT_VERSION`; overlays do not persist | `FileFacts` node arena plus `CompactRows<RoleTarget>`; versioned packed bincode DTO. Decode validates spans, kinds, roles, row boundaries, source length, and counts before publication | Provider counters distinguish memory hit, persisted hydration, extraction, unavailable, and unknown. Persistence benchmarks cover time, memory, size, corruption, version, generation, replacement, GC, and concurrency | **Promoted to SQLite** in `structural_facts_snapshots` |
| Snapshot structural index | `SnapshotStructuralIndexCache`; CodeQuery physical planning | Analyzer-snapshot memory value. Key binds workspace identity, canonical storage generations, exact scope, representation version, and complete file/fact inputs | Complete postings and selected compact rows behind `CompleteValueCache`; partial, cancelled, unavailable, or over-budget builds do not publish | Query profiles report lookup/hit/miss/build/wait, work, retained bytes, cancellation, unavailability, and fallback | **Memory-only**; persistence requires its own equivalent-candidate matrix |
| Direct import topology | `SnapshotDerivedLayerCache`; structural import expansion | Analyzer-snapshot memory value. `DerivedLayerRequest` binds generation, layer kind, support/configuration, and representation version | `CompactDirectedGraph<ProjectFile>` with completeness/support metadata. Only complete bounded values publish | Derived-layer profiles report hits, builds, waits, completeness, work, time, retained bytes, and fallbacks | **Memory-only**; SQL graph prototype was discarded |
| Semantic artifact and callable CFGs | Per-adapter `CompleteSemanticArtifactCache`; ICFG, oracle, and data-flow consumers | Complete per-mounted-source artifact. `SemanticArtifactKey` binds mount, relative path, language, disk/overlay revision, adapter version, IR version, configuration, and dependency fingerprint | Dense procedure-local IDs, typed semantic side tables, canonical control-edge table, outgoing offsets, and incoming edge-ID rows. Only complete validated artifacts publish to the byte-bounded single-flight cache | Semantic work/counts and cache reuse are benchmarked. The CFG layout matrix proved bidirectional edge-ID rows. The packed control/call experiment measured rebuild, build/write, warm/cold hydrate, RSS, bytes, invalidation, and checksum | **Memory-only; measured SQLite no-go** because VS Code cold-write overhead exceeded 250 ms |
| Bounded ICFG snapshot | `WorkspaceIcfgProvider`; inspection and bounded data-flow clients | Generation- and request-local. Root `ProcedureHandle`, workspace generation, dispatch/oracle semantics, `IcfgSnapshotLimits`, and source artifact keys define validity; context-bearing dense IDs are not durable | Canonical edge table, outgoing offsets, incoming edge IDs, bounded call contexts, typed boundaries, proof, and completeness. Partial semantic outcomes remain visibly partial | Node/edge/boundary counts, semantic work, renderers, and contract tests exist. CFG lifecycle work measured an optimistic call projection, not a durable whole-workspace ICFG | **Ephemeral generation-local view**; never persist a whole-workspace ICFG |
| Value-flow snapshot and call bindings | `WorkspaceSemanticOracle`; heap, receiver, and future solver clients | Request-local projection over exact procedure/artifact handles, oracle limits, adapter/oracle versions, configuration, and generation | Finite typed relation arena with value, parameter, receiver, return, capture, allocation, and call-binding relations. Open/unknown sets and exceeded budgets remain explicit | Oracle benchmark reports relations, maximum breadth/path length, provenance handles, caps, elapsed time, and complete-artifact reuse | **Request-local; measured raw-persistence no-go** |
| Heap, points-to, alias, and update-eligibility answers | `HeapOracle` and query projections | Request-local. Exact point/value/location handles, access-path and candidate limits, oracle semantics, configuration, and generation define validity | Bounded candidates and relation records with proof/completeness; summary-tailed paths and update certificates remain typed | Oracle benchmark reports candidate breadth, path length, truncation, open sets, retained provenance, and receiver projection overhead | **Request-local; measured raw-persistence no-go** |
| Bounded data-flow worklist and reached result | `src/analyzer/dataflow`; one caller-owned solve | Strictly request-local. Concrete seeds, outcome-derived ICFG, client transfer implementation, five solver limits, cancellation, and run order feed deterministic run-local `FactId`s | FIFO worklist, interned finite facts, reached `(IcfgNodeId, FactId)` rows, nondominated path-quality frontiers, coverage, and termination. Incomplete input/work never becomes a complete negative | `SolverWork`, termination, coverage, facts, reached rows, and completeness are public. The #817 data-flow lifecycle benchmark adds fresh-process time, counts, RSS, shallow retained bytes, and checksums | **Ephemeral, not persistence-eligible**; repeating a solve is not summary reuse |
| Witness predecessors and paths | Future #820/#823 solver layer | Request-local unless projected into a complete reusable summary. Identity must include the exact result/summary key and witness budget | Bounded predecessor choices or reconstructed path, never a retained enumeration of all paths | Not implemented or measured | **Ephemeral by default** |
| Semantic procedure summary | Future `dataflow::summary`; multiple analysis clients | In-memory first. Required key dimensions include semantic artifact, adapter/IR, call/value/heap semantics, context abstraction, solver/summary version, configuration, callee/SCC dependency fingerprint, proof, and completeness | Shape pending a concrete #820/#823 summary consumer. Recursive SCC members must publish atomically only after convergence | Must measure cross-query and cross-process reuse, composition cost, retained bytes/RSS, serialized size, and targeted invalidation | **Pending shape and evidence** |
| Taint transfer summary | Future `taint::summary`; batched taint clients | In-memory first. Carrier key plus taint algebra, propagation-event matcher dependency when embedded, external/unknown-call semantics, context/access-path abstraction, and callee/SCC fingerprint. Sink-only presentation/classification inputs stay outside | Symbolic boundary/heap input-to-output relation with sanitization, escapes, uncertainty, local generators, and internal sink observations; no policy message/CWE/CVSS or concrete origin | Must prove reuse across sink-only and presentation changes and safe misses for transfer-changing inputs | **Pending #821/#823 shape and evidence** |
| Protocol summary | Future `typestate::summary`; finite-state clients | In-memory first. Semantic carrier key plus canonical compiled protocol/binding-plan hash, solver/summary version, dependencies, configuration, proof, and completeness | Symbolic incoming-state to outgoing-state/effect relation. Dense execution handles and policy aliases are never durable identity | Must prove recursive convergence, cross-caller reuse, cross-process benefit, and targeted rule/dependency invalidation | **Pending #822/#823 shape and evidence** |

## Invalidations that every promoted semantic artifact must cover

- Source content and mounted workspace identity.
- Disk versus overlay origin and overlay revision.
- Language and adapter semantic version.
- Semantic IR and representation/DTO version.
- Analysis configuration and dependency fingerprint.
- Solver, summary, context, access-path, exceptional-flow, and unknown-call semantics where applicable.
- Protocol or transfer-affecting rule hashes for client-specific summaries.
- Callee or recursive-SCC dependency changes.
- Corrupt, partial, interrupted, cancelled, and budget-truncated writes.
- Analyzer-store generation, liveness, replacement, cascade cleanup, and garbage collection.
- Concurrent readers and writers.
- Windows-safe workspace-relative path reconstruction.

Reporting-only metadata, policy messages, CWE labels, CVSS overlays, result limits, and sink-only observers do not invalidate a reusable transfer summary unless they change propagation or completeness semantics.

## Evidence

- `.agents/plans/sqlite-backed-compact-structural-snapshots.md`
- `.agents/docs/sqlite-backed-compact-graph-applicability.md`
- `.agents/docs/semantic-cfg-lifecycle-benchmark-2026-07-20.md`
- `.agents/docs/semantic-oracle-lifecycle-benchmark-2026-07-21.md`
- `.agents/plans/all-language-cfg-icfg-rollout.md`
- `.agents/plans/issue-820-bounded-dataflow-tabulation.md`
- `.agents/plans/language-agnostic-composable-typestate-platform.md`

Revision note (2026-07-24): Created the first issue #817 inventory after the CFG/ICFG, oracle, snapshot structural-index, and bounded data-flow foundations landed. It records existing promotion and no-go decisions while leaving summary persistence explicitly dependent on concrete #823 shapes and new measurements.
