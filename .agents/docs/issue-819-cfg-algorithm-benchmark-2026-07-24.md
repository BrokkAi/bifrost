# Issue #819 CFG algorithm benchmark — 2026-07-24

## Decision

Keep the reusable CFG algorithms crate-internal and compute RPO, SCCs, loop regions, and shortest paths on demand. Retain only the existing ICFG-builder return-path mask, whose repeated consumer and immutable-artifact scope are already concrete. Do not add persisted or global derived-result storage.

Do not implement dominators or post-dominators under #819. There is no named SSA, control-dependence, strong-update, or pruning consumer; there is consequently no correctness claim or benchmark target against which a dominance implementation could be justified.

The retained machine-readable evidence is `issue-819-cfg-algorithm-benchmark-2026-07-24.json` beside this note.

## Provenance and method

The retained run used:

- Bifrost commit `537262d7c2fe58c1f190d910f904413302be7792`, with a clean tree and the SHA-256 empty-tree fingerprint `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Rust `1.96.0` (`ac68faa20`, LLVM 22.1.2), Cargo release profile, `aarch64-apple-darwin`.
- VS Code at exactly `19e0f9e681ecb8e5c09d8784acaa601316ca4571`, clean.
- Spring PetClinic at exactly `f182358d02e4a68e52bdbabf55ca7800288511e7`, clean.
- `std::time::Instant` monotonic wall time.
- One cold derivation followed by three complete recomputations for every algorithm on every graph. Every recomputation was required to return the same work counts, retained-byte estimate, and SHA-256 result digest as the cold run.

The synthetic matrix covers a 100,000-node chain, a 20,000-node branch-heavy DAG, nested reducible cycles, a two-entry irreducible cycle, disconnected SCCs with a self-loop, and exceptional/multiple-exit topology. The corpus matrix materialized 133,316 VS Code procedure CFGs (6,094,518 points and 6,399,332 edges) and 227 PetClinic procedure CFGs (9,833 points and 10,992 edges). VS Code was partial by one of 5,633 files; 5,632 files produced complete semantics. PetClinic completed all 49 files.

## Determinism and stack safety

All retained recomputations matched their cold result digests and exact node/edge work. The unit suite independently proves that permuting rich-edge construction leaves DFS/RPO, SCCs, loop regions, and shortest-path selection unchanged after canonical freezing; parallel edges retain distinct typed identities.

The 100,000-node chain completed every iterative traversal without recursion. Representative cold release times were:

| Algorithm | Cold time | Node visits | Edge visits | Retained result bytes |
| --- | ---: | ---: | ---: | ---: |
| Forward reachability | 8.429 ms | 100,000 | 99,999 | 900,000 |
| Reverse reachability | 7.794 ms | 100,000 | 99,999 | 900,000 |
| DFS/RPO | 6.606 ms | 100,000 | 99,999 | 2,400,000 |
| Kosaraju SCC | 22.395 ms | 200,000 | 199,998 | 3,200,000 |
| Loop regions | 96.520 ms | 400,000 | 399,996 | 0 |
| Shortest path | 5.906 ms | 100,000 | 99,999 | 1,599,992 |

The zero retained bytes for chain loop regions is expected: the graph has no cyclic SCC. Loop-region work is exactly four whole-graph passes in this implementation: Kosaraju’s two passes, deterministic DFS back-edge discovery, and one entry/self-loop scan.

The corpus totals also follow the declared accounting. PetClinic DFS visits each point and edge once (9,833/10,992), Kosaraju twice (19,666/21,984), and loop derivation four times (39,332/43,968). VS Code shows the same exact multiples. Reachability and shortest paths visit only their reachable subgraphs.

## Absolute corpus costs

Aggregated cold release costs over every materialized procedure were:

| Dataset | Forward | Reverse | DFS/RPO | SCC | Loop regions | Shortest path |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| VS Code | 3,031.1 ms | 2,391.8 ms | 3,878.8 ms | 8,671.3 ms | 9,120.7 ms | 2,955.6 ms |
| PetClinic | 1.221 ms | 1.036 ms | 1.677 ms | 3.416 ms | 3.818 ms | 1.096 ms |

The three-recomputation totals were respectively 7,506.3/6,151.0/9,849.6/24,704.1/27,974.1/6,167.0 ms for VS Code and 3.383/2.955/4.464/9.777/11.020/3.031 ms for PetClinic. These are absolute measurements, not claims of stable ratios; the JSON preserves the exact result digest and retained byte total for every row.

## Consumer and lifecycle audit

The repository audit found one current repeated whole-CFG derivation: ICFG return-affecting gap scoping computes entry reachability and exit reverse reachability, and may ask for the same `(ProcedureHandle, exit)` mask while stitching multiple call contexts. `SnapshotBuilder::return_path_masks` already memoizes that result for one immutable artifact instance. The #819 integration now uses the shared reachability implementation underneath that cache and preserves the existing semantic precharge and cancellation outcome.

No production consumer currently repeats whole-snapshot DFS/RPO, SCC, loop-region, or shortest-path derivation. The IFDS/IDE-shaped solver operates over its own exploded problem-state worklist rather than using RPO or dominance. Heap strong updates require explicit certificates rather than inferring dominance. Retaining those currently unrequested results would add memory and invalidation obligations without avoiding demonstrated production work.

The lifecycle decision is therefore:

- Keep the base `ProcedureSemantics` CFG immutable with dense typed point/edge identities and canonical bidirectional adjacency.
- Keep the ICFG return-path mask query-local and keyed by artifact-instance-scoped `ProcedureHandle`.
- Compute other algorithm results on demand with request-local node/edge budgets and cancellation.
- Add no global cache, snapshot field, SQLite table, persistence schema, dependency, or public query/RQL surface.

## Dominance no-go

Dominators and post-dominators remain absent by design:

1. No named current consumer needs SSA placement, control dependence, dominance-based heap updates, or dominance pruning.
2. The current solver and heap certificate model do not require dominance.
3. With no consumer, there is no representative query, acceptance criterion, retained-result policy, or benchmark target.
4. Implementing dominance now would turn an evidence-gated roadmap option into unused state whose correctness and lifecycle could not be validated against product behavior.

This is the completed #819 decision, not deferred implementation. A later issue should name the consumer and its correctness contract before adding a dominance algorithm or cache.
