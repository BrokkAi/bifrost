# Measure and introduce compact graph relations for workspace queries

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost repeatedly builds read-heavy relationships such as structural fact roles, file imports, type ancestry, declaration ownership, and caller-to-callee usage edges. Many of those relationships currently use one allocation per node or adjacency row and repeat rich keys on every edge. This experiment will determine, with reproducible measurements, where compressed sparse row and compressed sparse column storage lowers memory and improves or preserves query speed without weakening exact declaration identity or structured resolution.

Compressed sparse row, abbreviated CSR, stores every row's values in one contiguous array and uses an offset array to identify each row's slice. Compressed sparse column, abbreviated CSC, applies the same representation to incoming rather than outgoing relationships. After this work, at least one production query path will use compact storage with demonstrated behavior parity and a material retained-memory improvement. Issue #748 will contain the commands, commits, measurements, and promote-or-discard decisions for every experiment.

The work happens on branch `748-explore-compact-csrcsc-graph-representations-for-workspace-queries`. Each completed milestone receives a checkpoint commit and a review pass before the next milestone begins.

## Progress

- [x] (2026-07-15T13:53:57Z) Verified the issue branch is clean, attached, synchronized with `origin/master` at `da0dc303f085`, and already contains the merged prerequisite work from issues #751 through #754.
- [x] (2026-07-15T13:53:57Z) Re-read `.agents/PLANS.md`, issue #748, the current structural fact implementation, the benchmark harness, and the newly merged weighted usage-graph PageRank implementation.
- [x] (2026-07-15T14:15:00Z) Added a reproducible structural-fact benchmark that reports cold extraction time, warm role-heavy matching time, fact and role counts, retained estimated bytes, process peak RSS, repository identity, and one versioned JSON line.
- [x] (2026-07-15T14:20:00Z) Captured the unmodified structural-role baseline at three synthetic sizes and on `/Users/dave/Workspace/test-repos/vscode` at `a5914335df0bf1cae7d818a168ef321def9f8572`.
- [x] (2026-07-15T14:29:00Z) Replaced per-node structural role vectors with one contiguous role array and row offsets, appending directly during extraction and preserving source order across `query_code`, Rune IR, reference classification, and structured call-site consumers.
- [x] (2026-07-15T14:29:00Z) Compared and promoted the structural-role candidate: retained bytes fell 28.9% on `vscode`, optimized warm reads were at parity in a load-matched A/B, and all focused behavior plus warnings-as-errors checks passed.
- [x] (2026-07-15T14:47:31Z) Added and captured a generated file-dependency baseline that exercises both import-based PageRank and complete reverse RQL traversal with identical files and edges.
- [x] (2026-07-15T15:11:55Z) Introduced shared compact rows plus directed CSR/CSC storage, migrated import PageRank and completed RQL import graphs, measured alternating optimized A/B binaries, and promoted the candidate.
- [x] (2026-07-15T15:29:00Z) Added and captured a generated exact-identity hierarchy/ownership baseline covering reverse-index construction, direct and transitive reads, RQL subtypes, members-owner round trips, and standalone owner lookup.
- [x] (2026-07-15T15:40:44Z) Replaced the common rich reverse hierarchy map and redundant per-key memo sets with exact-identity keyed CSR rows, measured alternating optimized A/B binaries, promoted hierarchy CSR, and rejected a workspace CSC for query-local singular ownership.
- [x] (2026-07-15T15:46:38Z) Added and captured a generated Go weighted usage-relevance baseline for the dense `WorkspaceUsageGraph`, including first and warm graph construction plus PageRank and phase RSS.
- [x] (2026-07-15T15:56:34Z) Adapted the dense-ID `WorkspaceUsageGraph` to outgoing compact weighted rows, removed PageRank's per-row adapter, measured preserved release binaries at 500 and 2,000 modules, and discarded the candidate because its sub-megabyte theoretical saving produced no repeatable end-to-end memory or read benefit.
- [ ] Run the checked-in performance regression suite on representative pinned repositories, complete final review and CI-equivalent validation, publish the conclusion to #748, and summarize which structures should remain map-based.

## Surprises & Discoveries

- Observation: the four main-first prerequisites are complete and present on current `origin/master` rather than merely closed administratively.
  Evidence: GitHub reports #751, #752, #753, and #754 closed; history contains `ae35f530`, `cf486820`, `90126471`, and `72cbd7de` or their merged equivalents.

- Observation: issue #781 already introduced `WorkspaceUsageCatalog` and `WorkspaceUsageGraph` with dense integer edge endpoints plus a reusable weighted PageRank kernel. The remaining usage-graph opportunity is contiguous adjacency, avoiding the rich-key aggregation stage, and safe reuse, not inventing dense usage identity from scratch.
  Evidence: `src/analyzer/usages/workspace_graph.rs` stores `WorkspaceUsageEdge { from: usize, to: usize, counts }`; `src/relevance.rs` currently expands those edges into `Vec<Vec<(usize, f64)>>` before PageRank.

- Observation: the structural-role pilot has more consumers than the matcher alone. Rune IR rendering and reference-kind classification read `NormalizedNode::roles` directly, so the compact API must serve iteration by node as well as filtering by role.
  Evidence: direct reads appear in `src/analyzer/structural/matcher.rs`, `src/analyzer/structural/search.rs`, and `src/analyzer/structural/rune_ir.rs`.

- Observation: the checked-in scenario benchmark measures stable end-to-end analyzer tasks but does not currently include `query_code`. The dedicated structural benchmark is therefore required for the pilot, while the scenario suite remains the regression gate for unrelated tasks.
  Evidence: `benchmark/targets.toml` covers workspace build, symbol navigation, summaries, relevance, usages, smells, definition lookup, and hierarchy scenarios, but not structural matching.

- Observation: real repositories may contain analyzed files with no structural facts. The `vscode` checkout has three such files, including a deliberate zero-byte JavaScript fixture, so the benchmark must distinguish candidate, extracted, and skipped file counts.
  Evidence: the first repository run stopped at `extensions/typescript-language-features/test-workspace/foojs.js`; the file is zero bytes and the provider contract explicitly returns `None` for empty source.

- Observation: structural fact storage is already a large resident cost on a real TypeScript workspace. `vscode` produced 6,276,000 facts and 4,258,462 roles with 1,604,467,430 estimated retained bytes.
  Evidence: the successful repository benchmark raised peak RSS from 888,274,944 bytes after analyzer construction to 2,342,944,768 bytes after fact extraction and 2,744,664,064 bytes after three warm role-heavy queries.

- Observation: this host currently has two Rust 1.96.0 builds with the same commit hash but different LLVM builds. `cargo` and `rustc` resolve through rustup, while `cargo-clippy` and `clippy-driver` resolve through Homebrew, producing `E0514` against rustup-built dependencies.
  Evidence: rustup reports LLVM 22.1.2 while `/opt/homebrew/bin/rustc` reports LLVM 22.1.6. Tests must pin `RUSTC` to `rustup which rustc`, and Clippy must invoke rustup's `cargo-clippy` binary directly on this host.

- Observation: the compact role rows materially reduce both retained logical bytes and process high-water RSS. On `vscode`, retained facts fell from 1,604,467,430 to 1,140,998,282 bytes, a 28.9% reduction; peak RSS after extraction fell from 2,342,944,768 to 1,973,108,736 bytes, a 15.8% reduction.
  Evidence: the unchanged repository benchmark extracted the same 6,276,000 facts and 4,258,462 roles from the same `a5914335df0bf1cae7d818a168ef321def9f8572` checkout.

- Observation: debug timings on this host vary substantially with compiler rebuild and background load. The clean real-repository candidate was 6.5% slower to extract and 5.0% slower for the warm role-heavy query than the historical baseline, while analyzer construction—unaffected by role storage—was 13.6% slower in the same comparison.
  Evidence: the candidate reported 40.956 s analyzer construction, 32.573 s extraction, and 6.691 s matching versus 36.068 s, 30.593 s, and 6.370 s historically. A same-compiler small A/B narrowed the warm-read difference to 7.12 ms versus 6.53 ms, so optimized A/B validation is required before calling this a read regression.

- Observation: RQL and relevance do not currently share a compatible graph lifecycle. RQL resolves forward rows lazily to preserve file/edge budgets and unsupported-provider diagnostics, and only completes the workspace graph for `importers_of`; relevance deliberately explores a two-hop graph around seeds on every request.
  Evidence: `DirectImportGraph` tracks `unsupported`, `resolved_files`, `resolved_edges`, `complete`, and `truncated`, while `relevance::build_import_graph` stops after `IMPORT_DEPTH` and combines forward plus reverse discovery around its frontier. The experiment should share compact row mechanics without forcing an eager full-workspace cache.

- Observation: a dense generated dependency graph provides useful end-to-end signal for both consumers. With 1,000 files and 17,982 edges, the pre-change warm median is 132.160 ms for import PageRank and 483.503 ms for complete `importers_of` traversal.
  Evidence: peak RSS rose from 66,453,504 bytes after analyzer construction to 100,499,456 after relevance and 127,320,064 after RQL reverse traversal, leaving measurable room for compact construction and read storage.

- Observation: optimized same-binary A/B measurements were necessary to separate graph-layout effects from compiler and host noise. Across three alternating runs of preserved release test binaries, compact direct PageRank traversal reduced the warm median from 38.618 ms to 17.818 ms (53.9%), while complete RQL reverse traversal remained effectively at parity at 133.480 ms versus 131.658 ms.
  Evidence: the candidate no longer allocates one weighted adjacency vector per file before PageRank. Median peak RSS after relevance fell from 89,489,408 to 88,522,752 bytes (1.1%), and after RQL traversal from 113,115,136 to 111,935,488 bytes (1.0%).

- Observation: compact storage should be a representation primitive, not a shared graph lifecycle. Relevance still constructs a request-local two-hop graph, while RQL still resolves forward rows incrementally and freezes only after complete or terminally truncated reverse traversal.
  Evidence: `ImportGraphBuilder::finish` produces the relevance snapshot; `DirectImportGraph::freeze` consumes its incremental forward map only when `ensure_complete_import_graph` reaches a terminal state.

- Observation: the common Java/C#/C++/Python/Ruby/PHP/Scala hierarchy path retains a global reverse map whose values are separately allocated `Arc<HashSet<CodeUnit>>` rows, while every queried row is also copied into a weighted memo cache. Go and Rust maintain distinct language-specific hierarchy indexes and should not be folded into the first common-path experiment.
  Evidence: `build_direct_descendant_index` returns `HashMap<CodeUnit, Arc<HashSet<CodeUnit>>>`; the common providers clone a row, insert another `Arc<HashSet<_>>` into `direct_descendants`, and return another owned set.

- Observation: ownership is structurally singular but is not currently a retained workspace relation. Per-file `FileState.children` maps retain parent-to-child rows, while standalone RQL `owner` scans that file's type declarations and records a query-local `owner_by_member` cache; `members | owner` already records the owner without scanning.
  Evidence: `IndexedDeclarations::owner_of` searches `analyzer.direct_children(candidate)` only on a standalone owner miss, and `QueryStep::Members` calls `record_owner` for every emitted child. An eager workspace CSC for this query-local path is unlikely to be justified without a much larger per-file child-layout change.

- Observation: the generated 800-type / 799-edge hierarchy makes reverse-index construction and both ownership paths measurable without exhausting provenance budgets. The first direct-descendant lookup costs 242.494 ms and raises peak RSS by 7,405,568 bytes; warm transitive provider reads are 1.449 ms, warm RQL subtypes are 459.111 ms, members-owner is 866.424 ms, and standalone owner is 722.372 ms.
  Evidence: `tests/measure_hierarchy_relations.rs` uses a breadth-four bounded-depth Java tree, four member methods per type, exact result-count assertions, one analyzer thread, and seven warm iterations.

- Observation: a one-way keyed CSR is a better hierarchy shape than the bidirectional `CompactDirectedGraph`. Only ancestors with outgoing rows need hash lookup; every descendant can remain a dense arena ID, and no incoming orientation is consumed because direct ancestors already come from language-specific structured resolution.
  Evidence: `DirectDescendantIndex` retains one exact `CodeUnit` arena, `HashMap<CodeUnit, u32>` only for ancestors with rows, and `CompactRows<u32>` descendants. At 800 types, only about 200 breadth-four parents require row lookup rather than all 800 nodes.

- Observation: the old per-key `direct_descendants` memo caches duplicated the global reverse index without removing return allocations. Every lookup cloned a cached `HashSet`, while the compact index can collect the same owned API result directly from a slice; removing these caches improved traversal and lowers retained state after broad queries.
  Evidence: across three alternating release processes, full provider descendants fell from 0.516 ms to 0.219 ms first (57.6%) and from 0.224 ms to 0.192 ms warm (14.1%). RQL subtypes remained at parity because structural matching and provenance rendering dominate that path.

- Observation: `WorkspaceUsageGraph` is currently private to usage-based relevance and its calibration benchmark; the public `usage_graph` tool has a separate richer rendering path. Compaction can therefore preserve an edge iterator adapter for calibration while measuring public-tool regressions separately, rather than forcing public call-site payloads into the ranking graph.
  Evidence: direct consumers of `WorkspaceUsageGraph.edges` are `related_files_by_usage_graph` and `relevance/weight_benchmark.rs`; `searchtools::usage_graph` independently builds its filtered response.

- Observation: the new generated usage-relevance fixture reproduces the existing Go memory workload at a smaller configurable scale and makes the ranking representation measurable. At 500 modules it implies at least 3,500 catalog nodes and exactly 3,000 aggregated call edges; first ranking takes 1,229.977 ms, warm ranking 814.111 ms, and peak RSS grows from 35,520,512 bytes after analyzer construction to 81,985,536 after the first rank and 83,591,168 after warm reranking.
  Evidence: `tests/measure_usage_relevance_graph.rs` uses one helper target and six caller methods per module, asserts `sub/sub.go` ranks first, uses one analyzer thread, and reports one versioned JSON line.

- Observation: compacting only the final weighted usage adjacency is too small a lever for the current end-to-end path. At 2,000 modules the candidate replaces 12,000 retained 24-byte `{ usize, usize, counts }` edges with 12-byte `{ u32, counts }` targets plus about 56 KB of row offsets, and avoids roughly 528 KB of temporary PageRank row headers and weighted pairs; resolver/catalog construction still drives a roughly 400 MB process high-water mark.
  Evidence: alternating preserved release binaries were at parity at 500 modules. At 2,000 modules, baseline first/warm ranking ranges were 2,915.780-2,968.974 ms / 1,893.032-1,934.331 ms and candidate ranges were 2,965.992-3,006.331 ms / 1,926.133-1,937.840 ms; peak RSS ranges overlapped with no candidate reduction.

## Decision Log

- Decision: begin with structural fact roles and keep the first compact representation local to `FileFacts` until its measurements are known.
  Rationale: role rows are immutable, already keyed by dense fact IDs, and avoid cross-language identity questions. A local pilot proves the storage mechanics without committing the repository to a universal graph API.
  Date/Author: 2026-07-15 / Codex

- Decision: measure both retained logical bytes and process peak RSS.
  Rationale: `FileFacts::estimated_bytes()` can precisely compare retained cache payloads, while RSS includes parser, allocator, analyzer, and temporary-construction effects. Either measure alone would give an incomplete conclusion.
  Date/Author: 2026-07-15 / Codex

- Decision: compare cold extraction separately from warm role-heavy matching.
  Rationale: compact rows may reduce allocations during extraction and improve locality during reads, but flattening or offset construction can add build cost. The experiment must show both sides of that tradeoff.
  Date/Author: 2026-07-15 / Codex

- Decision: do not add a permanent generic compact graph module until a second concrete relation needs the same mechanics.
  Rationale: a reusable API should be factored from two proven consumers rather than designed around hypothetical uniformity among roles, imports, hierarchy edges, and usage payloads.
  Date/Author: 2026-07-15 / Codex

- Decision: retain exact domain identity outside compact adjacency storage.
  Rationale: file paths, exact `CodeUnit` values, JS/TS defining-file identity, overload groups, and persisted blob-local keys have different equality rules. Dense IDs are snapshot-local indices into domain-owned arenas, not semantic identities by themselves.
  Date/Author: 2026-07-15 / Codex

- Decision: promote compact structural role rows as the first production issue #748 result.
  Rationale: the representation removes one vector header and allocation per fact, reduces retained `vscode` facts by 28.9% and process high-water RSS by about 15%, preserves exact fact and role counts plus source order, and shows no repeatable optimized warm-read regression. Direct append also avoids a transient flattening allocation.
  Date/Author: 2026-07-15 / Codex

- Decision: extract and promote crate-private `CompactRows` and `CompactDirectedGraph` primitives after the import experiment proved a second concrete consumer.
  Rationale: structural roles, request-local import PageRank, and terminal RQL import graphs now share fixed-width row offsets and contiguous values without sharing domain identity or construction policy. The optimized import benchmark shows a material PageRank read improvement, no repeatable RQL read regression, and a small repeatable RSS reduction.
  Date/Author: 2026-07-15 / Codex

- Decision: make weighted PageRank consume an adjacency view rather than require `Vec<Vec<(usize, f64)>>`.
  Rationale: usage ranking can retain its weighted vectors until its own experiment, while unweighted compact imports expose CSR/CSC rows directly. This isolates numerical PageRank from storage layout and removes the import path's last per-row reconstruction allocation.
  Date/Author: 2026-07-15 / Codex

- Decision: promote one-way exact-identity CSR for the shared reverse hierarchy index and remove its redundant per-key descendant memo caches.
  Rationale: the common Java, C#, C++, Python, Ruby, PHP, Scala, JavaScript, and TypeScript path has immutable reverse rows, and the optimized A/B shows materially faster provider traversal plus a repeatable 606,208-byte lower peak after hierarchy traversal at only 800 types. Exact duplicate-FQN and module-scoped identity tests remain green. Go and Rust retain their specialized indexes until measured independently.
  Date/Author: 2026-07-15 / Codex

- Decision: do not introduce workspace CSC or eager dense identity for RQL ownership in this milestone.
  Rationale: ownership is singular and already stored per file as parent-to-child facts; `members | owner` records its exact reverse relation query-locally, and standalone `owner` scans only the member's file under the existing work budget. Optimized owner timings stayed at parity after hierarchy compaction, so a workspace graph would add lifecycle and memory cost without evidence of benefit. A future immutable per-file `children` layout should use a single-parent reverse array rather than general CSC.
  Date/Author: 2026-07-15 / Codex

- Decision: retain the existing dense weighted usage edge vector and PageRank adapter rather than promote compact outgoing rows.
  Rationale: the candidate preserves exact results but only removes well under 1 MB at the 14,000-node / 12,000-edge scale, while usage resolution and catalog construction consume hundreds of megabytes. Alternating release runs show no repeatable RSS reduction or read improvement. A future usage-memory effort should target rich-key resolver/catalog state or reuse across reranks before revisiting final adjacency layout; no incoming CSC consumer exists.
  Date/Author: 2026-07-15 / Codex

## Outcomes & Retrospective

The structural-role, file-dependency, and reverse-hierarchy experiments are promoted. Together they justify shared crate-private compact row mechanics while preserving domain-specific identities and lifecycles. RQL ownership is explicitly not promoted to a workspace graph: its singular, per-file, query-local shape does not justify CSC. Weighted usage adjacency is also not promoted: its dense edge IDs were already compact enough that changing only final storage did not move resolver-dominated end-to-end metrics. The remaining milestone is the representative regression suite, full validation, and final issue report.

Milestone 1 outcome 2026-07-15T14:20:00Z: the representation-neutral benchmark is implemented and exercises nonzero facts and semantic role edges. Synthetic retained storage scales from 7,844,400 bytes at 36,100 facts to 123,759,200 bytes at 564,400 facts. The real `vscode` run establishes a 1.530 GB retained-storage baseline and proves the role representation is large enough for the pilot to produce a meaningful signal.

Milestone 2 outcome 2026-07-15T14:29:00Z: direct CSR-style extraction removes every per-node role allocation and stores one `u32` offset per fact boundary plus one exact-sized role buffer. At 564,400 generated facts, retained bytes fell from 123,759,200 to 90,357,600 (27.0%). On `vscode`, retained bytes fell by 463,469,148 (28.9%), peak RSS after extraction fell by 369,836,032 (15.8%), and peak RSS after warm matching fell by 414,253,056 (15.1%). In the adjacent optimized large-fixture pair where analyzer setup was load-matched, warm reads were 88.98 ms for compact rows versus 89.53 ms for the baseline. All 86 structural unit tests, the structured call-site test, documented query tests, tutorials, all 57 pipeline tests, formatting, and all-target/all-feature Clippy with warnings denied pass. The candidate is promoted.

Milestone 3 baseline 2026-07-15T14:47:31Z: `tests/measure_file_dependency_graph.rs` generates a Java hub/ring graph whose hub both imports and is imported by every node. This makes forward personalized PageRank and reverse RQL traversal cover the same full graph without depending on Git history. At the default 801 files / 4,800 edges, warm medians are 38.536 ms relevance and 216.907 ms `importers_of`; at 1,000 files / 17,982 edges they are 132.160 ms and 483.503 ms. The harness passes focused all-feature Clippy.

Milestone 3 outcome 2026-07-15T15:11:55Z: `CompactRows<T>` now owns validated contiguous row offsets and values, and `CompactDirectedGraph<K>` adds snapshot-local exact identities with sorted outgoing CSR and incoming CSC. Structural roles reuse the row primitive without changing their measured representation. Relevance emits dense import edges during its existing two-hop exploration and PageRank traverses compact rows directly through a storage-neutral adjacency view. RQL retains its incremental forward map and diagnostics until reverse traversal completes or truncates, then consumes that map into compact forward and reverse rows and drops redundant construction state. Three alternating optimized runs at 1,000 files / 17,982 edges moved median first relevance from 331.219 ms to 312.926 ms, warm relevance from 38.618 ms to 17.818 ms, first RQL traversal from 199.590 ms to 203.174 ms, and warm RQL traversal from 133.480 ms to 131.658 ms. Median peak RSS after relevance fell by 966,656 bytes and after RQL by 1,179,648 bytes. The first-RQL difference is within run variance; warm RQL reads are at parity. Exact output-count assertions, 86 structural tests, four PageRank unit tests, 27 relevance integration tests, 57 query-pipeline tests, formatting, and all-target/all-feature Clippy with warnings denied pass. The candidate is promoted.

Milestone 4 baseline 2026-07-15T15:29:00Z: `tests/measure_hierarchy_relations.rs` generates one exact Java declaration per file in a bounded-depth breadth-four tree, with four member methods that call a local sink. At 800 types / 799 hierarchy edges, analyzer construction is 668.868 ms; the first direct-descendant lookup that materializes the global reverse index is 242.494 ms and its warm median is 0.001 ms; full provider descendants are 3.209 ms first and 1.449 ms warm. RQL transitive subtypes are 466.728 ms first and 459.111 ms warm; all-class `members | owner` is 960.740 ms first and 866.424 ms warm; standalone call-site `enclosing_decl | owner` is 722.748 ms first and 722.372 ms warm. Peak RSS rises from 36,896,768 after analyzer construction to 44,302,336 after hierarchy-index construction, 53,116,928 after RQL subtypes, 87,490,560 after members-owner, and 98,222,080 after standalone owner. The next change will compact only the shared global reverse hierarchy index first; the query-local ownership path remains a separately measured promote-or-discard decision.

Milestone 4 outcome 2026-07-15T15:40:44Z: the common reverse hierarchy index now stores exact `CodeUnit` identities once, hash-indexes only ancestors that own rows, and retains all descendant endpoints in `CompactRows<u32>`. Nine providers no longer retain a second weighted Moka cache of per-key descendant sets. In three alternating release process runs, median first full-descendant traversal moved from 0.516 ms to 0.219 ms and warm traversal from 0.224 ms to 0.192 ms. RQL subtypes were 156.554 ms versus 156.598 ms first and 156.296 ms versus 155.590 ms warm; members-owner was 289.814 ms versus 290.238 ms warm; standalone owner was 236.270 ms versus 237.158 ms warm. Those end-to-end paths are at parity. Median peak RSS after the hierarchy query fell from 42,876,928 to 42,270,720 bytes; after the complete ownership workload it fell from 81,248,256 to 80,773,120 bytes. All 182 focused hierarchy, update/cache, exact-identity pipeline, and language-provider tests pass, as does all-target/all-feature Clippy with warnings denied. Hierarchy CSR is promoted; ownership CSC is discarded.

Milestone 5 baseline 2026-07-15T15:46:38Z: `tests/measure_usage_relevance_graph.rs` builds a deterministic Go workspace and calls the public `most_relevant_files` surface in `usage_graph` ranking mode, thereby exercising catalog construction, weighted edge aggregation, the dense ranking graph, PageRank, and file aggregation. At 500 modules / at least 3,500 nodes / 3,000 edges, analyzer construction is 452.258 ms, first ranking is 1,229.977 ms, and the five-iteration warm median is 814.111 ms. Peak RSS is 35,520,512 bytes after the analyzer, 81,985,536 after first ranking, and 83,591,168 after warm ranking. The exact first result is `sub/sub.go` and is stable across every rerank.

Milestone 5 outcome 2026-07-15T15:56:34Z: the candidate stored each outgoing weighted target as `{ u32, UsageReferenceCounts }` in `CompactRows`, exposed a representation-neutral edge iterator to calibration, and let weighted PageRank read rows directly. Exact ranking output remained `sub/sub.go`. Across three alternating 500-module release processes, baseline versus candidate medians were 495.447 ms versus 490.197 ms first, 369.238 ms versus 363.862 ms warm, 67,436,544 versus 68,599,808 bytes RSS after first ranking, and 68,534,272 versus 71,204,864 bytes after warm ranking. The small timing difference is within variance and RSS moved in the wrong direction. Two alternating 2,000-module runs likewise overlapped: baseline first/warm ranges were 2,915.780-2,968.974 ms / 1,893.032-1,934.331 ms, candidate ranges were 2,965.992-3,006.331 ms / 1,926.133-1,937.840 ms, baseline final RSS was 400,130,048-420,560,896 bytes, and candidate final RSS was 417,988,608-418,873,344 bytes. Because the candidate's retained plus temporary saving is under 1 MB at this scale and does not affect end-to-end metrics, the representation edit is discarded while the benchmark is retained.

## Context and Orientation

`src/analyzer/structural/extract.rs` parses one source file with tree-sitter and performs two iterative passes. The first pass creates `NormalizedNode` facts in preorder. The second pass uses each language's `StructuralSpec` to collect a fact name and `Vec<RoleTarget>`, then assigns that vector to `NormalizedNode::roles`. A role target describes a semantic AST relationship such as a call's callee, receiver, argument, or keyword argument. `src/analyzer/structural/facts.rs` stores all facts for one file in `FileFacts` and estimates their retained bytes for a Moka byte-budgeted cache.

`src/analyzer/structural/matcher.rs` scans facts and repeatedly filters a node's roles. `src/analyzer/structural/search.rs` also reads roles when classifying resolved references and rendering decorators. `src/analyzer/structural/rune_ir.rs` renders every role in source order. Any representation change must preserve that order and expose slices without allocation.

`src/relevance.rs` builds a two-hop import graph for legacy relevance and now also consumes the whole-workspace usage graph added by issue #781. The usage graph lives in `src/analyzer/usages/workspace_graph.rs`. Its node catalog uses exact ecosystem-specific identity and its final edges already carry dense integer endpoints, but construction still starts from rich-key maps and PageRank still expands edges into one `Vec` per node.

The checked-in performance regression harness is documented in `benchmark/README.md` and configured by `benchmark/targets.toml`. It operates on pinned repositories cached below `benchmark/.cache/repos` and emits reports below `benchmark/benchmark-output`. Large reusable repositories also exist under `/Users/dave/Workspace/test-repos`; use them read-only and record their exact Git commit before quoting results.

CSR represents `N` rows and `E` values with `N + 1` offsets plus `E` contiguous values. For structural roles, row `i` belongs to fact `i`, and `offsets[i]..offsets[i + 1]` selects its roles. A bidirectional graph can store outgoing CSR plus incoming offsets and incoming edge IDs that point into the outgoing edge array, so payloads are not duplicated.

## Plan of Work

Milestone 1 creates `tests/measure_structural_facts_memory.rs` and any small reusable helper it needs under `tests/common/`. The ignored test will generate a deterministic, role-dense TypeScript workspace, construct a `TypescriptAnalyzer` with a large enough structural-cache budget to avoid eviction, materialize and retain every file's `FileFacts`, and report cold extraction duration, fact count, role count, summed `estimated_bytes()`, and peak RSS. It will then run a role-heavy `CodeQuery` repeatedly against the warm cache and report a median duration. Fixture scale must be configurable through environment variables, and output must include one versioned JSON line. `FileFacts` may gain representation-neutral count accessors so the same benchmark compiles before and after storage changes.

Capture baseline runs at small, medium, and large synthetic sizes. Then run a semantically comparable `query_code` workload against a suitable TypeScript or Python checkout under `/Users/dave/Workspace/test-repos`, recording the repository commit. The real-repository run may use the CLI plus `/usr/bin/time -l` if direct fact-retention metrics are not available through the public service boundary. Keep the pre-change binary or benchmark JSON in `/tmp`; do not check generated output into the repository.

Milestone 2 changes structural facts so nodes no longer own `Vec<RoleTarget>`. `FileFacts` will own one contiguous role buffer and one offset per row boundary. Extraction must append each fact's roles in fact-ID order and then freeze the arrays. Consumers will call representation-neutral methods on `FileFacts`, such as iterating all roles for a fact ID or filtering that slice by role. Do not build per-node vectors and flatten them afterward if direct append can preserve the same semantics, because that would retain the construction allocation spike the experiment is meant to remove.

Run all structural query, Rune IR, reference traversal, docs-example, and pipeline tests. Repeat the exact Milestone 1 commands. Promote the change only if behavior is identical, retained logical storage decreases materially, and extraction or matching does not regress beyond normal run variance. Record the raw JSON lines and percentage deltas in this plan and on issue #748. If it fails those criteria, revert only the representation experiment while retaining useful benchmark infrastructure.

Milestone 3 evaluates imports. Build a snapshot-local `FileId` arena and compact forward relation from structured import resolution, with an incoming relation that references the same edges. Compare it against the maps in `DirectImportGraph`, analyzer reverse-import caches, and the import PageRank adapter. The experiment must preserve unsupported-provider diagnostics, query budgets, deterministic ordering, two-hop relevance semantics, and Windows-safe paths. Once structural rows and file adjacency demonstrate the same offset/value mechanics, factor the smallest shared crate-private primitive and migrate both consumers to it.

Milestone 4 evaluates type hierarchy and membership. Dense IDs must map exact `CodeUnit` values, never FQN strings. Measure direct supertypes, transitive subtypes, member enumeration, and owner lookup on diamond and duplicate-FQN fixtures plus a large Java repository. A single-owner reverse array is preferable to CSC for ownership if the existing contract proves ownership singular.

Milestone 5 evaluates the usage graph. Start from `WorkspaceUsageCatalog` and `WorkspaceUsageGraph`, preserving `UsageReferenceCounts`, truncation metadata, unproven inbound counts, and JS/TS file-scoped identity. Replace the PageRank `Vec<Vec<_>>` expansion with a flat weighted adjacency view, then determine whether the rich-key `UsageEdgeWeights` aggregation can emit dense edge events earlier. Compare public `usage_graph`, usage-based relevance, dead-code consumers, and the ignored Go/Python/JS/TS memory fixtures. Apply path filters and hot-callee caps to uncapped compact information rather than caching a query-specific truncated graph.

Milestone 6 runs formatting, Clippy with all targets and features, the full `nlp,python` suite, the pinned performance regression harness on representative repositories, and focused memory benchmarks. The final issue report will classify each candidate as promoted, promising but deferred, or unsuitable, with evidence. Update `Outcomes & Retrospective`, post the conclusion to #748, and only then mark the epic complete.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/1d60/bifrost` on branch `748-explore-compact-csrcsc-graph-representations-for-workspace-queries`.

Before source changes, verify state with:

    git fetch
    git status --short --branch
    git rev-parse HEAD origin/master @{upstream}

Build and run the initial structural benchmark with commands recorded here once its exact environment-variable names are implemented. The expected shape is:

    BIFROST_SEMANTIC_INDEX=off cargo test --test measure_structural_facts_memory -- --ignored --nocapture

    BIFROST_STRUCTURAL_BENCH_FILES=... BIFROST_STRUCTURAL_BENCH_CALLS_PER_FILE=... \
      BIFROST_SEMANTIC_INDEX=off cargo test --test measure_structural_facts_memory -- --ignored --nocapture

The test must print a line beginning with a stable marker such as `BIFROST_STRUCTURAL_FACTS_BENCHMARK_JSON ` followed by valid JSON.

After every structural representation edit, run at minimum:

    cargo fmt --all -- --check
    BIFROST_SEMANTIC_INDEX=off cargo test analyzer::structural
    BIFROST_SEMANTIC_INDEX=off cargo test --test code_query_pipelines
    BIFROST_SEMANTIC_INDEX=off cargo test --test code_query_docs --test code_query_tutorials

Validate the checked-in performance harness and run selected repositories with:

    cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml
    cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo <name>

Before a pushed or final checkpoint, run:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

Use `scripts/with-isolated-cargo-target.sh` if a matched isolated toolchain is required. Do not use manually named Cargo target directories.

On the current host, the matching Clippy invocation is:

    /Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/cargo-clippy \
      clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

The structural pilot is behaviorally acceptable only if existing JSON and RQL matching, argument ordering, keyword matching, decorator ranges, Rune IR output, reference-kind classification, cache invalidation, and query budgets remain unchanged. Its benchmark must report nonzero fact and role counts. The same generated source and query must be used before and after the storage change.

A compact representation is promoted only when its retained-memory reduction is material and repeatable. Use repeated timings and report the distribution or median rather than selecting one favorable run. A small performance change inside normal variance is acceptable; a repeatable slowdown must be explained and justified by a larger memory benefit or the experiment is discarded.

Import, hierarchy, and usage experiments must compare exact output sets and deterministic ordering against the current implementation. PageRank comparisons use the existing numerical tolerances. Traversals remain iterative, cycle-safe, cancellation-aware where applicable, and bounded by existing execution limits.

The final goal is accepted when issue #748 contains reproducible evidence for every evaluated candidate, at least one low-risk production path uses compact storage with a demonstrated benefit, the regression suite shows no actionable unrelated slowdown, and the repository passes formatting, warnings-as-errors Clippy, and the full feature-enabled test suite.

## Idempotence and Recovery

Synthetic benchmarks create temporary workspaces and are safe to rerun. Repository benchmarks must treat `/Users/dave/Workspace/test-repos` and `benchmark/.cache/repos` as read-only inputs. Generated JSON and copied binaries belong in `/tmp` or ignored benchmark-output directories.

Each representation milestone is isolated by a checkpoint commit. If an experiment fails its promotion criteria, record the evidence in this plan and issue #748, then revert only that milestone's representation commit; retain benchmark improvements that are independently useful. Never mask structured resolver gaps with source-text scanning.

## Artifacts and Notes

The original issue #748 baseline, before prerequisite fixes, reported a 2,000-module Go usage graph with 14,002 nodes, 12,000 edges, and about 174.8 MB peak growth. Python and JS/TS produced zero edges at that time; #752 repaired those fixtures, so those old numbers are not valid comparison baselines for later usage work.

Issue #781 measured current Bifrost usage-based relevance on a warm debug build at roughly 40.5 seconds for compact graph construction, 10 ms for PageRank, and 15.8 ms for file aggregation. This indicates that resolver construction, not numerical ranking, dominates the usage path. Re-measure on this branch before drawing conclusions because host state and repository revisions can change.

Structural-role baseline at Bifrost representation commit `da0dc303f0854e28c1c2864b8d7fc08fd2dfe28c`, single-threaded, debug test profile:

    BIFROST_STRUCTURAL_BENCH_FILES=100 BIFROST_STRUCTURAL_BENCH_CALLS_PER_FILE=25 BIFROST_STRUCTURAL_BENCH_ITERATIONS=7 BIFROST_SEMANTIC_INDEX=off cargo test --test measure_structural_facts_memory -- --ignored --nocapture
    facts=36100 roles=17500 retained=7844400 extraction_ms=151.302 match_median_ms=6.565 rss_after_extraction=44875776

    BIFROST_STRUCTURAL_BENCH_FILES=200 BIFROST_STRUCTURAL_BENCH_CALLS_PER_FILE=50 BIFROST_STRUCTURAL_BENCH_ITERATIONS=7 BIFROST_SEMANTIC_INDEX=off cargo test --test measure_structural_facts_memory -- --ignored --nocapture
    facts=142200 roles=70000 retained=30949200 extraction_ms=640.279 match_median_ms=21.371 rss_after_extraction=94617600

    BIFROST_STRUCTURAL_BENCH_FILES=400 BIFROST_STRUCTURAL_BENCH_CALLS_PER_FILE=100 BIFROST_STRUCTURAL_BENCH_ITERATIONS=7 BIFROST_SEMANTIC_INDEX=off cargo test --test measure_structural_facts_memory -- --ignored --nocapture
    facts=564400 roles=280000 retained=123759200 extraction_ms=2576.947 match_median_ms=354.477 rss_after_extraction=246054912

    BIFROST_STRUCTURAL_BENCH_REPO=/Users/dave/Workspace/test-repos/vscode BIFROST_STRUCTURAL_BENCH_ITERATIONS=3 BIFROST_STRUCTURAL_BENCH_PARALLELISM=1 BIFROST_SEMANTIC_INDEX=off cargo test --test measure_structural_facts_memory -- --ignored --nocapture
    workspace_commit=a5914335df0bf1cae7d818a168ef321def9f8572 candidate_files=6556 extracted_files=6553 skipped_files=3 facts=6276000 roles=4258462 retained=1604467430 extraction_ms=30593.007 match_median_ms=6370.008 rss_after_extraction=2342944768 rss_after_matching=2744664064

File-dependency baseline at Bifrost commit `df76cfbdb140f54984ec98a5c677b4c4e98d94dd`, single-threaded, debug test profile:

    BIFROST_SEMANTIC_INDEX=off cargo test --test measure_file_dependency_graph -- --ignored --nocapture
    files=801 edges=4800 relevance_first_ms=501.728 relevance_warm_median_ms=38.536 importers_first_ms=315.253 importers_warm_median_ms=216.907 rss_after_analyzer=40583168 rss_after_relevance=53084160 rss_after_importers=65552384

    BIFROST_FILE_GRAPH_BENCH_FILES=999 BIFROST_FILE_GRAPH_BENCH_FANOUT=16 BIFROST_FILE_GRAPH_BENCH_ITERATIONS=7 BIFROST_SEMANTIC_INDEX=off cargo test --test measure_file_dependency_graph -- --ignored --nocapture
    files=1000 edges=17982 relevance_first_ms=1194.168 relevance_warm_median_ms=132.160 importers_first_ms=825.381 importers_warm_median_ms=483.503 rss_after_analyzer=66453504 rss_after_relevance=100499456 rss_after_importers=127320064

File-dependency optimized A/B at the `868c8d9f49c625be8ca3bbcf9ba9de46f49a666e` baseline and its uncommitted compact candidate, single-threaded release test profile, 1,000 files / 17,982 edges / 15 warm iterations. Each figure below is the median of three alternating preserved-binary process runs:

    baseline relevance_first_ms=331.219 relevance_warm_median_ms=38.618 importers_first_ms=199.590 importers_warm_median_ms=133.480 rss_after_relevance=89489408 rss_after_importers=113115136

    candidate relevance_first_ms=312.926 relevance_warm_median_ms=17.818 importers_first_ms=203.174 importers_warm_median_ms=131.658 rss_after_relevance=88522752 rss_after_importers=111935488

Hierarchy/ownership optimized A/B at baseline commit `05033258e0afa80e12e54a6c37e6c9f71ed54f1e` and its compact candidate, single-threaded release test profile, 800 types / 799 edges / four member methods / seven warm iterations. Each figure is the median of three alternating preserved-binary process runs:

    baseline direct_first_ms=75.476 descendants_first_ms=0.516 descendants_warm_median_ms=0.224 rql_subtypes_first_ms=156.554 rql_subtypes_warm_median_ms=156.296 members_owner_warm_median_ms=289.814 standalone_owner_warm_median_ms=236.270 rss_after_hierarchy_index=34390016 rss_after_rql_subtypes=42876928 rss_after_standalone_owner=81248256

    candidate direct_first_ms=75.694 descendants_first_ms=0.219 descendants_warm_median_ms=0.192 rql_subtypes_first_ms=156.598 rql_subtypes_warm_median_ms=155.590 members_owner_warm_median_ms=290.238 standalone_owner_warm_median_ms=237.158 rss_after_hierarchy_index=34275328 rss_after_rql_subtypes=42270720 rss_after_standalone_owner=80773120

Weighted usage-relevance baseline at Bifrost commit `e0bc329569d74d430de65818e4cf473293c3eca7`, single-threaded debug test profile:

    BIFROST_SEMANTIC_INDEX=off cargo test --test measure_usage_relevance_graph -- --ignored --nocapture
    modules=500 expected_minimum_nodes=3500 expected_edges=3000 analyzer_build_ms=452.258 ranking_first_ms=1229.977 ranking_warm_median_ms=814.111 ranking_results=1 first_result=sub/sub.go rss_after_analyzer=35520512 rss_after_first_ranking=81985536 rss_after_warm_ranking=83591168

Weighted usage-relevance optimized A/B at baseline commit `0003183ad4383b8e8807e7e1a21dbedab0e1569f` and its uncommitted compact candidate, single-threaded release profile. The 500-module figures are medians of three alternating preserved-binary process runs:

    baseline modules=500 analyzer_build_ms=162.800 ranking_first_ms=495.447 ranking_warm_median_ms=369.238 rss_after_analyzer=27607040 rss_after_first_ranking=67436544 rss_after_warm_ranking=68534272

    candidate modules=500 analyzer_build_ms=162.958 ranking_first_ms=490.197 ranking_warm_median_ms=363.862 rss_after_analyzer=27377664 rss_after_first_ranking=68599808 rss_after_warm_ranking=71204864

At 2,000 modules / at least 14,000 nodes / 12,000 edges / two warm iterations, two alternating runs produced these ranges:

    baseline ranking_first_ms=2915.780..2968.974 ranking_warm_median_ms=1893.032..1934.331 rss_after_first_ranking=371032064..393379840 rss_after_warm_ranking=400130048..420560896

    candidate ranking_first_ms=2965.992..3006.331 ranking_warm_median_ms=1926.133..1937.840 rss_after_first_ranking=388825088..391315456 rss_after_warm_ranking=417988608..418873344

## Interfaces and Dependencies

The first benchmark may add representation-neutral methods to `FileFacts`:

    pub fn role_count(&self) -> usize;
    pub fn roles(&self, node: u32) -> &[RoleTarget];
    pub fn role_targets(&self, node: u32, role: Role) -> impl Iterator<Item = &RoleTarget>;

The exact public visibility should be no broader than existing structural consumers and integration benchmark needs. After Milestone 2, `NormalizedNode` must not own a role vector. `FileFacts` should own offsets and values using fixed-width offsets where limits make that safe:

    role_offsets: Box<[u32]>
    roles: Box<[RoleTarget]>

Do not introduce a third-party graph dependency. The representation is simple enough to implement with standard slices and existing project hash maps at the identity boundary. If a shared primitive is justified after the import experiment, it should remain crate-private, accept caller-owned domain IDs and payloads, validate offset overflow, provide allocation-free row slices, and support incoming edge IDs without duplicating payloads.

Revision note 2026-07-15T13:53:57Z: Created the issue #748 experiment ExecPlan after verifying all prerequisites, current branch state, the structural-role consumers, and the newly merged usage-graph PageRank implementation.

Revision note 2026-07-15T14:20:00Z: Recorded the completed structural benchmark harness, the empty-file repository discovery, and synthetic plus `vscode` baseline evidence before changing role storage.

Revision note 2026-07-15T14:25:00Z: Documented the host's dual-Rust compiler cache incompatibility and the required single-compiler validation workaround.

Revision note 2026-07-15T14:29:00Z: Recorded the implemented structural-role CSR candidate, its targeted behavior checks, and synthetic plus `vscode` memory results; left promotion pending optimized timing and lint validation.

Revision note 2026-07-15T14:29:00Z: Promoted compact structural role rows after optimized A/B read parity, focused behavior validation, and warnings-as-errors Clippy passed.

Revision note 2026-07-15T14:47:31Z: Added the file-dependency benchmark, recorded default and dense baselines, and narrowed the sharing goal to representation mechanics because RQL and relevance require different graph lifecycles.

Revision note 2026-07-15T15:11:55Z: Promoted shared compact rows and directed CSR/CSC after alternating optimized A/B runs showed substantially faster direct PageRank reads, RQL read parity, modest repeatable RSS savings, and focused behavior plus lint validation.

Revision note 2026-07-15T15:29:00Z: Added the exact-identity hierarchy and ownership benchmark, captured its 800-type baseline, and narrowed the first candidate to the common retained reverse hierarchy index because ownership is currently singular, per-file, and query-local in the RQL path.

Revision note 2026-07-15T15:40:44Z: Promoted exact-identity one-way hierarchy CSR after alternating optimized A/B and cross-language validation; recorded that RQL ownership should remain query-local and use a single-parent reverse array only if per-file child storage is later compacted.

Revision note 2026-07-15T15:46:38Z: Added the weighted usage-relevance benchmark, captured its 500-module baseline, and confirmed the compact ranking graph can remain separate from the public usage-graph rendering model while retaining an iterator adapter for calibration.

Revision note 2026-07-15T15:56:34Z: Discarded compact weighted usage adjacency after preserved release binaries at 500 and 2,000 modules showed no repeatable end-to-end memory or read improvement; retained the representation-neutral benchmark and redirected future usage-memory work toward resolver/catalog state.
