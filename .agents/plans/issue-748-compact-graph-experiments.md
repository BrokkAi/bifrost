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
- [ ] Replace per-node structural role vectors with one contiguous role array and row offsets, preserving source order and all `query_code`, Rune IR, and reference-classification behavior.
- [ ] Compare the structural-role candidate with its baseline, review it, and either promote it or revert it with the result recorded on issue #748.
- [ ] Prototype a shared file-dependency relation for RQL import traversal and import PageRank, measure forward and reverse reads, and make a promote-or-discard decision.
- [ ] Prototype compact hierarchy and ownership relations using exact `CodeUnit` identity, measure direct and transitive traversal, and make a promote-or-discard decision.
- [ ] Adapt the dense-ID `WorkspaceUsageGraph` introduced by #781 to contiguous outgoing and incoming edge storage without reintroducing rich-key construction, then measure graph construction, PageRank, public rendering, and memory.
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

- Observation: this host currently has two Rust 1.96.0 builds with the same commit hash but different LLVM builds. An unconstrained Cargo invocation can compile dependencies with rustup's compiler and the crate with Homebrew's compiler, producing `E0514` even in a fresh isolated target.
  Evidence: both the shared target and `scripts/with-isolated-cargo-target.sh cargo clippy` failed with incompatible-crate diagnostics; rustup reports LLVM 22.1.2 while `/opt/homebrew/bin/rustc` reports LLVM 22.1.6. Validation commands must pin `RUSTC` to `rustup which rustc` on this host.

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

## Outcomes & Retrospective

No representation experiment has been promoted yet. Planning and prerequisite verification are complete. The first observable outcome will be a structural-role benchmark that can run unchanged before and after the compact representation, followed by a measured promote-or-discard decision.

Milestone 1 outcome 2026-07-15T14:20:00Z: the representation-neutral benchmark is implemented and exercises nonzero facts and semantic role edges. Synthetic retained storage scales from 7,844,400 bytes at 36,100 facts to 123,759,200 bytes at 564,400 facts. The real `vscode` run establishes a 1.530 GB retained-storage baseline and proves the role representation is large enough for the pilot to produce a meaningful signal.

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

Revision note 2026-07-15T14:35:00Z: Documented the host's dual-Rust compiler cache incompatibility and the required single-compiler validation workaround.
