# Ruby usage-graph cleanup: modular layout, cached semantics, precomputed dispatch mode, edge path

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md` at the repository root.

This plan is the Ruby follow-up deliberately carved out of `.agents/plans/unified-symbol-resolution.md` (checked in; its Decision Log records why Ruby was excluded there). Ruby's problems are structural rather than "swap a map": one monolithic file, workspace-wide facts rebuilt on every query, a per-candidate file re-parse in the hot path, and a missing whole-workspace edge path that silently excludes Ruby from `usage_graph` and dead-code analysis.

## Purpose / Big Picture

Ruby's usage analysis (`scan_usages` for a single target) works but is the structural outlier among Bifrost's eleven languages, and Ruby has no caller-to-callee edge support at all: `usage_graph` and the dead-code smell analysis cover nine languages and skip Ruby entirely. After this plan, Ruby's usage code lives in the same modular layout as every sibling language; workspace facts (ancestor and mixin maps) are computed once with analyzer state instead of once per query; method dispatch classification (instance vs. singleton vs. `module_function`) is recorded when declarations are collected instead of re-parsing the declaring file for every candidate; and Ruby has an inverted-edge builder wired into the same dispatch as the other languages, with dead-code tests to prove it.

Observable outcomes: existing Ruby suites keep passing; a new `tests/ruby_dead_code_smells.rs` demonstrates Ruby dead-code detection end to end; and `src/analyzer/usages/ruby_graph.rs` shrinks to a facade over a `ruby_graph/` directory like its siblings.

## Progress

- [x] (2026-07-07) Plan drafted from a survey of `ruby_graph.rs` and the Ruby analyzer.
- [x] (2026-07-07T14:33Z) Milestone 1: mechanically split `src/analyzer/usages/ruby_graph.rs` into facade plus `ruby_graph/{resolver,extractor,hits,syntax}.rs`; behavior-only validation passed with zero test edits.
- [x] (2026-07-07T14:33Z) Milestone 2: hoisted ancestor and mixin lookup maps into lazy `RubyAnalyzer` semantic facts; `RubySemanticIndex::build*` is now a per-query view and performs no `all_declarations()` scan.
- [x] (2026-07-07T14:33Z) Milestone 3: recorded Ruby method dispatch mode in analyzer parse state, rewired method lookup to consult `RubyAnalyzer::method_dispatch_mode`, and deleted the usage-layer `is_singleton_method_declaration` re-parse helper.
- [x] (2026-07-07T20:10Z) Milestone 4: added Ruby's inverted-edge path (`build_ruby_usage_edges` + `RubyEdgeResolver`), wired Ruby into `usage_graph` and dead-code bulk analysis, and added Ruby usage-graph/dead-code suites.

## Surprises & Discoveries

- Observation: The Ruby declaration collector already computes singleton context at collection time (`method_is_singleton_context`, `src/analyzer/ruby/declarations.rs:471-483`, used at :416 and :464 for field FQN encoding) but does not persist it for methods, so the usage layer re-derives it by re-reading and re-parsing the declaring file per candidate (`is_singleton_method_declaration`, `src/analyzer/usages/ruby_graph.rs:1680-1711`).
  Evidence: the two functions perform the same parent-walk over `singleton_method`/`singleton_class`/`class`/`module` node kinds; the usage-side copy additionally handles `module_function`.
- Observation: `RubySemanticIndex::build_with_target` (`ruby_graph.rs:290-336`) iterates `analyzer.all_declarations()` (every class/module in the workspace) calling `type_hierarchy_provider().get_direct_ancestors(unit)` per unit, plus a full pass over `ruby.mixin_relations()`, on every single query — yet none of that depends on the query target; only the `target` field and the `factory_return_cache` are per-query.
  Evidence: the only uses of `target` in the built struct are `target_matches_constant` and factory inference; `ancestors` and the three mixin maps are pure workspace facts.
- Observation: Ruby is absent from the per-language edge dispatch in `src/code_quality/dead_code_smells.rs` (arms exist for Rust :778, Python :862, Java :896, Scala :920, Go :943, C# :966, C++ :992, PHP :1016, JS/TS :1164) and `ruby_graph.rs` implements no `UsageEdgeResolver`, unlike every other `*_graph` module.
  Evidence: `grep -l UsageEdgeResolver src/analyzer/usages/*.rs` lists every language facade except `ruby_graph.rs`; there is no `ruby_dead_code_smells.rs` test suite while eight sibling suites exist.
- Observation: The Milestone 2 query-invariance diagnosis was correct. The moved maps are now built only in `RubyAnalyzer::semantic_facts`, and `RubySemanticIndex::build_with_target` only stores `analyzer`, `ruby`, a borrow of `ruby.semantic_facts()`, the optional target, and the per-query factory-return cache.
  Evidence: `rg -n "all_declarations\\(" src/analyzer/usages/ruby_graph src/analyzer/ruby/mod.rs` shows no usage-layer `all_declarations()` call; the only new scan is `src/analyzer/ruby/mod.rs:168` inside `RubySemanticFacts::build`.
- Observation: The Milestone 3 collector diagnosis was correct. The collector already had the singleton-context parent walk; after this work it persists the dispatch classification for methods through `ParsedFile::set_ruby_method_dispatch_mode` instead of discarding the fact.
  Evidence: `src/analyzer/ruby/declarations.rs` now calls `set_ruby_method_dispatch_mode` from both `visit_method` and `add_member_function`; `rg is_singleton_method_declaration src/analyzer/usages/ruby_graph src/analyzer/ruby` returns no matches.
- Observation: The old usage-layer `module_function` walker only looked at statements before the method node, but Ruby's named form is commonly written after the method it exports.
  Evidence: the new internal test `analyzer::ruby::tests::dispatch_mode_tests::classifies_named_module_function_method` covers `def normalize ...; module_function :normalize` and passes.
- Observation: The new edge builder could reuse `RubySemanticIndex::build_for_lookup`, `ruby_receiver_type`, `ruby_seed_assignment`, factory-return inference, and `RubyAnalyzer::method_dispatch_mode` without changing the query-path scanner, but the query scanner itself remains target-specific and is not a reusable no-target edge walker.
  Evidence: `src/analyzer/usages/ruby_graph/inverted.rs` builds a fresh target-free `RubySemanticIndex` inside each parsed-file closure and calls the shared receiver helpers directly; `RubyFileScan` still owns `RubyTargetSpec`, hit sets, and unsafe-inference bookkeeping.
- Observation: `usage_graph` had a Ruby node label but no Ruby ecosystem, so adding only the edge builder would still have left Ruby nodes under `unknown` while Ruby edges were impossible to merge cleanly.
  Evidence: before Milestone 4, `Ecosystem::of(Language::Ruby)` returned `Unknown` in `src/searchtools.rs`; the implementation adds `Ecosystem::Ruby`, a `usage_graph::resolve_ruby` pass, and wire label `ruby`.

## Decision Log

- Decision: Split the file first (Milestone 1), before any behavior change.
  Rationale: The later milestones rewrite specific regions; reviewing them inside a 1959-line file is error-prone, and the sibling layout (`resolver.rs`/`extractor.rs`/`hits.rs`) is the established convention.
  Date/Author: 2026-07-07 / Claude
- Decision: Cache ancestor/mixin maps in the Ruby analyzer's state lifecycle rather than memoizing inside the usages layer.
  Rationale: They are workspace facts derived from declarations and `mixin_relations`; analyzer state is rebuilt wholesale on re-analysis, so caching there gets invalidation for free — the same reasoning that put `DefinitionLookupIndex` and `UsageFactsIndex` on the analyzer (see the unified plan's Decision Log). A usages-side memo would be a second cache with its own staleness story.
  Date/Author: 2026-07-07 / Claude
- Decision: Build `RubySemanticFacts` lazily with an `Arc<OnceLock<RubySemanticFacts>>` owned by `RubyAnalyzer`.
  Rationale: Ancestor and mixin maps are only needed by Ruby usage/get-definition paths, so eager construction would add cost to analyzer users that never ask for those paths. Placing the `OnceLock` on `RubyAnalyzer` still ties invalidation to `update` and `update_all`, because those constructors allocate fresh analyzer cache state.
  Date/Author: 2026-07-07 / Codex
- Decision: Record method dispatch mode at declaration-collection time (Milestone 3) instead of caching the re-parse result.
  Rationale: The collector already walks the exact node structure needed; persisting the fact at the source follows the repo's root-cause philosophy, and it deletes the per-candidate `read_source` + `parse_ruby_tree` entirely instead of amortizing it.
  Date/Author: 2026-07-07 / Claude
- Decision: Store Ruby method dispatch modes in the generic parsed/analyzer state and persisted payload, keyed by `CodeUnit`.
  Rationale: This makes the classification a declaration-collection fact, not a Ruby usage side cache. The payload version was bumped from 3 to 4 so storage-backed analyzers do not hydrate rows missing the dispatch map.
  Date/Author: 2026-07-07 / Codex
- Decision: Treat `RubyMethodDispatchMode::ModuleFunction` as matching both instance and singleton lookup modes.
  Rationale: Ruby's `module_function` copies the method to the module's singleton side while leaving a private instance method, which is the behavioral contract Milestone 3 requires. `ruby_method_lookup_mode_matches` now encodes that directly from analyzer state.
  Date/Author: 2026-07-07 / Codex
- Decision: The edge path (Milestone 4) records only resolutions the query path already treats as proven; unresolved or unproven-receiver calls produce no edge.
  Rationale: `ruby_graph.rs`'s module doc states the policy: Ruby is dynamic, so hits are emitted only when parser and analyzer facts prove the target. Edges must follow the same conservatism — a wrong edge poisons dead-code analysis. This mirrors how the query path surfaces `UnsafeInference` instead of guessing.
  Date/Author: 2026-07-07 / Claude
- Decision: The invocation-context-keyed factory-return cache (`FactoryInferenceKey` = method + invocation owner) stays exactly as designed.
  Rationale: Ruby self-returning factories genuinely need the calling owner, not just the method FQN; this was the reason Ruby could not adopt the shared single-key `callable_return_type` map (unified plan, Decision Log).
  Date/Author: 2026-07-07 / Claude
- Decision: Milestone 4 uses a dedicated target-free Ruby inverted scanner instead of reshaping `RubyFileScan` into a shared query/edge walker.
  Rationale: `RubyFileScan` is built around one `RubyTargetSpec`, target hit recording, and unsafe-inference diagnostics. A separate scanner can still reuse the proven semantic pieces (`RubySemanticIndex::build_for_lookup`, receiver typing, local assignment seeding, factory-return inference, dispatch-mode filtering) while keeping this milestone scoped and avoiding speculative edges.
  Date/Author: 2026-07-07 / Codex
- Decision: Ruby edge coverage is the conservative proven subset: constant references, class/module receiver method calls, `Klass.new` to `Klass.initialize`, bare/self lexical receiver calls, locally typed receivers, and factory-return-typed receivers. Dynamic `send`/`public_send`, `alias_method`, and Ruby field edges remain on the per-target query path for now.
  Rationale: The subset covers the Milestone 4 dead-code and `usage_graph` requirements without inventing new inference. Edges are recorded only when method resolution returns exactly one candidate; ambiguous candidate sets, unknown receivers, and same-name guesses record nothing.
  Date/Author: 2026-07-07 / Codex
- Decision: Add a dedicated Ruby ecosystem to `usage_graph`.
  Rationale: Ruby now has an edge builder, so its nodes and edges need the same language identity as the other package-scoped ecosystems. Keeping Ruby under `Unknown` would make the output misleading and would prevent a clean per-language node-membership set.
  Date/Author: 2026-07-07 / Codex

## Outcomes & Retrospective

Milestones 1 through 4 are complete. The facade `src/analyzer/usages/ruby_graph.rs` delegates to `ruby_graph/extractor.rs`, `ruby_graph/hits.rs`, `ruby_graph/resolver.rs`, `ruby_graph/syntax.rs`, and the new edge modules `ruby_graph/inverted.rs` and `ruby_graph/shared.rs`. `RubySemanticIndex` no longer builds workspace-invariant ancestor/mixin maps per query; it borrows the analyzer-owned `RubySemanticFacts` and keeps only target/factory-return state per lookup. Method lookup mode now comes from `RubyAnalyzer::method_dispatch_mode`, backed by dispatch metadata recorded during declaration collection and persisted through analyzer state; the usage-layer `is_singleton_method_declaration` re-parse helper is gone.

Validation on 2026-07-07T14:33Z: `cargo fmt` passed; `BIFROST_SEMANTIC_INDEX=off cargo test -p brokk-bifrost analyzer::ruby::tests::dispatch_mode_tests --lib` passed 5 tests; `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_ruby_test --test ruby_lsp_goto_definition --test ruby_lsp_find_references --test ruby_analyzer_test --test ruby_type_hierarchy_test --test ruby_import_test --test get_definition_test` passed 455 tests; `cargo clippy --all-targets --all-features -- -D warnings` passed cleanly.

Milestone 4 adds `build_ruby_usage_edges`, `RubyEdgeResolver`, `src/analyzer/usages/ruby_graph/inverted.rs`, Ruby `usage_graph` dispatch, Ruby dead-code bulk dispatch, `tests/ruby_dead_code_smells.rs`, and `tests/usage_graph_ruby_test.rs`. The edge builder uses the shared inverted-edge engine and records only unique proven resolutions. Ruby dead-code analysis no longer falls back to one-symbol scans for ordinary function/class candidates, and `usage_graph` now emits Ruby nodes under the `ruby` ecosystem with Ruby caller-to-callee edges.

Validation on 2026-07-07T20:10Z: `cargo fmt` passed; `BIFROST_SEMANTIC_INDEX=off cargo test --test ruby_dead_code_smells --test usage_graph_ruby_test` passed 9 tests; `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_ruby_test --test ruby_lsp_goto_definition --test ruby_lsp_find_references --test ruby_analyzer_test --test ruby_type_hierarchy_test --test ruby_import_test --test get_definition_test --test cross_language_self_usages --test ruby_dead_code_smells --test usage_graph_ruby_test` passed 473 tests; `cargo clippy --all-targets --all-features -- -D warnings` passed cleanly.

The main limitation deliberately left for review is coverage breadth: dynamic dispatch (`send`, `__send__`, `public_send`), `alias_method`, and field edges were not added to the inverted edge path. They remain supported where previously supported by the target-specific query path, but Milestone 4 chose conservative no-edge behavior for those shapes rather than broadening inference under whole-workspace dead-code analysis.

Plan revision note, 2026-07-07T14:33Z: updated Progress, Surprises & Discoveries, Decision Log, and Outcomes after executing Milestones 1 through 3. The updates record the lazy analyzer-owned semantic facts cache, persisted dispatch-mode analyzer metadata, validation evidence, and the explicit Milestone 4 boundary.

Plan revision note, 2026-07-07T20:10Z: updated Progress, Surprises & Discoveries, Decision Log, and Outcomes after executing Milestone 4. The updates record the conservative Ruby edge coverage, `usage_graph` ecosystem wiring, validation evidence, and final limitations for review.

## Context and Orientation

All paths are relative to the repository root, the git worktree at `/mnt/optane/bifrost-shared-usage-index` on branch `shared-usage-index-refactor`.

Bifrost analyzes code with tree-sitter. `RubyAnalyzer` (`src/analyzer/ruby/mod.rs`, with `adapter.rs`, `declarations.rs`, `hierarchy.rs`, `imports.rs`, `mixins.rs`, `cache.rs`) wraps the generic `TreeSitterAnalyzer` and implements `IAnalyzer` (`src/analyzer/i_analyzer.rs`). A `CodeUnit` is one declaration (class, module, method, field) with `fq_name()`, `identifier()`, `source()` (its file), `is_class()`/`is_module()`/`is_function()` predicates. Ruby encodes constant nesting with `$`-joined FQN segments and singleton fields with a `$singleton.` marker (see `declarations.rs:416-464`).

The usage subsystem is `src/analyzer/usages/`. Two distinct capabilities matter here. The "query path" (`scan_usages`) finds usages of one target symbol; Ruby implements it via `RubyUsageGraphStrategy::find_graph_usages` (`src/analyzer/usages/ruby_graph.rs:45-140`), which builds a `RubyTargetSpec` (what to look for), a `RubySemanticIndex` (workspace facts + per-query state), then re-parses each candidate file and walks it with `RubyFileScan`. The "edge path" (`usage_graph` and dead-code analysis) builds the whole-workspace caller-to-callee edge set; every language except Ruby implements it as a `UsageEdgeResolver` (`src/analyzer/usages/traits.rs`) whose `build_edges` uses the shared engine in `src/analyzer/usages/inverted_edges.rs` — `build_edges`/`parse_and_collect` drive per-file parallel scanning, `ClassRangeIndex` attributes a byte offset to its enclosing declaration, and `EdgeCollector::record` handles self-reference filtering and caps. The per-language dead-code dispatch lives in `src/code_quality/dead_code_smells.rs` (see the arms listed in Surprises & Discoveries).

`ruby_graph.rs` is one 1959-line file organized roughly as: strategy entry (lines 1-155), target modeling (`RubyTargetKind`, `RubyTargetSpec`, ~157-245), `RubySemanticIndex` (~266-578: ancestor/mixin maps, constant resolution via keyed `analyzer.definitions(...)` probes filtered by visible files, method-candidate resolution via `DefinitionLookupIndex::fqn_direct_children` filtered by name/visibility/dispatch mode), the file-scan driver (`RubyFileScan`, `RubyWalkState`, ~624-1030), receiver/constant/factory-return resolution (~1032-1611, including `ruby_factory_method_outcome` with its `FactoryInferenceKey` cache), and helpers (~1613-1959, including `is_singleton_method_declaration` and the `module_function` walkers). Line numbers drift; function names are the stable anchors.

Ruby-specific semantics that must not be genericized: lexical constant-nesting lookup (`constant_lookup_candidates` walks the enclosing module stack outward), mixin method-resolution order (prepended modules, then direct, then included — `resolve_method_candidates` encodes Ruby MRO), file visibility through `require` closures, Zeitwerk conventions and autoload (`visible_files_from`, `zeitwerk_visible_files_for`, `autoload_visible_files_for_constant`), and `module_function` (a call that makes subsequent or named module methods available as singleton methods).

Test environment: run suites as `BIFROST_SEMANTIC_INDEX=off cargo test --test <suite>` from the repo root. Existing Ruby coverage: `usages_ruby_test`, `ruby_lsp_goto_definition`, `ruby_lsp_find_references`, `ruby_analyzer_test`, `ruby_type_hierarchy_test`, `ruby_import_test`, `ruby_test_detection_test`. New tests needing small inline projects use `InlineTestProject` from `tests/common/inline_project.rs` (style anchors: `tests/usages_ruby_test.rs` for usage behavior, `tests/scala_dead_code_smells.rs` or `tests/php_dead_code_smells.rs` for the dead-code suite shape). Lint gate: `cargo fmt` then `cargo clippy --all-targets --all-features -- -D warnings`; the repo denies warnings.

## Plan of Work

### Milestone 1 — mechanical module split

Convert `src/analyzer/usages/ruby_graph.rs` into a facade plus `src/analyzer/usages/ruby_graph/` directory, mirroring the sibling layout: the facade keeps `RubyUsageGraphStrategy` and its trait impls; `ruby_graph/resolver.rs` takes `RubyTargetKind`, `RubyTargetSpec`, `ReceiverType`/`ReceiverMode`, `RubySemanticIndex` and its resolution methods, and `constant_lookup_candidates`; `ruby_graph/extractor.rs` takes `RubyFileScan`, `RubyWalkState`, the tree walk, and the receiver/factory inference functions; `ruby_graph/hits.rs` takes hit construction (currently inlined in `RubyWalkState::record_hit`); `ruby_graph/syntax.rs` takes the pure node predicates and `module_function` walkers. Movement only: no signature, logic, or visibility changes beyond what the module boundaries force (`pub(crate)`/`pub(super)` adjustments). If a helper is only sensibly placed by changing it, leave it where it is and note it — this milestone must diff as pure relocation.

Acceptance: `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_ruby_test --test ruby_lsp_goto_definition --test ruby_lsp_find_references` passes with zero test edits; lint gate clean.

### Milestone 2 — analyzer-cached ancestor and mixin maps

Move the construction of `ancestors`, `mixin_included_owners`, `mixin_prepended_owners`, and `mixin_class_owners` out of `RubySemanticIndex::build_with_target` into a struct owned by the Ruby analyzer's state lifecycle (a `RubySemanticFacts` built where the analyzer builds its other derived state — study how `RubyAnalyzer` stores `mixin_relations`/hierarchy data in `src/analyzer/ruby/` and place it in the same rebuild path; a lazily-initialized `OnceLock` inside that state is fine if eager construction is awkward — record the choice). `RubySemanticIndex` becomes a thin per-query view: a borrow of the cached facts plus the per-query `target` and `factory_return_cache`. `build_for_lookup` callers (grep for them — `get_definition` uses it) get the same treatment.

Acceptance: same suites as Milestone 1 plus `ruby_type_hierarchy_test` and `get_definition_test`; behavior identical; the `all_declarations()` iteration no longer occurs per query (verify by code inspection: `RubySemanticIndex::build*` no longer calls `all_declarations`).

### Milestone 3 — dispatch mode recorded at collection time

In `src/analyzer/ruby/declarations.rs`, where `visit_method` creates the method `CodeUnit`, also classify the method's dispatch mode: singleton (a `singleton_method` node, or any ancestor `singleton_class` before the enclosing `class`/`module` — the logic `method_is_singleton_context` already implements), or `module_function`-affected (port the detection from `module_function_applies_to_method` in the usages layer — the collector has the same tree in hand; note `module_function` makes a method available BOTH as a module singleton and as a private instance method, so model the mode as an enum such as Instance | Singleton | ModuleFunction rather than a boolean). Persist the classification in Ruby analyzer state keyed by CodeUnit (alongside whatever `declarations.rs` already records per unit) and expose an accessor on `RubyAnalyzer`, e.g. `method_dispatch_mode(&self, unit: &CodeUnit) -> RubyMethodDispatchMode`. Then rewrite `ruby_method_lookup_mode_matches` (and thereby `is_singleton_method_declaration`'s usage-path callers) to consult the accessor; delete the re-parse implementation. If `is_singleton_method_declaration` has callers outside the usages layer, migrate them too (grep first).

The behavioral contract to preserve, exactly: a method reached through an Instance receiver matches only instance dispatch; a Class/singleton receiver matches singleton dispatch; `module_function` methods match both class-side calls on the module and top-level/private instance calls, as the current re-parse logic decides. Write the classification tests against `ruby_analyzer_test`-style fixtures covering: plain instance method, `def self.foo`, method inside `class << self`, bare `module_function` affecting subsequent methods, and `module_function :name` affecting a named method.

Acceptance: all Ruby suites from Milestones 1-2 pass, plus new classification tests; grep confirms `parse_ruby_tree` is no longer called from `resolve_method_candidates`'s call graph.

### Milestone 4 — Ruby edge path

Implement the whole-workspace inverted-edge builder. Add `RubyEdgeResolver` implementing `UsageEdgeResolver` (`src/analyzer/usages/traits.rs` documents the contract; `scala_graph/shared.rs` and `php_graph/shared.rs` show the two-resolver wiring pattern) and a public `build_ruby_usage_edges(analyzer, nodes, keep_file)` entry in the facade matching the signature shape of `build_php_usage_edges`. Reuse the shared engine: `inverted_edges::build_edges`/`parse_and_collect` for file fan-out, `ClassRangeIndex` for caller attribution, `EdgeCollector` for recording. For callee resolution, reuse the Milestone 1-3 machinery: build one `RubySemanticFacts`-backed lookup (no per-file target, so use the `build_for_lookup` shape), resolve constants through `resolve_constant_path` and method calls through the same receiver-typing rules `RubyFileScan` applies (local inference seeding, `ruby_receiver_type`, factory-return inference), and record an edge only for a unique proven resolution — ambiguous candidate sets and unknown receivers record nothing. Wire a Ruby arm into `src/code_quality/dead_code_smells.rs` following the PHP arm's shape.

Scope gate: if reusing the query-path receiver machinery for the no-target case requires restructuring beyond `RubySemanticIndex`'s target-optionality (which already exists via `build_for_lookup`), implement the edge scan for the proven subset only — constant references, `Konstant.method` class-side calls, `Konstant.new` constructor-to-initialize edges, and self/locally-typed receivers — and record the narrowed scope in the Decision Log. Partial conservative coverage is acceptable; speculative edges are not.

Tests: new `tests/ruby_dead_code_smells.rs` modeled on `tests/php_dead_code_smells.rs` (an unused method is flagged; a method called through a proven receiver is not; a `module_function` method called module-side is not), and edge-shape assertions in `tests/usages_ruby_test.rs` or a new `tests/usage_graph_ruby_test.rs` mirroring `tests/usage_graph_scala_test.rs`, using `InlineTestProject`.

Acceptance: new suites pass; all prior Ruby suites and `cross_language_self_usages` still pass; the dead-code dispatch covers Ruby.

## Concrete Steps

Work from `/mnt/optane/bifrost-shared-usage-index`. After each milestone:

    cargo fmt
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_ruby_test --test ruby_lsp_goto_definition --test ruby_lsp_find_references --test ruby_analyzer_test --test ruby_type_hierarchy_test --test ruby_import_test --test get_definition_test
    cargo clippy --all-targets --all-features -- -D warnings

plus the milestone-specific new suites named above. Clippy must be completely clean.

Final Milestone 4 validation was run from `/mnt/optane/bifrost-shared-usage-index`:

    cargo fmt
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_ruby_test --test ruby_lsp_goto_definition --test ruby_lsp_find_references --test ruby_analyzer_test --test ruby_type_hierarchy_test --test ruby_import_test --test get_definition_test --test cross_language_self_usages --test ruby_dead_code_smells --test usage_graph_ruby_test
    cargo clippy --all-targets --all-features -- -D warnings

The combined test command passed 473 tests. Clippy completed with no warnings.

## Validation and Acceptance

The plan is accepted when: `ruby_graph.rs` is a facade over `ruby_graph/` (wc under ~200 lines for the facade); `RubySemanticIndex::build*` performs no `all_declarations()` pass; method dispatch classification comes from analyzer state with the re-parse deleted; `build_ruby_usage_edges` exists, is dispatched from `dead_code_smells.rs`, and `tests/ruby_dead_code_smells.rs` passes demonstrating Ruby dead-code detection end to end; all pre-existing Ruby suites pass unchanged throughout.

## Idempotence and Recovery

Ordinary source edits on a dedicated branch; every milestone leaves the tree green, so work can stop and resume at any boundary from this document alone. Milestone 1 is pure relocation and safest to land first; if a later milestone stalls, earlier ones remain valid commits. Do not use `git add -A`; stage only files changed for this plan. Implementation runs delegated to a coding agent must NOT create commits — leave changes in the working tree; the reviewer stages from `git status` and commits.

## Artifacts and Notes

The per-candidate re-parse being deleted in Milestone 3 (from `ruby_graph.rs::is_singleton_method_declaration`): it reads the whole declaring file, parses it, and relocates the method node by byte range — inside `resolve_method_candidates`'s per-candidate filter closure:

    let Ok(source) = analyzer.project().read_source(target.source()) else { return false; };
    let Some(tree) = parse_ruby_tree(&source) else { return false; };
    ...
    let Some(node) = ruby_method_node_for_ranges(tree.root_node(), ranges, &source) ...

The collector-side twin that already exists at declaration time (`declarations.rs::method_is_singleton_context`) walks the identical ancestor chain, proving the fact is available without any re-parse.

## Interfaces and Dependencies

At the end of Milestone 3, `RubyAnalyzer` (in `src/analyzer/ruby/mod.rs`) must expose:

    pub(crate) enum RubyMethodDispatchMode { Instance, Singleton, ModuleFunction }
    pub(crate) fn method_dispatch_mode(&self, unit: &CodeUnit) -> RubyMethodDispatchMode;

At the end of Milestone 4, the facade `src/analyzer/usages/ruby_graph.rs` must expose:

    pub fn build_ruby_usage_edges(
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: impl Fn(&ProjectFile) -> bool + Sync,
    ) -> Option<UsageEdges>;

matching the shape of `build_php_usage_edges` so the `dead_code_smells.rs` arm is uniform. Use `crate::hash::HashMap`/`HashSet`; keep traversals iterative (explicit stacks) per repo convention; no `BTreeMap` unless ordering is semantically required (the existing `BTreeSet` for hits is required ordering — keep it).
