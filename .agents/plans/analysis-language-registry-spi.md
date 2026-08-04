# Language registry and analyzer SPI: dispatch inversion inside brokk-bifrost-analysis

This ExecPlan is the gate-1 design for phase 3 of the analysis-crate vertical split. It is
self-contained: everything needed to implement it is in this file plus the current working
tree. Two checked-in companion documents provide background evidence but are not required
reading to execute the plan: `.agents/docs/analysis-crate-seam-matrix-2026-08.md` (the
measured reference inventory this design is derived from) and
`.agents/docs/analysis-crate-split-phase2-evaluation-2026-08.md` (why wall-clock build time
is not the goal of this stage). File/line citations below were verified at commit
`999a0d5c`; line numbers drift, so treat them as starting points for a search, not gospel.

## Purpose

Today the code-intelligence framework inside `crates/bifrost-analysis` reaches each of the
twelve analyzable languages *by name*, from at least five independently hand-maintained
places. When a language gains a capability, a human must remember to update every list;
when they forget, the language silently lacks the capability on one path while having it on
another. This is the same "two copies maintained in lockstep" hazard class that produced
the MCP pre-handshake authorization bypass documented in CLAUDE.md, and it has already
produced real divergence here: the dead-code path's list has only 9 languages (C++ and
Python are handled by separate special cases), Ruby never received a `UsageQueryResolver`
implementation, and JS/TS cannot participate in the shared workspace-edge shape at all.

After this plan is implemented, exactly one file in the crate enumerates the languages. Every
framework consumer (usage finding, workspace edges, receiver resolution, dead-code analysis,
the semantic engine, searchtools) looks capabilities up in a registry keyed by `Language`. A
new language, or a new capability on an existing language, is one descriptor edit. A
self-policing test fails the build if any framework file names a language module again.

This also unblocks phase-3 extraction: once no framework file names a language, moving a
language into its own crate is a mechanical file move plus visibility promotions, with the
descriptor as its registration point. That is deliberately *out of scope* here — this plan
changes no crate boundaries except one small pre-work move (milestone 0) and one proof move
(milestone 2). Everything else happens inside `brokk-bifrost-analysis`, which keeps the
promotion pain out of this stage entirely: registry and languages share a crate, so
`pub(crate)` suffices throughout.

## Orientation: the five language lists and the named reach-ins

A "dispatch list" here means a place where framework code (code that serves all languages)
matches on `Language` or names concrete per-language types in order to route work. As of
`999a0d5c` there are five, plus a set of scattered single-item reach-ins.

The five lists:

1. `analyzer/usages/finder.rs:726-811` — `graph_find_usages` is a 12-arm `match language`
   constructing `&<Lang>UsageGraphStrategy::new()` and passing it to
   `graph_strategy_find_usages(strategy: &dyn GraphUsageAnalyzer, ...)` (`finder.rs:709`).
2. `analyzer/usages/workspace_graph.rs:352-491` — the workspace edge path. A local macro
   `record_package_edges` is instantiated ten times against per-language free functions
   (`build_go_usage_edge_weights` and friends), and JS/TS is a fully hand-written eleventh
   arm (`workspace_graph.rs:434-491`) because its edge builder returns a differently keyed
   type (see decision 3).
3. `searchtools/scan_usages.rs:2476-2615` — an eleven-way sequence of direct
   `build_*_usage_edges` calls; a second, independent copy of list 2's knowledge.
4. `code_quality/dead_code_smells.rs:2387-2416` — `graph_strategy_for` is an if-chain over
   *nine* strategy types (C++ and Python deliberately absent, served by separate
   whole-workspace edge builds at `dead_code_smells.rs:1136` and `:1004`), plus a
   ten-entry per-language `build_*_usage_edges` sequence at `:906-1342` and a four-language
   bulk-eligibility block at `:1997-2085`.
5. `analyzer/multi_analyzer.rs` — `AnalyzerDelegate`, a 12-variant enum of concrete
   analyzers, with construction, plus `resolve_analyzer<T: Any>` (the sanctioned
   downcast-through-`MultiAnalyzer` helper).

The scattered reach-ins, all documented item-by-item in the seam matrix sections 4.1-4.7:
`analyzer/usages/receiver_query.rs:16,25` imports eleven `resolve_<lang>_bounded` and eleven
`resolve_<lang>_type_bounded` functions and dispatches them at `:2061` and `:2018`;
`receiver_query.rs:47` downcasts to all twelve analyzer types;
`analyzer/usages/get_definition/mod.rs:78` names nine;
`analyzer/usages/candidates.rs:652,657` call Python/Rust candidate-file hooks;
`analyzer/usages/finder.rs:367-402` calls PHP composer/import-alias candidate expansion;
`analyzer/semantic/service.rs:707,1235` name `TypescriptAdapter` and
`JsTsSemanticLowerer::typescript` — the only two references from the semantic engine into
any language; `receiver_query.rs:31,36` pull six `pub(in crate::analyzer::usages)` items
from `js_ts_graph::receiver_analysis` plus `JsTsReceiverFactProvider` — no other language's
receiver analysis is reached this way; and small `match language` sites at
`workspace_graph.rs:38,57,124` (`UsageEcosystem`), `receiver_query.rs:2097` (unsupported
reason), `:2143,2883,2953`, and `parsed_tree.rs:16`.

Relevant existing traits, from `analyzer/usages/traits.rs`: `UsageAnalyzer` (pub, one
method, used as `dyn` only by dead-code), `GraphUsageAnalyzer` (pub(crate), `dyn` in
finder immediately after the hardcoded match, so it currently buys nothing),
`UsageQueryResolver` and `UsageEdgeResolver` (pub(crate), ten and eleven monomorphic impls
respectively, zero polymorphic use — uniformity contracts, not dispatch), and
`CandidateFileProvider` (pub, genuinely polymorphic, language-agnostic, healthy — untouched
by this plan).

## Design decisions

Decision 1: a plain static registry, not link-time magic. A new module
`analyzer/languages.rs` defines `struct LanguageDescriptor` and a
`registry() -> &'static HashMap<Language, LanguageDescriptor>` backed by `LazyLock`,
assembled from twelve explicit `mod`-level constructor calls (`rust::descriptor()`,
`kotlin::descriptor()`, ...). Each language module owns its descriptor function next to its
code. We deliberately do not use `linkme`/`inventory`-style distributed registration:
explicit assembly in one file preserves greppability, keeps registration order and
completeness checkable by a unit test against `Language::ANALYZABLE`
(`bifrost-core` `analyzer/model.rs:43`), and adds no build dependencies. The registry file
and `multi_analyzer.rs`'s `AnalyzerDelegate` enum become the only two files allowed to name
language modules; the delegate enum stays because concrete per-language analyzer *storage*
is the assembly layer's job, and collapsing it into trait objects would change the
`resolve_analyzer` contract for no benefit at this stage.

Decision 2: the descriptor carries function pointers and small trait objects, one field per
capability the five lists and reach-ins currently encode. The initial field set, derived
from the census above (names indicative, implementer may adjust spelling):

    pub(crate) struct LanguageDescriptor {
        language: Language,
        usage_strategy: fn() -> Box<dyn GraphUsageAnalyzer>,          // lists 1 and 4
        record_workspace_edges: Option<WorkspaceEdgeFn>,              // lists 2 and 3
        resolve_definition_bounded: BoundedDefinitionFn,              // receiver_query.rs:16
        resolve_type_bounded: BoundedTypeFn,                          // receiver_query.rs:25
        receiver_facts: Option<ReceiverFactsHooks>,                   // js_ts today, None elsewhere
        dead_code: DeadCodeSupport,                                   // list 4's (a)-(d) groups
        candidate_files: Option<CandidateFileFn>,                     // candidates.rs:652,657 + PHP hooks
        semantic: Option<SemanticHooks>,                              // service.rs:707,1235
        ecosystem: UsageEcosystem,                                    // workspace_graph.rs:38
        graph_unsupported_reason: Option<fn(...) -> ...>,            // receiver_query.rs:2097
    }

The governing rule is behavioral, not structural: after milestone 1, no file outside
`analyzer/languages.rs`, `analyzer/multi_analyzer.rs`, and the per-language directories may
contain the token `analyzer::rust::` (or any other language path) — the descriptor grows
exactly the fields needed to delete each such reference, and no more. Where a reach-in is a
single helper function (for example `cpp::identity::*` used by searchtools), the field is
that function's signature; where a language simply lacks the capability, the field is
`None` and the consumer's fallback is explicit at the consumption site instead of implicit
in a missing list entry.

Decision 3: the workspace edge path inverts to a sink. Today ten languages return
`UsageEdges`/`UsageEdgeWeights` keyed by fully-qualified-name strings, and JS/TS returns
`JsTsScopedUsageEdges` keyed by `UsageNodeKey { file, fqn }` — which is *why* it cannot
implement `UsageEdgeResolver` and why lists 2 and 3 each carry a hand-written JS/TS arm.
Rather than generalize the return type (a second associated type, or forcing everyone onto
the scoped key, both of which change ten languages to accommodate one), the edge entry
point becomes push-based: the descriptor's `record_workspace_edges` receives a
`&mut dyn UsageEdgeSink` with methods for both recording shapes (fqn-keyed and
file-scoped). The sink implementations live in `workspace_graph.rs` and
`scan_usages.rs` and own keying, deduplication, and the `UsageEcosystem` candidate-set
plumbing that the current macro duplicates. The per-language `build_*` functions survive
unchanged as private helpers behind each language's descriptor entry; `UsageEdgeResolver`
is deleted (it has zero polymorphic uses — it was documentation pretending to be dispatch).
This is the stress-case decision Jonathan's de-risk argument demanded: designing the
contract against JS/TS first, so the registry never ships an interface the hardest language
cannot implement.

Decision 4: `IAnalyzer` splits by signature closure, not by theme. A new trait — working
name `CodeUnitIndex` — receives every `IAnalyzer` method whose signature closes over types
already in `brokk-bifrost-core` (`CodeUnit`, `ProjectFile`, `Language`, `Range`,
`SignatureMetadata`, plain strings/collections): the declarations/definitions accessors,
skeleton/source/signature rendering, search entry points, `parent_of`, children accessors,
`languages()`, `is_analyzed`, and the metrics that return core types.
`IAnalyzer: CodeUnitIndex + Send + Sync + Any` retains everything whose signature touches
analysis-side types (`UsageFactsIndex`, `FuzzyResult`, `DefinitionIndexHandle`,
`AnalyzerSnapshotCaches`, `SummaryFileProjection`, structural/semantic providers, smell and
budget types), all provider-accessor methods, the `as_capability` escape hatch, and the
`*_for_test` counter hooks (including the two Scala-specific ones, which are flagged as a
cleanup candidate but not moved — they are test plumbing, not API). The split is proven by
finally moving `analyzer/capabilities.rs` and `analyzer/pool_memo.rs` to `bifrost-core` in
milestone 2 with their generic bounds rewritten to `T: CodeUnitIndex` — the exact move that
stage 2 attempted and had to abandon because `IAnalyzer` was indivisible. Implementors need
no change beyond `impl` block splitting: every existing analyzer implements both traits.

Decision 5: the semantic engine goes fully language-blind. Its only two language references
(`service.rs:707` constructing `TypescriptAdapter`, `:1235` calling
`JsTsSemanticLowerer::typescript`) become `SemanticHooks` descriptor fields consulted where
the engine currently hardcodes them. Every other language already reaches the engine
through the `ProgramSemanticsLowerer` registration macro, so this is two call sites.

Decision 6: Ruby gets a `UsageQueryResolver`-shaped scan. `ruby_graph.rs:73-173` inlines
what the other ten languages express through `UsageQueryResolver::try_new`/`find_usages`.
Since decision 3 deletes `UsageEdgeResolver` and this plan standardizes the strategy entry
points, the Ruby scan is folded into the common shape at the same time — small, mechanical,
and it removes the one asymmetry that would otherwise need a permanent footnote in the
descriptor contract.

Decision 7: perf neutrality is a requirement, not a hope. All registry indirection is
per-query or per-scan (one `HashMap` lookup plus one indirect call), never per-node or
per-edge; the language-internal hot loops remain monomorphic. The reference differential
and the scan_usages surface tests are the behavioral gate; any measurable regression in the
usage-graph benchmarks fails the milestone.

Decision 8 (pre-work): `analyzer/js_ts/cache.rs` moves to `brokk-bifrost-core` as
`compact_graph`-adjacent utility code (working name `weighted_cache.rs`), because it is a
generic weighted-cache helper that nine *other* languages import — the sole inter-language
dependency outside the JVM realm, per matrix section 5.3. This is required for any future
extraction regardless of every other decision, is invisible to behavior, and shrinks the
entangled surface before the registry work begins.

## Milestones

Milestone 0 — relocate the weighted cache. Move `analyzer/js_ts/cache.rs` (four public
functions: `build_weighted_cache`, `weight_code_unit_vec_by_unit`, `weight_code_unit_set`,
`weight_project_file_set`) to `crates/bifrost-core/src/weighted_cache.rs`, re-export from
`brokk-bifrost-analysis` at the old `analyzer::js_ts::cache` path so the nine importing
language modules compile unchanged, run the standard gates, commit. Acceptance: workspace
tests green; `git log --follow` shows a rename, not a delete/add.

Milestone 1 — the registry, and the deletion of every framework language reference. Create
`analyzer/languages.rs` with `LanguageDescriptor` and the registry; add a
`descriptor()` constructor to each of the twelve language modules; convert, in order (each
its own commit, tests green at every step): (a) finder.rs list 1 and dead-code list 4's
strategy chain onto `usage_strategy`; (b) receiver_query's two bounded-resolver tables onto
descriptor fields; (c) the edge sink of decision 3, converting workspace_graph.rs list 2,
scan_usages.rs list 3, and dead-code's per-language edge builds, including the JS/TS
hand-written arm and the C++/Python dead-code special cases, deleting `UsageEdgeResolver`;
(d) Ruby's resolver fold-in (decision 6); (e) the semantic hooks (decision 5); (f) the
js_ts receiver-facts generalization and the remaining scattered reach-ins (candidates,
PHP finder hooks, searchtools' cpp identity block, small `match language` sites), each
either onto a descriptor field or explicitly allowlisted with a comment stating why it is
assembly-layer code. Finish with the self-policing gate: a unit test in
`analyzer/languages.rs` that walks `crates/bifrost-analysis/src`, and asserts that outside
the per-language directories only `languages.rs` and `multi_analyzer.rs` (and the explicit
allowlist) contain `analyzer::<lang>::` path tokens, and that the registry covers exactly
`Language::ANALYZABLE`. Acceptance: that test passing; full workspace gates green; the
reference differential flat against the pre-milestone baseline on a warmed corpus run.

Milestone 2 — the `IAnalyzer` split. Introduce `CodeUnitIndex` in
`crates/bifrost-core/src/analyzer/` per decision 4; make `IAnalyzer` extend it; split the
`impl` blocks of the twelve analyzers plus `MultiAnalyzer` and the test fakes; move
`capabilities.rs` and `pool_memo.rs` to core with bounds rewritten to `CodeUnitIndex`
(preserving `PoolSafeMemo::get`'s `#[cfg(test)]` gating exactly); re-export at old paths.
Acceptance: workspace green; `brokk-bifrost-core` compiles and its unit tests pass
standalone (`cargo test -p brokk-bifrost-core --lib`); no downstream crate source changes.

Milestone 3 — checkpoint, not code. Re-run the phase-2 evaluation methodology (cold
`--timings` featureless workspace build, warm touch-rebuild loops) and record the numbers
in `.agents/docs/analysis-crate-split-phase2-evaluation-2026-08.md` as a follow-up section.
This stage is expected to be build-time-neutral; the deliverable is the measurement plus a
stop/go recommendation for the per-language extractions, which are a separate future
ExecPlan. Nothing in milestones 0-2 is wasted if the answer is stop: the lockstep-list
hazard is gone either way.

## Validation

Every milestone runs the standard gates from CLAUDE.md: `cargo fmt`, `cargo clippy
--workspace --all-targets --all-features -- -D warnings` (through
`scripts/with-isolated-cargo-target.sh`; `PYO3_PYTHON` set per the uv 3.12 environment),
`cargo-nextest run --workspace` with `BIFROST_SEMANTIC_INDEX=off`, and workspace doctests.
Milestone 1 additionally requires behavior invariance evidence: the suite_usages,
suite_smells, scan_usages surface, and get_definition suites unchanged, plus one
`bifrost_reference_differential --cache-mode ephemeral` smoke on a mixed-language corpus
showing an identical divergence census before and after. The self-policing source-walk test
is the permanent regression guard; it is the analogue of the structural adapter suite's
`STRUCTURAL_ADAPTER_PENDING` gate and must be written to fail loudly with the offending
file list, not just a count.

## Progress

- [ ] Milestone 0: weighted cache relocated to core, gates green
- [ ] Milestone 1a: registry module + twelve descriptors + finder/dead-code strategy dispatch
- [ ] Milestone 1b: receiver_query bounded-resolver tables onto descriptors
- [ ] Milestone 1c: edge sink; lists 2 and 3 and dead-code edges converted; UsageEdgeResolver deleted
- [ ] Milestone 1d: Ruby UsageQueryResolver fold-in
- [ ] Milestone 1e: semantic engine hooks; engine language-blind
- [ ] Milestone 1f: remaining reach-ins converted or allowlisted; source-walk gate landed
- [ ] Milestone 1 acceptance: differential smoke flat, all suites green
- [ ] Milestone 2: CodeUnitIndex split; capabilities.rs + pool_memo.rs moved to core
- [ ] Milestone 3: measurements recorded; stop/go recommendation written

## Decision log

- 2026-08-04: Plan created. Ordering rationale (registry before any extraction, js_ts
  stress cases designed first) is Jonathan's de-risk call: the four dispatch lists and the
  edge-shape mismatch are the same inversion problem, so the registry must be validated
  against the hardest consumer before any file moves make rework expensive.
- 2026-08-04: Static explicit registry chosen over linkme/inventory-style distributed
  registration (greppability, completeness testable against Language::ANALYZABLE, zero new
  dependencies). AnalyzerDelegate enum retained as assembly-layer storage.
- 2026-08-04: Sink-based edge recording chosen over generalizing UsageEdgeResolver's
  return type; UsageEdgeResolver deleted rather than kept as a vestigial uniformity
  contract. JS/TS's {file, fqn}-scoped edges and the ten fqn-keyed edge builders both
  flow through the same sink interface.
- 2026-08-04: IAnalyzer split criterion is signature closure over core types, proven by
  moving capabilities.rs/pool_memo.rs (the stage-2 leftover) in milestone 2. Scala-specific
  test hooks flagged but deliberately not addressed in this plan.
