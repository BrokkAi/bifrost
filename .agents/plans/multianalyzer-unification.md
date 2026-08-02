# Unify workspace analyzer handles: compositional merged definition index, then collapse Single into Multi

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Bifrost serves code intelligence for a workspace through a single `IAnalyzer` handle. Today that handle has two shapes: a multi-language workspace gets a `MultiAnalyzer` that routes each file to the analyzer for that file's language, while a single-language workspace gets the one concrete per-language analyzer with no routing layer in front. Every consumer must therefore behave correctly against both shapes, and every concrete analyzer must defend itself against files it does not serve. That duality has already produced real bugs: the `analyze_git_hotspots` panic fixed in commit `aae03f4e` (issue #1417) happened precisely because a single-language workspace handed a bare Rust analyzer a list of git-churn files that included non-Rust files, and an infallible `generations[&storage_key]` map index panicked.

After this change, every workspace with at least one analyzable language is served by a `MultiAnalyzer` — some just hold a single delegate. Routing and refusal semantics ("we do not analyze this file") live in exactly one place. The observable outcomes: all existing analyzer, searchtools, code-quality, and MCP integration tests pass with the unified handle; a definition-index query through a single-language workspace handle still builds the delegate's SQL-backed index exactly once (proved by a counter pin, see Validation); and the `WorkspaceAnalyzer::Single` variant no longer exists in the source tree.

Doing the collapse naively would regress single-language workspaces (most workspaces), because `MultiAnalyzer` today maintains an expensive workspace-level cache — a fully materialized merged definition index rebuilt from full declaration scans — and drops its workspace-level caches far more eagerly than the concrete analyzers do. So the work is sequenced: Milestone 1 makes `MultiAnalyzer`'s merged index compositional (cheap views over the delegates' own Arc-backed indexes) and fixes its cache-retention behavior; Milestone 2 collapses `WorkspaceAnalyzer::Single` into `Multi`. Milestone 1 is a standalone win for multi-language workspaces even if Milestone 2 were abandoned.

## Progress

- [x] (2026-08-02) Investigation complete: cache inventory, handle asymmetries, and consumer audit recorded below.
- [x] (2026-08-02) ExecPlan written.
- [x] (2026-08-02) Milestone 1: `DefinitionIndexHandle` view type replacing the materialized merged index in `MultiAnalyzer`.
- [x] (2026-08-02) Milestone 1: cache-retention parity in `MultiAnalyzer::update` / `clone_with_project`.
- [x] (2026-08-02) Milestone 1: tests (counter pins for build-once and no-full-scan; retention across irrelevant updates).
- [x] (2026-08-02) Milestone 2: collapse `WorkspaceAnalyzer::Single` into `Multi` in `crates/bifrost-analysis/src/analyzer/workspace.rs`.
- [x] (2026-08-02) Milestone 2: fix fallout (ordering pins, direct constructions of `Single`, kotlin-realm no-op check).
- [x] (2026-08-02) Milestones merged (merge commit, both branches preserved); Milestone 2's `imported_files_from_infos` forwarder verified present alongside Milestone 1's `multi_analyzer.rs` changes.
- [x] (2026-08-02) Follow-up: the three "pre-existing" lib failures triaged as silent master breakage invisible to CI and fixed — cpp dispatch pins re-pinned to #1440's retain-ambiguous-targets contract, scala epoch test's literal hash removed (the fingerprint includes CARGO_PKG_VERSION, so a hex pin breaks at every release; the PHP twin already avoids one), kotlin syntax.rs module doc s-expressions fenced as text so they stop being a doctest.
- [x] (2026-08-02) Follow-up: added the missing CI gate — an `analysis-unit` job in ci.yml running `cargo test -p brokk-bifrost-analysis --lib` and `--doc`, because `default-members = ["."]` means no existing job ran the analysis crate's unit tests or doctests.
- [ ] Final validation: fmt, clippy all-targets all-features, focused featureless test suite for the analysis crate.

## Surprises & Discoveries

- Observation: `SnapshotDerivedLayerCache` (in `crates/bifrost-analysis/src/analyzer/structural/execution/derived.rs`) is generation-guarded: every read/write is validated against a `source_generations` vector and the cache rotates itself when generations advance. Retaining the cache Arc across analyzer updates is therefore safe by construction; the eager resets in `MultiAnalyzer::update` are pure waste, not a correctness measure.
  Evidence: `SnapshotDerivedLayerCache::with_generation` compares `current.source_generations` against the caller's and replaces the generation (dropping cached values) on advance.
- Observation: the two definition indexes are built by different mechanisms. `TreeSitterAnalyzer`'s per-language index is SQL-store-backed (`sql_global_usage_definition_index`, `tree_sitter_analyzer.rs:6785`) and Arc-shared across plain clones and overlay snapshots (`clone_with_project` keeps the Arc). `MultiAnalyzer`'s merged index is a full in-memory rematerialization from `all_declarations()` of every delegate with cloned identifier strings (`multi_analyzer.rs:744-750`), and is dropped by every `update`, `update_all`, and `clone_with_project` because those all construct through `new_with_derived_layer_budget`, which allocates a fresh `OnceLock`.
- Observation: both callers exist simultaneously. External consumers call `global_usage_definition_index()` on the workspace handle (`searchtools/sources.rs`, `searchtools/summaries.rs`, `usages/candidates.rs`); the per-language usage-graph resolvers (`usages/java_graph/inverted.rs`, `usages/kotlin_graph/resolver.rs`, `usages/ruby_graph.rs`) call it on the concrete analyzer they are built inside. In a multi-language workspace today, both indexes get built and held — a duplicate resident copy of essentially the same data. Collapsing Single into Multi without Milestone 1 would extend that duplication to single-language workspaces.
- Observation: the consumer audit in the Context section badly understated the blast radius. It named
  `usages/candidates.rs:182` as "the only cross-crate-file consumer of `by_fqn`". The real count is about
  90 call sites across roughly 40 files, and they use far more of the index than the listed query surface:
  `by_fqn`, `by_normalized_fqn`, `identifier`, `types_in_package`, `package_types`, `members_for_owner_name`
  and `package_files` are all borrowing (`&[CodeUnit]`-returning) accessors reached through
  `IAnalyzer::global_usage_definition_index()`.
  Evidence: `cargo check -p brokk-bifrost-analysis --lib` after the trait signature change reported 92 errors
  in 40 files; the full inventory is in the audit summarized in the Decision Log entry on owned results.
- Observation: `CodeUnit` is `CodeUnit(Arc<CodeUnitInner>)` (`analyzer/model.rs:1863`) and `ProjectFile` is
  `ProjectFile(Arc<ProjectFileInner>)`, so an owned `Vec<CodeUnit>` result costs one allocation plus refcount
  bumps, not a deep copy of strings. That is what makes the "owned results everywhere, no borrowing slice
  accessors" shape in this plan's Interfaces section affordable at every one of those call sites rather than
  only at the three the plan had audited.
  Evidence: `GlobalUsageDefinitionIndex::fqn` already returned `Vec<CodeUnit>` by cloning and is used on hot
  resolution paths today.
- Observation: seven call sites could not simply gain a `&`: they held a lazy iterator or a `Vec<&CodeUnit>`
  borrowed from what is now a temporary handle (`cpp_graph/resolver.rs:7429/7459/7523`,
  `java_graph/extractor.rs:566`, `java_graph/return_type.rs:446`, `scala_graph/inverted.rs:4752`,
  `scala_graph/resolver.rs:191`), and one returned borrows out of the function
  (`cpp_graph/resolver.rs:7786 cpp_global_field_linkage_peers -> impl Iterator<Item = &'a CodeUnit> + 'a`).
  The first group was fixed by binding the owned result to a local; the last needed
  `DefinitionIndexHandle::into_shards()`, which is the only accessor yielding `&'a` shard references that
  outlive the handle.
  Evidence: `error[E0716]` / `error[E0515]` at exactly those lines.
- Observation: three lib tests already fail on the parent commit `3c4fdb94` and are unrelated to this work:
  `analyzer::store::tests::scala_scalachess_fqn_recovery_epoch_invalidates_stale_rows_and_reuses_current`
  (a pinned epoch hash mismatch) and the two cpp call-dispatch pins
  `analyzer::usages::call_relations::tests::exact_dispatch_keeps_multiple_cpp_bodies_unproven` and
  `exact_dispatch_preserves_cpp_navigation_uncertainty`. They were verified against a pristine
  `git archive HEAD` tree.
  Evidence: see the Artifacts and Notes section.
- Milestone 2 observation: the plan predicted ordering fallout from `MultiAnalyzer::analyzed_files` sorting and deduping. There was none. `TreeSitterAnalyzer::analyzed_files` already ends in `files.sort(); files.dedup();` (`tree_sitter_analyzer.rs:4024-4080`, cached via `analyzed_live_files`), so both shapes returned the same sorted vector before the collapse; and every assertion site treats the result as a set, a containment check, or a one-element vector. No expectation needed updating.
- Milestone 2 observation: the fallout was not where the plan looked. `WorkspaceAnalyzer::Single` appears nowhere in `crates/*/src`; the three direct uses live in the repository-root integration suites, which belong to the facade package `brokk-bifrost`, not to `brokk-bifrost-analysis`. `cargo test -p brokk-bifrost-analysis` therefore compiles none of them and reports green while `suite_persistence` and `suite_usages` fail to build. The plan's acceptance command is necessary but not sufficient: `cargo test -p brokk-bifrost` is the one that sees this milestone's fallout.
- Milestone 2 observation: `AnalyzerDelegate::language()` (`multi_analyzer.rs`) had exactly one caller, the `Single` arm of `program_semantics_provider_for_file`, and became dead code the moment that arm went. `MultiAnalyzer` routes by `language_for_file` against its `BTreeMap` key instead, so the method is not needed by the surviving path.
- Milestone 2 surprise, and the only real regression the collapse produced: `MultiAnalyzer`'s `ImportAnalysisProvider` impl never overrode `imported_files_from_infos`, so it answered the trait default `None` (`capabilities.rs:52-58`). `resolve_imported_files_from_infos` (`capabilities.rs:78-93`) then degrades to projecting imported *declarations* back to their source files, and an import whose target file declares nothing contributes no file edge at all. Ruby `require_relative` loaders are exactly that shape, so the transitive-importer candidate walk (`usages/candidates.rs:261-285`) never built the edge `lib/loader.rb -> app/main.rb`, never made `app/main.rb` a candidate, and `scan_usages_by_location` reported `verified_absent` with zero hits. Caught by `tests/suite_symbols/searchtools_service.rs::scan_usages_by_location_traverses_declarationless_ruby_loaders`.
  This is a pre-existing defect, not one the collapse introduced: `MultiAnalyzer` is already the handle for every multi-language workspace, so the same silent degradation was live for all five providers implementing `imported_files_from_infos` (Ruby, Go, C++, JavaScript, TypeScript), and for the second consumer of that helper at `structural/execution/derived.rs:1093`. The collapse merely routed a single-language Ruby test onto the broken path for the first time. Fixed at the root by adding the missing per-file forwarder next to its twin `imported_code_units_from_infos`, whose doc comment already described this exact failure mode for the sibling method. A multi-language pin (`..._alongside_another_language`) now covers the case that was broken all along; both tests fail if the forwarder is removed.
- Milestone 2 observation, important for sequencing: Milestone 1 does **not** subsume this fix, and the plan's premise that Milestone 2 is safe once Milestone 1 lands is incomplete. Verified by experiment: making `global_usage_definition_index` return the sole delegate's own index (the shape Milestone 1's compositional view produces for a one-delegate workspace) leaves the Ruby test failing identically. The definition index is only consulted *inside* the Ruby file scan, after the candidate file set has been chosen; this regression happens strictly earlier, during candidate discovery.
- Milestone 2 observation: three test failures in `brokk-bifrost-analysis` and one doctest failure predate this work and are unrelated to it (verified by reverting the milestone diff and re-running at `3c4fdb94`): `analyzer::store::tests::scala_scalachess_fqn_recovery_epoch_invalidates_stale_rows_and_reuses_current` (a pinned epoch hash no longer matching), `analyzer::usages::call_relations::tests::exact_dispatch_keeps_multiple_cpp_bodies_unproven` and `..::exact_dispatch_preserves_cpp_navigation_uncertainty` (both expect `targets` to be empty and get two unproven C++ bodies), and the doctest at `analyzer/kotlin/syntax.rs:20` (an unfenced tree-sitter s-expression rustdoc tries to compile). Counts are identical before and after: 1921 passed, 3 failed.
- Observation: the merged view cannot mirror the borrowing accessor `GlobalUsageDefinitionIndex::by_fqn(&self) -> &[CodeUnit]` across shards without materializing. The only cross-crate-file consumer of `by_fqn` (`usages/candidates.rs:182`) merely iterates the slice, so an owned/iterating method on the view suffices.

- Integration observation: the one semantic collision between the concurrently developed milestones was
  invisible to textual merge: Milestone 1's new test pins formatted assert messages with
  `AnalyzerDelegate::language()`, the method Milestone 2 deleted as dead. The merge auto-merged cleanly and
  the failure only appeared as two `E0599`s in the featureless `cargo test -p brokk-bifrost-analysis --lib`
  build. Fixed by iterating `delegates()` as `(language, delegate)` pairs — the `BTreeMap` key is the
  language — so Milestone 2's deletion stands.
- Integration surprise: the documented clippy gate cannot see that class of error at all. The root manifest
  sets `default-members = ["."]`, so `cargo clippy --all-targets --all-features` (the form CLAUDE.md
  prescribed) lints only the facade package and merely compiles the `crates/*` members as dependencies,
  skipping their `#[cfg(test)]` unit-test targets. It reported a clean 461-target run at a commit whose lib
  tests did not compile. Verified by experiment: a deliberate `E0599` probe inserted into
  `multi_analyzer.rs`'s test module passes the no-`--workspace` form and fails
  `cargo clippy -p brokk-bifrost-analysis --all-targets --all-features` (and the `--workspace` form).
  CLAUDE.md (via its `AGENTS.md` symlink target) now prescribes `--workspace`.
  Evidence: validation logs `clippy-all.log` (false green, "Finished ... 2m 35s") versus
  `analysis-lib.log` (E0599 at `multi_analyzer.rs:1494/1529`) at merge commit `f993a9c3`.

## Decision Log

- Decision: sequence the work as (1) compositional merged index + retention parity, (2) Single-to-Multi collapse — and land them as separate commits.
  Rationale: the collapse alone would regress index build time and resident memory on single-language workspaces, which are the common case. The compositional index is independently valuable for multi-language workspaces (removes a full-declaration-scan rebuild per update/overlay snapshot).
  Date/Author: 2026-08-02, Jonathan + Claude (design conversation).
- Decision: replace the materialized merged index with a view over the delegates' Arc-backed indexes rather than special-casing `delegates.len() == 1`.
  Rationale: a length-one special case is exactly the kind of narrow fallback CLAUDE.md's design philosophy bans; composition fixes the root cause for all delegate counts, and invalidation then follows the delegates' own (correct) invalidation automatically.
  Date/Author: 2026-08-02, Jonathan + Claude.
- Decision: change the return type of `IAnalyzer::global_usage_definition_index` rather than keeping `&GlobalUsageDefinitionIndex`.
  Rationale: a trait method returning a reference to one concrete map-backed struct forces every implementor to materialize that struct. Backwards compatibility is explicitly not a concern in this repository; all consumers are in-crate.
  Date/Author: 2026-08-02, Claude.
- Decision: in `MultiAnalyzer::update`, retain the workspace-level `AnalyzerSnapshotCaches` Arc when no delegate had relevant changes, and allocate fresh caches when any did — mirroring `TreeSitterAnalyzer` semantics (`update` with empty change set is a pure `clone()` that retains everything; `from_state` on real changes resets).
  Rationale: parity with the delegate level is the conservative step. The generation guard would make always-retaining safe too; that is noted as a possible follow-up, not done here, to keep this change's behavior reasoning simple.
  Date/Author: 2026-08-02, Claude.

- Decision: give `DefinitionIndexHandle` inherent query methods that keep the concrete index's method names
  (`by_fqn`, `by_normalized_fqn`, `identifier`, `types_in_package`, `package_files`, ...) but return owned
  values, and implement `BoundedDefinitionLookup` and `RustDefinitionProvider` on it by delegating to those
  inherent methods.
  Rationale: with about 90 call sites, keeping the names meant most of them compiled unchanged, so the diff
  stays readable and reviewable as "the return type changed", not "everything was rewritten". Owned results
  are the shape the plan's Interfaces section already prescribed, and `Arc`-backed `CodeUnit`/`ProjectFile`
  make them cheap. Same-named inherent methods also avoid forcing a `use BoundedDefinitionLookup` import into
  40 files, since inherent methods win name resolution.
  Date/Author: 2026-08-02, Claude (Milestone 1 implementation).
- Decision: struct fields that used to hold `support: &'a GlobalUsageDefinitionIndex` now hold
  `support: &'a DefinitionIndexHandle<'a>`, with the handle bound to a local in the enclosing function.
  Rationale: the alternative (owning a `DefinitionIndexHandle<'a>` in the field) forced a `&` at every one
  of the ~40 places the field is passed to a `&dyn BoundedDefinitionLookup` / `&dyn RustDefinitionProvider`
  parameter, and forced an un-cloneable handle to be duplicated for nested contexts. Holding a reference
  keeps every use site byte-identical and matches how these functions already bound `support` to a local.
  Affected: `usages/ruby_graph/{extractor,inverted}.rs`, `usages/rust_graph/{extractor,inverted}.rs`,
  and `{rust,go,python,php}/diagnostics.rs`.
  Date/Author: 2026-08-02, Claude.
- Decision: `MultiAnalyzer::update` decides retention from a per-delegate "was this delegate updated" flag
  collected alongside the delegate in the same parallel map, rather than by recomputing the routing
  predicate over `changed_files`.
  Rationale: a second pass would duplicate `should_receive_changed_file`, and the two copies could drift.
  The flag is a local, not a mode parameter, so it does not run into the flag-parameter rule.
  Date/Author: 2026-08-02, Claude.
- Decision: `UsageFactsIndex::build_from_declarations` and `GoImportNamespaces::has_dot_member` take
  `&DefinitionIndexHandle<'_>` rather than `&GlobalUsageDefinitionIndex`; their non-analyzer callers
  (`scala_graph/inverted.rs`, `tree_sitter_analyzer.rs`, and two unit tests) wrap their locally built index
  in `DefinitionIndexHandle::Single`.
  Rationale: one parameter type for a value that can now come from either a single analyzer or a workspace
  handle; wrapping is free (`Single` is a borrow).
  Date/Author: 2026-08-02, Claude.
- Decision: `CSharpAnalyzer::usage_declaration_candidates_by_identifier` changes its return type from
  `&[CodeUnit]` to `Vec<CodeUnit>`.
  Rationale: it returned a borrow straight out of the definition index, which no longer exists across shards.
  Its only caller (`usages/csharp_graph/resolver.rs`) immediately called `.to_vec()`, so the change removes a
  copy rather than adding one.
  Date/Author: 2026-08-02, Claude.

- Decision: rewrite `crates/bifrost-mcp/src/searchtools_service.rs`'s
  `failed_merged_index_build_is_not_published_to_other_requests` as
  `failed_shard_index_build_is_not_published_to_other_requests` rather than delete it.
  Rationale: the property it protects still exists and still matters, it just moved down a level. On a
  Java+Python service with a deliberately stale Java store, one query now attempts two shard builds; the
  build count is 2 after the first request and 3 after the retry, which pins exactly that the failing Java
  shard rebuilds while the healthy Python shard stays published. The old assertion (1 then 2) counted merged
  builds that no longer happen.
  Date/Author: 2026-08-02, Claude.
- Decision: `DefinitionIndexHandle` does not carry a `by_fqn` method; the ~30 call sites that used
  `by_fqn` on a handle call `fqn` instead.
  Rationale: on `GlobalUsageDefinitionIndex` the two are genuinely different (`by_fqn` borrows a slice, `fqn`
  clones). On the handle every result is owned, so keeping both names would be two spellings of one operation.
  The first draft kept `by_fqn` as an alias to minimize churn; that is exactly the kind of redundancy the
  parsimony rule bans, and deleting it cost one compiler-guided pass.
  Date/Author: 2026-08-02, Claude.
- Decision (Milestone 2): fix the missing `MultiAnalyzer::imported_files_from_infos` forwarder here, in `multi_analyzer.rs`, rather than deferring it or working around it in `workspace.rs`.
  Rationale: it is the root cause and it belongs to the routing layer this milestone makes universal -- CLAUDE.md's "follow problems to their source" applies directly, and the alternative (leaving one language's usage scanning silently degraded) is the narrow-fallback smell the same section bans. The edit is one method next to its existing twin, deliberately kept separable from Milestone 1's work in the same file.
  Date/Author: 2026-08-02, Claude.
- Decision (Milestone 2): recover the concrete `RustAnalyzer` in `tests/suite_usages/usages_rust_graph_test.rs` through the existing `resolve_analyzer::<RustAnalyzer>` helper rather than a new match on `WorkspaceAnalyzer::Multi` plus a `delegates()` walk.
  Rationale: that helper is exactly the dual-shape downcast the plan expected to keep working, it is already public through the facade (`brokk_bifrost::analyzer::resolve_analyzer`), and the test then stops caring which handle shape the workspace has -- which is the point of the milestone.
  Date/Author: 2026-08-02, Claude.
- Decision (Milestone 2): keep the two `WorkspaceAnalyzer` variant assertions in `tests/suite_persistence/workspace_analyzer_test.rs` (flipped to `Multi`) instead of deleting them in favour of the neighbouring `languages()` assertions.
  Rationale: "every workspace with at least one analyzable language is a `MultiAnalyzer`" is this milestone's user-visible contract, and these two tests are the only place that states it. The `languages()` assertions next to them still pin that the delegate set stayed at one language, so the pair together says single-language workspace, unified handle.
  Date/Author: 2026-08-02, Claude.
- Decision (Milestone 2): add the lone-Kotlin check to `tests/suite_analyzers/jvm_shared_realm.rs` as `lone_kotlin_workspace_handle_resolves_without_realm_widening`, built through `WorkspaceAnalyzer::build`, alongside the existing `kotlin_only_workspace_resolves_exactly_as_before`.
  Rationale: the existing test hand-builds a `MultiAnalyzer` from delegates, so it never exercised the wrap-up match this milestone changed. The new one goes through the real construction path, pins the `Multi` shape, and pins both halves of the realm contract: Kotlin's own hierarchy still resolves, and a Java declaration in an unanalyzed sibling file stays unresolved (`JvmSourceRealm::of` finds one member, `has_peers_of(Kotlin)` is false, `kotlin_realm()` returns `None`, no widening).
  Date/Author: 2026-08-02, Claude.

## Outcomes & Retrospective

### Milestone 1 (2026-08-02)

Achieved. `MultiAnalyzer` no longer materializes a merged definition index. `IAnalyzer::global_usage_definition_index`
returns `DefinitionIndexHandle<'_>`; a per-language analyzer returns `Single` over its existing Arc-backed
SQL-built index and `MultiAnalyzer` returns `Merged` over its delegates' handles, in `BTreeMap<Language, _>`
order. The four merged-index fields, the materializing builder, and the `query_has_store_error` whole-view
fallback are gone: a delegate whose store read fails now degrades to its own recorded-error fallback shard,
so the failure stays visible and confined to that language. `MultiAnalyzer::update` shares the workspace
`AnalyzerSnapshotCaches` Arc when no delegate saw a relevant change and allocates fresh otherwise.

Cost of the change, for the next contributor's calibration: the trait signature change touched about 90 call
sites in 40 files, ten times what the plan's consumer audit predicted (see Surprises). Almost all of them were
mechanical once the handle kept the concrete index's method names; the genuinely hard ones were the eight
listed in Surprises.

Remaining: Milestone 2 (collapsing `WorkspaceAnalyzer::Single` into `Multi`), which is independent and was
being implemented concurrently.

Lesson: an ExecPlan's consumer audit is the single number worth double-checking before committing to a trait
signature change. This plan's audit grepped for `global_usage_definition_index()` and then reported only the
call sites reached through the workspace handle, which silently dropped every per-language resolver that
reaches the same trait method through a concrete analyzer. The decision itself survived the correction --
owned results really are cheap here, because `CodeUnit` is `Arc`-backed -- but a plan that had stated 90 sites
up front would have sequenced the work differently, probably converting the index's borrowing accessors to
owned ones as a separate, independently reviewable commit first.

### Milestone 2 (2026-08-02)

`WorkspaceAnalyzer` is `Empty` + `Multi`; every workspace with at least one analyzable language is a `MultiAnalyzer`, and the twelve-arm delegate unwrap in `analyzer()` is gone. `grep -rn "WorkspaceAnalyzer::Single\|Self::Single" crates/bifrost-analysis/src` returns nothing.

The mechanical part was as small as predicted. What the plan got wrong was where the risk lived. It expected fallout in ordering pins (there was none -- both shapes already sorted) and expected Milestone 1 to be the thing that makes the collapse safe. In fact the collapse exposed an unrelated, pre-existing hole in `MultiAnalyzer`'s provider forwarding that Milestone 1 does not touch, and the plan's own acceptance command could not see any of the fallout because the tests that construct `WorkspaceAnalyzer` belong to the facade package. Both corrections are recorded above; the second one is worth carrying into future milestones of this kind, since the routing layer forwards a large trait surface method by method and a missing override fails silently rather than loudly.

Validation at completion: `brokk-bifrost-analysis --lib` 1921 passed / 3 failed, byte-identical to the pre-change baseline (all three pre-existing, see Surprises); `code_quality --lib` 67 passed, keeping the #1417 pin green; the facade suites pass -- analyzers 690, bench_policy 209, cross_language 308, issues 137, lsp_parity 157, mcp_cli 101, persistence 93, semantic 606, smells 335, usages 1444, symbols 1154 with the one pre-existing `diff_analysis_test` failure; `cargo clippy --workspace --all-targets -D warnings` clean.

### Integration (2026-08-02)

The two milestones were implemented concurrently on separate branches and combined with a merge commit
(not a rebase) so each side's original commits remain traceable. The only textual conflict was this plan
file; `multi_analyzer.rs` merged cleanly because Milestone 2 confined itself to two hunks (deleting the
dead `AnalyzerDelegate::language()` and adding the `imported_files_from_infos` forwarder) away from
Milestone 1's merged-index work. Post-merge semantic checks: the forwarder survives and its pins pass; the delegate-count-sensitive MCP
shard pin (build counts 2 then 3) is unaffected by the collapse since its service already held two
delegates. One cross-branch collision surfaced and was fixed at integration (Milestone 1 test pins using
the delegate method Milestone 2 deleted — see Surprises), and chasing why the clippy gate missed it
exposed the `default-members` blind spot, also in Surprises, now corrected in CLAUDE.md/AGENTS.md.
Combined validation at the integration head: `cargo test -p brokk-bifrost-analysis --lib` 1922 passed /
3 failed (exactly the three pre-existing failures both agents verified at the base commit: the scala
epoch-hash pin and the two cpp call-dispatch pins); `cargo test -p brokk-bifrost --no-fail-fast` all
suites ok except the pre-existing environmental `suite_symbols::diff_analysis_test` (this host's git
rejects `init -b`), with Milestone 2's new pins passing; `cargo test -p brokk-bifrost-mcp` ok;
`cargo fmt --check` clean; `scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets
--all-features -- -D warnings` clean.

## Context and Orientation

All paths are relative to the repository root. The code lives in `crates/bifrost-analysis/`.

An "analyzer" is an object implementing the `IAnalyzer` trait (`src/analyzer/i_analyzer.rs`), the monolithic interface for code-intelligence queries: declarations in a file, definitions of a name, usage analysis, structural (RQL) search, source retrieval, and so on. Each supported language has a concrete analyzer (e.g. `RustAnalyzer` in `src/analyzer/rust/mod.rs`), which wraps the generic `TreeSitterAnalyzer<A>` (`src/analyzer/tree_sitter_analyzer.rs`) with a language adapter `A`. `MultiAnalyzer` (`src/analyzer/multi_analyzer.rs`) holds a `BTreeMap<Language, AnalyzerDelegate>` of concrete analyzers ("delegates") and implements `IAnalyzer` by routing each call to the delegate for the file's detected language (`delegate_for_file`, which keys on `language_for_file(file)` — extension-based detection in `src/analyzer/common.rs` returning the typed `Language::None` for unanalyzable files).

`WorkspaceAnalyzer` (`src/analyzer/workspace.rs`) is the enum that decides which shape a workspace gets. Its constructor `build_filtered` builds one delegate per detected language and then wraps: zero delegates gives `Empty(EmptyAnalyzer)`, exactly one gives `Single(Box<AnalyzerDelegate>)` (the bare concrete analyzer serves the whole workspace), two or more give `Multi(Box<MultiAnalyzer>)`. Every match on `Single` vs `Multi` is inside `workspace.rs`; nothing else pattern-matches the enum. That is what makes Milestone 2 mechanically small.

The "global usage definition index" (`GlobalUsageDefinitionIndex`, `src/analyzer/global_usage_definition_index.rs`) is a set of hash maps from names to declarations: by fully-qualified name, by identifier, by (file, identifier), plus package existence sets, used to resolve references during usage analysis and search. It is expensive: it holds cloned strings and `CodeUnit`s for every declaration in scope. There are two build paths today:

- `TreeSitterAnalyzer` builds its own per-language index lazily from the SQL store (`try_global_usage_definition_index_handle` calling `sql_global_usage_definition_index`, around `tree_sitter_analyzer.rs:6761`), holds it in `Arc<OnceLock<Arc<GlobalUsageDefinitionIndex>>>`, and shares the Arc across `clone()` and `clone_with_project` (overlay snapshots). On a real content update (`update` with non-empty relevant changes), the analyzer is rebuilt through `from_state`, which starts a fresh `OnceLock` — correct invalidation. On an update with an empty change set, `update` returns `self.clone()`, retaining the built index.
- `MultiAnalyzer::global_usage_definition_index` (`multi_analyzer.rs:730`) lazily materializes a second, merged index by draining `all_declarations()` from every delegate into `GlobalUsageDefinitionIndex::from_declarations` — a full declaration scan per delegate plus a full copy of all strings. This merged copy lives in the `MultiAnalyzer`'s own `OnceLock` and is thrown away by `update`, `update_all`, and `clone_with_project`, all of which construct fresh state via `new_with_derived_layer_budget` — even when the update touched no relevant file and every delegate was retained by `clone()`.

`AnalyzerSnapshotCaches` (`src/analyzer/i_analyzer.rs:201`) wraps a `SnapshotDerivedLayerCache` (`src/analyzer/structural/execution/derived.rs`) holding derived structural-query layers under an LRU byte budget. Both `TreeSitterAnalyzer` and `MultiAnalyzer` own one, each budgeted `config.memo_cache_budget_bytes() / 8`. Structural search takes whichever handle it was given (`analyzer.snapshot_caches()`, `src/analyzer/structural/search/mod.rs:4690`). The cache is generation-guarded (see Surprises), so serving stale layers is impossible regardless of retention policy.

`BoundedDefinitionLookup` (`global_usage_definition_index.rs:34`) is an existing pub(crate) trait describing candidate-shaped definition lookups (`fqn`, `fqn_in_language`, `file_identifier`, `fqn_direct_children`, `package_exists`, ...). `GlobalUsageDefinitionIndex` implements it. It is the natural shape for the compositional view.

Consumers of `IAnalyzer::global_usage_definition_index()` as of this writing (audit with `grep -rn "global_usage_definition_index()" crates --include=*.rs`):

- via the workspace handle: `src/searchtools/sources.rs`, `src/searchtools/summaries.rs`, `src/analyzer/usages/candidates.rs` (the only user of the borrowing `by_fqn` accessor).
- via the concrete analyzer they run inside: `src/analyzer/usages/java_graph/inverted.rs`, `src/analyzer/usages/java_graph/return_type.rs`, `src/analyzer/usages/kotlin_graph/resolver.rs`, `src/analyzer/usages/ruby_graph.rs`.
- `src/analyzer/typescript/mod.rs:544` forwards to its inner `TreeSitterAnalyzer`.
- tests in `multi_analyzer.rs` (build-count pins, around lines 1440-1510).

The trait's default implementation (`i_analyzer.rs:426`) returns a static empty index.

Store note: nothing in this plan changes extractor behavior or persisted schema, so no per-language epoch salt bump (`src/analyzer/store/epoch.rs`) and no cache migration is needed.

## Milestone 1: compositional merged definition index and cache-retention parity

Goal: after this milestone, a definition-index query through a `MultiAnalyzer` handle builds each delegate's SQL-backed index once (lazily, per delegate) and answers by consulting those shards; no full-declaration-scan rematerialization exists anywhere; and a `MultiAnalyzer::update` that touches no relevant files retains both the delegates' built indexes and the workspace-level derived-layer caches. Multi-language workspaces get faster and smaller with no behavior change; nothing depends on Milestone 2.

Work, in order:

First, introduce the view type. In `src/analyzer/global_usage_definition_index.rs`, define next to the existing index:

    pub enum DefinitionIndexHandle<'a> {
        Single(&'a GlobalUsageDefinitionIndex),
        Merged(Vec<&'a GlobalUsageDefinitionIndex>),
    }

(Exact carrier for `Merged` may be adjusted during implementation — e.g. borrowing the delegates' Arcs — but it must not clone index contents.) Implement on it the query surface the workspace-handle consumers actually use, delegating for `Single` and chaining shards for `Merged`: `fqn`, `fqn_in_language`, `fqn_in_any_language`, `file_identifier`, `fqn_direct_children`, `fqn_exists`, `package_exists`, `package_exists_in_language`, `package_exists_in_any_language`, `fqn_prefix_exists`, plus whatever `searchtools/sources.rs`, `searchtools/summaries.rs`, and `usages/candidates.rs` currently call on the concrete index (audit at implementation time; `candidates.rs`'s `by_fqn` slice iteration becomes iteration over an owned `fqn` result or a chained iterator method). Cross-shard results follow shard order (delegates iterate in `BTreeMap<Language, _>` order, so ordering is deterministic); within a shard the index's existing `sort_entries` ordering is preserved. No cross-shard dedup is needed: a `CodeUnit` carries its source file, and one file belongs to exactly one delegate. Verify during implementation that no consumer relies on globally sorted cross-language ordering; if one does, sort in the view method that consumer uses and record it in the Decision Log.

Second, change the trait. In `src/analyzer/i_analyzer.rs`, change `fn global_usage_definition_index(&self) -> &GlobalUsageDefinitionIndex` to return `DefinitionIndexHandle<'_>`; the default implementation returns `Single` of the static empty index. `TreeSitterAnalyzer` returns `Single` of its Arc-backed index (existing lazy SQL build and store-error fallback semantics unchanged). The per-language wrapper analyzers and `typescript/mod.rs` forward as today. Update the direct consumers listed in Context to accept the handle; functions that took `&GlobalUsageDefinitionIndex` as a parameter (e.g. `java_lombok_accessor_field_candidates` in searchtools, `ruby_graph.rs`'s `support` field) take `DefinitionIndexHandle<'_>` (or stay on the concrete type where the caller is a concrete analyzer and provably stays one — prefer the handle for uniformity unless a borrow problem argues otherwise; record the choice).

Third, make `MultiAnalyzer` compositional. In `src/analyzer/multi_analyzer.rs`, `global_usage_definition_index` returns `Merged` built by asking each delegate for its index handle (which triggers each delegate's own lazy SQL build on first use). Delete the now-dead fields and their maintenance: `global_usage_definition_index`, `global_usage_definition_index_build_count`, `global_usage_definition_index_build_lock`, `global_usage_definition_fallback`, and the `query_has_store_error`-gated fallback block in the old builder (per-shard store errors now degrade per-shard through each delegate's existing recorded-error fallback, which surfaces failures instead of silently emptying the whole merged index). Delete or rewrite the build-count tests around `multi_analyzer.rs:1440-1510`: the merged build count no longer exists; the delegate build counts (`global_usage_definition_index_build_count_for_test` on concrete analyzers) become the observable.

Fourth, retention parity in `MultiAnalyzer::update` (`multi_analyzer.rs:657`): when the per-delegate `relevant` change sets are all empty (every delegate was `clone()`d), construct the new `MultiAnalyzer` sharing `Arc::clone(&self.snapshot_caches)` instead of allocating fresh caches; when any delegate changed, allocate fresh (parity with `from_state`). `update_all` always allocates fresh. `clone_with_project` keeps allocating fresh workspace-level caches (parity with `TreeSitterAnalyzer::clone_with_project`, which resets `snapshot_caches` while keeping the definition index — and after this milestone the merged index needs no retention because it is recomputed from the delegates' retained Arcs on demand, which is the actual win for overlay snapshots).

Acceptance for Milestone 1 (all from the crate root, `crates/` workspace):

    cargo test -p brokk-bifrost-analysis --lib
    cargo test -p brokk-bifrost-analysis

with all suites passing, plus two new behavior pins in the multi-analyzer test module:

- Build-once pin: construct a two-language `InlineTestProject` workspace (use the shared inline harness `tests/common/inline_project.rs` if writing an integration test, or the existing in-module test fixtures), run a definition query through the workspace handle, and assert each delegate's `global_usage_definition_index_build_count_for_test()` is exactly 1 and `full_declaration_scan_count` (the existing counter on `TreeSitterAnalyzer`) did not increase due to the merged view.
- Retention pin: after the query, call `update` with a change set containing only an irrelevant file (e.g. `README.md`), re-run the query on the returned analyzer, and assert the delegate build counts are still 1 (no rebuild) — this fails before this milestone because the old merged index was dropped and rematerialized via full scans.

## Milestone 2: collapse WorkspaceAnalyzer::Single into Multi

Goal: after this milestone, `WorkspaceAnalyzer` has exactly two variants, `Empty` and `Multi`; a single-language workspace is a `MultiAnalyzer` holding one delegate; and the twelve-arm delegate unwrap in `WorkspaceAnalyzer::analyzer()` is gone. Routing and refusal live only in `MultiAnalyzer` for workspace-handle callers; the concrete analyzers' interior guards (the `generations.get(...)?` refusal from #1417, the foreign-file refusal in `fetch_file_state_for_key_with_source`) remain, because `MultiAnalyzer`'s own fan-out paths (e.g. import analysis asking every delegate about arbitrary files) intentionally bypass routing.

Work, in order: in `src/analyzer/workspace.rs`, merge the `1 =>` arm of `build_filtered`'s wrap-up match into the `_ => Multi(...)` arm; delete the `Single` variant and its arms in `clone_with_project`, `analyzer()`, `update`, `update_all`, and `program_semantics_provider_for_file` (the Multi arm already covers the semantics — `MultiAnalyzer::program_semantics_provider_for_file` routes by file). Fix every compile error that falls out; audit tests for direct `WorkspaceAnalyzer::Single` construction or matching and update them to the unified shape.

Known fallout to check deliberately rather than discover:

- Ordering: `MultiAnalyzer::analyzed_files` sorts and dedups; a bare analyzer's order may have differed. Any test pinning file-list order for single-language workspaces may need its expectation updated (the sorted order is the better contract; keep it).
- The `Empty` variant stays. Folding `EmptyAnalyzer` into a zero-delegate `MultiAnalyzer` is out of scope: `EmptyAnalyzer` has bespoke stubs and `MultiAnalyzer::project()` panics with no delegates.
- `kotlin_realm` (`multi_analyzer.rs:376`) with a lone Kotlin delegate: `JvmSourceRealm::of` must yield no widening (realm requires Kotlin plus another JVM language). Confirm with a single-language Kotlin workspace test if one does not already exist.
- The dual-shape downcast helper at `multi_analyzer.rs:25-32` keeps working (its direct-downcast arm still serves tests that construct concrete analyzers); no change needed.
- The hotspots regression pin from #1417 (`cargo test -p brokk-bifrost-analysis code_quality --lib`) must still pass; single-language workspaces now reach `cyclomatic_complexities_for_file` through `MultiAnalyzer::summary_file_projection` routing, which refuses foreign files at the routing layer before the interior generation check even runs.

Acceptance for Milestone 2: `grep -rn "WorkspaceAnalyzer::Single\|Self::Single" crates/bifrost-analysis/src` returns nothing; the full featureless test suite for the crate passes; `cargo test -p brokk-bifrost-analysis code_quality --lib` passes. Add `cargo test -p brokk-bifrost --no-fail-fast`: the integration suites that construct and match `WorkspaceAnalyzer` live in the repository-root `tests/` directory, which belongs to the facade package, so the analysis crate's own suite cannot see this milestone's fallout (see Surprises).

## Concrete Steps

Work from the repository root. This work does not touch semantic search / NLP, so per CLAUDE.md do not enable the `nlp` feature for routine validation.

    cargo test -p brokk-bifrost-analysis --lib          # fast inner loop
    cargo test -p brokk-bifrost-analysis                # integration suites
    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Note on clippy inside this worktree: this plan is executed inside a nested worktree (`.claude/worktrees/*`), where the `clippy-no-cuda` alias is broken (duplicate alias arrays merge); always use the expanded command above. Commit checkpoints per milestone on the current branch; never `git add -A` (stage explicit paths), and never use bare `git stash` (the stash ref is shared across worktrees of this repository).

## Validation and Acceptance

Milestone acceptance criteria are given inline in each milestone. Overall acceptance: both milestones' pins pass; the whole `brokk-bifrost-analysis` featureless suite passes; clippy with `--all-targets --all-features -D warnings` is clean; and reading `workspace.rs` shows only `Empty` and `Multi` variants. The user-visible claim to verify end to end: on a single-language fixture workspace, `analyze_git_hotspots` over history containing non-source files returns a report (foreign files categorized with complexity 0) with no panic and no full-declaration scans attributable to the merged index — observable via the existing counters used by the #1417 regression pin.

## Idempotence and Recovery

All steps are additive code edits validated by tests; re-running tests is always safe. If Milestone 1 lands and Milestone 2 stalls, stop: Milestone 1 is independently shippable. If a consumer of `DefinitionIndexHandle` turns out to need an API the view cannot provide without materializing (a borrowing slice across shards), do not add a materializing fallback — record it in Surprises, and either move that consumer to an owned query or reconsider the enum carrier; the prohibition on regex/text fallbacks in CLAUDE.md applies in spirit: no hidden copies to paper over a structural mismatch.

## Artifacts and Notes

Milestone 1 validation on this host (2026-08-02), from the worktree root. Five test failures are pre-existing
on the parent commit `3c4fdb94` and unrelated to this work; each was verified by extracting a pristine tree
with `git archive HEAD | tar -x -C <scratch>` and running the same tests there, where they fail identically:

    analyzer::store::tests::scala_scalachess_fqn_recovery_epoch_invalidates_stale_rows_and_reuses_current
    analyzer::usages::call_relations::tests::exact_dispatch_keeps_multiple_cpp_bodies_unproven
    analyzer::usages::call_relations::tests::exact_dispatch_preserves_cpp_navigation_uncertainty
    doctest crates/bifrost-analysis/src/analyzer/kotlin/syntax.rs (line 20)
    suite_symbols diff_analysis_test::analyze_diff_rejects_blob_endpoints_and_keeps_commits_available_with_alternate

The last one is environmental rather than a code defect: it shells out to `git init -b master` and this host's
git rejects `-b` ("unknown switch `b'"). Anyone reproducing on a newer git should see it pass.

Why the two required Milestone 1 pins genuinely fail before the change, reasoned rather than measured (the
intermediate tree does not compile, because the trait signature change and the `MultiAnalyzer` change are the
same edit): the old merged builder never touched a delegate's own definition index at all -- it drained
`all_declarations()` from each delegate and rebuilt a separate index. So before the change,
`delegate.global_usage_definition_index_build_count_for_test()` after a workspace definition query was 0, not
the 1 the build-once pin asserts, and `full_declaration_scan_count_for_test()` was one scan per delegate, not
the 0 both pins assert. The retention pin fails a second way: `MultiAnalyzer::update` went through
`new_with_derived_layer_budget`, which allocated a fresh `AnalyzerSnapshotCaches`, so
`Arc::ptr_eq(&analyzer.snapshot_caches, &updated.snapshot_caches)` was false for every update including one
carrying only `README.md`.

Results with those five excluded:

    cargo test -p brokk-bifrost-analysis --lib   1922 passed; 3 failed (all pre-existing)
    cargo test -p brokk-bifrost --no-fail-fast   every suite ok; 1 failed (pre-existing, environmental)
    cargo test -p brokk-bifrost-mcp              118 + 30 passed; 0 failed
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
                                                 Finished in 3m 32s, clean


The investigation transcript behind the Decision Log lives in this plan's Context section; key line references (verified 2026-08-02 at commit `950aec47`): merged-index materialization `multi_analyzer.rs:744-750`; merged-index drop sites `multi_analyzer.rs:331-339` (clone_with_project) and `:657-677` (update/update_all via `new_with_derived_layer_budget`); delegate SQL build `tree_sitter_analyzer.rs:6761-6793`; delegate retention `tree_sitter_analyzer.rs:7014-7016` (no-op update) and `:1671-1683` (clone_with_project keeps index, resets derived caches); workspace wrap-up match `workspace.rs:315-324`; foreign-file interior guard precedent `tree_sitter_analyzer.rs:3263-3281`.

## Interfaces and Dependencies

No new external dependencies. End state of the public-in-crate surface:

In `crates/bifrost-analysis/src/analyzer/global_usage_definition_index.rs`:

    pub enum DefinitionIndexHandle<'a> { Single(&'a GlobalUsageDefinitionIndex), Merged(Vec<&'a GlobalUsageDefinitionIndex>) }

with query methods mirroring the `BoundedDefinitionLookup` shape (owned `Vec<CodeUnit>` results, no borrowing slice accessors).

In `crates/bifrost-analysis/src/analyzer/i_analyzer.rs`:

    fn global_usage_definition_index(&self) -> DefinitionIndexHandle<'_>;

In `crates/bifrost-analysis/src/analyzer/workspace.rs`:

    pub enum WorkspaceAnalyzer { Empty(EmptyAnalyzer), Multi(Box<MultiAnalyzer>) }

`MultiAnalyzer` loses its four merged-index fields; its `update` shares `snapshot_caches` when no delegate had relevant changes.
