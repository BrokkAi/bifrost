# Scala usage-analysis performance fix

This ExecPlan is a living document. It follows `.agent/PLANS.md` and must keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while work proceeds.

## Purpose / Big Picture

Scala usage analysis currently spends too much time repeatedly scanning all declarations and reparsing Scala files while resolving type names and hierarchy information. After this change, Scala type resolution uses the workspace `DefinitionLookupIndex`, Scala raw supertypes and trait declarations are recorded during declaration collection, and hierarchy/override logic uses cached analyzer state instead of file I/O and fresh parsing. The behavior is verified by existing Scala usage, hierarchy, import, persistence, and cross-language tests plus new targeted coverage for class/object preference and trait hierarchy state.

## Progress

- [x] (2026-07-07) Read the relevant resolver, inverted graph, hierarchy, declaration collection, index, tree-sitter analyzer, payload, epoch, and Scala hierarchy test files.
- [x] (2026-07-07) Confirmed root causes A, B, and C match the current implementation.
- [x] (2026-07-07) Implemented A by replacing resolver scans with `DefinitionLookupIndex` lookups and consolidating preferred Scala type selection in `resolver.rs`.
- [x] (2026-07-07) Implemented B by moving Scala parent type-node extraction to `scala/supertypes.rs`, recording raw supertypes in declaration collection, and resolving hierarchy from `raw_supertypes`.
- [x] (2026-07-07) Implemented C by carrying `scala_traits` through parsed file, file state, analyzer state, persistence payload, and lookup accessors.
- [x] (2026-07-07) Implemented bounded D with a package-to-types map in `ScalaProjectTypes::build` and hash lookups in `NameResolver::for_file`.
- [x] (2026-07-07) Added behavior-focused tests for non-`$` preference through get-definition and hierarchy from collected supertypes.
- [x] (2026-07-07) Ran `cargo fmt`, the required Scala/persistence/cross-language test set with `BIFROST_SEMANTIC_INDEX=off`, the added get-definition test, and `cargo clippy --all-targets --all-features -- -D warnings`; all passed.

## Surprises & Discoveries

- Observation: `ProjectTypes` already had two local versions of the preferred non-`$` class choice: `preferred_scala_type` and `type_by_normalized_fqn`.
  Evidence: `src/analyzer/usages/scala_graph/inverted.rs` has a helper at the bottom and an inline candidate choice in `type_by_normalized_fqn`.
- Observation: `PAYLOAD_VERSION` is part of the epoch hash for all languages, but the repository also has per-language epoch salts. For B/C, the Scala salt is the narrower invalidation knob requested by the task; the payload version must still change because the serialized payload struct gains a field.
  Evidence: `src/analyzer/persistence/epoch.rs` hashes `PAYLOAD_VERSION` and `LanguageEpoch::SALT`.
- Observation: A usage-based class/object preference test is not a precise assertion for A, because usage scanning a companion-object target still matches class type references through target normalization.
  Evidence: The temporary `usages_scala_graph_test` scenario reported `Foo` type-reference hits for target `lib.Foo$`; the final test uses get-definition to observe the resolved declaration FQN directly.

## Decision Log

- Decision: Keep this plan in `.agents/plans/scala-usage-analysis-performance.md` but do not commit it.
  Rationale: The task is a significant refactor and repo instructions require ExecPlans for this scale of work, while the user explicitly instructed not to commit.
  Date/Author: 2026-07-07 / Codex.
- Decision: Share Scala parent type extraction from a new Scala module-level helper rather than keeping it in hierarchy.
  Rationale: Declaration collection and hierarchy both need the same tree-sitter node semantics, and the hierarchy provider should no longer parse files.
  Date/Author: 2026-07-07 / Codex.
- Decision: Implement D in the bounded form by precomputing package type lists from `DefinitionLookupIndex` inside `ScalaProjectTypes::build`.
  Rationale: This is a local replacement for two linear `package_types()` scans in `NameResolver::for_file` and does not require broader resolver restructuring.
  Date/Author: 2026-07-07 / Codex.

## Outcomes & Retrospective

Implemented all requested deliverables A, B, C, and bounded D. Scala declared-type resolution now uses `DefinitionLookupIndex` lookups with a shared preferred-type helper. Scala hierarchy no longer reparses source to find parent types; declaration collection records raw supertypes. Scala trait status is recorded in analyzer state and persisted. Wildcard import package type exposure now uses a precomputed package map. Validation passed with formatting, the requested test set, the added get-definition preference test, and clippy.

Measured on delta-io/delta (1210 Scala files, release build, transient service): cold `usage_graph` — which includes `ScalaProjectTypes::build`, `build_method_override_targets`, and the whole-workspace inverted edge build — dropped from 108,180 ms to 989 ms (~109x) with byte-identical graph output (21393 nodes, 24719 edges before and after). Workspace init unchanged (~1.2 s). The diagnosis came from `perf` profiles of live benchmark workers: ~90% of CPU was in the `all_declarations()` linear scans and their per-unit `fq_name()`/normalization allocations.

## Context and Orientation

`src/analyzer/usages/scala_graph/resolver.rs` resolves Scala type text during usage scanning. Its `scala_declared_type_in_package` and `scala_declared_type_fqn` helpers currently iterate over `ScalaAnalyzer::all_declarations()`. `src/analyzer/definition_lookup_index.rs` already stores class declarations by `(package, simple name)` and by normalized fully qualified name.

`src/analyzer/scala/hierarchy.rs` resolves direct ancestors and trait information for Scala. It currently reparses source files to find each declaration node. `src/analyzer/scala/declarations.rs` already visits every type declaration node while building `ParsedFile`, which is the correct time to extract raw parent type text and trait status.

`src/analyzer/tree_sitter_analyzer.rs` owns the per-file and merged analyzer state. `src/analyzer/persistence/payload.rs` serializes `FileState` for persisted baselines. `src/analyzer/persistence/epoch.rs` computes language-specific invalidation fingerprints.

## Plan of Work

First, add shared Scala helpers for preferred type selection and parent type extraction. Use the preferred helper from the resolver and `ScalaProjectTypes`. Use the parent extraction helper from declaration collection, and remove the parsing path from hierarchy.

Next, add `scala_traits: HashSet<CodeUnit>` through `ParsedFile`, `FileState`, `AnalyzerState`, capacities, aggregation, accessor, and persistence payload. Mark trait declarations in Scala declaration collection and use the accessor in hierarchy and override target building.

Then, evaluate the bounded wildcard-import package map optimization. If it only requires building a `HashMap<String, Vec<(String, CodeUnit)>>` once in `ScalaProjectTypes::build` and replacing the package scans in `NameResolver::for_file`, implement it. Otherwise skip it.

Finally, add tests and run formatting, targeted tests, payload-related tests, and clippy exactly as requested.

## Concrete Steps

Work from `/tmp/bifrost-projecttypes-cache`. Edit the Scala resolver/inverted graph, Scala declarations/hierarchy, tree-sitter analyzer state, persistence payload/epoch, and tests. Do not commit.

Run:

    cargo fmt
    BIFROST_SEMANTIC_INDEX=off cargo test --test scala_analyzer_test --test scala_type_hierarchy_test --test usages_scala_graph_test --test usage_graph_scala_test --test scala_import_test --test scala_skeleton_test --test intellij_scala_goto_definition --test scala_source_code_test --test analyzer_persistence --test cross_language_receiver_definition --test cross_language_self_usages --test cross_language_import_hits
    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

The new class/object preference test must show that a type reference resolving through `scala_declared_type_fqn` prefers `Foo` over `Foo$` when both normalize to the same name. The hierarchy test must show direct ancestors still resolve from raw supertypes and trait detection still distinguishes trait relationships without reparsing.

All required commands must complete successfully. If any existing test changes behavior, investigate and report the behavior rather than silently rewriting expectations.

## Idempotence and Recovery

The implementation is source-only and can be repeated safely. If a test command fails, fix the root cause and rerun the relevant command. If a diagnosis proves wrong, stop and report the corrected diagnosis rather than forcing the requested shape.

## Artifacts and Notes

Final report must separately cover A, B, C, and D, list touched files, describe epoch invalidation, include exact commands and outcomes, and note any behavior changes observed.
