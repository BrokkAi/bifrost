# Shared usage-graph symbol index refactor

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. It is self-contained and describes the work needed to replace per-language ad hoc usage-graph lookup indexes with shared keyed symbol-index primitives.

## Purpose / Big Picture

The `usage_graph` search tool builds a caller-to-callee graph for a repository. Large Scala repositories are currently extremely slow because Scala return-type resolution does a broad scan over all known project types when a same-package lookup misses. After this work, usage-graph resolution has a shared symbol index for type, member, and callable return-type lookup, and Scala uses keyed lookups instead of declaration-wide scans. The behavior is visible by running the Scala usage-graph tests and by profiling Scala `generate_commit_worker.py` processes: CPU should no longer be dominated by `scala_graph::inverted::return_type_fqn` and hash-map value iteration.

## Progress

- [x] (2026-07-07) Created isolated worktree `/mnt/optane/bifrost-shared-usage-index` on existing branch `shared-usage-index-refactor` after pruning stale `/tmp/bifrost-shared-usage-index` metadata.
- [x] (2026-07-07) Drafted this ExecPlan under `.agents/plans/`.
- [x] (2026-07-07) Added shared `src/analyzer/usages/symbol_index.rs`.
- [x] (2026-07-07) Migrated Scala `ProjectTypes` to the shared symbol index and removed O(all types) fallback lookup.
- [x] (2026-07-07) Added targeted tests for shared index behavior and Scala return-type lookup.
- [x] (2026-07-07) Ran formatting, focused Scala tests, shared-index tests, and clippy in the recreated `/mnt/optane` worktree.
- [x] (2026-07-07) Committed only files changed for this refactor on the current branch.

## Surprises & Discoveries

- Observation: The generic usage-graph edge engine already exists in `src/analyzer/usages/inverted_edges.rs`; the fragmented part is the symbol-resolution index layer around type, member, and return-type lookup.
  Evidence: `inverted_edges.rs` owns file fan-out, `EdgeCollector`, caller attribution, self-reference filtering, and cap merging.
- Observation: Scala’s expensive fallback is in `src/analyzer/usages/scala_graph/inverted.rs` in `return_type_fqn`, where `by_package.values().find(...)` scans all declared types for each unresolved return type.
  Evidence: Live `perf` sampling showed `brokk_bifrost::analyzer::usages::scala_graph::inverted::return_type_fqn` plus hash-map iteration/string comparison as the dominant native CPU path.
- Observation: Scala analyzer declarations can collapse overloads under the same member FQN, while the AST-local `factory_returns` map can preserve multiple return annotations.
  Evidence: The existing `overloaded_factory_receiver_emits_no_partial_edge` test failed in the prior attempt until local call-result inference treated an existing multi-return `factory_returns` entry as authoritative ambiguity instead of falling through to the shared index.
- Observation: Preserving a `members` vector in `WorkspaceSymbolIndex` matters because overloads can share a displayed member FQN.
  Evidence: The final pre-crash cleanup changed `members()` away from map values so override-target construction can still see every declaration that the analyzer provides.

## Decision Log

- Decision: Add a shared symbol-index helper rather than trying to unify language AST walkers.
  Rationale: Tree-sitter node shapes and import visibility rules differ by language, but the indexed lookup shapes are common. This keeps language-specific structured parsing intact while preventing declaration-wide lookup fallbacks.
  Date/Author: 2026-07-07 / Codex
- Decision: Migrate Scala first and keep Java/C#/PHP/Go/Rust/Python/JS/TS/C++ as follow-up consumers unless the first implementation naturally exposes a small adapter.
  Rationale: Scala is the active production bottleneck, and a staged migration keeps the first commit reviewable while establishing the shared API.
  Date/Author: 2026-07-07 / Codex
- Decision: For Scala local factory-call inference, prefer the AST-local return map when it has an entry, even if that entry is ambiguous, and use the shared index only when no AST-local entry exists.
  Rationale: The AST-local path distinguishes same-FQN overload return annotations that the analyzer declaration list can collapse. Falling through after an ambiguous AST-local result reintroduced an unsound partial edge.
  Date/Author: 2026-07-07 / Codex

## Outcomes & Retrospective

The first implementation milestone is complete in `/mnt/optane` after the `/tmp` worktree was lost. The shared symbol-index module exists, Scala `ProjectTypes` uses it for type/member/return lookups, and the previous `by_package.values().find(...)` return-type fallback is gone in the working tree. Validation passed with `cargo fmt`, `cargo test --test usage_graph_scala_test -- --nocapture`, `cargo test --test usages_scala_graph_test -- --nocapture`, `cargo test symbol_index -- --nocapture`, and `cargo clippy-no-cuda`. The checkpoint is committed on `shared-usage-index-refactor`. The remaining work in this ExecPlan is broader migration of Java/C#/PHP and the other language adapters onto the shared helper where it fits.

## Context and Orientation

The usage subsystem lives under `src/analyzer/usages/`. `src/analyzer/usages/inverted_edges.rs` is the language-agnostic engine for whole-workspace `usage_graph`: it parses or receives each file, lets a language-specific scanner record resolved callees, attributes each callee to an enclosing caller declaration, filters self references, and merges edges. The language-specific `*_graph/inverted.rs` files still own AST traversal and reference extraction.

A symbol index in this plan means a tree-free set of hash maps built from analyzer declarations. It does not parse source text. It stores facts such as "package `example` contains type simple name `Service` with fqn `example.Service`", "owner `example.Service` has member `run`", and "callable `example.make` returns type `example.Service`". A keyed lookup means a direct hash-map lookup by those facts, not scanning all declarations.

Scala currently defines `ProjectTypes` in `src/analyzer/usages/scala_graph/inverted.rs`. Before this change, that type contained package/type maps, member maps, return-type maps, and extension-method maps. The broad scan fallback appeared in `return_type_fqn`, which tried a same-package lookup and then scanned all package-map values to see whether the return type text was already a fully-qualified name. This is the primary behavior removed by this plan.

## Plan of Work

Add `src/analyzer/usages/symbol_index.rs` and expose it from `src/analyzer/usages/mod.rs` as `pub(crate) mod symbol_index`. The module defines data structs for type declarations and member declarations, plus a builder that constructs a `WorkspaceSymbolIndex`. The index supports exact type lookup, normalized type lookup, package/simple lookup, owner/member/arity lookup, normalized member import lookup, and callable return-type lookup. It does not expose a method that linearly scans all declarations for normal resolution.

Migrate Scala `ProjectTypes` to contain a `WorkspaceSymbolIndex` plus Scala-only extension method maps. Preserve existing public methods on `ProjectTypes` and `NameResolver` where other modules depend on them. Rebuild Scala type and member declarations into the shared builder, then change `return_type_fqn` to use only keyed index lookups. Exact FQN return types are handled by a direct type-fqn map, not by scanning values.

Add tests for the shared index itself and Scala usage graph behavior. Use inline test projects for Scala tests. Include a regression case with many unrelated type declarations and return types so the code path is exercised without reintroducing broad scans.

## Concrete Steps

From `/mnt/optane/bifrost-shared-usage-index`, edit the files named above. Run:

    cargo fmt
    cargo test --test usage_graph_scala_test -- --nocapture
    cargo test --test usages_scala_graph_test -- --nocapture
    cargo test symbol_index -- --nocapture
    cargo clippy-no-cuda

On CUDA-capable machines, replace `cargo clippy-no-cuda` with:

    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

The refactor is accepted when Scala usage-graph tests pass, the shared symbol-index tests pass, and clippy reports no warnings. A pre-change profile of large Scala `generate_commit_worker.py` processes showed `return_type_fqn` and hash-map iteration dominating CPU; after this change, that exact broad-scan fallback should no longer exist in source, and profiling the same path should move CPU to actual file walking or other resolver work.

## Idempotence and Recovery

The worktree is isolated at `/mnt/optane/bifrost-shared-usage-index`, not `/tmp`, so it should survive WSL temporary-directory cleanup. If a test command fails due to build artifacts, rerun it after fixing code; no destructive cleanup is required. Do not use `git add -A`; stage only files changed for this plan. If the branch needs to be abandoned, remove only the worktree path with `git worktree remove /mnt/optane/bifrost-shared-usage-index` from the main checkout after confirming no desired changes remain.

## Artifacts and Notes

The old Scala return-type fallback looked up same-package types and then scanned all package-map values:

    by_package
        .get(&(package_name.to_string(), base.to_string()))
        .cloned()
        .or_else(|| by_package.values().find(|fqn| *fqn == base).cloned())

The new behavior uses direct keyed lookups:

    type_index
        .type_by_package_simple(package_name, base)
        .or_else(|| type_index.type_by_fqn(base))
        .or_else(|| type_index.type_by_normalized_fqn(&scala_normalized_fq_name(base)))
        .map(|decl| decl.fqn.clone())

## Interfaces and Dependencies

In `src/analyzer/usages/symbol_index.rs`, define `WorkspaceSymbolIndexBuilder`, `WorkspaceSymbolIndex`, `TypeDecl`, and `MemberDecl`. Use the repository’s `crate::hash::HashMap`. Keep all types `pub(crate)` unless tests need narrower visibility through the module. `WorkspaceSymbolIndex::members()` must iterate a stored vector of all members rather than map values so same-FQN overload declarations are not collapsed for consumers such as Scala override-target construction.

Revision note 2026-07-07 / Codex: Recreated the lost `/tmp` work in `/mnt/optane`, updated the recovery path, documented the overload ambiguity and all-member iteration decisions so the plan can be resumed from the checked-in file alone, recorded the successful validation commands after rerunning them in the new worktree, and marked the checkpoint commit complete.
