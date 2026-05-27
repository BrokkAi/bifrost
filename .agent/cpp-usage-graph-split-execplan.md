# Split C++ Usage Graph Strategy

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md`.

## Purpose / Big Picture

The C++ usage graph strategy currently lives in one large source file that mixes high-level orchestration, tree-sitter traversal, C++ name and visibility resolution, local inference, and hit construction. This refactor makes the C++ implementation match the smaller facade/extractor/resolver/hits module pattern already used by the other language usage graph strategies. The observable behavior must not change: the existing C++ usage graph tests should pass before and after the split, and public usage APIs remain stable.

## Progress

- [x] (2026-05-27T11:26Z) Switched to `dave/136-split-cpp-usage-graph-strategy`, ran `git fetch`, and rebased onto `origin/master`.
- [x] (2026-05-27T11:26Z) Created this ExecPlan before editing Rust source.
- [x] (2026-05-27T11:34Z) Split the current C++ strategy into facade, extractor, resolver, and hits modules.
- [x] (2026-05-27T11:34Z) Ran `cargo test --test usages_cpp_graph_test`; 25 tests passed.
- [x] (2026-05-27T11:34Z) Ran `cargo test --test cpp_analyzer_test`; 24 tests passed.
- [x] (2026-05-27T11:37Z) Ran `cargo fmt`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`; formatting and clippy passed.

## Surprises & Discoveries

- Observation: The worktree was already on an issue branch named `136-split-c-usage-graph-strategy-into-extractor-and-resolver-modules`, not detached.
  Evidence: `git status --short --branch` reported that branch before switching to the requested `dave/...` branch.

## Decision Log

- Decision: Keep the existing `src/analyzer/usages/cpp_graph.rs` file as the public facade and place implementation helpers under `src/analyzer/usages/cpp_graph/`.
  Rationale: This matches the established pattern in `csharp_graph`, `java_graph`, `go_graph`, and the other split strategies while preserving the exported `CppUsageGraphStrategy` path.
  Date/Author: 2026-05-27 / Codex

## Outcomes & Retrospective

No implementation outcome yet.

- 2026-05-27T11:34Z: The C++ usage graph suite passes after the module split. Remaining work is adjacent analyzer validation, formatting, and clippy cleanup.
- 2026-05-27T11:37Z: The refactor is complete and validated. The public facade remains in `src/analyzer/usages/cpp_graph.rs`, while extraction, resolution, and hit construction now live in sibling internal modules.

## Context and Orientation

The C++ usage graph strategy is exposed as `CppUsageGraphStrategy` from `src/analyzer/usages/cpp_graph.rs`. A usage graph strategy implements `UsageAnalyzer`, receives one or more target `CodeUnit`s, scans candidate `ProjectFile`s, and returns a `FuzzyResult` through `GraphUsageOutcome`.

The current file has four responsibilities that should become separate modules. The facade validates the target language, resolves the C++ analyzer, filters candidate files, owns fallback behavior, and enforces `max_usages`. The extractor parses C++ files with tree-sitter, walks syntax nodes, maintains local inferred bindings, detects raw candidate references, and triggers C++-specific text scans. The resolver owns `TargetSpec`, `TargetKind`, include visibility, C++ name normalization, receiver/type/member matching, and analyzer resolution. The hits module converts proven references into `UsageHit`s while filtering declarations and duplicate/invalid text hits.

The compatibility oracle is `tests/usages_cpp_graph_test.rs`, which covers include visibility, namespace identity, constructors, methods, fields, aliases, overload arity, fallback boundaries, and text-only false positives. `tests/cpp_analyzer_test.rs` is adjacent coverage for C++ analyzer behavior used by the resolver.

## Plan of Work

First, create the new `src/analyzer/usages/cpp_graph/` directory with `extractor.rs`, `resolver.rs`, and `hits.rs`. Move code without changing behavior. Keep function names stable where practical so the diff stays reviewable.

Second, reduce `src/analyzer/usages/cpp_graph.rs` to `mod extractor; mod hits; mod resolver;`, the `CppUsageGraphStrategy` type, its `UsageAnalyzer` implementation, and the orchestration in `find_graph_usages`. The facade should import only the cross-module items it needs: `ScanState`, `scan_file`, `TargetSpec`, `VisibilityIndex`, and `resolve_cpp_analyzer`.

Third, make helper visibility `pub(super)` only for items used across the new sibling modules. Private helpers should stay private inside their owning module.

Finally, run the focused tests and gates. If a failure reveals that a helper belongs in a different module for borrow or dependency reasons, move the helper and record the reason here.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/d24e/bifrost`.

Initial branch update:

    git checkout -B dave/136-split-cpp-usage-graph-strategy
    git fetch
    git rebase origin/master

Refactor the modules, then validate:

    cargo test --test usages_cpp_graph_test
    cargo test --test cpp_analyzer_test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

Acceptance means the refactor is internal and behavior-compatible. `cargo test --test usages_cpp_graph_test` must pass with the existing tests. `cargo test --test cpp_analyzer_test` must pass. `cargo fmt --check` must report no formatting drift, and `cargo clippy --all-targets --all-features -- -D warnings` must pass without warnings.

No public API changes are expected. Existing imports of `brokk_bifrost::usages::CppUsageGraphStrategy` must continue to compile.

## Idempotence and Recovery

The split is source-only and can be retried by comparing against `git diff`. If a move introduces compile errors, keep the facade minimal and fix module visibility/imports before changing behavior. Do not run `git add`, `git commit`, or `git push` unless the user explicitly asks.

## Artifacts and Notes

The requested branch update completed with:

    Current branch dave/136-split-cpp-usage-graph-strategy is up to date.

Focused usage graph validation completed with:

    test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Adjacent analyzer validation completed with:

    test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Formatting and lint validation completed with:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

## Interfaces and Dependencies

At the end of the work, `src/analyzer/usages/cpp_graph.rs` must still define:

    pub struct CppUsageGraphStrategy

    impl CppUsageGraphStrategy {
        pub fn new() -> Self
        pub fn can_handle(target: &CodeUnit) -> bool
        pub(crate) fn find_graph_usages(...) -> GraphUsageOutcome
    }

    impl UsageAnalyzer for CppUsageGraphStrategy

The new internal modules must not introduce crate-public APIs. Cross-module helpers should use `pub(super)`.
