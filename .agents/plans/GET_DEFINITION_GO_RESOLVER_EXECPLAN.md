# Graph-backed Go get_definition resolution

This ExecPlan is a living document. It is maintained according to `.agent/PLANS.md`.

## Purpose / Big Picture

The public `get_definition` tool should resolve Go references with the same import and local-shadowing semantics as the Go usage graph. Before this work, `get_definition` used a small ad hoc import map that handled qualified imports but discarded dot imports such as `import . "example.com/app/sub"`. A user clicking `Helper()` from a dot-imported package would get `no_definition` even though the workspace indexed `example.com/app/sub.Helper`. This plan fixes that by sharing the Go usage graph's workspace package namespace and local-shadowing behavior with `get_definition`.

## Progress

- [x] (2026-06-18) Verified the bug: `go_imports` in `src/analyzer/usages/get_definition.rs` filters out the `.` alias, while `src/analyzer/usages/go_graph/resolver.rs` and `src/analyzer/usages/go_graph/inverted.rs` already model dot-imported packages and local shadowing.
- [x] (2026-06-18) Decided to implement the larger fix requested by the user instead of a narrow dot-import fallback.
- [x] (2026-06-18) Added a shared Go reference resolver under `src/analyzer/usages/go_graph/reference.rs`.
- [x] (2026-06-18) Wired `get_definition` to a cached workspace `GoProjectGraph` in `DefinitionBatchContext`.
- [x] (2026-06-18) Added `get_definition` regression tests for dot-import success and local shadowing.
- [x] (2026-06-18) Ran `cargo test --test get_definition_test`; 73 tests passed after fixing active-scope shadow tracking.
- [x] (2026-06-18) Ran `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings`; clippy passed after collapsing one guarded match arm.

## Surprises & Discoveries

- Observation: `get_definition` already batches requests through `DefinitionBatchContext`, which is the right place to cache a workspace Go graph once per tool call.
  Evidence: `resolve_definition_batch` creates one `DefinitionBatchContext` and maps every request through it.

- Observation: The first local-shadow traversal exited the containing function scope before checking whether the lookup name was shadowed.
  Evidence: `go_local_binding_shadows_dot_imported_definition` initially resolved to `example.com/app/sub.Helper`; recording `locals.is_shadowed(...)` at the lookup node fixed the test.

## Decision Log

- Decision: Use `GoProjectGraph::namespace_packages` rather than rebuilding import alias and dot-import resolution inside `get_definition`.
  Rationale: The graph resolver already handles module paths, package clause names, explicit aliases, and dot imports. Reusing it prevents semantic drift.
  Date/Author: 2026-06-18 / Codex

- Decision: Keep the older raw import-path fallback only for boundary diagnostics when a qualified import cannot be resolved to a workspace package.
  Rationale: Users should still see `unresolvable_import_boundary` for external imports, but workspace imports should be resolved through the graph-backed namespace.
  Date/Author: 2026-06-18 / Codex

## Outcomes & Retrospective

The graph-backed Go resolver now resolves dot-imported unqualified definitions and blocks those resolutions when a local parameter or variable shadows the imported name. The focused `get_definition` test suite passes with the new behavior, and `cargo clippy --all-targets --all-features -- -D warnings` is clean.

## Context and Orientation

The public tool is implemented in `src/searchtools.rs` and delegates language-specific lookup to `src/analyzer/usages/get_definition.rs`. The current Go path is `resolve_go`, which computes the current package, checks a hand-built import map for qualified references like `sub.Helper`, and falls back to same-package and same-file declarations for bare references like `Helper`.

The Go usage graph lives under `src/analyzer/usages/go_graph`. `resolver.rs` builds `GoProjectGraph`, a workspace structure containing parsed Go files, module resolution, export indexes, and import binders. `GoProjectGraph::namespace_packages` returns two pieces of import namespace information for a file: explicit alias/package bindings for qualified references, and dot-imported package names for unqualified references. `inverted.rs` shows the desired semantics: a bare name resolves to the same package and to dot-imported packages unless a local variable or parameter shadows the name.

## Plan of Work

Add a new module, `src/analyzer/usages/go_graph/reference.rs`, that exposes a crate-internal `resolve_go_reference` helper. It accepts a `GoProjectGraph`, `GoAnalyzer`, source file, source text, and `ResolvedReferenceSite`. It returns candidate fully qualified names, whether the reference was blocked by local shadowing, and which workspace import packages were resolved. For qualified references, it uses `namespace_packages` and suppresses import resolution when the qualifier is locally shadowed. For bare references, it returns the same-package candidate and dot-import candidates unless the bare name is locally shadowed.

Update `src/analyzer/usages/go_graph.rs` to include and re-export this helper within `crate::analyzer::usages`. Also re-export `GoProjectGraph`, `build_workspace_go_graph`, and `preparse_go_files` for `get_definition`.

Update `DefinitionBatchContext` in `src/analyzer/usages/get_definition.rs` with a lazy `go_graph` cache. Build it from `analyzer.project().analyzable_files(Language::Go)`, `preparse_go_files`, and `build_workspace_go_graph`. Then update `resolve_go` to receive the full `ResolvedReferenceSite` and optional graph. Try graph-backed candidates first. If graph-backed lookup reports a local shadow, return `no_definition` instead of falling through to package/import guesses. Keep the old raw import-path fallback for external boundary diagnostics when a qualified import alias is not resolved to a workspace package.

Add tests in `tests/get_definition_test.rs`: one for dot-import success and one where a local `Helper` shadows a dot-imported `Helper`, expecting `no_definition`.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, edit the files named above. Run:

    cargo test --test get_definition_test
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings

The focused test should pass with the new Go tests included. Formatting should produce no remaining diff except formatting of the intended files. Clippy should finish without warnings.

## Validation and Acceptance

Acceptance is behavior-based. `get_definition` for `Helper()` in a file containing `import . "example.com/app/sub"` resolves to `example.com/app/sub.Helper`. If the same file declares a local parameter or variable named `Helper` before the reference, `get_definition` returns `no_definition` because the local binding shadows the dot-imported symbol.

Existing qualified Go import behavior must continue to pass: `sub.Helper()` resolves to `example.com/app/sub.Helper`, and unresolved selectors do not fall back to unrelated same-package leaf names.

## Idempotence and Recovery

The change is additive except for replacing the Go branch of `get_definition`. If tests fail, inspect only the files touched by this plan and use `git diff` to verify no unrelated file such as `src/bin/semantic_index_profile.rs` was changed. Re-running tests and formatting is safe.

## Artifacts and Notes

The unrelated untracked file `src/bin/semantic_index_profile.rs` existed before this work and must not be staged or committed as part of this fix.

## Interfaces and Dependencies

`src/analyzer/usages/go_graph/reference.rs` must expose these crate-internal items:

    pub(in crate::analyzer::usages) struct GoReferenceResolution {
        pub fqn_candidates: Vec<String>,
        pub resolved_import_packages: Vec<String>,
        pub shadowed: bool,
    }

    pub(in crate::analyzer::usages) fn resolve_go_reference(
        graph: &GoProjectGraph,
        go: &GoAnalyzer,
        file: &ProjectFile,
        source: &str,
        site: &ResolvedReferenceSite,
    ) -> Option<GoReferenceResolution>

The helper should use the existing `LocalInferenceEngine<String>` only to track names that shadow package or dot-import symbols. It does not need to infer receiver types for this task.
