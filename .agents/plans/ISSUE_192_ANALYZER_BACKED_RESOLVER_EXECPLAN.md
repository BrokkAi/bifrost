# Finish Shared Resolver Cache Ownership for Analyzer-Backed Usage Languages

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`. A future contributor should be able to start from this file alone, inspect the named source files, run the listed commands, and continue the work without needing earlier issue threads.

## Purpose / Big Picture

Bifrost exposes two usage-analysis tools. `scan_usages` answers a narrow question such as "where is this one method used?", while `usage_graph` builds whole-workspace caller-to-callee edges. Before this work, analyzer-backed languages such as Java and C# owned their forward scan setup and inverted edge setup separately, which made cache ownership harder to reason about and made it easier for the two paths to drift.

Issue #192 finishes the shared resolver/cache ownership migration only for analyzer-backed languages: Java, C#, C++, PHP, and Scala. The project-graph languages Rust, Go, Python, JavaScript, and TypeScript are out of scope here because PR #189 already replaced that direction and owns the public `usage_graph` identity model, including language-aware node and edge metadata.

The observable outcome is that existing `scan_usages` and `usage_graph` responses remain schema-compatible with #189, while analyzer-backed language internals use mode-specific resolver entrypoints that centralize parsing and analyzer access. This can be verified with the language-specific usage graph and forward usage tests listed below.

## Progress

- [x] (2026-06-17T07:52Z) Synced the worktree onto `origin/master`, which includes merged PR #189 at `27268d56d724fbc0cb07a447edfc8605aa119308` and later master commits.
- [x] (2026-06-17T07:52Z) Created branch `192-finish-shared-resolvercache-ownership-for-analyzer-backed-usage-languages` from current `origin/master`.
- [x] (2026-06-17T07:52Z) Replayed Java analyzer-backed resolver work from commit `6ece78b`, excluding the obsolete `.agents/plans/ISSUE_185_SHARED_USAGE_RESOLVER_EXECPLAN.md` edit.
- [x] (2026-06-17T07:52Z) Replayed C# analyzer-backed resolver work from commit `46bce28`, excluding the obsolete `.agents/plans/ISSUE_185_SHARED_USAGE_RESOLVER_EXECPLAN.md` edit.
- [x] (2026-06-17T07:52Z) Added this #192 ExecPlan scoped only to Java, C#, C++, PHP, and Scala.
- [x] (2026-06-17T07:52Z) Ran `cargo fmt`; it produced no Rust source changes after the replay.
- [x] (2026-06-17T07:52Z) Ran and passed `cargo test --test usage_graph_java_test`.
- [x] (2026-06-17T07:52Z) Ran and passed `cargo test --test usages_java_graph_test`.
- [x] (2026-06-17T07:52Z) Ran and passed `cargo test --test usage_graph_csharp_test`.
- [x] (2026-06-17T07:52Z) Ran and passed `cargo test --test usages_csharp_graph_test`.
- [x] (2026-06-17T07:52Z) Ran and passed `cargo test --test usage_graph_test --test usage_graph_java_test --test usage_graph_csharp_test`.
- [x] (2026-06-17T07:52Z) Ran and passed `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-06-17T08:05Z) Migrated C++ analyzer-backed usage internals to mode-specific resolver/cache ownership.
- [x] (2026-06-17T08:05Z) Added C++ `usage_graph` regression tests for path-filtered callers and skipping unrelated malformed out-of-scope callers.
- [x] (2026-06-17T08:05Z) Ran and passed `cargo fmt` after the C++ slice.
- [x] (2026-06-17T08:05Z) Ran and passed `cargo test --test usage_graph_cpp_test`.
- [x] (2026-06-17T08:05Z) Ran and passed `cargo test --test usages_cpp_graph_test`.
- [x] (2026-06-17T08:05Z) Ran and passed `cargo test --test usage_graph_test --test usage_graph_cpp_test`.
- [x] (2026-06-17T08:05Z) Ran and passed `cargo clippy --all-targets --all-features -- -D warnings` after the C++ slice.
- [x] (2026-06-17T08:44Z) Migrated PHP analyzer-backed usage internals to mode-specific resolver/cache ownership.
- [x] (2026-06-17T08:44Z) Added PHP `usage_graph` regression tests for path-filtered callers and skipping unrelated malformed out-of-scope callers.
- [x] (2026-06-17T08:44Z) Ran and passed `cargo fmt` after the PHP slice.
- [x] (2026-06-17T08:44Z) Ran and passed `cargo test --test usage_graph_php_test`.
- [x] (2026-06-17T08:44Z) Ran and passed `cargo test --test usages_php_graph_test`.
- [x] (2026-06-17T08:44Z) Ran and passed `cargo test --test usage_graph_test --test usage_graph_php_test`.
- [x] (2026-06-17T08:44Z) Ran and passed `cargo clippy --all-targets --all-features -- -D warnings` after the PHP slice.
- [x] (2026-06-17T09:32Z) Migrated Scala analyzer-backed usage internals to mode-specific resolver/cache ownership.
- [x] (2026-06-17T09:32Z) Added Scala `usage_graph` regression tests for path-filtered callers and skipping unrelated malformed out-of-scope callers.
- [x] (2026-06-17T09:32Z) Ran and passed `cargo fmt` after the Scala slice.
- [x] (2026-06-17T09:32Z) Ran and passed `cargo test --test usage_graph_scala_test`.
- [x] (2026-06-17T09:32Z) Ran and passed `cargo test --test usages_scala_graph_test`.
- [x] (2026-06-17T09:32Z) Ran and passed `cargo test --test usage_graph_test --test usage_graph_scala_test`.
- [x] (2026-06-17T09:32Z) Ran and passed `cargo clippy --all-targets --all-features -- -D warnings` after the Scala slice.

## Surprises & Discoveries

- Observation: The Java and C# cherry-picks conflicted only on `.agents/plans/ISSUE_185_SHARED_USAGE_RESOLVER_EXECPLAN.md`.
  Evidence: `git cherry-pick -n 6ece78b` and `git cherry-pick -n 46bce28` each reported `CONFLICT (modify/delete)` for that plan file and no source-code conflicts. The file was removed from each cherry-pick as requested.

- Observation: The #192 branch starts from a newer master than the exact #189 merge commit.
  Evidence: `git log --oneline --decorate -5` showed `5ec9cd7` at `origin/master`, with `27268d5 refactor(usages): drop ProjectUsageGraph, add per-language reference identity (#189)` in its history.

- Observation: C++ edge scans already filtered caller files before parsing ASTs; the migration preserved that behavior by moving setup into `CppEdgeResolver`.
  Evidence: `cargo test --test usage_graph_cpp_test` passed new `path_filter_only_emits_matching_cpp_callers` and `scoped_usage_graph_skips_unrelated_invalid_cpp_callers` tests.

- Observation: PHP edge scans already filtered caller files before parsing ASTs; the migration preserved that behavior by moving setup into `PhpEdgeResolver`.
  Evidence: `cargo test --test usage_graph_php_test` passed new `path_filter_only_emits_matching_php_callers` and `scoped_usage_graph_skips_unrelated_invalid_php_callers` tests.

- Observation: Scala edge scans already filtered caller files before parsing ASTs; the migration preserved that behavior by moving setup into `ScalaEdgeResolver`.
  Evidence: `cargo test --test usage_graph_scala_test` includes new `path_filter_only_emits_matching_scala_callers` and `scoped_usage_graph_skips_unrelated_invalid_scala_callers` tests.

## Decision Log

- Decision: Scope #192 only to analyzer-backed languages: Java, C#, C++, PHP, and Scala.
  Rationale: PR #189 superseded the earlier #185 project-graph direction and owns Rust, Go, Python, JS, TS, and public `usage_graph` identity changes.
  Date/Author: 2026-06-17 / Codex

- Decision: Preserve #189's public `usage_graph` contract and keep resolver/cache changes internal.
  Rationale: The purpose of #192 is to reduce duplicated analyzer-backed implementation paths, not to change tool schemas or language-aware node identity.
  Date/Author: 2026-06-17 / Codex

- Decision: Do not introduce a generic resolved-reference event model in #192.
  Rationale: Earlier review feedback found unused generic event scaffolding misleading unless a language has a real dual-consumer stream using it. Mode-specific resolver types are simpler and match the currently migrated Java and C# shape.
  Date/Author: 2026-06-17 / Codex

- Decision: Keep query and edge resolver entrypoints separate.
  Rationale: `scan_usages` needs forward-query fallback behavior and per-target candidate filtering, while `usage_graph` needs whole-graph edge aggregation with path and test filtering. Separate types prevent accidentally using an edge-only resolver for a forward query.
  Date/Author: 2026-06-17 / Codex

## Outcomes & Retrospective

Java and C# were brought forward onto the post-#189 codebase as internal resolver/cache ownership refactors, and their focused graph/forward usage suites plus clippy pass. The public tool schema remains owned by #189.

The C++ slice now also uses internal mode-specific resolver/cache ownership. `CppQueryResolver` owns forward query setup, and `CppEdgeResolver` owns edge-side file discovery, filtered parsing, include-closure visibility construction, and delegation to the inverted C++ edge walker.

The PHP slice now also uses internal mode-specific resolver/cache ownership. `PhpQueryResolver` owns forward query setup, including optional `PhpHierarchyIndex` construction for method and field targets. `PhpEdgeResolver` owns edge-side file discovery and filtered parsing before delegating to the inverted PHP edge walker.

The Scala slice completes the #192 analyzer-backed migration. `ScalaQueryResolver` owns forward query setup, and `ScalaEdgeResolver` owns edge-side file discovery, filtered parsing, and project-wide type indexing before delegating to the inverted Scala edge walker. All analyzer-backed languages now use mode-specific resolver/cache ownership while preserving the #189 public `usage_graph` output contract.

## Context and Orientation

The repository root is `/Users/dave/.codex/worktrees/a04c/bifrost`. Usage analysis code lives under `src/analyzer/usages/`. Each language-specific module has a forward `scan_usages` strategy and, for graph-capable languages, an inverted edge builder consumed by `usage_graph`.

An "analyzer-backed language" in this plan means a language whose usage logic depends on a language analyzer implementation exposed through `IAnalyzer`, rather than the now-removed shared `ProjectUsageGraph` direction for project-graph languages. The analyzer-backed languages in scope are:

- Java: `src/analyzer/usages/java_graph.rs` and `src/analyzer/usages/java_graph/`.
- C#: `src/analyzer/usages/csharp_graph.rs` and `src/analyzer/usages/csharp_graph/`.
- C++: `src/analyzer/usages/cpp_graph.rs` and `src/analyzer/usages/cpp_graph/`.
- PHP: `src/analyzer/usages/php_graph.rs` and `src/analyzer/usages/php_graph/`.
- Scala: `src/analyzer/usages/scala_graph.rs` and `src/analyzer/usages/scala_graph/`.

PR #189 changed the public graph identity model. Code in #192 must preserve that language-aware output, including language/ecosystem metadata on `usage_graph` nodes, edges, and truncation data. If tests need updates, update expected metadata only when the implementation behavior remains the same.

## Plan of Work

First, validate the Java and C# replay. Run `cargo fmt`, the Java and C# usage tests, and clippy. If assertions fail only because #189 added or renamed language-aware metadata, update tests to match #189 while preserving resolver behavior. If behavior regresses, fix the resolver internals rather than changing expected edges.

Next, migrate C++. Inspect `src/analyzer/usages/cpp_graph.rs`, its `extractor`, `resolver`, and `inverted` modules, and mirror the Java/C# pattern only where it fits. Add a crate-internal shared module such as `src/analyzer/usages/cpp_graph/shared.rs` with a query resolver for `scan_usages` and an edge resolver for `usage_graph`. Keep fallback-safe behavior and callsite caps unchanged. Add focused tests for path filtering, test exclusion if C++ test detection applies, and skipping unrelated invalid out-of-scope caller files if the edge path can filter before parsing.

Then migrate PHP. Use a PHP-specific shared module and keep PHP's existing analyzer resolution, namespace handling, and fallback behavior intact. Add parity tests that prove `scan_usages` still resolves the existing supported cases and that `usage_graph` respects path and test filters without parsing out-of-scope callers unnecessarily.

Finally, migrate Scala. Scala interacts with Java through `src/analyzer/usages/java_graph/jvm_scala.rs`, so preserve any existing Java/Scala cross-language behavior. Introduce shared resolver/cache ownership only where both forward and inverted Scala paths can use it without changing public results.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/a04c/bifrost

Confirm branch and base:

    git status --short --branch
    git log --oneline --decorate -5

After each language migration, run the focused test for that language before continuing. For the already replayed Java and C# slices, run:

    cargo fmt
    cargo test --test usage_graph_java_test
    cargo test --test usages_java_graph_test
    cargo test --test usage_graph_csharp_test
    cargo test --test usages_csharp_graph_test
    cargo test --test usage_graph_test --test usage_graph_java_test --test usage_graph_csharp_test
    cargo clippy --all-targets --all-features -- -D warnings

Commit after each stable slice. The commit message should explain why the resolver/cache ownership changed, not just list moved files.

## Validation and Acceptance

The Java and C# slices are accepted when all listed Java/C# tests pass and clippy reports no warnings. The tests should demonstrate that:

- `scan_usages` still returns the same `FuzzyResult`-backed hits for supported Java and C# references.
- `usage_graph` still returns language-aware nodes, edges, and truncation data compatible with #189.
- Path-filtered `usage_graph` calls emit edges only from matching caller files.
- `include_tests=false` excludes test callers where the language's test detection supports it.
- Edge scans do not need to parse unrelated invalid caller files outside a path filter.

The full #192 plan is accepted when Java, C#, C++, PHP, and Scala all use internal mode-specific resolver/cache ownership, the public tool schemas remain unchanged from #189, and the final validation command succeeds:

    cargo clippy --all-targets --all-features -- -D warnings

## Idempotence and Recovery

The sync and cherry-pick steps have already been performed on branch `192-finish-shared-resolvercache-ownership-for-analyzer-backed-usage-languages`. If a future contributor needs to recreate the branch, start from current `origin/master` and replay only analyzer-backed commits or equivalent patches; do not replay the older #185 project-graph commits for Rust, Go, Python, JS, or TS.

If a cherry-pick or migration creates `.agents/plans/ISSUE_185_SHARED_USAGE_RESOLVER_EXECPLAN.md`, remove it. #192 is the living plan for this continuation. If a test fails after a metadata assertion change from #189, inspect the actual JSON response and update only the expected language/ecosystem metadata when edge behavior is still correct.

## Artifacts and Notes

Branch setup evidence:

    ## 192-finish-shared-resolvercache-ownership-for-analyzer-backed-usage-languages...origin/master
    5ec9cd7 (HEAD -> 192-finish-shared-resolvercache-ownership-for-analyzer-backed-usage-languages, tag: py-v0.2.1, origin/master, origin/HEAD) updated project name to prefix brokk
    27268d5 refactor(usages): drop ProjectUsageGraph, add per-language reference identity (#189)

Cherry-pick conflict evidence:

    CONFLICT (modify/delete): .agents/plans/ISSUE_185_SHARED_USAGE_RESOLVER_EXECPLAN.md deleted in HEAD and modified in 6ece78b
    CONFLICT (modify/delete): .agents/plans/ISSUE_185_SHARED_USAGE_RESOLVER_EXECPLAN.md deleted in HEAD and modified in 46bce28

Validation evidence:

    cargo test --test usage_graph_java_test
    test result: ok. 9 passed; 0 failed

    cargo test --test usages_java_graph_test
    test result: ok. 32 passed; 0 failed

    cargo test --test usage_graph_csharp_test
    test result: ok. 8 passed; 0 failed

    cargo test --test usages_csharp_graph_test
    test result: ok. 25 passed; 0 failed

    cargo test --test usage_graph_test --test usage_graph_java_test --test usage_graph_csharp_test
    test result: ok. 8 passed; 0 failed
    test result: ok. 9 passed; 0 failed
    test result: ok. 7 passed; 0 failed

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile

C++ validation evidence:

    cargo test --test usage_graph_cpp_test
    test result: ok. 8 passed; 0 failed

    cargo test --test usages_cpp_graph_test
    test result: ok. 26 passed; 0 failed

    cargo test --test usage_graph_test --test usage_graph_cpp_test
    test result: ok. 8 passed; 0 failed
    test result: ok. 7 passed; 0 failed

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile

PHP validation evidence:

    cargo test --test usage_graph_php_test
    test result: ok. 8 passed; 0 failed

    cargo test --test usages_php_graph_test
    test result: ok. 26 passed; 0 failed

    cargo test --test usage_graph_test --test usage_graph_php_test
    test result: ok. 8 passed; 0 failed
    test result: ok. 7 passed; 0 failed

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile

Scala validation evidence:

    cargo test --test usage_graph_scala_test
    test result: ok. 8 passed; 0 failed

    cargo test --test usages_scala_graph_test
    test result: ok. 21 passed; 0 failed

    cargo test --test usage_graph_test --test usage_graph_scala_test
    test result: ok. 8 passed; 0 failed
    test result: ok. 7 passed; 0 failed

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile

## Interfaces and Dependencies

Java now exposes internal resolver types in `src/analyzer/usages/java_graph/shared.rs`:

    pub(crate) struct JavaQueryResolver<'a>
    pub(crate) struct JavaEdgeResolver<'a>

`JavaQueryResolver::find_usages` owns forward query setup. `JavaEdgeResolver::build_edges` owns edge-side parsed-file setup before delegating to the inverted Java edge builder.

C# now exposes internal resolver types in `src/analyzer/usages/csharp_graph/shared.rs`:

    pub(crate) struct CSharpQueryResolver<'a>
    pub(crate) struct CSharpEdgeResolver<'a>

`CSharpQueryResolver::find_usages` owns forward query setup. `CSharpEdgeResolver::build_edges` owns edge-side parsed-file setup before delegating to the inverted C# edge builder.

C++ now exposes internal resolver types in `src/analyzer/usages/cpp_graph/shared.rs`:

    pub(crate) struct CppQueryResolver<'a>
    pub(crate) struct CppEdgeResolver

`CppQueryResolver::find_usages` owns forward query setup. `CppEdgeResolver::build_edges` owns edge-side parsed-file and visibility-index setup before delegating to the inverted C++ edge builder.

PHP now exposes internal resolver types in `src/analyzer/usages/php_graph/shared.rs`:

    pub(crate) struct PhpQueryResolver<'a>
    pub(crate) struct PhpEdgeResolver<'a>

`PhpQueryResolver::find_usages` owns forward query setup. `PhpEdgeResolver::build_edges` owns edge-side parsed-file setup before delegating to the inverted PHP edge builder.

Scala now exposes internal resolver types in `src/analyzer/usages/scala_graph/shared.rs`:

    pub(crate) struct ScalaQueryResolver<'a>
    pub(crate) struct ScalaEdgeResolver<'a>

`ScalaQueryResolver::find_usages` owns forward query setup. `ScalaEdgeResolver::build_edges` owns edge-side parsed-file and project-type setup before delegating to the inverted Scala edge builder.

## Revision Notes

2026-06-17: Created this plan after #189 merged and after replaying only the Java and C# analyzer-backed resolver work onto current `origin/master`. The older #185 plan edits were intentionally dropped because #189 superseded the project-graph language direction.

2026-06-17: Updated progress, outcomes, and artifacts after running formatting, focused Java/C# tests, combined usage graph regression tests, and clippy successfully.

2026-06-17: Completed the C++ shared resolver/cache ownership slice, added edge-scope regression tests, and recorded validation evidence.

2026-06-17: Completed the PHP shared resolver/cache ownership slice, added edge-scope regression tests, and recorded validation evidence.

2026-06-17: Completed the Scala shared resolver/cache ownership slice, added edge-scope regression tests, and completed the analyzer-backed language migration plan.
