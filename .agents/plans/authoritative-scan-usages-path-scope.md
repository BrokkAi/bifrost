# Make scan_usages path scopes authoritative

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agents/PLANS.md`. Individual ExecPlans live under `.agents/plans/`.

## Purpose / Big Picture

`scan_usages` accepts `paths` to limit the files in which usages can be found. Today the common layer builds a filtered candidate set, but several language strategies add files back after that filter, so a path-scoped query can silently return out-of-scope callers. After this change, a `paths` scope is authoritative: internally-added importer files, target definition files, and Rust fallback scan files must be intersected with the caller's scoped file set.

The observable result is that a query such as `scan_usages({"symbols":["Greeter.hello"],"paths":["scoped/Caller.java"]})` returns only callers in `scoped/Caller.java`, even for JS/TS importers, JVM-family target source files, and Rust empty-scope fallback cases.

## Progress

- [x] (2026-07-06) Confirmed current code still passes only a plain candidate set to graph strategies.
- [x] (2026-07-06) Wrote this ExecPlan before changing the cross-language usage interfaces.
- [x] (2026-07-06) Add an internal scan-scope type that carries candidate files plus an authoritative flag.
- [x] (2026-07-06) Thread the scan scope through graph strategy dispatch and per-language query resolvers.
- [x] (2026-07-06) Update JS/TS, C#, PHP, Java, Scala, and Rust strategies to respect authoritative scope when adding files.
- [x] (2026-07-06) Add regression tests for scoped JS/TS importers, C#/PHP/Java/Scala target-source leakage, and Rust empty-scope fallback.
- [ ] Run targeted tests and format.

## Surprises & Discoveries

- Observation: Public `UsageAnalyzer::find_usages` should stay source-compatible for existing tests and callers.
  Evidence: Many integration tests call strategy `find_usages` directly with a candidate set.
- Observation: Empty `files` arrays in `scan_usages` usage entries are omitted from JSON.
  Evidence: The JS/TS path-scope regression returned a resolved zero-hit usage entry with no serialized `files` key, so the test asserts that `files` is null.

## Decision Log

- Decision: Preserve public `UsageAnalyzer::find_usages` and add authoritative scope only to internal graph-query plumbing.
  Rationale: The path authority requirement is a `scan_usages` contract, while existing strategy tests use candidate sets as non-authoritative scan hints.
  Date/Author: 2026-07-06 / Codex.

## Outcomes & Retrospective

Not yet complete.

- 2026-07-06: Implemented the authoritative scope plumbing and path-scope regression tests. Remaining work is formatting, targeted validation, commit, push, and closing #507.

## Context and Orientation

`src/searchtools.rs` builds the `paths` filter in `scan_usages` and passes an `ExplicitCandidateProvider` into `UsageFinder::query_with_provider`. `src/analyzer/usages/finder.rs` chooses the graph strategy and currently passes only `&HashSet<ProjectFile>` to each strategy. `src/analyzer/usages/traits.rs` defines the internal graph-query traits. The affected language strategies live under `src/analyzer/usages/*_graph*.rs`.

An authoritative scope means "these are the only files where a usage answer may live." If a strategy computes additional files from importers, target definition files, or fallback text scans, it must keep only files already in the authoritative set.

## Plan of Work

Introduce `UsageScanScope<'a>` in `src/analyzer/usages/traits.rs` with `candidate_files`, `is_authoritative`, and helper methods for checking whether a file is allowed. Add a `UsageFinder::with_authoritative_scope` builder and have `scan_usages` set it when `paths` is present.

Thread `&UsageScanScope` through `GraphUsageAnalyzer` and `UsageQueryResolver`. Keep the public `UsageAnalyzer::find_usages` method unchanged by creating a non-authoritative scope inside each public strategy entrypoint.

For JS/TS, only add `index.importers_of_seeds` and `target.source()` when the scan scope is not authoritative, or when those files are already included in the authoritative set. For C#, PHP, Java, and Scala, only add `target.source()` when it is in scope. For Rust, make `effective_scan_files` return the filtered candidate set directly when the scope is authoritative; if the set is empty, return an empty set rather than falling back to target source/importers/textual candidates.

Add integration tests in `tests/searchtools_service.rs` using `InlineTestProject` where practical. Keep fixtures minimal and behavior-focused.

## Concrete Steps

Run from `/home/jonathan/Projects/bifrost`:

    cargo fmt
    cargo test --test searchtools_service <new_path_scope_tests>
    cargo test --test usages_rust_graph_test <rust_scope_test_if_added>

## Validation and Acceptance

The new tests must fail before the scope change and pass after it. Existing path-scope tests for Java and Go must continue to pass. A full targeted validation should include:

    cargo test --test searchtools_service scan_usages_paths

and any language-specific tests added for Rust or JS/TS scope behavior.

## Idempotence and Recovery

The changes are ordinary source edits and tests. If a broad trait change causes compile failures, use `rg "find_graph_usages|find_usages(" src/analyzer/usages` to update every implementation consistently. Re-running tests is safe.

## Artifacts and Notes

No artifacts yet.

## Interfaces and Dependencies

Add in `src/analyzer/usages/traits.rs`:

    pub(crate) struct UsageScanScope<'a> { ... }

    impl<'a> UsageScanScope<'a> {
        pub(crate) fn new(candidate_files: &'a HashSet<ProjectFile>, authoritative: bool) -> Self;
        pub(crate) fn candidate_files(&self) -> &'a HashSet<ProjectFile>;
        pub(crate) fn is_authoritative(&self) -> bool;
        pub(crate) fn allows(&self, file: &ProjectFile) -> bool;
    }

Update internal graph-query traits to accept `&UsageScanScope<'_>` while preserving the public `UsageAnalyzer` trait.
