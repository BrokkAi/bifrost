# Scala static usage graph strategy

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Scala files are already parsed by Bifrost, but usage lookup for Scala symbols still falls back to regex matching. After this change, `UsageFinder` will route Scala targets through a syntax-aware graph strategy that can prove package-local references, imports, type references, object-member references, and simple receiver/member references before falling back to regex for unsupported shapes. A user can see the behavior by running `cargo test --test usages_scala_graph_test` and observing that structured references are found while unrelated same-name symbols are ignored.

## Progress

- [x] (2026-05-22 12:41Z) Created this ExecPlan from issue 114 and confirmed the working branch rebases cleanly on `origin/master`.
- [x] (2026-05-22 12:50Z) Added structured Scala import metadata and `ImportAnalysisProvider` support; `cargo test --test scala_import_test` passes.
- [x] (2026-05-22 12:50Z) Implemented `ScalaUsageGraphStrategy`, exported it, and routed `Language::Scala` through `UsageFinder`.
- [x] (2026-05-22 12:50Z) Added focused usage graph tests for package/import/type/object/member behavior; `cargo test --test usages_scala_graph_test -- --nocapture` passes.
- [x] (2026-05-22 12:52Z) Ran the full planned validation set: targeted tests, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` all pass.

## Surprises & Discoveries

- Observation: the current issue worktree was already on `114-add-scala-static-usage-graph-strategy`, not detached.
  Evidence: `git status --short --branch` printed `## 114-add-scala-static-usage-graph-strategy...origin/114-add-scala-static-usage-graph-strategy` before creating `dave/issue-114-scala-usage-graph`.

- Observation: Scala grouped imports are easiest to consume downstream when each grouped member is expanded into one normalized `ImportInfo`.
  Evidence: `import foo.bar.{Qux, Quux as Alias}` now stores `import foo.bar.Qux` and `import foo.bar.Quux as Alias`, while preserving the original raw import statement in `import_statements_of`.

- Observation: snippet context can include nearby unrelated same-name calls even when the graph hit itself is correct.
  Evidence: the usage graph routing test and wildcard-member negative test assert hit line/offset behavior instead of using snippet exclusion as proof.

## Decision Log

- Decision: implement Scala import metadata in `ScalaAnalyzer` before the graph strategy.
  Rationale: candidate discovery and graph seeding need structured import information; raw import strings alone are not enough for grouped, aliased, and wildcard imports.
  Date/Author: 2026-05-22 / Codex

- Decision: keep the first implementation flow-insensitive and tree-sitter based.
  Rationale: issue 114 explicitly excludes compiler-grade Scala behavior such as implicits, extension methods, overload resolution, path-dependent types, and macro-generated code.
  Date/Author: 2026-05-22 / Codex

- Decision: normalize Scala object FQNs by removing the analyzer's trailing `$` marker during graph matching.
  Rationale: Scala source imports and qualifiers use `Utility`, while Bifrost declarations represent objects as `Utility$`; the graph needs these to compare equal without changing declaration identity.
  Date/Author: 2026-05-22 / Codex

## Outcomes & Retrospective

Issue 114 is implemented. Scala imports now have structured metadata, `UsageFinder` routes Scala targets through `ScalaUsageGraphStrategy`, and the graph proves package/import/type/object/member references without claiming compiler-grade Scala resolution. The focused tests cover routing, grouped and aliased imports, wildcard object-member imports, inheritance/type references, local receiver inference, unrelated same-name negatives, and `max_usages`.

The remaining limitations are intentional and match the issue scope: no implicit conversions or givens, no extension-method resolution, no overload resolution, no path-dependent type support, no macro-generated code, and no interprocedural data-flow.

## Context and Orientation

The usage subsystem lives under `src/usages`. `UsageFinder` in `src/usages/finder.rs` chooses a graph strategy based on the target `CodeUnit` language and falls back to `RegexUsageAnalyzer` when no graph strategy exists or a graph strategy returns `FuzzyResult::Failure`. Existing graph strategies such as `src/usages/java_graph.rs` and `src/usages/go_graph.rs` show the local pattern for parsing candidate files with tree-sitter, proving references, producing `UsageHit` values, and enforcing `max_usages`.

The Scala analyzer lives in `src/analyzer/scala_analyzer.rs`. It already parses packages, classes, traits, objects, enums, functions, vals, vars, enum cases, raw import statements, and simple call receivers. It does not yet store structured `ImportInfo` entries or implement `ImportAnalysisProvider`.

`tests/common/inline_project.rs` provides `InlineTestProject`, the preferred helper for small in-test Scala projects.

## Plan of Work

First, extend `ScalaAnalyzer` so each raw `import_declaration` also produces one or more `ImportInfo` records. The parser must cover `import foo.Bar`, `import foo.{Bar, Baz}`, `import foo.{Bar as Alias}`, and `import foo.*`. The analyzer will implement `ImportAnalysisProvider` using those records, package names, and declarations to identify imported code units, reverse references, and whether a candidate file can be imported from a source file.

Second, add `src/usages/scala_graph.rs`. The new `ScalaUsageGraphStrategy` will resolve a target into a target specification: type, constructor, method, or field. It will parse Scala candidate files with tree-sitter, seed visible type and object aliases from same-package declarations plus imports, scan identifiers and selection expressions, and emit `UsageHit` only when the reference is proven to target the requested `CodeUnit`.

Third, export the strategy from `src/usages/mod.rs` and register `Language::Scala` in `UsageFinder::new()`.

Fourth, add `tests/usages_scala_graph_test.rs` using `InlineTestProject::with_language(Language::Scala)`. Tests must cover routing, same-package references, explicit/grouped/aliased/wildcard imports, constructors, inheritance/type annotations, companion/object member references, receiver-inferred instance calls and fields, unrelated same-name negatives, and `max_usages`.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/5d5e/bifrost`.

    git fetch origin
    git rebase origin/master
    git checkout -b dave/issue-114-scala-usage-graph

Then implement the milestones above. Use `apply_patch` for manual edits.

## Validation and Acceptance

Run the milestone tests while editing:

    cargo test --test scala_import_test
    cargo test --test scala_analyzer_test
    cargo test --test usages_scala_graph_test

Before completion, run:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Acceptance is that the new Scala graph tests pass, `UsageFinder` uses the graph strategy for Scala targets, false-positive same-name references are excluded, and `TooManyCallsites` is returned when proven hits exceed the requested limit.

## Idempotence and Recovery

The test projects are created in temporary directories and are safe to rerun. If a graph scan cannot infer a seed, it should return `FuzzyResult::Failure` so `UsageFinder` can retry with regex fallback. If local edits fail formatting or clippy, fix the code and rerun the same commands.

## Artifacts and Notes

Final verification:

    cargo test --test scala_import_test
    cargo test --test scala_analyzer_test
    cargo test --test usages_scala_graph_test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

All commands completed successfully on 2026-05-22.

## Interfaces and Dependencies

Add `pub use scala_graph::ScalaUsageGraphStrategy;` to `src/usages/mod.rs`.

Add `mod scala_graph;` to `src/usages/mod.rs`.

In `src/usages/finder.rs`, import `ScalaUsageGraphStrategy` and insert `Language::Scala` into `graph_analyzers`.

In `src/analyzer/scala_analyzer.rs`, implement the existing `ImportAnalysisProvider` trait for `ScalaAnalyzer`; do not add a new public trait.
