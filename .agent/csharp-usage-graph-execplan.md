# Add C# static usage graph strategy

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This plan follows `.agent/PLANS.md`.

## Purpose / Big Picture

Bifrost can parse C# declarations today, but C# usage lookup still falls back to broad text matching. After this change, C# symbols will first use a static usage graph that understands namespaces, `using` directives, type references, constructors, static members, and simple locally inferred instance receivers. Users should see fewer unrelated same-name matches while still getting regex fallback when the graph cannot prove a structured answer.

## Progress

- [x] (2026-05-22T12:53Z) Confirmed baseline C# analyzer tests pass: `cargo test --test csharp_analyzer_test --test csharp_analyzer_update_test`.
- [x] (2026-05-22T12:54Z) Synced the existing issue branch with `git fetch && git rebase` and created `dave/issue-115-csharp-usage-graph`.
- [x] (2026-05-22T13:05Z) Added focused C# usage graph tests covering routing, namespace visibility, constructors, records, members, negatives, and limits.
- [x] (2026-05-22T13:14Z) Implemented C# analyzer namespace/import helpers and `ImportAnalysisProvider` exposure.
- [x] (2026-05-22T13:20Z) Implemented and registered `CSharpUsageGraphStrategy`.
- [x] (2026-05-22T13:32Z) Ran focused, regression, format, and clippy validation successfully.
- [x] (2026-05-22T13:34Z) Updated this ExecPlan with final evidence and retrospective.

## Surprises & Discoveries

- Observation: The checked-out branch was already `115-add-c-static-usage-graph-strategy`, not detached.
  Evidence: `git status --short --branch` reported `## 115-add-c-static-usage-graph-strategy...origin/115-add-c-static-usage-graph-strategy`.
- Observation: Existing C# analyzer coverage is healthy before the usage graph work.
  Evidence: `cargo test --test csharp_analyzer_test --test csharp_analyzer_update_test` passed 8 tests total.
- Observation: C# declarations carry package names, but the file-level package slot can remain empty because the custom C# visitor initializes `ParsedFile` with an empty package.
  Evidence: same-namespace usage tests missed `Shared.Target` until `namespace_of_file` derived the namespace from declarations in the file.
- Observation: The existing C# imports query does not currently make normal `using` directives available through `TreeSitterAnalyzer::import_info_of`.
  Evidence: a diagnostic run over an inline file containing `using Beta;` showed `using_namespaces_of` was empty when it read only `import_info_of`; reading normal `using Namespace;` lines from source made candidate routing and namespace visibility pass.

## Decision Log

- Decision: Implement this as a C#-specific tree-sitter strategy rather than trying to share the C++ or Java graph directly.
  Rationale: C# namespace and `using` rules are closest to Java in shape, but receiver/member syntax and declaration nodes differ enough that a dedicated strategy is clearer and keeps the v1 limits explicit.
  Date/Author: 2026-05-22 / Codex
- Decision: Treat ambiguous structured matches as graph failure so `UsageFinder` can fall back to regex, but treat proven empty structured results as success.
  Rationale: A graph-backed result should not convict unrelated same-name symbols; fallback remains available for unsupported shapes.
  Date/Author: 2026-05-22 / Codex
- Decision: Parse normal C# `using Namespace;` directives from source in the C# helper instead of relying on `import_info_of`.
  Rationale: The query-backed import store was empty for inline C# projects, while the graph and candidate provider need namespace visibility now. The parser remains deliberately narrow and skips aliases, `using static`, and extern-style forms.
  Date/Author: 2026-05-22 / Codex
- Decision: Resolve bare C# type names only through same-namespace or normal-using visibility, not by globally matching every declaration with the same short name.
  Rationale: Global short-name matching made `Alpha.Target` and `Beta.Target` ambiguous in a file that only imported `Beta`; C# v1 should fail closed or resolve through explicit visibility.
  Date/Author: 2026-05-22 / Codex

## Outcomes & Retrospective

Implemented the C# static usage graph strategy and routed C# targets through it before regex fallback. The final behavior covers namespace-aware type references, fully-qualified references, same-namespace references, records as type declarations, constructor calls, inheritance/interface references, generic type arguments, static method/property/field references, simple local receiver inference for parameters and locals, conservative unsupported receiver failure, unrelated same-name negatives, and `TooManyCallsites`.

The main remaining limits are intentional v1 boundaries: alias using, `using static`, extern aliases, extension methods, dynamic dispatch, LINQ semantics, reflection, conditional compilation, and cross-file partial-class merging remain out of scope.

## Context and Orientation

`src/usages/finder.rs` owns routing from a target `CodeUnit` to a language-specific graph analyzer. `src/usages/mod.rs` declares and exports usage strategy modules. Existing strategies such as `src/usages/java_graph.rs`, `src/usages/cpp_graph.rs`, and `src/usages/go_graph.rs` show the local pattern: resolve a language analyzer, derive a target specification, scan candidate files with tree-sitter, and return `FuzzyResult`.

`src/analyzer/csharp_analyzer.rs` parses C# files into classes, functions, constructors, properties, and fields. It currently captures raw `using_directive` imports but does not expose `ImportAnalysisProvider`, so `MultiAnalyzer` cannot use C# imports for candidate narrowing. The C# tree-sitter query files live under `resources/treesitter/c_sharp/`.

## Plan of Work

First add `tests/usages_csharp_graph_test.rs` using `InlineTestProject::with_language(Language::CSharp)`. The tests must show routing through `UsageFinder`, namespace and `using` visibility, fully-qualified references, same-namespace references, constructors, inheritance/interface references, generic type arguments, static method/property/field references, locally inferred instance member references, conservative negative cases, and `TooManyCallsites`.

Next extend `CSharpAnalyzer` with public helper methods that the graph can use: file namespace lookup, C# file filtering, visible type resolution, and `using`-based import capability methods. Normal `using Namespace;` and same-namespace visibility are in scope. Alias using, `using static`, `global using`, extern aliases, extension methods, and cross-file partial class merging are out of scope for this v1 unless already needed by tests.

Then add `src/usages/csharp_graph.rs`. The strategy should resolve `CSharpAnalyzer` from either a direct analyzer or `MultiAnalyzer`, derive a target kind from the `CodeUnit`, scan only C# candidate files plus the target source, parse each file with `tree_sitter_c_sharp`, and collect `UsageHit` values for proven references. It should use `LocalInferenceEngine<String>` to seed simple type bindings for variables and parameters so `service.Run()` can resolve when `service` is known to be `Target`.

Finally update routing and exports, run validation, and update this ExecPlan with outcomes.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/8880/bifrost`.

1. Create and maintain this ExecPlan.
2. Add tests in `tests/usages_csharp_graph_test.rs`.
3. Add analyzer helpers and import capability in `src/analyzer/csharp_analyzer.rs`.
4. Add `src/usages/csharp_graph.rs`, update `src/usages/mod.rs`, and register `Language::CSharp` in `src/usages/finder.rs`.
5. Run:

        cargo test --test usages_csharp_graph_test
        cargo test --test csharp_analyzer_test --test csharp_analyzer_update_test
        cargo test --test usages_java_graph_test --test usages_cpp_graph_test --test usages_go_graph_test
        cargo fmt --check
        cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

Acceptance is behavior-level: a C# target passed to `UsageFinder` returns graph-proven hits for namespace-aware type and member references, does not include unrelated same-name symbols from another namespace, reports `TooManyCallsites` when graph hits exceed the supplied limit, and falls back to regex only when the graph cannot prove a structured answer.

The new `usages_csharp_graph_test` should fail before implementation because no C# graph strategy is registered. After implementation it should pass, and the existing C# analyzer tests should remain green.

## Idempotence and Recovery

The tests use temporary inline projects and can be rerun safely. If a graph scan proves too broad, prefer tightening the structured proof and returning `Failure` for ambiguous cases rather than adding text-only shortcuts. If query changes break analyzer persistence epoch expectations, rerun the focused analyzer tests and update this plan with the discovery.

## Artifacts and Notes

Baseline evidence:

    running 6 tests
    test result: ok. 6 passed; 0 failed
    running 2 tests
    test result: ok. 2 passed; 0 failed

Final validation evidence:

    cargo test --test usages_csharp_graph_test
    test result: ok. 6 passed; 0 failed

    cargo test --test csharp_analyzer_test --test csharp_analyzer_update_test
    test result: ok. 6 passed; 0 failed
    test result: ok. 2 passed; 0 failed

    cargo test --test usages_java_graph_test --test usages_cpp_graph_test --test usages_go_graph_test
    usages_cpp_graph_test: 25 passed
    usages_go_graph_test: 29 passed
    usages_java_graph_test: 24 passed

    cargo fmt --check
    passed

    cargo clippy --all-targets --all-features -- -D warnings
    passed

## Interfaces and Dependencies

At completion, `src/usages/csharp_graph.rs` defines:

    pub struct CSharpUsageGraphStrategy { ... }
    impl CSharpUsageGraphStrategy {
        pub fn new() -> Self;
        pub fn can_handle(target: &CodeUnit) -> bool;
    }
    impl UsageAnalyzer for CSharpUsageGraphStrategy { ... }

`src/usages/mod.rs` declares `mod csharp_graph;` and exports `pub use csharp_graph::CSharpUsageGraphStrategy;`.

`src/usages/finder.rs` imports `CSharpUsageGraphStrategy` and inserts `Language::CSharp` into `graph_analyzers`.

Revision note 2026-05-22: Initial ExecPlan created before code edits because issue #115 adds a significant analyzer feature with multiple milestones and explicit v1 limits.

Revision note 2026-05-22: Updated after implementation to record the source-read `using` helper, file-namespace fallback, final validation evidence, and remaining v1 limitations.
