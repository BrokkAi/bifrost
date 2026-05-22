# Add Go static usage graph strategy

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Bifrost currently analyzes Go declarations and imports, but usage lookup for Go falls back to broad regular-expression matching. After this change, Go symbols can be looked up through a tree-sitter-backed graph strategy that understands package imports, same-package references, qualified selectors such as `model.Album`, and simple receiver/member references such as `album.ImageFiles`.

The behavior is observable through `cargo test --test usages_go_graph_test`: those tests build small inline Go projects, ask `UsageFinder` or `GoUsageGraphStrategy` for symbol usages, and verify that the graph finds only syntax-aware references.

## Progress

- [x] (2026-05-22T08:25Z) Confirmed the branch `111-add-go-static-usage-graph-strategy` is up to date with its upstream.
- [x] (2026-05-22T08:25Z) Inspected existing Rust, Python, and Java usage graph strategies plus `GoAnalyzer` import/declaration support.
- [x] (2026-05-22T08:35Z) Added and wired `src/usages/go_graph.rs`.
- [x] (2026-05-22T08:35Z) Added focused inline Go usage graph tests.
- [x] (2026-05-22T08:35Z) Ran targeted tests, formatting, and clippy; all requested checks passed.
- [x] (2026-05-22T09:01Z) Hardened Go usage graph coverage from 7 to 14 tests across dot imports, blank imports, versioned module paths, candidate boundaries, richer type positions, receiver seed forms, local shadowing, and conservative negative cases.

## Surprises & Discoveries

- Observation: Bifrost's `GoAnalyzer` already parses package clauses, imports, package-level funcs/types/vars/consts, receiver methods, struct fields, and interface methods.
  Evidence: `src/analyzer/go_analyzer.rs` exposes these as `CodeUnit`s and implements `ImportAnalysisProvider`.

- Observation: Brokk's main checkout has Go analyzer behavior and at least one Go field usage test, but no direct Go static usage graph strategy to port wholesale.
  Evidence: searches in `/Users/dave/Workspace/BrokkAi/brokk` found Rust/Python/JS-TS graph strategies and Go analyzer tests, not a Go graph strategy.

- Observation: Default Go import identifiers can differ from the import path tail when module paths carry semantic-import suffixes.
  Evidence: `import "gopkg.in/yaml.v3"` is used as `yaml.Marshal`, while the raw path tail is `yaml.v3`.

- Observation: The initial receiver inference handled pointer constructors but missed plain composite literals and alias chains in one constructor-heavy scenario.
  Evidence: the hardening test for `album := model.Album{}`, `copy := album`, and `next := copy` initially returned 3 hits instead of the expected 5.

## Decision Log

- Decision: Implement a Bifrost-native Go strategy using existing Rust-side graph primitives where they fit and direct Go AST traversal for language-specific references.
  Rationale: The existing `ProjectUsageGraph` can model import edges, while Go receiver and selector references need Go-specific node handling.
  Date/Author: 2026-05-22 / Codex

- Decision: Keep the first implementation flow-insensitive and local.
  Rationale: Issue #111 explicitly excludes a full `go/types` implementation, dynamic dispatch, embedded promotion, module replacement, and interprocedural data flow.
  Date/Author: 2026-05-22 / Codex

- Decision: Treat local shadows of import aliases and dot-imported names as blockers for graph proofs.
  Rationale: Once a local parameter, variable, or short declaration owns the same token, the graph cannot safely treat that token as a package namespace or dot-imported symbol.
  Date/Author: 2026-05-22 / Codex

## Outcomes & Retrospective

The implementation is complete for issue #111's flow-insensitive scope. Go targets now route through `GoUsageGraphStrategy` before regex fallback. The strategy proves same-package references, package-qualified imports, aliased imports, dot imports, versioned module path imports, common type-position references, locally inferred receiver method calls, struct field reads/writes, and `max_usages` limits.

The hardening wave expanded the Go usage graph suite to parity-style coverage for the current scope. It also fixed two in-scope bugs: semantic import suffixes such as `.v3` are stripped from default import-local names, and receiver inference now uses AST type references plus local shadow tracking to support plain composite literals and alias chains without over-counting local shadows.

The intentional limits remain: this does not implement full `go/types`, dynamic interface dispatch, embedded method or field promotion, build tags, vendoring/module replacement semantics, reflection, or interprocedural receiver inference.

## Context and Orientation

The usage subsystem lives under `src/usages`. `UsageFinder` in `src/usages/finder.rs` selects a language-specific graph analyzer before falling back to `RegexUsageAnalyzer`. Existing graph strategies include `src/usages/python_graph.rs`, `src/usages/rust_graph.rs`, and `src/usages/java_graph.rs`.

The Go analyzer lives in `src/analyzer/go_analyzer.rs`. It is tree-sitter based and already provides Go declarations and import facts. Go package-level variables and constants are represented as field code units with short names like `_module_.Name`; struct fields are represented as field code units with short names like `Album.ImageFiles`; methods are function code units with short names like `Album.Title`.

A usage hit is represented by `UsageHit` from `src/usages/model.rs`. A graph strategy returns `FuzzyResult::Success` with a set of hits, `FuzzyResult::Failure` when it cannot infer a graph seed and should allow regex fallback, or `FuzzyResult::TooManyCallsites` when hit count exceeds the caller's limit.

## Plan of Work

Create `src/usages/go_graph.rs` with a `GoUsageGraphStrategy` implementing `UsageAnalyzer`. The strategy should downcast either a direct `GoAnalyzer` or the Go delegate inside `MultiAnalyzer`. It should build a per-query `GoProjectGraph` from analyzed Go files, parse those files with tree-sitter-go, build package import bindings from `GoAnalyzer::import_info_of`, and build export indexes from `GoAnalyzer::declarations`.

Wire the strategy into `src/usages/mod.rs` and `src/usages/finder.rs` so `Language::Go` uses the graph before regex fallback.

Add `tests/usages_go_graph_test.rs` using `InlineTestProject::with_language(Language::Go)`. The tests should prove routing, same-package references, imported package selectors, aliases, negative same-name packages, type references, receiver methods, struct fields, and `max_usages`.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/d23e/bifrost`.

Run:

    git fetch
    git rebase

Then edit the files listed in the plan, run:

    cargo test --test usages_go_graph_test
    cargo test --test go_import_test --test go_analyzer_test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

The new tests should pass and should fail before the graph strategy exists because Go would either fall back to regex or miss selector/member-specific cases. Acceptance is met when `UsageFinder` returns graph-proven Go usage hits for package selectors and receiver fields/methods, avoids unrelated same-name packages, and returns `TooManyCallsites` when requested.

## Idempotence and Recovery

The changes are additive except for module wiring. Tests can be rerun safely. If the graph strategy returns `FuzzyResult::Failure`, `UsageFinder` still falls back to regex, preserving prior behavior for unsupported Go forms.

## Artifacts and Notes

Verification completed from `/Users/dave/.codex/worktrees/d23e/bifrost`:

    cargo test --test usages_go_graph_test
    test result: ok. 14 passed; 0 failed; 0 ignored

    cargo test --test go_import_test --test go_analyzer_test
    tests/go_analyzer_test.rs: 13 passed
    tests/go_import_test.rs: 4 passed

    cargo fmt --check
    exit code 0

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile ... exit code 0

## Interfaces and Dependencies

`src/usages/go_graph.rs` must define:

    pub struct GoUsageGraphStrategy;
    impl GoUsageGraphStrategy {
        pub fn new() -> Self;
        pub fn can_handle(target: &CodeUnit) -> bool;
    }
    impl UsageAnalyzer for GoUsageGraphStrategy;

`src/usages/mod.rs` must declare `mod go_graph;` and publicly export `GoUsageGraphStrategy`.

`src/usages/finder.rs` must insert `Language::Go` into `graph_analyzers`.

Revision note, 2026-05-22: Created the initial plan from issue #111 and local code inspection so the implementation can be resumed from this file alone.

Revision note, 2026-05-22: Updated the plan after implementation and verification so it records the completed behavior, known limits, and exact checks run.

Revision note, 2026-05-22: Updated after the Go coverage hardening wave to record expanded tests, the versioned-import and receiver-alias fixes, and the new verification result.
