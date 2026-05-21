# Java usage analysis for bifrost

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/dave/.codex/worktrees/063b/bifrost/.agent/PLANS.md).

## Purpose / Big Picture

`bifrost` already has structured usage analysis for JavaScript/TypeScript, Python, and Rust, but Java still falls through to `RegexUsageAnalyzer`. After this change, Java usage resolution should take a tree-sitter-first structured path that can prove representative type, constructor, method, and field usages more precisely than regex alone, while still falling back to regex when the structured pass cannot justify a hit.

The first iteration does not attempt JDT parity. It is intentionally conservative and is meant to establish the Java-specific strategy, the right test surface, and a safe fallback boundary.

## Progress

- [x] (2026-05-21 10:50Z) Confirmed issue `#77` scope and current `bifrost` state: Java routes to regex while JS/TS, Python, and Rust already have graph-backed strategies.
- [x] (2026-05-21 11:10Z) Chose the architecture for v1: a dedicated Java structured strategy that reuses `UsageFinder`, candidate narrowing, `UsageHit`, `FuzzyResult`, and `LocalInferenceEngine`, without forcing Java into the JS/TS export-graph model.
- [ ] Implement `src/usages/java_graph.rs`, wire it into `UsageFinder`, and expose the minimum Java analyzer helpers the strategy needs.
- [ ] Add focused Java usage tests using `tests/common/inline_project.rs`.
- [ ] Run targeted tests, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`; then tighten any false-positive or fallback behavior found during validation.

## Surprises & Discoveries

- Observation: Java already has several useful primitives that the other language strategies had to build separately.
  Evidence: `src/analyzer/java_analyzer.rs` already exposes import analysis, same-package reachability, type hierarchy resolution, enclosing-code-unit lookup, and type identifier extraction.

- Observation: the biggest gap is not candidate discovery, but receiver proof.
  Evidence: Java can cheaply identify relevant files through imports and package-level references, but method and field usage precision depends on proving that a receiver expression refers to the target owning type.

## Decision Log

- Decision: implement a Java-specific structured strategy rather than a Java export graph.
  Rationale: Java imports do not map naturally onto the JS/TS export graph model already used in `src/usages/js_ts_graph.rs`, and `bifrost` has no JDT/classpath resolver. A dedicated tree-sitter scanner with conservative receiver proof fits the current architecture better.
  Date/Author: 2026-05-21 / Codex

- Decision: keep v1 conservative and let `UsageFinder` fall back to regex when proof is weak.
  Rationale: the project goal is to improve materially over regex without inventing false certainty. Structured misses are acceptable in v1; structured false positives are not.
  Date/Author: 2026-05-21 / Codex

## Outcomes & Retrospective

This rollout is in progress. The intended first outcome is a safe Java-specific strategy with focused tests that cover representative type, constructor, method, and field lookups. Follow-up milestones are expected for static imports, anonymous classes, lambdas, `super` dispatch, and more nuanced overload cases.

## Context and Orientation

The relevant code lives in two places. The shared usage-analysis orchestration is under `src/usages/`, where `src/usages/finder.rs` chooses a strategy based on language and `src/usages/traits.rs` defines the `UsageAnalyzer` interface. The Java language facts live in `src/analyzer/java_analyzer.rs`, which is a tree-sitter analyzer that already knows about packages, imports, supertypes, declarations, and enclosing code units.

Today, `src/usages/finder.rs` routes JavaScript, TypeScript, Python, and Rust through structured strategies and sends everything else to `src/usages/regex_analyzer.rs`. Java therefore behaves like a text search with language-tuned regex patterns, not a structural usage lookup.

The v1 Java design intentionally reuses existing shared pieces. Candidate file narrowing still comes from `ImportGraphCandidateProvider` in `src/usages/candidates.rs`. Result shapes still use `FuzzyResult` and `UsageHit` from `src/usages/model.rs`. Scope-local receiver inference uses `LocalInferenceEngine` in `src/usages/local_inference.rs`. What is new is only the Java-specific structured scan that proves a subset of Java reference shapes.

## Plan of Work

Add `src/usages/java_graph.rs` with a new `JavaUsageGraphStrategy` implementation of `UsageAnalyzer`. The strategy will downcast to `JavaAnalyzer`, derive a target specification from the input `CodeUnit`, scan candidate Java files with tree-sitter Java, and emit `UsageHit` entries only when it can prove the reference structurally.

Expose the smallest needed helper surface in `src/analyzer/java_analyzer.rs`, specifically a public wrapper around type-name resolution in the context of a file. The strategy should use that helper rather than re-implementing package/import resolution locally.

Wire the strategy into `src/usages/finder.rs` for `Language::Java`, and export it from `src/usages/mod.rs` so tests can invoke it directly.

Add `tests/usages_java_graph_test.rs` using `InlineTestProject` from `tests/common/inline_project.rs`. Cover routing through `UsageFinder`, imported method calls, constructor usage, field load/store, type references, nested types, self-call filtering, typed receivers from base classes, candidate restriction behavior, and fallback behavior when a shadowed name makes the receiver unprovable.

## Concrete Steps

From the repository root:

    cargo test --test usages_java_graph_test
    cargo test --test usages_local_inference_test
    cargo test --test usages_rust_graph_test
    cargo test --test usages_python_graph_test
    cargo test --test usages_js_ts_graph_test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Expected outcome for the first test command after implementation:

    running N tests
    test usage_finder_routes_java_targets_through_graph_strategy ... ok
    test java_graph_strategy_finds_method_constructor_field_and_type_usages ... ok
    ...
    test result: ok. N passed; 0 failed

## Validation and Acceptance

Acceptance is behavioral, not purely structural.

After the change, `UsageFinder` should route Java targets through the new strategy by default. Representative Java method, constructor, field, and type lookups in the new focused tests should succeed without relying on regex-only matching. Cases where the strategy cannot prove the receiver or target identity should not return a confident structured hit; instead, they should surface as failure so the existing regex fallback can take over.

The ExecPlan is part of the deliverable. It must clearly state that no JDT port or classpath-backed semantic resolver is in scope and that further parity work belongs in later milestones.

## Idempotence and Recovery

These steps are additive and safe to rerun. The strategy file, analyzer helper, and tests can be edited incrementally while keeping the public `UsageFinder` interface stable. If a targeted test exposes a false positive, prefer tightening the structured proof and allowing regex fallback rather than widening the matching rules.

## Artifacts and Notes

The main new artifact is `src/usages/java_graph.rs`, which is intentionally separate from the existing JS/TS, Python, and Rust strategies so Java-specific tradeoffs remain obvious. The focused tests in `tests/usages_java_graph_test.rs` are the executable proof that the new path is meaningfully better than regex for the chosen cases.

## Interfaces and Dependencies

`src/usages/java_graph.rs` must define:

    pub struct JavaUsageGraphStrategy

with:

    impl UsageAnalyzer for JavaUsageGraphStrategy

The strategy depends on:

- `crate::analyzer::JavaAnalyzer` for package/import/type resolution and enclosing-code-unit lookup.
- `crate::usages::LocalInferenceEngine` for scope-aware variable and type-name bindings.
- `tree_sitter_java` for parsing Java candidate files.

The public `UsageFinder` API remains unchanged.

Change note: created this ExecPlan because issue `#77` is explicitly multi-milestone and needs a durable source of truth for both the implementation slice and the deferred parity follow-up work.
