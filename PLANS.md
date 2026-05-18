# Port Java test assertion smell reporting from Brokk

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/dave/.codex/worktrees/0df3/bifrost/.agent/PLANS.md).

## Purpose / Big Picture

After this change, Bifrost's MCP server will expose a `report_test_assertion_smells` tool that finds low-value or brittle Java test assertions using the same weighted heuristics already implemented in `../brokk`. A caller will be able to point the tool at Java test files and get a scored markdown report showing suspicious tests, why they were flagged, and a short excerpt. The first milestone is Java only even though the design should leave room for other languages later.

## Progress

- [x] (2026-05-18 10:50Z) Read the Brokk implementation in `brokk-core` and `brokk-shared`, then mapped the Bifrost integration points in `src/code_quality.rs`, `src/searchtools_service.rs`, `src/mcp_server.rs`, `src/analyzer/i_analyzer.rs`, and `src/analyzer/java_analyzer.rs`.
- [x] (2026-05-18 11:20Z) Added shared `TestAssertionWeights` and `TestAssertionSmell` analyzer model types plus the `IAnalyzer::find_test_assertion_smells` extension point.
- [x] (2026-05-18 11:20Z) Ported the Java-specific heuristic into `src/analyzer/java_analyzer.rs`, covering JUnit, AssertJ, Mockito verification, missing assertions, tautologies, constant-truth/equality checks, oversized literals, and anonymous test doubles.
- [x] (2026-05-18 11:20Z) Added `report_test_assertion_smells` to `src/code_quality.rs`, `src/searchtools_service.rs`, and `src/mcp_server.rs` with Brokk-aligned defaults and markdown formatting.
- [x] (2026-05-18 11:20Z) Added Java fixture coverage plus end-to-end Rust tests in `tests/java_test_assertion_smells.rs` and `tests/bifrost_mcp_server.rs`, then ran `cargo fmt`, `cargo test --test java_test_assertion_smells`, and `cargo test --test bifrost_mcp_server`.

## Surprises & Discoveries

- Observation: Bifrost already mirrors several Brokk code-quality tools and report formats, so this feature fits the existing abstraction cleanly instead of needing a new subsystem.
  Evidence: `src/code_quality.rs` already implements cognitive complexity, comment density, exception handling smells, and long-method/god-object reports.

- Observation: Brokk factors only a small shared helper for test-smell sorting and meaningful-assertion credit; most of the Java logic is local to `JavaAnalyzer`.
  Evidence: `brokk-shared/src/main/java/ai/brokk/analyzer/TreeSitterAnalyzer.java` contains `TestSmellCandidate`, `addTestSmellCandidate`, and `testMeaningfulAssertionCredit`, while `JavaAnalyzer.java` owns the assertion classification.

- Observation: The default Java anonymous-test-double score is 3, so it does not appear in the default `min_score=4` report unless the caller lowers the threshold or the anonymous shape is repeated.
  Evidence: The first MCP test run showed the anonymous-double row only after calling `report_test_assertion_smells` with `min_score: 3`.

## Decision Log

- Decision: Start with the exact Java heuristic and keep the trait/report surface generic.
  Rationale: The user explicitly wants Java first, but the existing code-quality architecture in Bifrost is shared across analyzers. Keeping the data model generic avoids repainting the API when Python, Rust, or C# are added later.
  Date/Author: 2026-05-18 / Codex

- Decision: Write a local ExecPlan for this port.
  Rationale: The work spans analyzer behavior, public MCP schema, and tests. A living plan will keep the port sequence, validation commands, and design choices explicit while implementation is in progress.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

Completed for the Java-first scope. Bifrost now exposes a Java-capable `report_test_assertion_smells` MCP tool with Brokk-aligned defaults, deterministic markdown output, and targeted regression tests that prove both the direct report function and stdio MCP path work. Remaining future work is language expansion beyond Java.

## Context and Orientation

Bifrost is a Rust implementation of analyzer-backed search and code-quality tools. The MCP entrypoint is `src/mcp_server.rs`, which advertises tool schemas and forwards tool calls into `src/searchtools_service.rs`. The service owns a `WorkspaceAnalyzer` and dispatches each tool into helper modules such as `src/searchtools.rs`, `src/file_tools.rs`, or `src/code_quality.rs`.

Language analyzers implement the `IAnalyzer` trait in `src/analyzer/i_analyzer.rs`. Shared report logic should depend on trait methods and shared record types defined there, not on a concrete language implementation. Java analysis lives in `src/analyzer/java_analyzer.rs`, which wraps the generic tree-sitter support in `src/analyzer/tree_sitter_analyzer.rs`.

The feature to port already exists in the sibling Brokk repository. The report entrypoint is `brokk-core/src/main/java/ai/brokk/tools/CodeQualityToolsMcp.java`, and the Java smell detection is in `brokk-shared/src/main/java/ai/brokk/analyzer/JavaAnalyzer.java`. The important Java terms in this feature are simple:

- A "test assertion smell" is a test assertion pattern that is suspicious because it is tautological, too shallow, excessively literal, or otherwise low-value.
- "Shallow" means a weak assertion such as nullness or type-only checks.
- An "anonymous test double" is an inline anonymous class used as a mock or stub inside a test, which is often a sign the test setup should be extracted or reused.

## Plan of Work

First, extend `src/analyzer/i_analyzer.rs` with Rust equivalents of Brokk's `TestAssertionWeights` and `TestAssertionSmell`, plus a default trait method `find_test_assertion_smells(&self, file, weights)` that returns an empty vector for analyzers that do not support the heuristic yet.

Next, port the Java implementation into `src/analyzer/java_analyzer.rs`. Reuse the existing tree-sitter traversal helpers in that file where possible. Keep the port narrowly focused on Java test methods, using annotations to detect tests and method invocations to classify JUnit, AssertJ, and Mockito patterns. Factor only the truly shared helpers into `src/analyzer/tree_sitter_analyzer.rs` if that avoids duplicating the same sorting or excerpt logic already present there.

Then add a public report function in `src/code_quality.rs` that mirrors Brokk's MCP behavior: accept a file list and optional weight overrides, filter to test-containing files, collect findings from the analyzer, sort them deterministically, and render the same markdown table plus truncation note.

Finally, expose the new tool through `src/searchtools_service.rs` and `src/mcp_server.rs`, then add regression coverage. The minimum useful coverage is one direct Java analyzer test for the heuristic and one MCP stdio test proving the tool is listed and returns the expected report against a small Java fixture.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/0df3/bifrost`.

During implementation, use:

    cargo test --test <targeted-test-name>

After the feature is wired, run:

    cargo fmt
    cargo test --test bifrost_mcp_server
    cargo test --test java_test_assertion_smells

If the new analyzer test is folded into an existing file instead of a new test target, update the second command to the real target name and keep this plan synchronized.

## Validation and Acceptance

Acceptance is behavioral:

1. `tools/list` must advertise `report_test_assertion_smells`.
2. Calling `report_test_assertion_smells` against a Java fixture containing intentionally weak tests must return a markdown report headed `## Test assertion smells`.
3. The report must include scored rows with kind, assertion count, symbol, file, reasons, and excerpt, and it must suppress files that either do not exist or are not detected as tests.
4. The Java analyzer test must prove at least one tautological or shallow assertion finding and one anonymous-test-double or no-assertion style finding so the port exercises more than one heuristic path.

## Idempotence and Recovery

All edits are additive and safe to re-run. If a partial port fails to compile, continue by fixing the type surface first in `src/analyzer/i_analyzer.rs` and then the Java analyzer, since the report layer depends on those types. If a test fixture proves awkward, create a new dedicated fixture file under `tests/fixtures/testcode-java` rather than mutating broad shared fixtures in a way that would destabilize unrelated parity tests.

## Artifacts and Notes

Important source references for the port:

    ../brokk/brokk-core/src/main/java/ai/brokk/tools/CodeQualityToolsMcp.java
    ../brokk/brokk-shared/src/main/java/ai/brokk/analyzer/IAnalyzer.java
    ../brokk/brokk-shared/src/main/java/ai/brokk/analyzer/TreeSitterAnalyzer.java
    ../brokk/brokk-shared/src/main/java/ai/brokk/analyzer/JavaAnalyzer.java

## Interfaces and Dependencies

At the end of this work, these Rust interfaces should exist:

    pub struct TestAssertionWeights { ... }
    impl TestAssertionWeights { pub fn defaults() -> Self { ... } }

    pub struct TestAssertionSmell { ... }

    trait IAnalyzer {
        fn find_test_assertion_smells(
            &self,
            file: &ProjectFile,
            weights: TestAssertionWeights,
        ) -> Vec<TestAssertionSmell>;
    }

And these report-layer entrypoints should exist:

    pub struct ReportTestAssertionSmellsParams { ... }
    pub struct ReportTestAssertionSmellsResult { pub report: String, pub truncated: bool }
    pub fn report_test_assertion_smells(
        analyzer: &dyn IAnalyzer,
        params: ReportTestAssertionSmellsParams,
    ) -> ReportTestAssertionSmellsResult

Revision note: created this ExecPlan to guide a multi-file Java-first port of Brokk issue #81 behavior into Bifrost and to keep implementation progress observable.

Revision note: updated progress and discoveries after completing the Java-first implementation and targeted validation.
