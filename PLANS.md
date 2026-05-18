# Multi-language test assertion smell parity

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/dave/.codex/worktrees/0df3/bifrost/.agent/PLANS.md).

## Purpose / Big Picture

Bifrost now has a Java-capable `report_test_assertion_smells` tool with the correct modular report structure, workspace-boundary hardening, and stronger parity tests. The next milestone is to extend the same MCP tool across the other analyzers so Bifrost can reach practical parity with Brokk’s Java-level usefulness on additional languages without fragmenting the public tool surface.

The tool contract stays generic and stable:

- one MCP tool: `report_test_assertion_smells`
- one shared report format
- one shared analyzer result model: `TestAssertionSmell` and `TestAssertionWeights`

Language-specific work should stay inside each analyzer’s `find_test_assertion_smells` implementation and its tests.

## Progress

- [x] (2026-05-18 10:50Z) Read the Brokk implementation in `brokk-core` and `brokk-shared`, then mapped the Bifrost integration points in the analyzer, code-quality, service, and MCP layers.
- [x] (2026-05-18 11:20Z) Added shared `TestAssertionWeights` and `TestAssertionSmell` analyzer model types plus the `IAnalyzer::find_test_assertion_smells` extension point.
- [x] (2026-05-18 11:20Z) Ported the Java-specific heuristic into `src/analyzer/java_analyzer.rs`, covering JUnit, AssertJ, Mockito verification, missing assertions, tautologies, constant-truth/equality checks, oversized literals, and anonymous test doubles.
- [x] (2026-05-18 11:20Z) Added `report_test_assertion_smells` to the report, service, and MCP layers with Brokk-aligned defaults and markdown formatting.
- [x] (2026-05-18 12:35Z) Reworked the Java tests to use inline projects and expanded them toward Brokk’s Java coverage.
- [x] (2026-05-18 14:40Z) Fixed the review findings by moving the report onto the modular `src/code_quality/` layout, hardening path resolution against `..` traversal, aligning equal-score ordering with Brokk parity, and tightening the direct Java report tests.
- [x] (2026-05-18 16:10Z) Completed Wave 1 by adding initial `report_test_assertion_smells` support for JavaScript, TypeScript, and Python, along with direct inline-project regression tests for each language and a full Java/MCP regression pass.
- [x] (2026-05-18 17:05Z) Completed Wave 2 by adding initial C#, Go, and Rust support plus direct inline-project regression coverage, then reran the Java and MCP suites to keep the multi-language surface stable.
- [x] (2026-05-18 17:55Z) Completed Wave 3 by adding initial Scala and PHP support, cleaning up the resulting warnings, and rerunning the Java and MCP suites alongside the new direct tests.
- [ ] Next: decide whether C++ is worth onboarding now or whether it first needs explicit test-detection support before this feature can be made reliable there.

## Surprises & Discoveries

- Observation: the public tool/report side is no longer the bottleneck.
  Evidence: `src/code_quality/test_assertion_smells.rs`, `src/searchtools_service.rs`, and `src/mcp_server.rs` are already generic and dispatch via `IAnalyzer::find_test_assertion_smells`.

- Observation: most analyzers already have `contains_tests` support, which means Bifrost already has a language-by-language test-file detection base for this feature.
  Evidence: `src/analyzer/{go,javascript,typescript,python,rust,csharp,scala,php}_analyzer.rs` all implement `contains_tests`, while only Java currently overrides `find_test_assertion_smells`.

- Observation: parity will not mean literal Java-rule cloning across languages.
  Evidence: Java relies on JUnit, AssertJ, and Mockito call shapes; JS/TS, Python, Rust, Go, and C# have different assertion and mocking idioms even though the smell categories overlap.

- Observation: the right reuse boundary is category-level semantics, not a single shared AST helper.
  Evidence: the report and scoring model are reusable, but assertion extraction is heavily syntax- and framework-specific in `src/analyzer/java_analyzer.rs`.

- Observation: JavaScript and TypeScript can share one assertion-smell extractor with language-specific parser selection.
  Evidence: both analyzers already share substantial import/test-detection helpers, and Wave 1 was implemented with a single `detect_js_ts_test_assertion_smells(...)` path in `src/analyzer/javascript_analyzer.rs`.

- Observation: C#, Go, and Rust were cheaper than Wave 1 because their dominant assertion idioms are explicit and regex-friendly.
  Evidence: Wave 2 landed as analyzer-local method/body scanners without needing shared AST traversal helpers beyond the existing test-file detection.

- Observation: after Wave 3, every analyzer that already had built-in test detection now has at least an initial `find_test_assertion_smells` implementation.
  Evidence: Java, JavaScript, TypeScript, Python, C#, Go, Rust, Scala, and PHP all participate; only C++ remains outside the rollout because it does not currently have the same test-detection foundation.

## Decision Log

- Decision: keep one shared MCP/report surface and add language support behind analyzer overrides.
  Rationale: callers should not need a new tool per language, and the current Rust surface already supports per-language implementations cleanly.
  Date/Author: 2026-05-18 / Codex

- Decision: treat Java as the reference behavior and port smell categories, not parser details.
  Rationale: parity should mean “same classes of findings with comparable scoring semantics,” not forcing non-Java analyzers to mimic Java-specific assertion APIs.
  Date/Author: 2026-05-18 / Codex

- Decision: implement languages in rollout waves instead of trying for all analyzers in one pass.
  Rationale: the hard part is framework-specific precision, and a staged rollout keeps false positives manageable while preserving a clean report contract.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

Java is complete enough to be the template: the analyzer hook exists, the MCP tool is stable, the report layer is modular, and the test suite now catches both security and parity regressions. Remaining work is multi-language analyzer support plus language-appropriate regression suites.

## Context and Orientation

The main entrypoints are now:

- [src/code_quality/test_assertion_smells.rs](/Users/dave/.codex/worktrees/0df3/bifrost/src/code_quality/test_assertion_smells.rs): shared report assembly and filtering
- [src/analyzer/i_analyzer.rs](/Users/dave/.codex/worktrees/0df3/bifrost/src/analyzer/i_analyzer.rs): `find_test_assertion_smells` trait hook
- [src/analyzer/model.rs](/Users/dave/.codex/worktrees/0df3/bifrost/src/analyzer/model.rs): shared `TestAssertionWeights` and `TestAssertionSmell`
- [tests/java_test_assertion_smells.rs](/Users/dave/.codex/worktrees/0df3/bifrost/tests/java_test_assertion_smells.rs): the current parity-style reference suite

Non-Java analyzer candidates that already detect test files:

- JavaScript
- TypeScript
- Python
- Go
- Rust
- C#
- Scala
- PHP

C++ currently does not appear to have test detection wired, so it should be treated as a later follow-up rather than an immediate parity target.

## Plan of Work

Start by extracting a repeatable implementation recipe from the Java port:

1. detect test files
2. identify assertion-equivalent calls and no-assertion cases
3. map assertion shapes into the shared smell categories
4. apply the shared scoring model
5. render through the existing report function
6. prove behavior with inline-project tests

Then execute language waves in descending payoff order.

### Wave 1: high-leverage dynamic test ecosystems

Implement JavaScript, TypeScript, and Python next.

- JavaScript and TypeScript should share as much as possible around Jest/Vitest/Mocha/Chai-style assertion detection and mock/spy verification equivalents.
- Python should target `unittest` and `pytest` idioms first, including bare `assert`, `self.assert*`, `pytest.raises`, and common mock verification patterns.

These languages likely give the highest coverage payoff after Java because they already have test detection and are common in repos where assertion-style heuristics are valuable.

### Wave 2: statically typed test frameworks with explicit assertion APIs

Implement C#, Go, and Rust after Wave 1.

- C#: xUnit/NUnit/MSTest and common mock verification patterns.
- Go: `testing` package patterns, `require/assert` families, and shallow checks around `err`, `nil`, and boolean conditions.
- Rust: built-in `assert!` / `assert_eq!` / `matches!`, plus common test-module patterns and panic assertions.

These languages are strong candidates for good precision because their assertion forms are relatively structured, but they need bespoke AST matching.

### Wave 3: lower-volume or framework-diverse follow-ups

Implement Scala and PHP after the first two waves are stable.

- Scala: ScalaTest / specs2 / munit style assertions and matcher chains.
- PHP: PHPUnit assertions and common inline doubles.

Only after that should we decide whether C++ is worth adding now or whether it first needs a separate test-detection foundation.

## Concrete Steps

For each language rollout:

1. Read the analyzer’s existing `contains_tests` implementation and AST helpers.
2. Inspect the sibling Brokk repo for any related language heuristics or framework detection patterns.
3. Add `find_test_assertion_smells` in that analyzer, keeping syntax-specific helpers local to the analyzer file unless both JS and TS can clearly share one helper.
4. Add one dedicated direct Rust test file per language using `tests/common/inline_project.rs`.
5. Build a parity-style suite around the shared smell categories:
   - no assertions
   - self-comparison / tautology
   - constant truth / equality
   - shallow assertions
   - meaningful assertions not flagged
   - assertion-equivalent verify / throws / raises patterns
   - oversized literal where the language/framework supports it
   - anonymous or inline doubles where the language idiom exists
6. Run targeted tests for that language plus `tests/bifrost_mcp_server.rs` if the MCP surface changed.

## Validation and Acceptance

Acceptance is per language, not all-or-nothing.

For each new language:

1. `report_test_assertion_smells` must produce findings for that language without changing the tool schema.
2. Non-test files for that language must stay silent.
3. At least one assertion-equivalent pattern that is not a literal assertion call must be recognized where the language/framework has such a concept.
4. The direct report test must include both positive and negative cases and must assert row-level details where parity or scoring matters.
5. The shared Java suite must remain green to prove no regression of the reference implementation.

Program-level completion means Bifrost supports the shared smell categories across every analyzer that already has reliable test detection and for which the framework conventions can be recognized with acceptable precision.

## Idempotence and Recovery

Each language rollout should be independently shippable. If one language proves noisy or framework-fragile, leave the shared tool in place and keep that analyzer returning an empty list until its heuristics are strong enough. Do not weaken Java parity or the shared report contract to accommodate a weaker language implementation.

If shared helpers start emerging, prefer small shared utilities for scoring, sorting, or excerpt normalization. Do not force a giant cross-language “test smell engine” abstraction unless at least two concrete analyzers demonstrably need the same code.

## Interfaces and Dependencies

The shared interface should stay unchanged:

    trait IAnalyzer {
        fn find_test_assertion_smells(
            &self,
            file: &ProjectFile,
            weights: TestAssertionWeights,
        ) -> Vec<TestAssertionSmell>;
    }

The intended implementation pattern is:

    shared report layer
      -> analyzer.contains_tests(file)
      -> analyzer.find_test_assertion_smells(file, weights)
      -> shared markdown rendering

Language-specific analyzers own:

- test assertion extraction
- framework recognition
- smell classification
- assertion-equivalent credits
- inline double detection where applicable

## Artifacts and Notes

Reference sources:

    ../brokk/brokk-core/src/main/java/ai/brokk/tools/CodeQualityToolsMcp.java
    ../brokk/brokk-shared/src/main/java/ai/brokk/analyzer/IAnalyzer.java
    ../brokk/brokk-shared/src/main/java/ai/brokk/analyzer/TreeSitterAnalyzer.java
    ../brokk/brokk-shared/src/main/java/ai/brokk/analyzer/JavaAnalyzer.java

Primary local reference implementation:

    src/analyzer/java_analyzer.rs
    src/code_quality/test_assertion_smells.rs
    tests/java_test_assertion_smells.rs

Revision note: expanded the original Java-first ExecPlan into a multi-language parity program after the Java implementation and review-fix pass were completed.
