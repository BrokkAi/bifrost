# Test assertion smell parity follow-up

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/dave/.codex/worktrees/0df3/bifrost/.agent/PLANS.md).

## Purpose / Big Picture

Bifrost now has initial `report_test_assertion_smells` support across every analyzer that already detects tests, but the new non-Java suites are still materially thinner than Brokk’s current language-specific parity suites. The goal of this follow-up is to close those test-suite gaps in staged waves, using Brokk’s current assertion-smell tests as the source of truth for missing scenarios.

## Progress

- [x] (2026-05-18 18:20Z) Compared Bifrost’s current assertion-smell tests against Brokk’s current language suites and confirmed that Java is close to parity while JS/TS, Python, C#, Go, Rust, Scala, and PHP are still starter-level.
- [x] (2026-05-18 18:40Z) Closed the current JS/TS and Python parity gaps against Brokk by adding snapshot-only JS coverage, non-test TS skip coverage, Python fixture false-positive coverage, and the missing self-comparison, meaningful-clean, and constant-truth/equality direct tests.
- [x] (2026-05-18 19:05Z) Closed the current C#, Go, and Rust parity gaps against Brokk by expanding the direct suites and adding the missing Go branch-based assertion detection plus Rust overspecified-literal/assertion-count behavior.
- [x] (2026-05-18 20:05Z) Closed the remaining Scala and PHP parity gaps by expanding the inline suites to match Brokk’s current cases and hardening both analyzers to distinguish constant truth/equality, nullness-only, overspecified literals, and shallow-only outcomes.
- [x] (2026-05-18 20:25Z) Converted the C++ “decision” into a real parity wave by adding C++ test detection plus assertion-smell support for gtest, Catch2, Boost.Test, and MSTest markers, along with an inline direct suite that mirrors Brokk’s current C++ coverage.

## Surprises & Discoveries

- Observation: Brokk is no longer Java-only for this feature.
  Evidence: `brokk-shared` now contains `JsTsTestAssertionSmellTest`, `PythonTestAssertionSmellTest`, `CSharpTestAssertionSmellTest`, `GoTestAssertionSmellTest`, `RustTestAssertionSmellTest`, `ScalaTestAssertionSmellTest`, `PhpTestAssertionSmellTest`, and `CppTestAssertionSmellTest`.

- Observation: the biggest parity gap is not tool wiring but scenario breadth.
  Evidence: Bifrost’s non-Java tests are short starter suites, while Brokk’s cover more negative cases, more assertion-equivalent patterns, and more framework-specific smells such as JS snapshot assertions and Python fixture false-positive avoidance.

- Observation: the first parity wins come mostly from tests, but a few analyzer fixes were required.
  Evidence: JS/TS needed explicit snapshot-assertion detection, and Python needed fixture-aware test-function filtering to avoid false positives for `@pytest.fixture def test_*`.

- Observation: Go and Rust parity needed real analyzer behavior, not just more tests.
  Evidence: Brokk treats `t.Errorf`-style branches as assertion-like in Go and counts meaningful branches toward `assertionCount`; Rust also treats oversized string literals inside `assert_eq!` as scored smells.

- Observation: Scala and PHP had feature stubs but were missing the shallow-only aggregation behavior that Brokk’s parity cases depend on.
  Evidence: the direct parity cases for nullness-only assertions only passed once both analyzers tracked shallow assertions and emitted the derived `shallow-assertions-only` finding.

- Observation: C++ support was feasible without a tree-structured smell analyzer, but not with regex-only body capture.
  Evidence: the first C++ pass mis-associated gtest bodies around nested blocks; switching to regex-start detection plus brace matching fixed the body association case and eliminated false negatives for gtest assertions.

## Decision Log

- Decision: treat Brokk’s current language-specific test classes as the parity spec.
  Rationale: the implementation is already split per analyzer in both repos, so the most reliable way to close gaps is to port missing scenarios language by language rather than to reason from generic smell categories alone.
  Date/Author: 2026-05-18 / Codex

- Decision: keep the same staged wave structure as the earlier rollout and commit after each wave.
  Rationale: the user explicitly asked for similar waves, and the staged commits make it easy to review parity progress without mixing unrelated languages.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

The language waves are complete. Bifrost now has direct assertion-smell coverage for the same language set Brokk currently exercises, including C++. Remaining future work, if any, is incremental parity maintenance as Brokk evolves rather than a standing cross-language rollout gap.
