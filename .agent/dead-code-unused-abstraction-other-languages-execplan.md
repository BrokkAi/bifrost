# Extend dead-code and unused-abstraction smells beyond Rust

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, Bifrost’s `report_dead_code_and_unused_abstraction_smells` MCP tool will no longer be Rust-only. The tool will first support Python, then JavaScript and TypeScript, while preserving the conservative “skip inconclusive evidence” contract that the Rust-first milestone established. The user-visible proof is that the same MCP tool can report likely dead code and one-call abstractions for Python and JS/TS projects, with tests showing that real external usages suppress findings and unseedable or ambiguous cases are surfaced as skipped evidence instead of false positives.

This plan does not implement Java support immediately. Instead, it ends with an explicit Java decision point because Bifrost still lacks the JDT-backed Java usage precision that Brokk relies on for its Java-side dead-code analysis.

## Progress

- [x] (2026-05-19 12:05Z) Reviewed the completed Rust ExecPlan and current `src/code_quality/dead_code_smells.rs` implementation.
- [x] (2026-05-19 12:06Z) Confirmed that `UsageFinder` already routes Python targets through `PythonExportUsageGraphStrategy` and JS/TS targets through `JsTsExportUsageGraphStrategy`.
- [x] (2026-05-19 12:07Z) Recorded the rollout order and language-specific guardrails in this ExecPlan before code edits.
- [x] (2026-05-19 12:18Z) Generalized the Rust-only candidate filter in `src/code_quality/dead_code_smells.rs` into language-specific graph-backed query helpers without changing the public tool schema.
- [x] (2026-05-19 12:23Z) Added Python support and focused Python dead-code smell tests.
- [x] (2026-05-19 12:24Z) Added JavaScript and TypeScript support and focused JS/TS dead-code smell tests.
- [x] (2026-05-19 12:26Z) Re-ran the existing Rust smell suite and confirmed the generalized pipeline stayed green for Rust.
- [x] (2026-05-19 12:34Z) Ran `cargo test --test python_js_ts_dead_code_smells`, `cargo test --test rust_dead_code_smells`, `cargo test --test usages_python_graph_test`, `cargo test --test usages_js_ts_graph_test`, `cargo test --test searchtools_service`, `cargo test --test bifrost_mcp_server`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-05-19 12:35Z) Updated this ExecPlan with the final rollout outcome and the remaining Java deferral.

## Surprises & Discoveries

- Observation: The existing dead-code smell handler is already structured to support multi-language rollout without a trait refactor.
  Evidence: `src/code_quality/dead_code_smells.rs` already separates candidate selection, usage-query normalization, self/external usage filtering, score calculation, and report rendering into local helpers.

- Observation: Python and JS/TS have graph-backed usage strategies today, but their failure modes differ.
  Evidence: `src/usages/python_graph.rs` fails when no export seed resolves or the analyzer is not Python, while `src/usages/js_ts_graph.rs` fails when no JS/TS export seed resolves and `UsageFinder` explicitly falls back to regex for default usage searches. The smell tool must not treat that regex fallback as strong dead-code evidence for unseedable targets.

- Observation: The Rust milestone already established the right policy baseline for later languages.
  Evidence: The current tool skips truncated candidate-file sets, `Failure`, `Ambiguous`, and `TooManyCallsites` results instead of converting them into dead-code findings. That policy should remain unchanged for Python and JS/TS.

- Observation: For the smell tool, direct graph-strategy calls are a better fit than `UsageFinder` for non-Rust languages.
  Evidence: `UsageFinder` intentionally falls back to regex for JS/TS and for some unseeded Python cases, but the smell tool must treat those graph failures as inconclusive rather than as valid dead-code evidence.

- Observation: A barrel/re-export chain does count as usage evidence, but a single downstream call can still justifiably report as a one-call abstraction.
  Evidence: The initial TypeScript barrel test still produced a `1`-usage finding until the fixture was updated to call the re-exported symbol twice, proving the graph saw the barrel path correctly and the smell heuristic was working as designed.

## Decision Log

- Decision: Roll out Python before JavaScript/TypeScript.
  Rationale: Python already has a dedicated export-usage graph strategy, its declaration shapes are simpler to gate conservatively, and it does not have the same “graph failed, regex fallback still returned something” ambiguity that JS/TS introduces.
  Date/Author: 2026-05-19 / Codex

- Decision: Keep the dead-code smell handler in the tool layer.
  Rationale: The current design composes declarations plus `UsageFinder::query(...)`, and that is still the correct boundary for multi-language rollout. A new analyzer trait would add coupling without solving the real precision problem.
  Date/Author: 2026-05-19 / Codex

- Decision: Do not broaden Java support as part of the Python and JS/TS rollout.
  Rationale: Brokk’s Java path uses `JdtUsageAnalyzerStrategy`, which Bifrost does not have. Shipping “best-effort Java” in the same milestone would blur the line between graph-backed rollout and regex-heavy approximation.
  Date/Author: 2026-05-19 / Codex

## Outcomes & Retrospective

This rollout is complete for Python, JavaScript, and TypeScript. The existing `report_dead_code_and_unused_abstraction_smells` MCP tool now supports Rust, Python, JavaScript, and TypeScript with the same public schema and report layout.

The implementation kept the tool-layer design but changed the query path for supported languages: instead of relying on generic `UsageFinder` fallback behavior, the smell tool now invokes the language-specific graph strategies directly for Rust, Python, and JS/TS after building the same candidate file set. That preserves the conservative contract: graph failures, ambiguous outcomes, too-many-callsites results, and candidate-file truncation remain skipped evidence, not findings.

New tests prove the rollout end-to-end:

- Python: unused helper, one-call wrapper, and a symbol with multiple downstream uses that must not be flagged.
- JS/TS: unused export, one-call TypeScript adapter, barrel/re-export usage counting, and an unseedable local JavaScript symbol that is skipped instead of analyzed through regex fallback.
- Rust: the original smell tests still pass unchanged apart from the generalized report header text.

The only remaining planned gap is Java. That is still intentionally deferred because Bifrost does not have a JDT-equivalent Java usage engine, and broadening Java as part of this rollout would weaken the smell tool’s trust model.

## Context and Orientation

The completed Rust implementation lives in `src/code_quality/dead_code_smells.rs`. That file already contains the core pipeline:

1. Resolve project files.
2. Select candidate declarations.
3. Query usages through `UsageFinder`.
4. Reject inconclusive results.
5. Remove self-usages.
6. Count external usages.
7. Emit findings only when the non-self usage count is `0` or `1`.

`src/usages/finder.rs` is the central routing layer for language-specific usage logic. At the time of this plan:

- Rust targets route to `RustExportUsageGraphStrategy`.
- Python targets route to `PythonExportUsageGraphStrategy`.
- JavaScript and TypeScript targets route to `JsTsExportUsageGraphStrategy`.
- Other targets fall through to `RegexUsageAnalyzer`.

That routing matters because the smell tool must distinguish “graph-backed evidence” from “best-effort fallback.” For Python, graph failure should remain inconclusive. For JS/TS, declarations that cannot be seeded by the export graph should usually be excluded from the candidate set up front rather than analyzed through a weaker fallback path and mislabeled as dead code.

The current tests already give good orientation for the usage engines:

- `tests/usages_python_graph_test.rs` covers the Python graph strategy.
- `tests/usages_js_ts_graph_test.rs` covers the JS/TS graph strategy.
- `tests/rust_dead_code_smells.rs` covers the already-landed Rust smell behavior.

The contributor extending this feature should read those files first, then update the smell tool and add new smell-specific tests.

## Plan of Work

First, refactor `src/code_quality/dead_code_smells.rs` so the Rust-only candidate gate becomes a language-policy layer rather than a hard-coded `Language::Rust` check. Keep the public API and report format unchanged. Introduce small internal helpers that answer:

- whether a declaration kind is eligible for this language,
- whether a declaration should be considered seedable enough for smell analysis,
- how to describe skipped unsupported-language or unsupported-declaration cases when explicit `fq_names` are supplied.

Do not change the score formula, report table, truncation behavior, or Rust sort order in this refactor. The only acceptable behavior change in the first refactor pass is that Rust logic becomes expressed through a reusable policy helper and all existing Rust tests still pass unchanged.

Next, add Python support. Candidate selection should allow Python functions, classes, and module-level fields only when they resolve cleanly from existing analyzer declarations. Keep the current self/external usage filtering logic unchanged. Python queries should still call `UsageFinder::new().query(...)`, but any `FuzzyResult::Failure`, `FuzzyResult::Ambiguous`, `FuzzyResult::TooManyCallsites`, or candidate-file truncation must remain a skip. Do not introduce regex-only “best effort” candidate widening for Python. If the graph cannot seed a Python target, that target is inconclusive for this smell tool and should not be reported.

After Python is stable, add JavaScript and TypeScript support. This is the more delicate rollout because the general `UsageFinder` falls back to regex for JS/TS when `JsTsExportUsageGraphStrategy` cannot infer a seed. The smell tool must therefore constrain candidates more aggressively than Rust or Python:

- exported functions, exported classes, exported fields, and declarations that the existing graph tests prove seedable are eligible;
- local-only or unexported declarations that would trigger a graph failure should be excluded up front or skipped explicitly when targeted by `fq_names`;
- barrel and re-export scenarios must count as usage evidence when the graph resolves them;
- a graph failure for a targeted JS/TS declaration must remain skipped evidence, not a dead-code finding produced through regex fallback.

Once Python and JS/TS support exist, add a final plan section and test evidence that documents the remaining Java choice. This plan deliberately stops there. The follow-up contributor should either open a new Java-specific ExecPlan for “best-effort Java” or for “parity-driven Java after stronger Java usage resolution exists.”

## Concrete Steps

From `/Users/dave/.codex/worktrees/f0e5/bifrost`:

1. Edit `src/code_quality/dead_code_smells.rs` to replace the Rust-only language gate with internal per-language policy helpers.
2. Add Python candidate support in the same file without changing the public tool schema or report shape.
3. Add JavaScript and TypeScript candidate support in the same file, with stricter seedability checks than Python or Rust.
4. Add a dedicated Python smell test file or extend the existing smell test suite with Python cases using `tests/common/inline_project.rs`.
5. Add a dedicated JS/TS smell test file or extend the existing smell test suite with JavaScript and TypeScript cases using `tests/common/inline_project.rs`.
6. Re-run the Rust smell tests to prove the refactor did not change Rust behavior.
7. Run the targeted validation commands listed below and update this ExecPlan with the actual results.

Expected commands:

    cargo test --test rust_dead_code_smells
    cargo test --test usages_python_graph_test
    cargo test --test usages_js_ts_graph_test
    cargo test --test searchtools_service
    cargo test --test bifrost_mcp_server
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

If the smell rollout gets its own language-specific test files, add them to this list explicitly and update the plan when implementation is complete.

## Validation and Acceptance

Acceptance is behavioral:

1. The MCP tool name and JSON schema stay unchanged; only its language coverage grows.
2. All existing Rust smell tests continue to pass with no expectation changes.
3. A Python inline project with an unused helper reports a dead-code finding with `0` usages.
4. A Python one-call wrapper reports an unused-abstraction finding with `1` usage.
5. A Python symbol with real external usage is not reported.
6. A Python symbol whose usage graph cannot produce defensible evidence is skipped, not reported.
7. A JavaScript or TypeScript exported symbol with no consumers reports a dead-code finding.
8. A JavaScript or TypeScript one-call adapter reports an unused-abstraction finding.
9. A JS/TS barrel or re-export path counts as usage evidence and suppresses a dead-code finding.
10. A JS/TS declaration that cannot be seeded by the export graph is skipped or excluded from candidate selection; it is not labeled dead code via regex fallback.

## Idempotence and Recovery

The rollout should remain safe to retry because the work stays within `src/code_quality/dead_code_smells.rs` plus new tests. If a language addition proves too noisy, revert just that language’s candidate policy while leaving the generalized helper structure and already-green languages in place.

Do not “recover” a failing Python or JS/TS smell case by weakening the skip rules. Recovery should prefer narrowing candidate eligibility, tightening seedability checks, or adding a targeted skipped-evidence path. That preserves trust in the tool.

## Artifacts and Notes

The most important artifacts for this phase are the new language-specific smell tests. They are the executable specification for what “supported” means in Python and JS/TS.

When a declaration is skipped because it is not graph-seedable enough, keep the skipped evidence concise and stable. Good examples are:

    `<fq_name>`: usage analysis was ambiguous; evidence is inconclusive
    `<fq_name>`: no definition found
    `<fq_name>`: language/declaration shape is not yet supported for smell analysis

The exact text can be revised during implementation, but once tests are added it should remain stable unless there is a strong reason to change the wording.

## Interfaces and Dependencies

The public interface should remain exactly:

    pub struct ReportDeadCodeAndUnusedAbstractionSmellsParams
    pub struct ReportDeadCodeAndUnusedAbstractionSmellsResult
    pub fn report_dead_code_and_unused_abstraction_smells(
        analyzer: &dyn IAnalyzer,
        params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
    ) -> ReportDeadCodeAndUnusedAbstractionSmellsResult

Do not add new MCP tools, new analyzer traits, or new schema fields in this rollout.

Internal dependencies that must remain central:

- `crate::usages::UsageFinder` for bounded queries
- `crate::usages::FuzzyResult` for distinguishing success from inconclusive outcomes
- `tests/common/inline_project.rs` for compact multi-language fixtures
- existing usage-graph suites in `tests/usages_python_graph_test.rs` and `tests/usages_js_ts_graph_test.rs` as the behavioral source of truth for what the graph can already defend

If implementation reveals that JS/TS seedability needs a reusable helper from `src/usages/js_ts_graph.rs` or one of the analyzer modules, prefer extracting a narrow internal helper over duplicating graph-assumption logic in the smell tool.

Change note: created this follow-on ExecPlan after the Rust-first milestone completed so the remaining language rollout can proceed as a separate, self-contained implementation track without rewriting the completed Rust plan.

Change note: updated this ExecPlan after implementation to record the direct-graph query design, the final Python and JS/TS test evidence, and the explicit decision to leave Java for a separate follow-up.
