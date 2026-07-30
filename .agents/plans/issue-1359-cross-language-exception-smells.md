# Add cross-language exception-handling smell analysis

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agents/PLANS.md](../PLANS.md).

## Purpose / Big Picture

`report_exception_handling_smells` currently analyzes Java catch clauses and silently treats every other language as clean. After this work, callers can submit Java, Go, C/C++, JavaScript/JSX, TypeScript/TSX, Python, Rust, PHP, Scala, C#, Ruby, and Kotlin files and receive findings based on each language's real error-handling syntax. A clean result will mean the file was actually analyzed; unsupported or failed analysis will be reported explicitly.

The implementation uses the current Brokk Java analyzers and their tests as the compatibility reference for Java, Go, C/C++, JavaScript/TypeScript, Python, Rust, PHP, Scala, and C#. Brokk does not currently implement this feature for Ruby or Kotlin, so Bifrost supplies new structured tree-sitter profiles for those languages.

## Progress

- [x] (2026-07-30 20:05Z) Verified issue #1359, the clean matching branch, current Bifrost call path, and the current Brokk implementations and tests.
- [x] (2026-07-30 20:12Z) Wrote this ExecPlan with four independently testable milestones.
- [x] (2026-07-30 20:28Z) Milestone 1: made the analyzer/result/report boundary distinguish analyzed-clean, unsupported, and failed inputs; extracted shared stack-safe scoring and preserved all seven focused Java/report tests.
- [x] (2026-07-30 21:04Z) Milestone 2: ported Brokk behavior for C/C++, JavaScript/JSX, TypeScript/TSX, Python, PHP, Scala, C#, Go, and Rust; nine focused cross-language tests pass with positive and propagation/rethrow near-miss coverage.
- [x] (2026-07-30 21:24Z) Milestone 3: added structured Ruby `rescue`/`rescue_modifier` and Kotlin `catch_block` semantics; all eleven focused language tests pass, including meaningful rethrow near misses.
- [x] (2026-07-30 23:18Z) Milestone 4: completed mixed-language MCP/report integration, capability documentation, focused and full executable-test validation, and five-role specialist review; resolved the substantive semantic findings and recorded the unavailable policy tools and doc-test cache issue.

## Surprises & Discoveries

- Observation: Brokk already has deliberate non-Java error-model behavior rather than applying catch-clause rules universally.
  Evidence: current `GoAnalyzer` inspects deferred `recover()` and `if err != nil` handlers, while `RustAnalyzer` inspects `Err` match arms, `if let Err`, and `catch_unwind` contexts.

- Observation: Brokk's current coverage stops short of the issue's full language list.
  Evidence: `brokk-shared` has implementations and dedicated exception-smell tests for Java, Go, C/C++, JavaScript/TypeScript, Python, Rust, PHP, Scala, and C#, but none for Ruby or Kotlin.

- Observation: the existing trait cannot prove that an empty result is clean.
  Evidence: `IAnalyzer::find_exception_handling_smells` defaults to `Vec::new()`, and `MultiAnalyzer` also uses `unwrap_or_default()` when no delegate exists.

- Observation: the installed Bifrost skills are visible but their MCP code-intelligence and policy tools are not registered in this task.
  Evidence: tool discovery returned no callable `search_symbols`, `get_symbol_sources`, `list_policies`, or `run_policy` tools. Repository inspection therefore uses `rg`, direct source reads, and git history, and final validation must report the registration failure if it remains.

- Observation: the workspace package name is `brokk-bifrost-analysis`, not `bifrost-analysis`.
  Evidence: the first focused command failed package selection; rerunning `cargo test -p brokk-bifrost-analysis exception_smells` passed all seven selected tests.

- Observation: Kotlin's grammar places the catch parameter identifier and `user_type` directly under `catch_block`, and omits `statements` for an empty handler.
  Evidence: inspecting the parsed S-expression showed `(catch_block (simple_identifier) (user_type (type_identifier)))` for an empty catch and an additional `(statements ... (jump_expression ...))` for a rethrowing catch.

- Observation: `.c` and `.C` share the C++ analyzer family but do not mean the same language conventionally.
  Evidence: the final capability boundary reports lowercase `.c` as unsupported because native C return-code/errno semantics are not implemented, while uppercase `.C` remains available to the C++ parser profile.

- Observation: the shared target directory contained artifacts that rustc described as incompatible despite displaying the same compiler version.
  Evidence: all 1,836 executable analysis tests passed, after which doc tests and the first Clippy attempt failed with E0514 for cached dependencies. The required Clippy retry uses `scripts/with-isolated-cargo-target.sh` to avoid the contaminated shared target.

## Decision Log

- Decision: keep `ExceptionSmellWeights` and `ExceptionHandlingSmell` compatible with Brokk instead of replacing them with a new language-neutral scoring model.
  Rationale: Brokk already maps Go `error`/`recover()` and Rust `Err`/`catch_unwind` into the existing severity tiers and report columns, giving this port an established behavioral contract.
  Date/Author: 2026-07-30 / Codex

- Decision: introduce a typed per-file analysis outcome.
  Rationale: separate analyzed-empty, unsupported, and failed states are required to prevent unsupported semantics or source/parser failures from being rendered as clean.
  Date/Author: 2026-07-30 / Codex

- Decision: share scoring and traversal mechanics but keep syntax extraction language-specific.
  Rationale: empty/comment-only/small/log-only scoring is common, while catch clauses, rescue clauses, Go error branches, and Rust result patterns require different structured AST interpretation. This keeps the implementation DRY without mode-flagged mini parsers.
  Date/Author: 2026-07-30 / Codex

- Decision: implement Ruby bare `rescue` as the language's implicit `StandardError` handler and Kotlin catch types using their structured type nodes.
  Rationale: Brokk has no reference implementation for these languages, so the profiles must reflect their actual exception models rather than Java spellings.
  Date/Author: 2026-07-30 / Codex

- Decision: keep the language-specific AST extractors together in `analyzer/exception_handling.rs` instead of creating nine one-function facade modules.
  Rationale: every analyzer already reaches the same object-safe trait default, and the extractors share one parser lifecycle, result boundary, scorer, and handler builder. Separate functions retain language-specific syntax without adding repetitive facade wiring or mode flags.
  Date/Author: 2026-07-30 / Codex

- Decision: treat lowercase C inputs as explicitly unsupported instead of authoritative clean.
  Rationale: C has no catch syntax and the issue's capability-honesty criterion forbids silently applying the C++ catch detector to C return-code/errno handling. The MCP description states this boundary.
  Date/Author: 2026-07-30 / Codex

## Outcomes & Retrospective

All four milestones are complete. Java, Go, C++, JS/JSX, TS/TSX, Python, Rust, PHP, Scala, C#, Ruby, and Kotlin use structured parser nodes; lowercase C is explicit unsupported until native return-code/errno semantics exist. The final focused suite covers fifteen cases, including canonical Go/Rust propagation, nested Go ownership, exact broad-type classification, non-logging similarly named identifiers, C++ nested statement credit, mixed findings plus unsupported/failure notes, and malformed syntax. The final full smell suite passed 276 tests, the MCP server suite passed 24 tests, and all 1,836 executable analysis tests passed. Policy validation could not run because the installed skill's `list_policies` and `run_policy` tools were not registered. The shared-target doc-test phase hit E0514 cache incompatibility after the executable suite; task-scoped Clippy passed after pinning `PATH` to the repository's rustup toolchain so Cargo and Clippy did not mix Homebrew's LLVM-distinct binaries.

## Context and Orientation

The MCP tool is registered in `crates/bifrost-mcp/src/mcp_slopcop.rs` and dispatched by `crates/bifrost-mcp/src/searchtools_service.rs`. The report implementation in `crates/bifrost-analysis/src/code_quality/exception_smells.rs` resolves requested files and invokes `IAnalyzer::find_exception_handling_smells` for each file. `MultiAnalyzer` chooses the language delegate. Only `JavaAnalyzer` currently overrides the empty trait default, using `crates/bifrost-analysis/src/analyzer/java/exceptions.rs`.

An exception-handling smell is a review prompt for a handler that is broad or does little useful work. The current weights score broad handler categories and empty, comment-only, small, or log-only bodies, then subtract credit for meaningful statements. Go and Rust do not use language-level catch clauses, so their established Brokk behavior analyzes explicit error or panic handlers instead of ordinary propagation.

The cross-language behavior tests belong in `tests/suite_smells/exception_handling_smells.rs` and must be registered in `tests/suite_smells/main.rs`. They use `tests/common/inline_project.rs::InlineTestProject` so each case defines a small source project inline.

## Plan of Work

Milestone 1 establishes an honest result boundary before adding new findings. Add an outcome type in `crates/bifrost-analysis/src/analyzer/model.rs` with analyzed findings, unsupported semantics, and failed analysis variants. Change the trait and `MultiAnalyzer` to preserve that outcome. Update `crates/bifrost-analysis/src/code_quality/exception_smells.rs` to aggregate only analyzed findings and render stable unsupported/failure sections. Add `crates/bifrost-analysis/src/analyzer/exception_handling.rs` for shared iterative traversal, scoring, statement/body facts, excerpt compaction, sorting, and enclosing-symbol lookup. Refactor Java to use the shared mechanics without changing its current scores or output. Run focused library tests, format, and commit this milestone.

Milestone 2 ports the exact Brokk behavior for the remaining referenced analyzers. Add language-local `exceptions.rs` modules for C/C++, JS/TS, Python, PHP, Scala, C#, Go, and Rust, connected through their existing analyzer facades. Catch-family implementations interpret only grammar fields and nodes. Go detects deferred `recover()` handlers and canonical `if err != nil` bodies, while treating ordinary error returns as clean. Rust detects `Err` match arms, `if let Err`, and `catch_unwind`, while treating `?` propagation as clean. Port the corresponding Brokk positive and near-miss cases into the consolidated smell suite, run them, format, and commit this milestone.

Milestone 3 adds the two languages without a Brokk reference. Ruby iteratively visits `rescue` and `rescue_modifier`, reads structured exception/body fields, recognizes implicit `StandardError`, explicit broad classes, logger sends, `raise`, and `retry`, and avoids attributing nested rescue bodies to their parents. Kotlin iteratively visits catch blocks inside try expressions, reads structured parameter types and statement bodies, maps `Throwable`, `Exception`, and `RuntimeException`, and recognizes logger calls and `throw`. Add positive, meaningful-handler, rethrow/propagation, and nesting near misses for both languages, run them, format, and commit this milestone.

Milestone 4 completes the public contract. Update MCP descriptions to name native Go/Rust behavior and explicit unsupported/failure reporting. Add mixed-language tests proving that supported findings are retained while unsupported files never create findings or false-clean text. Run focused analysis and MCP tests, the full featureless smell suite, task-scoped Clippy, and `cargo fmt`. Attempt the required Bifrost code-smell policy run; if policy tools remain absent, record that registration failure rather than claiming a clean run. Review the complete diff with the guided-issue specialist reviewers, resolve substantive findings, update this plan, and commit the final milestone.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/8d5d/bifrost`.

For Milestone 1:

    cargo test -p brokk-bifrost-analysis exception_smells
    cargo fmt --check

For language milestones:

    cargo test --test suite_smells -- exception_handling_smells::
    cargo test -p brokk-bifrost-analysis exception_smells
    cargo fmt --check

For the final task-scoped gate, without the `nlp` feature:

    cargo fmt
    cargo test --test suite_smells
    cargo test -p brokk-bifrost-analysis
    cargo test -p bifrost-mcp --test bifrost_mcp_server
    cargo clippy --all-targets -- -D warnings

If an all-feature pre-push gate is later explicitly required, first check disk space and run it through `scripts/with-isolated-cargo-target.sh` as required by `AGENTS.md`.

## Validation and Acceptance

Every claimed language and dialect must have at least one positive finding and a realistic near miss. The positive must exercise the structured AST shape that owns the semantics, not merely a matching identifier. Go near misses include ordinary error propagation; Rust near misses include `?`; catch-family near misses include meaningful recovery or rethrowing. Nested constructs must be attributed only to the owning handler.

The report must distinguish these observations: a supported file with no findings, an unsupported file, and a failed source/parser analysis. A request containing only unsupported or failed files must not say that no smells were found. A mixed request must render findings only from analyzed languages while explicitly listing the other inputs. Existing Java score, reason, ordering, truncation, and table tests must continue to pass.

## Idempotence and Recovery

All edits are source and test changes and can be reapplied safely. Tests create temporary inline projects and do not mutate repository fixtures. Each milestone is committed separately on the existing issue branch, so a later milestone can be diagnosed against the last passing checkpoint without switching branches or discarding unrelated work. Do not use `git reset`, broad staging, or manually named Cargo target directories.

## Artifacts and Notes

Reference implementations are in the sibling Brokk checkout under `brokk-shared/src/main/java/ai/brokk/analyzer/`, with corresponding cases under `brokk-shared/src/test/java/ai/brokk/analyzer/code_quality/`. The relevant analyzers are `JavaAnalyzer`, `GoAnalyzer`, `CppAnalyzer`, `JsTsAnalyzer`, `PythonAnalyzer`, `RustAnalyzer`, `PhpAnalyzer`, `ScalaAnalyzer`, and `CSharpAnalyzer`.

## Interfaces and Dependencies

At the end of Milestone 1, `IAnalyzer::find_exception_handling_smells` returns a typed outcome rather than a bare vector. The outcome owns `Vec<ExceptionHandlingSmell>` only for analyzed files and carries an explicit stable reason for unsupported or failed analysis. `MultiAnalyzer` forwards this outcome without defaulting.

The shared exception module operates on tree-sitter `Node` values, `ProjectFile`, `ExceptionSmellWeights`, and `IAnalyzer` for enclosing-symbol lookup. It must use the registered parser selected by `parser_language_for_path`, iterative stacks or the existing iterative walk helpers, and AST fields. It must not use regexes, source splitting, or delimiter scanning as a substitute for grammar structure.

Revision note (2026-07-30): Initial plan created after verifying issue #1359 and comparing Bifrost with current Brokk master.

Revision note (2026-07-30): Marked Milestone 1 complete, recorded the validated Cargo package name, and summarized its passing focused tests.

Revision note (2026-07-30): Marked Milestone 2 complete and recorded the decision to colocate the language-specific extractors behind the shared trait default.

Revision note (2026-07-30): Marked Milestone 3 complete and recorded the Kotlin grammar shape that determined empty-body and rethrow handling.

Revision note (2026-07-30): Marked Milestone 4 complete after mixed-language integration, specialist review fixes, full executable-test validation, and explicit recording of unavailable policy tools and shared-target E0514 failures.
