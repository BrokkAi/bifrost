# Issue 503 LSP Click-Around Regression Fixtures

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, `Outcomes & Retrospective`, and `Timing Log` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. Keep the current branch; do not create or switch branches. Fetch remote refs when needed, but do not rebase unless the user explicitly asks. Stage only files changed for each milestone and commit directly on the current branch after Brokk Guided Review findings for that milestone have been fixed.

## Purpose / Big Picture

Bifrost's LSP features should behave coherently when a user clicks around realistic relation-heavy projects, not just when one narrow reported coordinate is selected. This work adds a marker-driven regression layer that opens small multi-file fixtures through the real `bifrost --lsp` server and asserts the responses for each click site. A future analyzer change should be able to run these tests and see whether definition, references, implementation, type definition, hierarchy, hover, and intentionally ambiguous sites still produce the expected editor-visible behavior.

The work is test-first. Production analyzer changes are allowed only when a new click-around fixture exposes a real current bug. Such fixes must use structured analyzer and tree-sitter data; do not add regex or source-text fallback behavior to hide missing structured support.

## Progress

- [x] (2026-07-07T00:00Z) Fetched remote refs and confirmed the current branch is `503-lsp-style-click-around-regression-fixtures-for-relation-heavy-lookups` with a clean worktree before edits.
- [x] (2026-07-07T00:00Z) Created this ExecPlan and began Milestone 0 harness implementation.
- [x] (2026-07-07T09:51Z) Milestone 0: added the shared marker/timing harness, added the Java smoke fixture, ran focused tests, ran Brokk Guided Review, fixed accepted findings, reran focused tests, updated timings, and prepared the milestone commit.
- [ ] Milestone 1: Go click-around fixture.
- [ ] Milestone 2: Rust click-around fixture.
- [ ] Milestone 3: PHP click-around fixture.
- [ ] Milestone 4: Scala click-around fixture.
- [ ] Milestone 5: Java click-around fixture.
- [ ] Milestone 6: C# click-around fixture.
- [ ] Milestone 7: C++ click-around fixture.
- [ ] Milestone 8: JavaScript click-around fixture.
- [ ] Milestone 9: TypeScript click-around fixture.
- [ ] Milestone 10: Python click-around fixture.
- [ ] Milestone 11: Ruby click-around fixture.
- [ ] Milestone 12: ignored stress fixtures and final sweep.

## Surprises & Discoveries

- Observation: The existing `tests/common/lsp_client.rs` already supports the protocol operations needed by the harness: definition-style position requests, references, implementation, type definition, hover, and hierarchy helper calls.
  Evidence: `LspServer` exposes `text_document_position_response`, `references_response`, `implementation_response`, `type_definition_response`, `hover_response`, `prepare_hierarchy`, and `hierarchy_relation`.

- Observation: The first marker parser accepted any `<alnum>` marker and would have stripped ordinary generic syntax such as `List<String>`.
  Evidence: Brokk Guided Review flagged the issue, and `common::lsp_click::tests::milestone_0_marker_parser_preserves_generic_syntax` now proves `List<String>` remains in the cleaned source.

- Observation: The first caret-comment parser could corrupt fixtures by truncating the previous source line.
  Evidence: Brokk Guided Review flagged `target();` followed by `// ^call` as a deleting case. `common::lsp_click::tests::milestone_0_marker_parser_strips_caret_marker_line_without_deleting_target` now proves the marker line is stripped without deleting the target or following source.

- Observation: The harness must use UTF-16 character offsets, not Unicode scalar counts, because LSP positions are UTF-16.
  Evidence: Brokk Guided Review flagged this, and `common::lsp_click::tests::milestone_0_marker_parser_counts_utf16_columns` now covers a supplementary emoji before a marker.

## Decision Log

- Decision: Add the click-around harness under `tests/common/lsp_click.rs` instead of expanding `tests/bifrost_lsp_server.rs`.
  Rationale: The existing LSP server test file is already large, while the planned language fixtures need a reusable marker parser, response normalizer, and timing collector. A shared integration-test helper keeps language milestones compact.
  Date/Author: 2026-07-07 / Codex.

- Decision: Record per-request timing as diagnostic evidence, not as assertions.
  Rationale: Timing thresholds are flaky in CI and on developer machines. The timing data is still valuable for spotting relation-heavy regressions during review and for comparing stress fixtures.
  Date/Author: 2026-07-07 / Codex.

- Decision: Require inline markers to contain an underscore.
  Rationale: The requested examples use names such as `<call_run>`, while ordinary generic syntax commonly uses simple names such as `<String>` or `<T>`. Requiring an underscore preserves generic source text without changing the readable marker style used by the fixtures.
  Date/Author: 2026-07-07 / Codex.

- Decision: Keep the raw temp-root writer in the click harness instead of reusing `InlineTestProject`.
  Rationale: `InlineTestProject` is the right default for analyzer fixtures, but this harness must strip marker annotations before writing files and then start the real LSP process with the temp root. Reusing `LspServer` is the important shared behavior for this layer.
  Date/Author: 2026-07-07 / Codex.

- Decision: Make `ClickExpectation::Locations` exact by default.
  Rationale: Extra or duplicate LSP destinations are editor-visible regressions. The weaker contains-only behavior would let false positives through the click-around suite.
  Date/Author: 2026-07-07 / Codex.

## Outcomes & Retrospective

Milestone 0 is complete. The repository now has a reusable LSP click fixture helper, parser coverage for marker edge cases, a Java smoke fixture for definition/references/empty-result behavior, and timing capture. No production analyzer code was changed.

Milestone 0 Brokk Guided Review outcome: security found path traversal risk in fixture paths; senior-dev, duplication, architecture, and devops found overlapping issues around caret marker corruption, generic syntax collision, exactness of location assertions, UTF-16 column accounting, and hierarchy prepare panics bypassing normal shutdown. Accepted fixes validate fixture paths, require underscores in inline markers, fix caret marker line stripping, count UTF-16 columns, assert exact location lists, avoid `prepare_hierarchy` panics inside relation operations, and preserve LSP shutdown before assertion panics. The InlineTestProject reuse suggestion was not adopted for the reason recorded in the Decision Log.

## Timing Log

- Milestone 0: Harness and Timing Infrastructure
  - Language: shared harness with Java smoke fixture.
  - Start: 2026-07-07T00:00Z.
  - End: 2026-07-07T09:51Z.
  - Focused test before review: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_0 --features nlp -- --nocapture` passed in 5.41s real time after the initial compile. The first cold compile-and-test run passed in 2m54s build time plus 4.26s test time.
  - Focused test after review fixes: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_0 --features nlp -- --nocapture` passed in 7.07s real time after recompiling the changed helper; test execution took 3.29s.
  - Click cases added: 3 LSP click cases plus 4 marker/path parser regression tests.
  - Slowest fixture/operation: `milestone_0_java_smoke`, case `call resolves to declaration`, marker `call_target`, operation `definition`, 35 ms after review fixes.
  - Ignored stress runtime: not applicable.

## Context and Orientation

LSP means Language Server Protocol, the editor protocol used for requests such as `textDocument/definition` and `textDocument/references`. Bifrost serves LSP over stdio from the `bifrost --lsp` process, and integration tests drive that process with `tests/common/lsp_client.rs::LspServer`.

A click fixture is a small in-test project containing source markers. Inline markers such as `<call_run>` are stripped before the file is written, and the marker's position becomes the LSP click position. Caret comments such as `// ^call_run` are also supported for later milestones when placing inline markers would make the source harder to read. Each test case names a marker, an LSP operation, and an expected response shape.

Response locations are compared by file URI plus LSP range start line and character. The expected locations are also markers, so tests do not need brittle raw line and column literals.

## Plan of Work

Milestone 0 adds `tests/common/lsp_click.rs`, exports it from `tests/common/mod.rs`, and creates `tests/lsp_click_around_regression.rs` with a Java smoke fixture. The smoke fixture must prove that the harness can run a successful definition lookup, a successful references lookup, and an expected-empty definition lookup.

Milestones 1 through 11 add one language fixture per milestone in `tests/lsp_click_around_regression.rs`. Each milestone should keep the fixture realistic but small, cover at least one positive and one negative or ambiguity case, and update this plan before review and commit.

Milestone 12 adds ignored stress fixtures for at least Go embedded promotion and Rust trait implementations, then runs the final validation sweep.

After each milestone, run focused tests, run Brokk Guided Review in uncommitted-changes mode, fix accepted findings, rerun focused tests, update this plan including timings, stage only files touched by the milestone, and commit directly on the current branch.

## Concrete Steps

Run commands from the repository root:

    cd /Users/dave/.codex/worktrees/bc63/bifrost

Milestone 0 focused validation:

    BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_0 --features nlp

Milestone language validation:

    BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression <language_filter> --features nlp

Final validation:

    BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression --features nlp
    BIFROST_SEMANTIC_INDEX=off cargo test --test bifrost_lsp_server implementation --features nlp
    BIFROST_SEMANTIC_INDEX=off cargo test --test bifrost_lsp_server type_hierarchy --features nlp
    cargo fmt
    cargo clippy-no-cuda
    git diff --check

Ignored stress validation:

    BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression --features nlp -- --ignored stress

## Validation and Acceptance

The shared harness is accepted when the Milestone 0 smoke test passes and its failure messages include fixture name, case name, marker, operation, elapsed milliseconds, and the raw response when an assertion fails.

Each language milestone is accepted when the new language filter passes before review, Brokk Guided Review has been run on the milestone diff, accepted findings have been fixed, the focused tests pass again, timings are recorded here, and a milestone commit has been created.

Normal tests must be deterministic. Do not fail because a request is slow. Timing belongs in diagnostics and this plan's `Timing Log`.

## Idempotence and Recovery

The fixtures use temporary directories and can be rerun safely. If a language fixture exposes a real analyzer failure, update `Surprises & Discoveries` with the evidence, fix forward in structured analyzer code, and keep the failing fixture as the regression. If Brokk Guided Review cannot run, record the blocker and stop before committing that milestone.

Do not use `git add -A`. Stage only files changed in the current milestone. Do not push or open a pull request unless explicitly asked.

## Artifacts and Notes

Revision note, 2026-07-07 / Codex: Created the plan and started Milestone 0 with a shared LSP click fixture helper. The initial helper supports inline markers, caret comment markers, location-bearing LSP response normalization, expected-empty assertions, hover substring assertions, hierarchy relation requests, and per-click elapsed time capture.

Revision note, 2026-07-07 / Codex: Milestone 0 pre-review implementation and focused validation are complete. The smoke fixture passed definition, references, and expected-empty definition assertions. Brokk Guided Review is the next gate before any commit.

Revision note, 2026-07-07 / Codex: Completed the Milestone 0 Guided Review gate. Accepted findings were fixed with path validation, safer marker parsing, UTF-16 columns, exact location assertions, non-panicking hierarchy prepare handling, and parser regression tests. `cargo fmt --check`, `git diff --check`, and focused Milestone 0 tests pass.
