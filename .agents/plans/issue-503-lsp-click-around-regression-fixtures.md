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
- [x] (2026-07-07T10:08Z) Milestone 1: added the Go embedded-promotion click-around fixture, ran focused tests, ran Brokk Guided Review, fixed accepted coverage findings and the exposed Go graph reference bug, reran focused tests, and prepared the milestone commit.
- [x] (2026-07-07T10:25Z) Milestone 2: added the Rust trait/impl click-around fixture, ran focused tests, ran Brokk Guided Review, fixed accepted coverage findings and the exposed Rust default-method / associated-type definition gaps, reran focused tests, and prepared the milestone commit.
- [x] (2026-07-07T10:35Z) Milestone 3: added the PHP interface/trait click-around fixture, ran focused tests, ran Brokk Guided Review, fixed accepted reference coverage findings and the exposed PHP factory/interface receiver graph gaps, reran focused tests, and prepared the milestone commit.
- [x] (2026-07-07T10:52Z) Milestone 4: added the Scala extension/trait click-around fixture, ran focused tests, ran Brokk Guided Review, fixed accepted wildcard-import precedence/ambiguity findings, reran focused tests, and prepared the milestone commit.
- [x] (2026-07-07T11:03Z) Milestone 5: added the Java interface/implementation/hierarchy click-around fixture, ran focused tests, ran Brokk Guided Review, fixed accepted wildcard/override coverage findings and the exposed Java method-family reference gap, reran focused tests, and prepared the milestone commit.
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

- Observation: The Go LSP fixture exposed a cross-package reference overmatch for promoted embedded fields. Querying `service.Base.ID` through the LSP references path returned `worker.ID` and `svc.ID` even though definition lookup correctly resolved those selectors to `AuditLog.ID` and `Service.ID`.
  Evidence: The review-added LSP case `base field references include only semantically valid promoted use` failed with three locations. The lower-level regression `go_graph_strategy_respects_imported_embedded_field_promotion_precedence` reproduced the same three hits in the Go usage graph before the fix.

- Observation: The Rust LSP fixture initially documented default trait method calls and `Self::Output` associated-type uses as expected-empty results, but review correctly treated both as relation-heavy sites with structured targets available in the fixture.
  Evidence: Changing `file.describe()` to expect `Worker.describe` and `Self::Output` to expect `Worker.Output` exposed definition gaps. The Rust resolver now resolves typed receiver calls to default trait methods when no concrete impl method exists, and resolves `Self::Output` inside a trait method through the enclosing trait scope.

- Observation: The PHP fixture exposed asymmetric behavior between definition and references for interface-typed and factory-returned receivers.
  Evidence: `textDocument/definition` resolved `$notifier->notify()` to the interface method and, after the PHP definition fix, `$factory->notify()` to the concrete method, but references from `Notifier::notify` initially omitted both call sites. Review strengthened the exact references expectation, leading to PHP graph fixes for interface receiver matching and free-function factory return seeding.

- Observation: The Scala fixture exposed that `textDocument/definition` did not resolve an unqualified top-level member reached through a package wildcard import, even though the references graph already modeled wildcard-imported members.
  Evidence: The first Scala fixture run returned `null` for `helper()` under `import support.*`. The Scala definition resolver now checks wildcard import metadata and the declaration index's direct children before falling through to unresolved callable handling.

- Observation: The first Scala wildcard-import definition fix introduced two review-visible semantic risks: wildcard members could outrank enclosing members, and multiple wildcard imports exposing the same direct member could return multiple go-to-definition targets.
  Evidence: Brokk Guided Review flagged both risks. The final fixture includes `localHelper()` proving enclosing-member precedence and `AmbiguousImports.helper()` proving ambiguous package wildcard imports return empty.

- Observation: The Java fixture exposed that interface method references did not include overriding declarations or concrete receiver calls through implementation types.
  Evidence: Strengthening `Task.run` references to expect `EmailTask.run`, `task.run()`, and `email.run()` initially returned only `task.run()`. The Java usage graph now builds a method-family owner set from type hierarchy descendants/ancestors, matches receiver types against that set, and records related method declarations.

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

- Decision: For Go qualified receiver inference, require both the imported package qualifier and the compatible receiver type name to match.
  Rationale: The previous predicate treated any `service.X` expression as the target owner once `service` was the imported owner package. That incorrectly seeded locals from `service.NewWorker()` and `service.NewService()` while resolving references for `Base.ID`. Carrying a per-namespace receiver-name map preserves structured import matching without source-text fallbacks.
  Date/Author: 2026-07-07 / Codex.

- Decision: Treat expected-empty LSP cases as negative coverage only when the target is intentionally ambiguous or unsupported by the language surface, not when a precise structured target is present in the fixture.
  Rationale: Review found that expected-empty assertions for Rust default trait methods and associated types would have locked in fixable analyzer gaps while still claiming milestone coverage. The fixture now asserts the intended structured definitions and keeps unsupported or ambiguous cases for later milestones explicit.
  Date/Author: 2026-07-07 / Codex.

- Decision: Keep LSP definition and references inverse expectations aligned when a click site has a precise structured target.
  Rationale: In the PHP milestone, definition proved that interface-typed and factory-returned receiver calls had precise targets. Excluding those calls from exact references would have locked in an editor-visible inconsistency. The PHP graph now mirrors the structured receiver inference used by definition for these cases.
  Date/Author: 2026-07-07 / Codex.

- Decision: Cover Scala wildcard imports with a package wildcard top-level function in the LSP fixture, and leave object wildcard member import asymmetry outside this milestone.
  Rationale: Existing lower-level Scala graph coverage already covers object wildcard member imports. The LSP milestone needs a stable wildcard-import click case while keeping the main Scala 3 fixture focused on extensions, precedence, inherited trait defaults, ambiguity, and hierarchy.
  Date/Author: 2026-07-07 / Codex.

- Decision: Resolve Scala package-wildcard direct members only after explicit member imports and enclosing/source-ancestor members, and return no definition when more than one wildcard import contributes a matching direct member.
  Rationale: This keeps get-definition aligned with Scala lookup precedence and the graph resolver's ambiguity model. The helper uses shared Scala import candidate construction instead of a get-definition-only copy.
  Date/Author: 2026-07-07 / Codex.

- Decision: Treat Java method references for inherited/interface methods as a method family when structured hierarchy proves the related owner declares the same method name and arity.
  Rationale: Editor references from an interface or inherited method should include overriding declarations and receiver calls on concrete implementation types, while unrelated same-name methods remain excluded by owner-family and arity checks.
  Date/Author: 2026-07-07 / Codex.

## Outcomes & Retrospective

Milestone 0 is complete. The repository now has a reusable LSP click fixture helper, parser coverage for marker edge cases, a Java smoke fixture for definition/references/empty-result behavior, and timing capture. No production analyzer code was changed.

Milestone 0 Brokk Guided Review outcome: security found path traversal risk in fixture paths; senior-dev, duplication, architecture, and devops found overlapping issues around caret marker corruption, generic syntax collision, exactness of location assertions, UTF-16 column accounting, and hierarchy prepare panics bypassing normal shutdown. Accepted fixes validate fixture paths, require underscores in inline markers, fix caret marker line stripping, count UTF-16 columns, assert exact location lists, avoid `prepare_hierarchy` panics inside relation operations, and preserve LSP shutdown before assertion panics. The InlineTestProject reuse suggestion was not adopted for the reason recorded in the Decision Log.

Milestone 1 is complete. The Go fixture now covers imported factory receiver typing, embedded field and method promotion, explicit field shadowing, same-depth ambiguity returning empty, shallower-vs-deeper promotion, canonical embedded-member references, and promoted base-field references that exclude unrelated same-name selectors.

Milestone 1 Brokk Guided Review outcome: security, duplication, devops, and architecture found no blocking issues. Senior-dev found two coverage gaps in the Go milestone: the fixture did not directly test shallower-vs-deeper promotion for `worker.ID`, and it did not assert that references for `Base.ID` excluded shadowed selectors. Both were accepted. Adding the second case exposed the Go usage graph bug recorded above; the fix narrows qualified receiver inference using structured import/type data, and the lower-level graph regression plus the LSP fixture now pass.

Milestone 2 is complete. The Rust fixture now covers typed trait-method calls resolving to concrete impl methods, explicit trait-path UFCS resolving to the trait method, default trait methods resolving through implemented traits, unrelated same-name inherent methods, trait method references, trait method implementation lookup, trait type implementation lookup, type definition from a type annotation, type hierarchy supertypes/subtypes, associated type use resolution, and associated type implementation lookup.

Milestone 2 Brokk Guided Review outcome: security/correctness and devops found no issues. Duplication found repeated timing-summary boilerplate and weak associated-type coverage; senior-dev and architecture found that expected-empty default-method and associated-type cases hid precise structured relations. Accepted fixes add a local timing summary helper, assert the intended default trait method and `Self::Output` definitions, add `textDocument/implementation` coverage for the trait associated type, and fix Rust definition resolution with structured trait-associated lookup. Adjacent Rust go-to-definition and type-hierarchy suites pass.

Milestone 3 is complete. The PHP fixture now covers interface-typed receiver definitions, concrete receiver definitions, factory-returned receiver definitions, trait methods imported by class `use`, in-class trait method calls, unrelated same-name methods, interface references including implementation declarations and typed/factory/interface receiver calls, trait method references, and implementation lookup for interface methods and types.

Milestone 3 Brokk Guided Review outcome: devops found no issues. Security/correctness, senior-dev, duplication, and architecture all found that the interface method reference expectation undercounted `interface_notify_call` and/or `factory_notify_call`. Accepted fixes strengthened the exact reference expectation, added free-function factory return seeding to PHP get-definition and the PHP graph scanner, and changed PHP graph receiver matching so interface-typed receivers count as references to the interface method. Focused PHP LSP, PHP graph, PHP go-to-definition, formatting, and diff checks pass.

Milestone 4 is complete. The Scala fixture now covers package wildcard imports, same-package relative wildcard extension imports, direct-member precedence over extensions, receiver mismatch, conflicting inherited trait-member ambiguity, trait default inheritance, unrelated same-name methods, references, implementation, and type hierarchy supertypes/subtypes.

Milestone 4 Brokk Guided Review outcome: devops found no issues. Security/correctness and architecture found that the first wildcard-import definition helper returned definitions for ambiguous wildcard imports; senior-dev found that it also ran before enclosing-member lookup; duplication found import-candidate construction drift. Accepted fixes moved wildcard direct-member lookup behind higher-precedence scopes, return no definition when multiple wildcard imports contribute matches, reuse a shared Scala graph import-candidate helper, and add LSP click cases for local precedence and ambiguous package wildcard imports. Focused Scala LSP, Scala get-definition, Scala graph, formatting, and diff checks pass.

Milestone 5 is complete. The Java fixture now covers interface and implementation methods, inherited overrides, constructor/class construction, nested types, wildcard import positive and ambiguous-null cases, references, implementation lookup, and type hierarchy supertypes/subtypes.

Milestone 5 Brokk Guided Review outcome: security/correctness, duplication, and devops found no issues. Architecture found that the interface method references case was too weak because it did not cover override declarations or concrete receiver calls. Senior-dev found that the wildcard ambiguity case needed a positive wildcard-import control and that inherited override relations were structurally present but not exercised. Accepted fixes strengthened the fixture, added Java graph regression coverage, and fixed Java usage graph method-family matching for hierarchy-related owners. Focused Java LSP, Java graph, Java definition, Java import/hierarchy, formatting, and diff checks pass.

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
- Milestone 1: Go
  - Language: Go.
  - Start: 2026-07-07T09:51Z.
  - End: 2026-07-07T10:08Z.
  - Focused test before review: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_1_go --features nlp -- --nocapture` passed in 8.26s real time after recompiling the changed test; test execution took 3.54s.
  - Focused test after review fixes: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_1_go --features nlp -- --nocapture` passed in 6.04s real time after recompiling the Go resolver; test execution took 3.94s. Additional focused graph checks `go_graph_strategy_respects_imported_embedded_field_promotion_precedence` and `go_graph_strategy_respects_go_embedded_promotion_precedence_and_ambiguity` passed.
  - Click cases added: 10 LSP click cases plus 1 lower-level Go usage graph regression.
  - Slowest fixture/operation: `milestone_1_go_embedded_promotion`, case `promoted field resolves through imported factory receiver`, marker `worker_record`, operation `definition`, 76 ms after review fixes.
  - Ignored stress runtime: not applicable.
- Milestone 2: Rust
  - Language: Rust.
  - Start: 2026-07-07T10:08Z.
  - End: 2026-07-07T10:25Z.
  - Focused test before review: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_2_rust --features nlp -- --nocapture` passed in 11.40s real time after recompiling the changed test; test execution took 6.89s.
  - Focused test after review fixes: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_2_rust --features nlp -- --nocapture` passed in 4.87s real time after recompilation was warm; test execution took 4.36s. Additional focused checks `rust_analyzer_goto_definition` and `rust_type_hierarchy_test` passed.
  - Click cases added: 14.
  - Slowest fixture/operation: `milestone_2_rust_trait_impls`, case `trait method call resolves to concrete impl declaration`, marker `file_work_call`, operation `definition`, 54 ms after review fixes.
  - Ignored stress runtime: not applicable.
- Milestone 3: PHP
  - Language: PHP.
  - Start: 2026-07-07T10:25Z.
  - End: 2026-07-07T10:35Z.
  - Focused test before review: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_3_php --features nlp -- --nocapture` passed in 5.95s real time after recompiling the changed test; test execution took 3.37s.
  - Focused test after review fixes: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_3_php --features nlp -- --nocapture` passed in 5.81s real time after recompiling the PHP graph changes; test execution took 4.27s. Additional focused checks for PHP interface receiver graph coverage and `phpactor_goto_definition` passed.
  - Click cases added: 11.
  - Slowest fixture/operation: `milestone_3_php_interface_traits`, case `interface-typed receiver resolves to interface method`, marker `interface_notify_call`, operation `definition`, 43 ms after review fixes.
  - Ignored stress runtime: not applicable.
- Milestone 4: Scala
  - Language: Scala.
  - Start: 2026-07-07T10:35Z.
  - End: 2026-07-07T10:52Z.
  - Focused test before review: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_4_scala --features nlp -- --nocapture` passed in 5.54s real time after recompiling the changed test and Scala definition resolver; test execution took 3.24s.
  - Focused test after review fixes: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_4_scala --features nlp -- --nocapture` passed in 18.02s real time after formatting/recompilation; test execution took 3.64s. Additional focused checks `get_definition_test scala_` and `usages_scala_graph_test scala_graph_` passed.
  - Click cases added: 15.
  - Slowest fixture/operation: `milestone_4_scala_extensions_traits`, case `wildcard imported helper resolves to top-level function`, marker `helper_call`, operation `definition`, 59 ms after review fixes.
  - Ignored stress runtime: not applicable.
- Milestone 5: Java
  - Language: Java.
  - Start: 2026-07-07T10:52Z.
  - End: 2026-07-07T11:03Z.
  - Focused test before review: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_5_java --features nlp -- --nocapture` passed in 5.57s real time after recompiling the changed test; test execution took 3.20s.
  - Focused test after review fixes: `/usr/bin/time -p env BIFROST_SEMANTIC_INDEX=off cargo test --test lsp_click_around_regression milestone_5_java --features nlp -- --nocapture` passed in 5.11s real time after recompiling the Java graph changes; test execution took 3.48s. Additional focused checks `usages_java_graph_test java_graph_strategy_`, `intellij_java_definition`, and `java_imports_and_hierarchy` passed.
  - Click cases added: 14.
  - Slowest fixture/operation: `milestone_5_java_interfaces_hierarchy`, case `interface-typed call resolves to interface method`, marker `task_run_call`, operation `definition`, 117 ms after review fixes.
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

Revision note, 2026-07-07 / Codex: Started Milestone 1 and added the Go embedded-promotion click-around fixture. The pre-review focused Go filter passed, covering imported factory receiver typing, promoted field and method definition, deeper promoted field lookup, explicit field shadowing, same-depth ambiguity returning empty, and declaration-to-reference lookup for the canonical embedded field.

Revision note, 2026-07-07 / Codex: Completed the Milestone 1 Guided Review gate. Accepted review findings expanded the Go fixture to cover shallower-vs-deeper promotion and exact `Base.ID` references. That exposed a structured Go graph bug where qualified receiver inference matched any imported package member by qualifier alone. The fix carries namespace-to-compatible-receiver-name bindings, and focused Go LSP and graph tests now pass.

Revision note, 2026-07-07 / Codex: Started Milestone 2 and added the Rust trait/impl click-around fixture. The pre-review focused Rust filter passes, covering typed trait-method calls resolving to concrete impl methods, explicit trait-path UFCS resolving to the trait method, default trait method and associated-type unsupported definition boundaries, unrelated inherent same-name method definition, trait method references, implementation lookup, type definition from a type annotation, and type hierarchy supertypes/subtypes.

Revision note, 2026-07-07 / Codex: Completed the Milestone 2 Guided Review gate. Accepted review findings strengthened default trait method and associated-type expectations instead of allowing expected-empty placeholders. The resulting resolver fixes use structured Rust trait/type-scope data: typed receiver calls can fall through to visible default trait methods, and `Self::Output` in a trait method resolves through the enclosing trait scope. Focused Rust LSP, Rust go-to-definition, Rust type-hierarchy, formatting, and diff checks pass.

Revision note, 2026-07-07 / Codex: Started Milestone 3 and added the PHP interface/trait click-around fixture. The pre-review focused PHP filter passes, covering interface-typed and concrete typed receiver definitions, factory-returned receiver definition, trait methods imported by class `use`, unrelated same-name methods, interface and trait method references, and implementation lookup for interface methods and types.

Revision note, 2026-07-07 / Codex: Completed the Milestone 3 Guided Review gate. Accepted review findings expanded interface-method references to include the interface-typed call and factory-returned call. The resulting PHP fixes use structured tree-sitter call nodes plus existing PHP type/function resolution and callable return-type helpers; no regex or text fallback was added. Focused PHP LSP, PHP graph, PHP go-to-definition, formatting, and diff checks pass.

Revision note, 2026-07-07 / Codex: Started Milestone 5 and added the Java interface/implementation/hierarchy click-around fixture. The pre-review focused Java filter passes, covering interface and concrete receiver definitions, inherited base methods, unrelated same-name methods, explicit constructor definitions, nested type definitions, ambiguous wildcard imports returning empty, interface references, implementation lookup, and type hierarchy supertypes/subtypes.

Revision note, 2026-07-07 / Codex: Completed the Milestone 5 Guided Review gate. Accepted review findings expanded Java wildcard coverage with a positive single-wildcard type case, strengthened interface method references to include override declarations and concrete receiver calls, and added inherited override implementation coverage. The resulting Java graph fix uses structured type hierarchy family owners and receiver facts; no source-text fallback was added. Focused Java LSP, Java graph, Java go-to-definition, Java import/hierarchy, formatting, and diff checks pass.
