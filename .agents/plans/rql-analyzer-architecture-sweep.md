# Split the RQL analyzer execution path into owned modules

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Recent RQL work added receiver evidence, occurrence rows, lexical resolution, materialization, paths, edges, and assertions. The behavior is correct, but some files now own several different tasks. This makes changes difficult to review and increases conflict risk.

After this work, each large RQL analyzer file has one clear task. The public API and query results do not change. Focused tests, formatting, Clippy, and policy checks give the proof.

## Progress

- [x] (2026-08-05) Inspected the clean worktree and fetched `origin/master`.
- [x] (2026-08-05) Fast-forwarded detached HEAD from `db9f60c32` to `dc0ba96f2`.
- [x] (2026-08-05) Measured the large files and mapped recent RQL commits.
- [x] (2026-08-05) Ran the initial `bifrost.code-smells` check. It was unreliable because the policy deadline expired.
- [x] (2026-08-05) Filed issue #1676 for a 61.577-second `most_relevant_files` usage-graph call.
- [x] (2026-08-05) Milestone 1: Split receiver-query tests and split source validation into RQL, JSON, shared, and test modules.
- [x] (2026-08-05) Milestone 2: Split the public CodeQuery result contract into seven domain modules and a small facade.
- [x] (2026-08-05) Milestone 3: Split structural search execution into eight owned modules and keep the facade below 4,000 lines.
- [x] (2026-08-05) Milestone 4: Split the large structural and cross-language test modules into nine behavior files and two small facades.
- [ ] Milestone 5: Extract policy assertion evaluation from the general policy evaluator.
- [ ] Milestone 6: Run all focused and repository validation gates.

## Surprises & Discoveries

- Observation: The detached checkout was two commits behind `origin/master`.
  Evidence: `git rev-list --left-right --count HEAD...origin/master` returned `0 2`. Both commits changed the RQL files in scope.

- Observation: The latest receiver evidence commit added about 2,000 lines to structural search and result handling.
  Evidence: Commit `8f11273e4` added 520 lines to `structural/search/mod.rs` and 1,106 lines to `structural/search/results.rs`.

- Observation: The baseline policy run did not produce a reliable result.
  Evidence: `run_policy` returned status `unreliable`, exit status 2, and `deadline_exceeded` after 3,786 ms of evaluation.

- Observation: Usage-graph relevance ranking is not interactive on this workspace.
  Evidence: The usage-graph request took 61.577 seconds. The same request with history and imports took 3.043 seconds. Issue #1676 records the exact request.

- Observation: RQL and JSON validation shared three typed validators.
  Evidence: The compiler found shared lexical-environment option metadata, regex validation, capture-name validation, and parameter-name validation after the first split.

- Observation: Only three result-contract items needed wider internal visibility.
  Evidence: Semantic rendering needs two label methods. The search engine and tests need the detailed-result invariant check.

- Observation: The structural search facade can stay below 4,000 lines without a new abstraction layer.
  Evidence: The facade is 3,992 lines. Eight child modules contain execution, seeds, imports, pipeline steps, receivers, relations, row relations, and rendering.

- Observation: The default Cargo and Clippy executables use incompatible LLVM builds on this host.
  Evidence: Cargo used LLVM 22.1.2 and Clippy used LLVM 22.1.6. The consistent Homebrew toolchain passed the isolated strict workspace gate.

## Decision Log

- Decision: Limit this sweep to the RQL analyzer execution path and its assertion-policy consumer.
  Rationale: `crates/bifrost-policy/src/source.rs` is a separate RQLP authoring front-end. Mixing its parser redesign into execution refactoring would expand the risk without improving analyzer ownership.
  Date/Author: 2026-08-05 / Codex

- Decision: Preserve all public names and wire formats.
  Rationale: This is an architecture change. A consumer must compile without path or JSON changes.
  Date/Author: 2026-08-05 / Codex

- Decision: Use real Rust child modules, not `include!` files.
  Rationale: Real modules make ownership clear. They also let the compiler check each boundary.
  Date/Author: 2026-08-05 / Codex

- Decision: Widen visibility only to `pub(super)` when a parent or sibling module needs an item.
  Rationale: The split must not create a larger crate or public API.
  Date/Author: 2026-08-05 / Codex

- Decision: Keep files near or below 4,000 lines. Prefer files below 3,000 lines when one clear boundary exists.
  Rationale: The user requested a practical 3,000-to-4,000-line limit. Cohesion is more important than equal file sizes.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

Milestone 1 replaced two large files with owned modules. Receiver-query production code is 3,677 lines. Query source validation now has a 501-line facade, 2,027-line RQL validator, 1,771-line JSON validator, 176-line shared validator, and 984-line test module. The 27 receiver-query tests and 33 query-source tests pass.

Milestone 2 replaced the 4,727-line result contract with a 421-line facade and seven files from 260 to 1,577 lines. All 93 structural-search unit tests pass. The public cancellable profile test also passes.

Milestone 3 replaced the 12,543-line structural search engine with a 3,992-line facade and eight files from 322 to 2,213 lines. All analysis targets compile. All 93 structural-search unit tests and 116 cross-language query-pipeline tests pass. The strict featureless workspace Clippy gate also passes.

Milestone 4 replaced the 5,156-line structural-search test file with four files from 905 to 1,501 lines and a 34-line facade. It replaced the 6,454-line cross-language pipeline test file with five files from 620 to 2,994 lines and a 42-line facade. All 93 structural-search tests and 116 cross-language pipeline tests pass after the move.

## Context and Orientation

All paths are relative to the repository root.

RQL is Bifrost's structural query language. A query first becomes a typed `CodeQuery`. The planner converts it to a physical plan. Structural search executes that plan against analyzer facts. Public result types then serialize the rows, proof data, and diagnostics.

`crates/bifrost-analysis/src/analyzer/structural/query/source.rs` is 5,447 lines. It validates RQL and JSON source and contains about 990 lines of unit tests. Its RQL and JSON validation paths use one shared diagnostic accumulator.

`crates/bifrost-analysis/src/analyzer/structural/search/mod.rs` is 12,543 lines. It owns execution state, plan execution, seed access, pipeline dispatch, receiver analysis, reference and hierarchy expansion, rendering, and budget diagnostics. Existing child modules already own occurrences, environments, paths, materialization, edges, semantic domains, and flow domains.

`crates/bifrost-analysis/src/analyzer/structural/search/results.rs` is 4,727 lines. It contains the public result contract for structural, semantic, flow, receiver, lexical, path, and edge rows. It also contains result completion and diagnostic types.

`crates/bifrost-analysis/src/analyzer/structural/search/tests.rs` is 5,156 lines. It tests index access, execution budgets, query profiles, semantic projections, and pipeline behavior.

`tests/suite_cross_language/code_query_pipelines.rs` is 6,454 lines. Its first section tests receiver behavior. Later sections test references, calls, hierarchy, paths, occurrences, lexical environment, materialization, and edge behavior.

`crates/bifrost-analysis/src/analyzer/usages/receiver_query.rs` is 5,864 lines. Production code ends at line 3,675. Its inline tests use the rest of the file.

`crates/bifrost-policy/src/evaluator.rs` is 8,089 lines. The assertion evaluator starts near line 951. Its assertion-specific block ends before the shared finding and CVSS projection code near line 3,295. Inline tests start near line 6,426.

The checkout is detached at `dc0ba96f2`. Repository rules do not permit branch creation or branch changes without an explicit user instruction. Checkpoint commits can still record each milestone on detached HEAD.

## Plan of Work

### Milestone 1: Remove unit tests from production files

Convert `crates/bifrost-analysis/src/analyzer/usages/receiver_query.rs` to `receiver_query/mod.rs`. Move its inline tests to `receiver_query/tests.rs`. Production code then has about 3,700 lines.

Convert `crates/bifrost-analysis/src/analyzer/structural/query/source.rs` to `source/mod.rs`. Move inline tests to `source/tests.rs`. Then move RQL validation to `source/rql.rs` and JSON validation to `source/json.rs`. Keep public entry points and the shared `Analysis` accumulator in `source/mod.rs`. Use `pub(super)` only for shared helpers.

Run receiver-query unit tests and query-source unit tests. Run `cargo fmt` and `git diff --check`. Commit the milestone with this plan update.

### Milestone 2: Split the public result contract

Keep `structural/search/results.rs` as the facade and common result envelope. Add child modules under `structural/search/results/` for semantic and flow results, receiver results, environment and path results, and diagnostics.

Move types with their small local implementations. Re-export each old name from `results.rs`. Do not change serialization tags, field order, derives, or old paths.

Run the public API, serialization, and query result tests. Run formatting and `cargo check --workspace --all-targets`. Commit the milestone.

### Milestone 3: Split structural search execution

Keep entry points, shared engine types, constants, and module declarations in `structural/search/mod.rs`.

Move physical-plan execution and union scheduling to `search/execution.rs`. Move structural seed access and seed execution to `search/seeds.rs`. Move per-step dispatch and shared pipeline accounting to `search/pipeline.rs`.

Move receiver-specific query and evidence projection to `search/receiver.rs`. Move calls, references, members, and hierarchy expansion to `search/relations.rs`. Move public row and provenance rendering to `search/render.rs`.

Existing focused modules remain the owners of occurrences, environments, paths, materialization, edges, typestate, value flow, and taint.

Use the compiler to find each required boundary. Widen only child entry points and shared private types to `pub(super)`. Do not add Boolean mode parameters or duplicate caches.

Run the structural-search unit tests, planner tests, cross-language structural tests, CodeQuery public API tests, and query pipeline tests. Run formatting and strict featureless Clippy. Commit the milestone.

### Milestone 4: Split large test modules

Convert `structural/search/tests.rs` to `structural/search/tests/mod.rs`. Group tests into index access, execution and budgets, and semantic projection modules. Keep shared fixtures and assertions in the parent test module.

Convert `tests/suite_cross_language/code_query_pipelines.rs` to `tests/suite_cross_language/code_query_pipelines/mod.rs`. Group tests into receiver, calls and references, and environment and materialization modules. Keep shared `run`, serialization, and result helpers in the parent.

Do not add new test binaries. The existing `mod code_query_pipelines;` line in the suite harness must continue to resolve.

Run both moved test groups and formatting. Commit the milestone.

### Milestone 5: Extract assertion evaluation

Move the assertion-specific evaluator from `crates/bifrost-policy/src/evaluator.rs` to `crates/bifrost-policy/src/assertion_evaluator.rs`. The new file owns assertion subject collection, occurrence and edge assertions, identity assertions, and their private support types.

Keep shared finding construction, severity, completeness, organizational risk, CVSS, taint, and typestate evaluation in `evaluator.rs`. Move inline evaluator tests to `evaluator/tests.rs` if the production facade remains above 4,000 lines.

Keep `PolicyEvaluator` behavior and all report shapes unchanged. Run assertion-policy, policy evaluation, policy CLI, and policy rendering tests. Run formatting and strict featureless Clippy. Commit the milestone.

### Milestone 6: Complete validation

Run `cargo fmt --all -- --check` and `git diff --check`.

Run focused featureless Rust tests for all moved modules. Run `cargo clippy --workspace --all-targets -- -D warnings` through `scripts/with-isolated-cargo-target.sh`.

Run one final Bifrost policy request with `bifrost.code-smells`, evaluation date `2026-08-05`, and `fail_on: warning`. The repository has no named executable policy roots. Treat an unreliable result as failed validation and record it exactly.

Review file sizes. Every selected production or test file must be below 4,000 lines. Record any deliberate exception and its cohesion reason.

## Concrete Steps

Run all commands from the repository root:

    /Users/dave/.codex/worktrees/bcf3/bifrost

Use these focused test families as the minimum set. Exact package flags can change if Cargo reports a more specific target name.

    cargo test -p brokk-bifrost-analysis --lib receiver_query
    cargo test -p brokk-bifrost-analysis --lib structural::query::source
    cargo test -p brokk-bifrost-analysis --lib structural::search
    cargo test --test structural_search_planner
    cargo test --test structural_search_cross_language
    cargo test --test code_query_public_api
    cargo test --test code_query_pipelines
    cargo test -p brokk-bifrost-policy --lib assertion

Use featureless validation unless a moved test requires Python. Do not enable NLP for this refactor.

## Validation and Acceptance

The old public Rust paths must compile without consumer edits. Serialized JSON and text results must remain byte-equivalent in existing tests.

All focused tests must pass. Formatting, strict Clippy, and whitespace checks must pass.

Each selected file must have one clear owner. No selected file can exceed 4,000 lines without a recorded reason.

The final policy result must be `clean`. If the tool returns `unreliable`, the plan must record the failed gate and its diagnostics.

## Idempotence and Recovery

Each milestone is code motion with focused tests. Repeat formatting and tests safely.

Commit each milestone on detached HEAD. Stage only files changed by that milestone. Do not create or change a branch.

If a move fails, use `git diff` to compare the old content with the new modules. Fix forward. Do not reset or discard unrelated files.

## Artifacts and Notes

Initial large-file counts:

    12543 crates/bifrost-analysis/src/analyzer/structural/search/mod.rs
     6454 tests/suite_cross_language/code_query_pipelines.rs
     5864 crates/bifrost-analysis/src/analyzer/usages/receiver_query.rs
     5447 crates/bifrost-analysis/src/analyzer/structural/query/source.rs
     5156 crates/bifrost-analysis/src/analyzer/structural/search/tests.rs
     4727 crates/bifrost-analysis/src/analyzer/structural/search/results.rs
     8089 crates/bifrost-policy/src/evaluator.rs

The policy baseline used only `bifrost.code-smells`. `.agents/docs/issue-1204-policy-pack-validation.md` states that the repository has no canonical executable policy roots.

## Interfaces and Dependencies

Do not add dependencies or workspace crates.

Keep all names currently reachable through `analyzer::structural::search`, `analyzer::structural::query::source`, and `analyzer::usages::receiver_query` at the same paths.

Keep all serde tags, field names, and result-domain labels unchanged.

Use existing analyzer structures. Do not add source-text parsing, regular-expression fallbacks, or string-splitting substitutes.

Revision note (2026-08-05): Created the plan after the live architecture, Git history, file sizes, policy state, and navigation latency were inspected.

Revision note (2026-08-05, Milestone 1): Recorded the receiver-query and source-validation splits, the shared typed validators, file sizes, and passing focused tests.

Revision note (2026-08-05, Milestone 2): Recorded the result-domain split, minimum visibility changes, file sizes, and passing structural-search tests.

Revision note (2026-08-05, Milestone 3): Recorded the execution split, the 3,992-line facade, and passing unit and cross-language tests.

Revision note (2026-08-05, Milestone 4): Recorded the two behavior-based test splits, file sizes, and passing test groups.
