# Improve Obvious get_definition Receiver And Member Resolution

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md` in this repository. It is self-contained so a future contributor can resume the work from this file and the current working tree alone.

## Purpose / Big Picture

Bifrost exposes `get_definition_by_location`, a searchtools/MCP operation that answers "what indexed definition does this source reference point at?" Issue #222 records usage-to-declaration misses where ordinary member references such as `service.execute`, `$repository->save`, `context.registry`, `this.title`, and `service.execute()` do not consistently resolve to the class member or field they name. After this work, Bifrost should resolve those obvious local receiver/member flows using structured local evidence such as typed parameters, typed locals, constructor-created values, `self`/`this`, simple aliases, class fields, and indexed owner-member declarations. It should not try to become a whole-program type checker.

The observable result is focused Rust tests in `tests/get_definition_test.rs` that call `get_definition_by_location` on small inline projects and return `resolved` with the expected owner-member FQN for the newly supported shapes. Unsupported receiver shapes must continue to return explicit `unsupported_*` or `no_definition` outcomes rather than broad same-name guesses. This plan intentionally does not modify `usagebench`; usagebench expected-failure cleanup is out of scope for this branch.

## Progress

- [x] (2026-06-24T09:54Z) Fetched and rebased branch `222-improve-get_definition_by_location-receiver-and-member-resolution`; Git reported the branch is up to date at `53fad27`.
- [x] (2026-06-24T09:54Z) Confirmed the worktree is clean and on branch `222-improve-get_definition_by_location-receiver-and-member-resolution`, not detached.
- [x] (2026-06-24T09:54Z) Created this issue-specific ExecPlan before code edits.
- [ ] Milestone 2: implement and test JS/TS obvious local flows.
- [ ] Milestone 3: implement and test Python/PHP/Scala obvious flows.
- [ ] Milestone 4: implement and test Rust obvious local method flow.
- [ ] Milestone 5: run final formatting, linting, and retrospective validation.

## Surprises & Discoveries

- Observation: The issue branch already exists and is tracking `origin/222-improve-get_definition_by_location-receiver-and-member-resolution`.
  Evidence: `git status --short --branch` printed `## 222-improve-get_definition_by_location-receiver-and-member-resolution...origin/222-improve-get_definition_by_location-receiver-and-member-resolution`.

## Decision Log

- Decision: Keep `usagebench` edits out of scope.
  Rationale: The user explicitly asked to implement Bifrost capability only and revisit usagebench separately.
  Date/Author: 2026-06-24 / Codex

- Decision: Add only structured local receiver/member support.
  Rationale: The project instructions reject regex/text-search fallbacks and source mini-parsers. Issue #222 asks for simple curated receiver flows, not advanced whole-program inference.
  Date/Author: 2026-06-24 / Codex

## Outcomes & Retrospective

No implementation milestones are complete yet. The current outcome is a clean, rebased branch with this living plan ready for code work.

## Context and Orientation

The public tool entry point is `get_definition_by_location` in `src/searchtools.rs`. Searchtools dispatches into language-specific resolver code under `src/analyzer/usages/get_definition/`. The shared driver is `src/analyzer/usages/get_definition/mod.rs`, which parses the requested file, identifies the reference at the requested location, and delegates by language.

The key concept in this plan is a "receiver": the expression before a member name. In `service.execute`, `service` is the receiver and `execute` is the member. A receiver is "obvious" when local source structure proves its owner type without needing whole-program inference. Examples include a typed parameter such as `service: Service`, a typed PHP parameter such as `Service $service`, a Scala constructor parameter `context: Context`, a Rust local initialized from `Service::new()`, a TypeScript annotation `const greeter: Greeter`, or `this`/`self` inside an indexed class.

`DefinitionLookupIndex` in `src/analyzer/definition_lookup_index.rs` indexes declarations by fully qualified name and by file-local identifier. The desired member lookup shape is to prove an owner FQN, append the member name, and then query the index for `Owner.member`. Language-specific code may also walk existing type hierarchy providers where that support already exists.

`LocalInferenceEngine` in `src/analyzer/usages/local_inference.rs` is the reusable scoped binding helper. It can record local symbols, aliases, shadows, and bounded precise targets. Use it where it fits; do not force syntax-specific parsing into the shared engine.

This plan targets the following files first:

- `src/analyzer/usages/get_definition/js_ts.rs`
- `src/analyzer/usages/get_definition/python.rs`
- `src/analyzer/usages/get_definition/php.rs`
- `src/analyzer/usages/get_definition/scala.rs`
- `src/analyzer/usages/get_definition/rust.rs`
- `tests/get_definition_test.rs`

## Plan of Work

Start with focused tests that describe the desired obvious flows. Use `tests/common/inline_project.rs` through `InlineTestProject`, as required by the analyzer test guidance, so each test defines a tiny project inline. Keep tests in `tests/get_definition_test.rs` near the existing language-specific `get_definition` tests.

For JS/TS, extend `src/analyzer/usages/get_definition/js_ts.rs` without changing the public API. Reuse existing import binder and JS/TS graph resolver helpers when possible. Add support only for locally proven receiver owners: class instances created with `new Owner`, TypeScript typed locals or parameters, simple aliases, `this.member` inside an indexed class, and object/schema property lookup patterns that are already represented in the analyzer index. If a dynamic object shape is not indexed or the receiver cannot be proven, return the existing `no_indexed_definition` style outcome.

For Python, PHP, and Scala, inspect the current resolver behavior before editing because these languages already have substantial receiver paths. Prefer filling narrow gaps, such as Python field/attribute definition priority, PHP typed receiver or `$this` gaps, and Scala constructor-created or typed receiver gaps. Reuse `LocalInferenceEngine`, `ClassRangeIndex`, type hierarchy providers, import binders, and language-specific AST helpers already present in the corresponding graph modules. Do not add source-text splitting fallbacks.

For Rust, reuse the existing AST-based local binding and type lookup helpers in `src/analyzer/usages/get_definition/rust.rs`. Add only the `service.execute` style flow if it is still missing: a local or parameter whose type can be resolved to an indexed struct/impl owner and whose method name is indexed as `Owner.execute`. Add a negative test for an unresolved or shadowed receiver so the resolver does not start guessing by member name.

Keep this ExecPlan current after every milestone. When a milestone passes, update `Progress`, record any new surprise, and add a short `Outcomes & Retrospective` entry. Because the repository instructions say to commit between ExecPlan milestones, checkpoint commit after each completed milestone with a message that explains both the code change and why the milestone boundary is correct.

## Concrete Steps

From `/Users/dave/.codex/worktrees/9edf/bifrost`, run focused tests while developing:

    cargo test --test get_definition_test <test_name>
    cargo test --test get_definition_test

After each milestone, run at least the focused test names added or changed in that milestone. At the final milestone, run:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    git diff --check

If `cargo clippy --all-targets --all-features -- -D warnings` is too slow or blocked by an environment issue, record the exact command and failure in this ExecPlan and run the narrower focused test suite before stopping.

## Validation and Acceptance

Acceptance is behavior-based. A user should be able to call `get_definition_by_location` on newly tested member references and see `status: "resolved"` plus a definition whose FQN is the owner-member FQN asserted by the test. Negative tests must show that unsupported or shadowed receiver shapes return `no_definition`, `unsupported_*`, or another existing explicit terminal state rather than resolving to an unrelated same-name member.

The final branch is accepted when:

- `tests/get_definition_test.rs` contains focused positive and negative tests for the implemented obvious flows.
- `cargo test --test get_definition_test` passes.
- `cargo fmt` has been run.
- `cargo clippy --all-targets --all-features -- -D warnings` passes, or any environment blocker is recorded with focused test evidence.
- `git diff --check` passes.
- No `usagebench` files are modified.

## Idempotence and Recovery

All edits are source and test changes. Re-running tests and formatting is safe. If an attempted resolver change introduces broad false positives, revert only the hunks from that milestone and keep this ExecPlan updated with the failed approach in `Surprises & Discoveries`. Do not revert unrelated user changes if they appear in the worktree.

If branch state becomes confusing, run:

    git status --short --branch
    git diff --stat
    git log --oneline --decorate -5

Use those outputs to update this plan before continuing.

## Artifacts and Notes

Issue #222 is titled "Improve get_definition_by_location receiver and member resolution". Its examples include Rust `service.execute`, Python `service.execute`, PHP `$repository->save`, Scala `service.execute`, JS/TS `greeter.greet`, JS `this.title`, TS `user.name`, and Python attribute access where initialization should be preferred over a later assignment.

## Interfaces and Dependencies

Do not change public API structs or MCP descriptors. The implementation must remain behind the existing `get_definition_by_location` behavior.

Use existing dependencies only:

- `DefinitionLookupIndex` for indexed FQN lookup.
- `LocalInferenceEngine` for bounded local facts where useful.
- Existing tree-sitter AST nodes and language graph helpers for syntax interpretation.
- Existing type hierarchy providers for inherited member lookup only where the language already exposes them.

Revision note 2026-06-24 / Codex: Initial ExecPlan created before implementation because issue #222 spans several language-specific `get_definition` resolvers and requires explicit milestone checkpoints.
