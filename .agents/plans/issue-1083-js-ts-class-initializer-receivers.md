# Model JavaScript and TypeScript class initializer receivers

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agents/PLANS.md` from the repository root and must be maintained in accordance with that file.

## Purpose / Big Picture

The JavaScript and TypeScript semantic adapter currently discovers methods, functions, arrows, and class static blocks as executable procedures, but it does not create a procedure for an initialized class field. As a result, `this` in instance and static field values has no source-backed execution owner, and an arrow inside a field can capture the receiver of an unrelated enclosing method. Class heritage and computed member names have the opposite requirement: they execute while the class definition is evaluated and therefore retain the surrounding receiver.

After this change, semantic artifacts for JavaScript, JSX, TypeScript, and TSX will contain initializer procedures for initialized fields. Instance initializers will own the constructed-instance receiver, static field initializers and static blocks will own the class-constructor receiver, and nested arrows will capture those exact receivers. The enclosing procedure will evaluate heritage and computed member names in deterministic source order without traversing field values, method bodies, or static blocks. The behavior is demonstrated through source-backed conformance, value-flow, and control-flow tests.

## Progress

- [x] (2026-07-23 08:16+02:00) Confirmed issue requirements, diagnosed the adapter, and fast-forwarded the existing issue branch to `origin/master` at `fb268ff7`.
- [x] (2026-07-23 08:16+02:00) Created this self-contained ExecPlan.
- [x] (2026-07-23 08:23+02:00) Milestone 1: materialized initialized fields, split class-member child ownership and declaration paths, and passed focused JS/JSX/TS/TSX conformance plus the pre-existing class-field-arrow regression.
- [x] (2026-07-23 08:33+02:00) Milestone 2: published instance/static initializer receivers, lowered initializer expressions without return effects, modeled heritage/computed-name class evaluation, bumped adapter fingerprints, and passed focused receiver/CFG/cancellation/deep-control tests.
- [x] (2026-07-23 09:27+02:00) Milestone 3: passed the complete semantic and all-feature Rust gates, addressed every confirmed specialist-review finding, reran strict Clippy, and recorded the final outcome.

## Surprises & Discoveries

- Observation: the JavaScript/TypeScript lowerer was recently decomposed by #1094.
  Evidence: the relevant implementation now lives in `src/analyzer/js_ts/semantic/{mod,inventory,syntax,values,control,tests}.rs`; the decomposition deliberately preserved the old behavior and adapter versions.

- Observation: the neutral semantic intermediate representation already supports every required row.
  Evidence: `ProcedureKind::Initializer`, `DeclarationSegmentKind::Initializer`, receiver values, static procedure properties, lexical parents, captures, and deferred-execution gaps are already used by the Java adapter and class static blocks.

- Observation: a correct fix must split both lexical parent and declaration path for children of fields and methods.
  Evidence: field values execute under an initializer while computed field names execute outside it; method bodies and parameters execute under the method while computed method names execute outside it. Changing only `lexical_parent` would still place a computed-name arrow under the wrong declaration path.

- Observation: once fields became procedures, the existing class-field-arrow selector matched both the initializer entry and nested lambda entry.
  Evidence: the focused pre-existing regression reported both `type:Worker::initializer:run` and `type:Worker::initializer:run::lambda:run`; selecting the complete lambda declaration path preserves the original assertion without hiding the new boundary.

- Observation: class declarations were previously used as an example of terminal unknown control syntax in a broad CFG boundary test.
  Evidence: after structured class-definition lowering, the full `semantic_cfg_contract` binary correctly showed `class Local {}` reaching its following call. The test now reserves terminal assertions for genuinely unsupported control constructs and separately proves the class continuation.

- Observation: TypeScript class heritage and member syntax mix runtime and erased forms under common grammar containers.
  Evidence: specialist review found that an implements-only clause, overload/abstract/declare computed members, and decorators could otherwise be misclassified as runtime expressions. Structured kind/modifier checks now exclude erased forms, while decorators publish a terminal `NormalControlFlow` unsupported gap.

- Observation: initializer input discovery cannot safely scan the whole field or static-block range for formal parameters.
  Evidence: the shared formal-parameter helper deliberately finds nested parameter owners within a range, which could duplicate a nested arrow's parameters onto its initializer. Initializers now skip formal-parameter layout entirely and emit only their owned receiver.

- Observation: the macOS toolchain paths mixed rustup Cargo/rustc with Homebrew rustdoc even though both reported Rust 1.96.0.
  Evidence: the first doc-test phase rejected compatible-looking artifacts with `E0514`; pinning `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin` first in `PATH` made the isolated doc phase and final monolithic all-feature run pass. The sandboxed full run also hit the repository's three known process-I/O permission tests, while the unrestricted run passed them.

## Decision Log

- Decision: keep the change private to the JavaScript/TypeScript adapter and bump only its adapter fingerprints.
  Rationale: the neutral IR contract does not change. JavaScript will move from `javascript-value-semantics-v6` to `v7`, and TypeScript from `typescript-value-semantics-v7` to `v8`.
  Date/Author: 2026-07-23 / Codex

- Decision: treat every JS/TS initializer as receiver-owning even when `ProcedureProperties::is_static` is true.
  Rationale: an instance field initializer receives the constructed instance, while a static field initializer or class static block receives the class constructor. This is deliberately different from the adapter's existing static-method policy, which remains unchanged.
  Date/Author: 2026-07-23 / Codex

- Decision: select child execution context from structured tree-sitter fields.
  Rationale: a field's `value` child belongs to its initializer, whereas its `name` or `property` child stays in the outer class-definition context. A method's `name` stays outer, while its body and parameters belong to the method. Source-text parsing would be less general and is prohibited by repository policy.
  Date/Author: 2026-07-23 / Codex

- Decision: evaluate only heritage runtime values and computed member-name nodes in the surrounding procedure.
  Rationale: field values, method bodies, and static blocks have their own procedures. Type-only heritage and decorators are outside this issue. Using the existing iterative expression scheduler preserves source order, budgets, cancellation, and stack safety.
  Date/Author: 2026-07-23 / Codex

- Decision: treat decorators as an explicit conservative boundary rather than partially lowering them.
  Rationale: class, member, and parameter decorator ordering is outside this issue, but silently continuing would under-approximate calls and exceptions. Decorated class definitions now publish a terminal point-scoped unsupported normal-control gap, and decorator subtrees do not publish misleading nested procedure or receiver-capture facts.
  Date/Author: 2026-07-23 / Codex

- Decision: restrict class-definition computed-name evaluation to runtime members and give initializers no formal-parameter layout.
  Rationale: TypeScript `implements`, overload signatures, abstract/declare members, and nested callable parameters are not inputs executed or owned by the initializer procedure. Structured grammar kinds, modifier tokens, and procedure kind provide exact boundaries without source parsing.
  Date/Author: 2026-07-23 / Codex

## Outcomes & Retrospective

Milestone 1 publishes initialized fields as source-backed initializer procedures in all four JS/TS parser flavors. Named and static identities, anonymous computed-field ordinals, and exact value-versus-computed-name arrow parenting are covered by `javascript_typescript_class_field_initializers_are_source_backed`. The pre-existing `javascript_scoped_gaps_and_class_field_arrow_name_are_source_backed` test was tightened to select the nested lambda by its complete declaration path now that the field initializer is itself executable.

Milestone 2 makes every initializer receiver-owning, including static fields and blocks, while preserving the old non-static method/function policy. `javascript_typescript_class_initializers_own_receivers` proves direct receiver flow and immediate-parent arrow captures for instance fields, static fields, static blocks, heritage, and computed names in both languages. `typescript_class_definition_and_initializer_execution_stay_separate` proves source-ordered outer evaluation, isolated field/method/static-block call sites, deterministic rendering, no manufactured return rows, and explicit deferred-scheduling gaps. The new AST collection is cancellation-polled, and the existing deep-control and nested-type boundary regressions remain green.

Milestone 3 hardened the implementation through five read-only specialist reviews covering security, duplication, issue intent, DevOps/CI, and architecture. Confirmed findings led to one shared child-ownership predicate, streaming cancellation-aware member collection, exact exclusion of implements/type-only members, conservative decorator boundaries and enumeration suppression, and receiver-only initializer inputs. The final focused binaries passed 132 semantic-language conformance tests, 41 CFG contract tests, and 14 value-language contract tests. Strict `cargo clippy --all-targets --all-features -- -D warnings` passed through the isolated-target helper. The final monolithic `cargo test --features nlp,python -- --test-threads=1` passed under the consistently pinned rustup toolchain: 1,703 library tests passed with 5 ignored, every binary and integration target passed, and rustdoc passed with zero doctests. Formatting and `git diff --check` are clean.

## Context and Orientation

The repository root is the working directory. `src/analyzer/js_ts/semantic/mod.rs` registers one flavor-driven lowerer for JavaScript/JSX and TypeScript/TSX, publishes adapter identities, relays lexical receiver demand, and lowers the enumerated procedures. An adapter identity is a cache fingerprint; changing behavior requires changing its version bytes so stale semantic artifacts cannot be reused.

`src/analyzer/js_ts/semantic/inventory.rs` walks the tree iteratively and constructs `ProcedureSpec` records. Every record has a dense `ProcedureId`, source-backed locator, lexical parent, body node, kind, and properties. Procedure IDs are allocated parent before child. Declaration paths are the stable file/type/procedure segments used to identify a procedure independently from its dense ID.

`src/analyzer/js_ts/semantic/syntax.rs` owns tree-sitter policy. `callable_shape` identifies which syntax nodes become procedures. `callable_name`, `field_matches`, and the execution-boundary helpers interpret structured fields and prevent nested execution from leaking into an outer scan.

`src/analyzer/js_ts/semantic/values.rs` creates parameters, receivers, captures, locals, and source-backed values. `src/analyzer/js_ts/semantic/control.rs` builds each procedure's control-flow graph through an explicit work stack. A control-flow graph, abbreviated CFG, records entry/exit points, evaluation order, and effects. A semantic gap is an explicit row saying that a capability such as deferred scheduling is not yet represented.

The behavior-level integration tests live in `tests/semantic_language_conformance.rs`, `tests/semantic_value_language_contract.rs`, and `tests/semantic_cfg_contract.rs`. Their shared `InlineTestProject` harness creates small source projects without bespoke temporary-directory setup.

## Plan of Work

Milestone 1 changes discovery and stable identity. Extend `callable_shape` so an initialized `field_definition` or `public_field_definition` becomes a non-synthetic `ProcedureKind::Initializer` with `DeclarationSegmentKind::Initializer`, its structured `value` as the body, and staticness derived from the syntax token. A declaration without a value remains absent. Derive an initializer name only from a non-computed structured `name` or `property`; computed fields remain anonymous and use the existing sibling-ordinal allocator.

Refactor iterative enumeration to preserve two contexts after discovering a procedure: the outer context and the procedure context. Choose both `lexical_parent` and `declaration_path` for every child. A field sends only its `value` child into the initializer context. A method sends its structured `name` child to the outer context and its body, parameters, and other existing children to the method context. Other callable shapes retain their current behavior. Keep traversal parent-before-child, iterative, budget-checked, and cancellation-aware. Add conformance tests across `.js`, `.jsx`, `.ts`, and `.tsx` proving initialized-only discovery, names, staticness, anonymous ordinals, and exact field-arrow parenting. Format, run the focused conformance tests, update this document, and checkpoint commit the milestone.

Milestone 2 changes receiver and CFG semantics. Add one adapter-private receiver-ownership predicate and use it both when filtering lexical capture demand in `mod.rs` and when emitting receiver inputs in `values.rs`. Initializers always own receivers; ordinary methods, constructors, and functions keep the existing non-static rule. This allows arrows under instance fields, static fields, and static blocks to capture the immediate initializer receiver without inheriting an outer receiver.

In `control.rs`, lower expression-bodied initializers directly to normal exit instead of manufacturing a return value and `ProcedureReturn` effect. Publish a field-initializer `DeferredExecution` gap until construction and class-evaluation scheduling are stitched, while preserving the existing static-block gap. Add structured class-definition evaluation for `class`, `class_declaration`, and `abstract_class_declaration`: collect the JavaScript heritage expression or TypeScript `extends_clause` value, then computed `name` or `property` nodes from class members in source order. Schedule those nodes through the existing expression work stack. Do not schedule type-only heritage, decorators, field values, method bodies, or static blocks.

Add value-flow tests for a nested class containing `extends this.Base`, `[this.key] = () => this`, instance and static direct/arrow fields, direct and arrow-producing computed method names, and a static block with direct/arrow `this`. Assert that computed names use the surrounding receiver, field/static-block values use their initializer receivers, arrow capture slots name the exact immediate parent, and the outer procedure is not polluted by field/static-block facts. Add CFG tests proving heritage/computed-name order, separation of execution boundaries, direct initializer normal completion, no return effects, and explicit deferred gaps. Add cancellation coverage for any new bounded class-member collection and repeat-render checks for deterministic locators. Format, run the three focused integration suites, update this document, and checkpoint commit the milestone.

Milestone 3 runs the repository gates and independent review. Run the complete relevant integration binaries, the full `nlp,python` suite, formatting, diff checks, and strict all-target/all-feature Clippy. Compute the complete change from `origin/master` and run the guided security, duplication, intent, operational, and architecture reviewers in parallel. Fix every confirmed finding, rerun the affected tests and gates, update this plan with evidence and the retrospective, and make the required post-review checkpoint commit. Do not push or open a pull request unless the user explicitly requests it.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/ba23/bifrost`.

Milestone 1 focused checks:

    cargo fmt
    cargo test --test semantic_language_conformance javascript_typescript_class_field_initializers_are_source_backed -- --exact
    git diff --check

Milestone 2 focused checks:

    cargo fmt
    cargo test --test semantic_language_conformance javascript_typescript_class_field_initializers_are_source_backed -- --exact
    cargo test --test semantic_value_language_contract javascript_typescript_class_initializers_own_receivers -- --exact
    cargo test --test semantic_cfg_contract typescript_class_definition_and_initializer_execution_stay_separate -- --exact
    cargo test --test semantic_cfg_contract typescript_adapter_lowers_deep_control_iteratively -- --exact
    git diff --check

Final validation:

    cargo fmt --check
    cargo test --test semantic_language_conformance
    cargo test --test semantic_value_language_contract
    cargo test --test semantic_cfg_contract
    cargo test --features nlp,python -- --test-threads=1
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    git diff --check

The focused commands must report the named tests as passed. The complete commands must finish with no failed tests, no formatting changes, no diff errors, and no Clippy warnings. On this macOS host, commands that invoke rustdoc must put `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin` first in `PATH`; all-feature tests additionally need the repository's established PyO3 dynamic-lookup `RUSTFLAGS`.

## Validation and Acceptance

Acceptance is behavioral:

1. Every initialized instance or static field in JavaScript, JSX, TypeScript, and TSX produces one source-backed initializer procedure; uninitialized declarations do not.
2. A simple field name appears in the initializer declaration segment. Multiple computed fields are anonymous but have distinct, repeatable sibling ordinals.
3. Direct `this` in an instance initializer flows from that initializer's receiver. Direct `this` in a static field or static block flows from the class-constructor receiver represented by that static initializer procedure.
4. An arrow under a field value has the initializer as both lexical parent and declaration-path parent, and its capture binding uses the initializer receiver. It never captures an unrelated outer method receiver.
5. Heritage and computed field/method names remain in the surrounding procedure. A nested arrow in a computed method name is parented to that surrounding context, never the method being named.
6. Heritage and computed names are connected in deterministic source order. Field values, method bodies, and static blocks are absent from that outer path and remain in their own procedures.
7. Expression-bodied initializers reach normal exit without `ProcedureReturn`, return values, or return-flow effects, and they publish an explicit deferred-scheduling gap.
8. Existing semantic tests remain green and the adapter remains iterative, bounded, and cancellation-aware.

## Idempotence and Recovery

All edits are source changes and tests; there are no migrations or destructive operations. Formatting and test commands are safe to repeat. The existing branch must remain checked out. Stage only the files changed for each milestone, never use `git add -A`, and preserve unrelated worktree changes if any appear. Use `scripts/with-isolated-cargo-target.sh` rather than manually creating a named temporary Cargo target directory.

If a milestone test fails, keep the ExecPlan progress entry marked partial, record the failure under `Surprises & Discoveries`, fix the root cause using structured AST/IR support, and rerun that milestone before committing.

## Artifacts and Notes

Issue #1083 is a follow-up to the receiver/capture work in #1076. Exact constructor insertion around derived `super()`, fully composing initializer fragments into constructor/class-evaluation ICFGs, general module-top-level execution, and decorator evaluation remain explicit non-goals.

The Bifrost code-intelligence server was not bound to this worktree during planning and exposed no activation tool. Repository inspection therefore used live source, `rg`, and git history. This tooling limitation does not change the implementation or validation contract.

## Interfaces and Dependencies

No public Rust API, wire type, database schema, or neutral semantic IR type changes. The implementation uses existing tree-sitter `Node` fields, `ProcedureSpec`, `ProcedureProperties`, semantic values/captures, `ProcedureCfgBuilder`, `Work::Expression`, and `schedule_expressions`.

The only durable identity changes are:

    JAVASCRIPT_ADAPTER_VERSION = b"javascript-value-semantics-v7"
    TYPESCRIPT_ADAPTER_VERSION = b"typescript-value-semantics-v8"

Revision note (2026-07-23): Created the initial self-contained implementation plan after confirming the current decomposed lowerer layout and synchronizing the issue branch with `origin/master`. Updated after Milestone 1 to record discovery/identity behavior and focused validation. Updated after Milestone 2 with receiver, CFG, cancellation, deterministic-render, and adjacent-regression evidence. Finalized after Milestone 3 with specialist-review fixes, complete validation evidence, and the toolchain/sandbox observations needed to reproduce the gates.
