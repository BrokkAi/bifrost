# Decompose the Java and JavaScript/TypeScript semantic lowerers

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The Java and shared JavaScript/TypeScript semantic adapters already implement the intended behavior, but each implementation is one several-thousand-line Rust file that mixes provider registration, procedure discovery, value and memory facts, control-flow lowering, syntax interpretation, and tests. After this change, a contributor can navigate those responsibilities through small, language-owned modules without changing any semantic artifact, adapter fingerprint, public path, execution order, budget accounting, or cancellation behavior. The result is observable by compiling the unchanged provider surfaces and running the unchanged semantic contract suites for Java, JavaScript, JSX, TypeScript, and TSX.

## Progress

- [x] (2026-07-22 19:23Z) Fetched live `origin/master`, created `brokk/issue-1082-decompose-java-and-js-ts-semantic` from commit `7de07c8c`, and confirmed the worktree was clean.
- [x] (2026-07-22 19:23Z) Read issue #1082, inspected both lowerers and their recent history, and identified the stable orchestration, inventory, value, control, syntax, and test seams.
- [x] (2026-07-22 19:23Z) Chose a one-way private module topology and recorded the implementation and validation strategy in this plan.
- [x] (2026-07-22 19:31Z) Captured exact pre-refactor semantic-render digests, artifact-key fingerprints, and `SemanticWork` rows for representative Java, JavaScript, JSX, TypeScript, and TSX fixtures with a temporary test probe.
- [x] (2026-07-22 19:43Z) Decomposed `src/analyzer/java/semantic.rs` into six private modules; `cargo check --all-targets`, the exact five-dialect equivalence probe, `semantic_provider_contract`, Java-filtered language/value contracts, and `git diff --check` passed.
- [x] (2026-07-22 19:44Z) Committed the validated Java milestone, now `de6948ab` after rebasing onto the final review base.
- [x] (2026-07-22 19:52Z) Decomposed `src/analyzer/js_ts/semantic.rs` into the same six private language-local modules while retaining one shared flavor-driven lowerer.
- [x] (2026-07-22 19:52Z) Re-ran the exact five-dialect equivalence probe after both splits; every render digest, artifact key, and `SemanticWork` field matched the pre-refactor baseline, then removed the temporary probe and its fixed temp project.
- [x] (2026-07-22 19:52Z) Ran the unchanged `semantic_language_conformance` (130 passed), `semantic_value_language_contract` (13 passed), and `semantic_provider_contract` (11 passed) suites plus `cargo check --all-targets` and `git diff --check`.
- [x] (2026-07-22 19:52Z) Committed the validated shared JS/TS milestone, now `d39874b7` after rebasing onto the final review base.
- [x] (2026-07-22 20:08Z) Passed `cargo fmt --all -- --check`, full-feature clippy with warnings denied, all three unchanged semantic contract suites, and the complete `nlp,python` feature-enabled test suite in the repository's self-cleaning isolated Cargo target.
- [x] (2026-07-22 20:08Z) Fetched and rebased cleanly onto live `origin/master` at `3bd7c9e8`; `git diff --check` remained clean and no language-semantic visibility expanded beyond the existing JS/TS facade constructors.
- [x] (2026-07-22 20:14Z) Completed security, duplication, intent, operations, and architecture reviews. Restored the two moved cancellation test modules after reviewers identified missing `#[cfg(test)] mod tests;` declarations; both tests and the corrected full-feature clippy graph pass.
- [x] (2026-07-22 20:16Z) Committed the review fix and final plan, pushed the clean rebased branch, and opened ready-for-review PR #1094 to fix #1082.

## Surprises & Discoveries

- Observation: The Bifrost MCP tools are installed but are not bound to this worktree, and this session exposes no workspace-activation tool.
  Evidence: `search_symbols`, `get_summaries`, `most_relevant_files`, and `find_filenames` all returned `Bifrost is not bound to a workspace`; source mapping therefore used `rg`, bounded source reads, and git history.

- Observation: The two lowerers have parallel responsibility boundaries but their implementations are not interchangeable.
  Evidence: Java uses initializer and constructor-specific control, while the shared JS/TS lowerer carries flavor validation, optional-chain, generator, async, and resource-disposal policy. The split must remain language-local rather than extracting a cross-language dispatcher.

- Observation: A purely contiguous file split would create a control/value dependency cycle because the original `LoweringContext` owns both caches and iterative control state.
  Evidence: control methods call local/value/effect helpers, while local-declaration and assignment lowering schedule `Work` items. The plan keeps scheduling methods in `control.rs`, moves state-only value and effect helpers to `values.rs`, and keeps the small shared state types in the parent `mod.rs`.

- Observation: On this macOS host, `cargo test --features nlp,python` currently fails while linking the library because CPython symbols are unresolved; the same equivalence test passes without optional features.
  Evidence: the linker reported undefined `_Py*` symbols before the temporary test ran. The repository's documented macOS extension-module invocation, `RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup'`, resolved the host linkage and the complete feature-enabled suite then passed.

- Observation: The shell initially paired rustup `cargo` and `rustc` with Homebrew `cargo-clippy`, whose LLVM patch versions differed even though the Rust version and commit matched.
  Evidence: clippy failed while reading an incompatible native object until `PATH` was pinned to the rustup 1.96.0 toolchain; the exact required `cargo clippy --all-targets --all-features -- -D warnings` command then passed.

- Observation: Repeated shared-target feature and linker configurations had accumulated 48.1 GiB of generated Cargo artifacts and exhausted the temporary volume late in the broad test gate.
  Evidence: `du -sh target` reported 46 GiB and the first unrestricted rerun ended with `StorageFull` during two unrelated tempdir tests. `cargo clean` removed 48.1 GiB, and the final complete run passed in `scripts/with-isolated-cargo-target.sh`, which removed its target afterward.

- Observation: Moving an inline `#[cfg(test)] mod tests` body into `tests.rs` also requires declaring that private child module in the parent; a source file alone is not discovered by Rust's module system.
  Evidence: duplication and intent reviewers found that both new `tests.rs` files were initially orphaned. Adding `#[cfg(test)] mod tests;` to each facade restored discovery, and `cargo test --lib free_this_scan_honors_cancellation` ran and passed both tests.

## Decision Log

- Decision: Keep the existing external module paths by replacing each `semantic.rs` with a `semantic/mod.rs` directory module.
  Rationale: `java::semantic` and `js_ts::semantic::JsTsSemanticLowerer` remain unchanged for all consumers, including the JavaScript and TypeScript facade modules.
  Date/Author: 2026-07-22 / Codex

- Decision: Use the same six private files for both languages: `mod.rs`, `inventory.rs`, `values.rs`, `control.rs`, `syntax.rs`, and `tests.rs`.
  Rationale: Parallel topology makes navigation predictable while every implementation and syntax rule remains language-owned.
  Date/Author: 2026-07-22 / Codex

- Decision: Keep `LoweringContext`, `Work`, edge targets, cleanup state, and similarly small shared data types private in the parent `mod.rs`; expose only inventory records and cross-module value methods as `pub(super)`.
  Rationale: Child modules can use parent-private fields directly. This avoids `pub(crate)` expansion and gives the implementation the dependency direction `syntax -> inventory/values -> control -> orchestration` without a generic utilities module.
  Date/Author: 2026-07-22 / Codex

- Decision: Keep local-declaration, assignment, parameter-default scheduling, cleanup scheduling, and edge construction in `control.rs`, even when they emit values.
  Rationale: Those routines own evaluation order and explicit `Work` scheduling. `values.rs` will own discovery, stable identity, inputs, mappings, effects, memory locators, and gaps, so it does not call back into control.
  Date/Author: 2026-07-22 / Codex

- Decision: Do not change adapter version bytes and do not implement class-field initializer semantics from #1083.
  Rationale: File topology does not invalidate artifacts, and #1083 is a separate behavior change whose inclusion would prevent exact before/after equivalence.
  Date/Author: 2026-07-22 / Codex

## Outcomes & Retrospective

Implementation, local validation, specialist review, and publication are complete in ready-for-review PR #1094: https://github.com/BrokkAi/bifrost/pull/1094. The only tooling follow-up is the Bifrost MCP installation being unbound to this worktree with no exposed activation tool.

The Java milestone now replaces the 3,657-line monolith with `control.rs` (2,331 lines), `inventory.rs` (176), `mod.rs` (276), `syntax.rs` (505), `tests.rs` (35), and `values.rs` (358). The representative Java artifact retained render digest `4e0bd646...cf1c`, key fingerprint `0a787864...2e8d`, and every original work counter. No Java consumer path or adapter byte changed.

The JS/TS milestone replaces the 4,095-line monolith with `control.rs` (2,687 lines), `inventory.rs` (187), `mod.rs` (322), `syntax.rs` (530), `tests.rs` (35), and `values.rs` (354). The existing `JsTsSemanticLowerer` constructors and all JavaScript/TypeScript adapter bytes remain unchanged. Exact artifact equivalence passed for `.js`, `.jsx`, `.ts`, and `.tsx` as well as the already-split Java adapter.

The final acceptance evidence is exact rather than merely compilation-based: the representative five-dialect render digests, artifact-key fingerprints, and every `SemanticWork` counter match the pre-refactor baseline; `semantic_language_conformance` passed 130 tests, `semantic_value_language_contract` passed 13, and `semantic_provider_contract` passed 11. Full-feature clippy passed with warnings denied, and the complete `cargo test --features nlp,python -- --test-threads=1` run passed outside the process-restricted sandbox in a self-cleaning isolated target. After review restored the two moved test-module declarations, both cancellation tests passed and all-target/all-feature clippy passed again against the corrected module graph.

Five read-only specialist passes covered security, duplication/cohesion, issue intent, operations, and architecture. They found one medium test-discovery omission and no remaining findings after its correction. Reviewers independently confirmed unchanged adapter identities and capabilities, byte-equivalent moved logic, narrow visibility, one shared flavor-driven JS/TS lowerer, one-way private seams, and no build, platform, or packaging regression.

## Context and Orientation

The repository root is the working directory. `src/analyzer/semantic/` contains the language-neutral executable-semantics intermediate representation and lowering substrate. An intermediate representation, abbreviated IR, is the validated graph of procedures, program points, control edges, values, memory facts, source mappings, gaps, and work accounting emitted by each language adapter. `src/analyzer/semantic/lowering.rs` provides `relay_receiver_capture_demand`, `lower_procedure_batch`, and `ProcedureLoweringSession`; it must not absorb Java or JavaScript/TypeScript syntax policy.

`src/analyzer/java/semantic.rs` currently registers `JavaSemanticLowerer`, discovers source-backed procedures, and lowers each procedure into the neutral IR. `src/analyzer/js_ts/semantic.rs` does the same for one shared flavor-driven `JsTsSemanticLowerer` used by `src/analyzer/javascript/semantic.rs` and `src/analyzer/typescript/semantic.rs`. The adapter version byte strings are stable artifact inputs. Dense identifiers and occurrence numbers are allocated in call order, so a behavior-neutral refactor must preserve statement order inside every moved function and preserve the order in which functions are called.

Both lowerers already use an explicit `Work` stack and `ProcedureCfgBuilder::drive_iteratively`; that is the stack-safe traversal required by repository policy. Procedure inventory also pushes syntax children in a deliberate order and checks budgets and cancellation. The refactor moves these bodies verbatim and changes only module paths, imports, and the minimum visibility needed for sibling modules.

For each language, `semantic/mod.rs` will retain provider identity, capabilities, orchestration, and the small parent-private state types used by more than one child. `inventory.rs` will own `ProcedureSpec`, `ProcedureEnumeration`, lexical-parent and receiver-capture inventory, declaration paths, and iterative enumeration. `values.rs` will own local preindexing, parameter/receiver/capture inputs, expression-value identity, source mappings, effect emission, memory locators, and semantic gaps. `control.rs` will own per-procedure setup, the iterative driver, evaluation order, statements, expressions, abrupt completion, cleanup routing, and CFG edges. `syntax.rs` will own structured tree-sitter field and kind interpretation. `tests.rs` will retain the existing cancellation unit test unchanged.

## Plan of Work

First transform the Java file into `src/analyzer/java/semantic/`. Preserve `JavaSemanticLowerer`, `ADAPTER_VERSION`, `java_capabilities`, and the `ProgramSemanticsLowerer` implementation in `mod.rs`. Move inventory declarations and enumeration unchanged into `inventory.rs`, making only the records, fields, enum, and entry function needed by the parent or control module `pub(super)`. Move structured Java container/callable, switch, child, field, scope, operator, and kind helpers to `syntax.rs`; publish only helpers used by a sibling module. Keep the shared lowering state in `mod.rs`. Move state-only value and mapping methods into an inherent `LoweringContext` implementation in `values.rs`, and retain all scheduling and routing methods in the corresponding implementation in `control.rs`. Run `cargo fmt`, compile, inspect errors as dependency-boundary feedback, and narrow any accidental visibility.

After Java compiles, run the Java-relevant portions of the unchanged semantic provider, language-conformance, and value-language contract suites. Inspect `git diff --color-moved=dimmed-zebra` and `git diff --check` to ensure the milestone is moves plus imports/visibility only. Update this plan with evidence and commit the Java milestone with a multiline message explaining why the seam is safe.

Then apply the same topology to `src/analyzer/js_ts/semantic.rs`, retaining both adapter version byte strings, `JsTsSemanticFlavor`, and the existing `pub(crate)` constructors in `mod.rs`. Keep JavaScript and TypeScript in one implementation. Do not implement field initializers, change receiver ownership, reorder optional-chain evaluation, or modify generator/async/resource gaps. Compile and run focused JavaScript, JSX, TypeScript, and TSX contract cases, review the move-aware diff, update the plan, and commit the second milestone.

Finally run the full unchanged acceptance suites and repository gates. Compare the pre-refactor and final adapter constants and use a move-aware diff to prove function bodies and call order remain equivalent. The semantic rendering and contract suites exercise deterministic artifact ordering across the affected languages; no schema or fingerprint change is expected. Run specialist security, duplication, intent, operations, and architecture reviews against `origin/master...HEAD`. Fix confirmed findings, update this living plan, and create the pull request only when all required gates are green.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/74bc/bifrost`.

The Java milestone uses these checks while the code is changing:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo check --all-targets --all-features
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_provider_contract
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_language_conformance java
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_value_language_contract java
    git diff --check

The JavaScript/TypeScript milestone uses:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo check --all-targets --all-features
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_provider_contract
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_language_conformance javascript
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_language_conformance typescript
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_value_language_contract
    git diff --check

The final acceptance gate is:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_language_conformance
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_value_language_contract
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test semantic_provider_contract
    scripts/with-isolated-cargo-target.sh cargo test --all-targets --features nlp,python
    git diff --check

Successful commands exit with status zero. The three named contract binaries must report no failed tests, clippy must emit no warnings, and the feature-enabled full suite must not silently skip the NLP-gated integration tests.

## Validation and Acceptance

Acceptance is topology plus equivalence. `src/analyzer/java/semantic.rs` and `src/analyzer/js_ts/semantic.rs` no longer exist as monoliths; their unchanged external modules resolve to directory `mod.rs` files. Provider orchestration, inventory, value/memory discovery, control lowering, syntax policy, and tests each have an explicit private owner. `src/analyzer/javascript/semantic.rs` and `src/analyzer/typescript/semantic.rs` continue importing the same `JsTsSemanticLowerer` path.

The adapter byte constants must match their values at `origin/master`: Java `java-value-semantics-v5`, JavaScript `javascript-value-semantics-v6`, and TypeScript `typescript-value-semantics-v7`. The final diff must contain no IR schema, capability membership, gap text, source-anchor, iteration order, evaluation order, budget, cancellation, or public API change. `git diff --color-moved` should classify the implementation bodies as moved code apart from module imports and narrow visibility markers.

The unchanged `semantic_language_conformance`, `semantic_value_language_contract`, and `semantic_provider_contract` suites must pass with `--features nlp,python`, followed by the repository formatter, full-feature clippy, and full-feature test gates. Reviewers must find no unresolved critical or high severity concern.

## Idempotence and Recovery

Formatting and validation commands are safe to repeat. Isolated Cargo runs must use `scripts/with-isolated-cargo-target.sh`, which removes its managed target directory on success, failure, or interruption. Do not create manually named Cargo target directories. If a module split fails to compile, preserve the original implementation through git history and correct imports or narrow visibility in the new files; do not reorder implementation statements to make the split easier. Each completed language milestone is committed independently so the other language can be recovered or retried without discarding validated work.

## Artifacts and Notes

The branch originally started from `7de07c8c` and was rebased before final review. Its current base is:

    origin/master 3bd7c9e8 M4 tier-2 tail: keras/Ocelot triage

The relevant history is:

    a4625155 Add normalized callable CFGs and a shared ICFG (#952)
    b5b0dc3f Generalize receiver facts into value, dispatch, and heap oracles (#1076)
    97324093 Refactor semantic IR and oracle module ownership (#1090)

The first two commits created and expanded the language lowerers. The third is the immediate precedent for private topology modules behind an unchanged facade.

The temporary equivalence probe established these render and artifact-key fingerprints from the fixed root `/tmp/bifrost-issue-1082-equivalence`:

    src/Main.java render=4e0bd64607f3578d9e5a0966e9ce802eb6cadb7e22037125af56e6e43bb5cf1c key=0a78786408502ec03a6518f8d53a4f3721f158501e5fb2d4df9db13a3a2f2e8d
    src/main.js render=4af148d9f973129b5cd5afc6da409f52c0b815626638e4f85958ee17cb7aead7 key=a20e89b3d0b82569f563102b7d6811957d86a163af18c10423f4cc0ba6f961af
    src/view.jsx render=874249dc6e5b6639c5738e5905a29be4bf21d9f65998c096c63c26baba4b4b89 key=936788103e6d02fa2daed8402d4be27ac16f526c1bd76e5f3502d00f236c086d
    src/main.ts render=e0c8893696ee8a9fcb6a088d3dcda3951bac12968de6d2a476a1060c93591c65 key=ab4b124f24e7324753122293c0e1bf69cb06088fce3de024a36cd7b56dd46204
    src/view.tsx render=9163b18910ff6c761f2703d367a28f09193993f6877c88b089faf721e3a0c180 key=f7a7d71efbf6ea06bad7ae2c2771eb1af69cfd7fdded15739b692b5cb59935aa

## Interfaces and Dependencies

No new external dependency or public interface is permitted. `impl_program_semantics_provider!(JavaAnalyzer, JavaSemanticLowerer)` must continue to register Java. `JsTsSemanticLowerer::javascript()` and `JsTsSemanticLowerer::typescript()` must remain `pub(crate)` and continue serving the separate facade modules. `ProgramSemanticsLowerer`, `SemanticAdapterIdentity`, `PreparedSyntaxTree`, `ProcedureLoweringSession`, `ProcedureCfgBuilder`, and the neutral `crate::analyzer::semantic::*` types remain the shared substrate.

Child modules are private. Inventory records and cross-module inherent methods may use `pub(super)` because that visibility stops at the language's `semantic` parent. Do not use `pub(crate)` merely to cross a sibling boundary, do not re-export child implementation modules, and do not introduce a common Java/JS statement or expression layer.

Revision note (2026-07-22 20:16Z): Recorded publication of ready-for-review PR #1094 and completed the plan.
