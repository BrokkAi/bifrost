# Consolidate semantic and CFG lowering without erasing language semantics

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently implements procedure discovery and control-flow lowering independently for ten languages. That independence correctly preserves language-specific syntax and semantics, but it also duplicates identity construction, budget accounting, control-edge scaffolding, call-gap handling, and common structured-control topology. The duplicated inventory logic has already drifted: C++ carries procedure identity work into batch lowering even though each procedure lowerer charges that identity again, while Go and Python intentionally carry traversal work only.

After this change, every language will still own syntax recognition, evaluation order, binding, dispatch, and language-specific control constructs. Shared code will own only syntax-free invariants: procedure identity allocation and work accounting, repeated lowering scaffolds, stable control-flow shapes, cleanup-route mechanics, and data-flow outcome bookkeeping. The result is observable through existing semantic conformance tests, new cross-language budget and topology tests, and a repeat of the PMD CPD survey showing that the high-mass clone families from issue #1159 have materially shrunk without changing rendered semantic graphs.

## Progress

- [x] (2026-07-24 17:05Z) Reproduced issue #1159 against master and classified the clone families into shared invariants versus language-owned semantics.
- [x] (2026-07-24 17:05Z) Fetched `origin`, verified GitHub authentication, and fast-forwarded the existing issue branch from `7a6d4e72` to current `origin/master` at `3317217e`.
- [x] (2026-07-24 17:05Z) Created this ExecPlan with phased, independently verifiable milestones.
- [x] (2026-07-24 17:48Z) Milestone 1: introduced the shared procedure-inventory builder, migrated all ten adapters, corrected C++ identity double-counting, and added cross-language budget parity tests.
- [x] (2026-07-24 18:19Z) Milestone 2: finished the syntax-free lowering kernel by sharing control targets, value interning, callable-resolution gaps, iterative-driver completion, and the identical await core.
- [x] (2026-07-24 18:47Z) Milestone 3: extracted small structured-control combinators for conditional choices, short-circuit conditions, and C-style loops while leaving AST classification in language adapters.
- [x] (2026-07-24 19:10Z) Milestone 4: extracted cleanup-route specialization and migrated the compatible try/finally implementations.
- [x] (2026-07-24 19:30Z) Milestone 5: centralized duplicated data-flow outcome status, deterministic ordering, and cancellation-atomic budget reservation without merging the distinct solver engines.
- [ ] Milestone 6: run formatting, focused and full feature-enabled tests, clippy, CPD remeasurement, adversarial review, and publish a draft pull request.

## Surprises & Discoveries

- Observation: the CPD findings are not stale despite concurrent data-flow work.
  Evidence: PMD 7.14.0 at the 80-token floor reproduced every pair total and the five largest clones from issue #1159 at commit `7a6d4e72`; the semantic target files remained structurally unchanged after fast-forwarding to `3317217e` except for already-landed shallow helper consolidation.

- Observation: the new reusable CFG algorithms are an example of the desired architecture rather than a new duplication source.
  Evidence: `src/analyzer/semantic/cfg_algorithms.rs` produced no CPD clone at the 80-token floor, and the new summary code reuses its bounded reachability routines.

- Observation: procedure inventory work accounting has diverged semantically.
  Evidence: `src/analyzer/cpp/semantic.rs::enumerate_procedures` returns identity preflight plus traversal work as the seed passed to `lower_procedure_batch`, while `ProcedureLoweringSession::start` charges retained procedure identity again. Go and Python return traversal-only work on successful enumeration, and `go_many_procedure_enumeration_is_budgeted_without_double_counting_identity_work` asserts that each procedure is charged once.

- Observation: Bifrost method-usage resolution has a likely false-negative and latency issue in this area.
  Evidence: `scan_usages_by_location` for `ProcedureLoweringSession::add_call_site` took 117 seconds and classified direct Java, JavaScript/TypeScript, and same-file test calls as unproven even though their receiver type is statically apparent. This is outside the implementation scope and should be reported separately.

- Observation: the repository's all-feature test command does not currently link on this macOS host when the `python` feature is enabled directly through Cargo.
  Evidence: `cargo test --features nlp,python --test semantic_language_conformance enumeration` compiled the Rust sources, then failed while linking `libbrokk_bifrost.dylib` with unresolved `_Py*` symbols. The default-feature semantic conformance and CFG contract suites both link and pass; the final gate will retry with the repository's Python build environment before classifying this as an external blocker.

## Decision Log

- Decision: use the existing issue branch and fast-forward it to current master rather than creating or switching branches.
  Rationale: repository instructions require work to land on the current branch, the branch contained no unique commits, and current master includes the tier-one helper consolidations mentioned by issue #1159.
  Date/Author: 2026-07-24 / Codex

- Decision: implement a procedure-inventory builder before a generic traversal trait.
  Rationale: locator construction, sibling ordinals, declaration paths, identity work, and traversal work are universal invariants; frame shape and traversal policy differ substantially for Go, Python, Ruby, Scala, and C++. Extracting the stable middle fixes the accounting defect without inventing a ten-language callback interface.
  Date/Author: 2026-07-24 / Codex

- Decision: represent successful inventory work as traversal-only seed work while retaining identity plus traversal work for interrupted outcomes.
  Rationale: each procedure lowerer owns and charges its retained `SemanticLocator`. Successful batch lowering must therefore inherit only one-time file traversal work, while cancellation and budget outcomes must report all work observed before interruption.
  Date/Author: 2026-07-24 / Codex

- Decision: introduce several small structured-control helpers rather than one universal lowerer trait or union of every language construct.
  Rationale: `if`, pre-test loop, post-test loop, C-style loop, and short-circuit topology are stable after nodes have been identified. Tree-sitter field names, labels, optional chaining, null-safe chaining, resource semantics, and evaluation order remain language-owned.
  Date/Author: 2026-07-24 / Codex

- Decision: keep bounded snapshot tabulation, recursive summary fixed-point scheduling, `SemanticBudget`, `CfgAlgorithmBudget`, and `SolverBudget` as distinct contracts.
  Rationale: these components share low-level bookkeeping invariants but have different domains, lifecycle, and result semantics. Issue #1159 calls for shared logic plus extensions, not abstraction by name alone.
  Date/Author: 2026-07-24 / Codex

## Outcomes & Retrospective

Milestone 1 removed 533 net lines across the language inventories while preserving each adapter's frame shape, container classification, callable recognition, and special prescans. `ProcedureInventoryBuilder` now owns declaration-path persistence, sibling ordinals, procedure identities, and the distinction between full observed work and traversal-only lowering seed work. This fixes the C++ double charge and makes wide non-callable syntax consume the nested-entry budget consistently across all ten adapters. The 137 semantic language conformance tests and 41 semantic CFG contract tests pass with default features.

Milestone 2 removed another 481 net lines by moving four syntax-free invariants into `semantic::lowering`: control destinations, the iterative drive/seal/freeze lifecycle, cached semantic-value retention, and paired callable-resolution gaps. The common await helper owns only suspend/resume points, values, events, and edges; operand discovery, exceptional cleanup routing, and Rust executor uncertainty remain language-owned. Twelve focused lowering unit tests, all 137 semantic language conformance tests, and all 41 semantic CFG contract tests pass.

Milestone 3 moved 335 repeated adapter lines behind typed scheduling combinators. C#, Java, and JavaScript/TypeScript now share conditional-choice and boolean short-circuit scheduling; C# and Java also share the complete C-style loop scope and work-stack topology while retaining their distinct field names and initializer classification. The shared implementation is deliberately explicit rather than macro-generated, so this architectural layer adds a small amount of net source while replacing the largest cross-language control clone with one reviewable invariant. The full semantic conformance and CFG contract suites pass.

Milestone 4 centralizes cleanup-region lookup, specialization allocation, dense point registration, destination-edge preservation, and route entry selection. C#, Java, JavaScript/TypeScript, PHP, Python, Ruby, and Scala now consume the shared route plan but retain their distinct executable-body, relay, resource, monitor, fixed-region, and diagnostic behavior. The same pass consolidated exact source-node mapping across all ten adapters. This milestone removes about 190 net lines; focused normal/exceptional cleanup relay and language try/finally/ensure tests pass.

Milestone 5 replaces the direct-ICFG and summary-specific semantic status enums with one `SemanticInputStatus` implementation and role-specific public aliases. Labels, accessors, commutative merge precedence, hashing, and deterministic ordering now have one source of truth. `DataflowRequest::reserve` centralizes the cancellation-check/staged-charge/recheck/commit transaction used by direct tabulation, transfer evaluation, and immediate summary reservations; the incoming-call multi-stage transaction remains bespoke because its budget cannot commit until later staging succeeds. Eight data-flow unit tests, 12 direct-client tests, and 22 summary tests pass. The milestone removes about 70 net lines.

## Context and Orientation

The repository root is the working directory. `src/analyzer/semantic/lowering.rs` contains syntax-free helpers used by every semantic adapter, including declaration-path utilities, procedure batch lowering, `ProcedureLoweringSession`, and `CallSiteScaffold`. `src/analyzer/semantic/cfg.rs` contains the mutable procedure CFG builder. Language adapters live in `src/analyzer/{cpp,csharp,go,php,python,ruby,rust,scala}/semantic.rs`; Java and JavaScript/TypeScript split the same responsibilities across `semantic/inventory.rs`, `semantic/control.rs`, `semantic/values.rs`, and related modules.

A procedure inventory is the ordered set of callable bodies discovered in one parsed source file. Every inventory entry has a stable `ProcedureId`, a `SemanticLocator` that identifies the procedure across requests, a lexical parent, and language-owned metadata. Enumeration currently maintains a stack of tree-sitter nodes, an arena of declaration-path entries, a map of sibling ordinals, and accumulated `SemanticWork`. `SemanticWork` is the observable measure used to stop expensive semantic materialization at configured limits.

Control-flow lowering converts one inventory entry into `ProcedureSemanticsParts`. A `ProgramPointId` identifies a CFG node, a `ControlEdgeKind` identifies how control transfers between points, and an adapter-local `Work` enum schedules iterative lowering without Rust recursion. The shared lowering kernel must operate only after the adapter has interpreted its tree-sitter syntax.

Data-flow solving begins after semantic CFGs and the interprocedural CFG are available. `src/analyzer/dataflow/input.rs` retains the semantic outcome status beside an ICFG snapshot. `src/analyzer/dataflow/summary_result.rs` repeats that same status shape for aggregate summary results and adds stable merge behavior. `src/analyzer/dataflow/budget.rs` defines `DataflowRequest`, which combines a mutable solver budget with a cancellation token.

The main behavior contracts are in `tests/semantic_cfg_contract.rs` and `tests/semantic_language_conformance.rs`. Tests use `tests/common/inline_project.rs` for small source projects. New cross-language tests must use `InlineTestProject` rather than handwritten temporary directories.

## Plan of Work

Milestone 1 creates `src/analyzer/semantic/inventory.rs` and exports it from `src/analyzer/semantic/mod.rs`. Define `ProcedureInventoryBuilder` with the workspace mount, relative path, language dialect, sibling-ordinal map, declaration-path arena, accumulated identity work, accumulated traversal work, next procedure index, and borrowed semantic budget. Its constructor builds the file declaration segment. A container method creates and records a nested declaration segment. A procedure method accepts a parent path, segment kind, optional name, and source anchor; it allocates the next `ProcedureId`, builds the procedure `SemanticLocator`, charges identity preflight against identity plus traversal work, records the callable path, and returns a `ProcedureIdentity`. Traversal charging must be explicit so Go and Python can charge prescanned children without double-charging stack entries. The builder exposes `observed_work()` for interrupted outcomes and `lowering_seed_work()` for completed enumeration.

Migrate each of the ten `enumerate_procedures` functions to the builder. Keep every frame type, callable-shape function, container classification, synthetic-scope rule, and traversal loop local. Ensure every adapter charges iterative traversal, including files without callables, and retains observed work on cancellation. Change completed inventories to carry traversal-only seed work where necessary. Add an exact C++ procedure count assertion parallel to the Go regression and add representative no-callable budget/cancellation tests for adapters that previously omitted traversal charging. Run focused semantic language and CFG contract tests, format, review the milestone diff, update this plan, and commit only milestone files.

Milestone 2 adds shared lowering primitives to `src/analyzer/semantic/lowering.rs` and, if scheduling types make the file incohesive, a new `src/analyzer/semantic/control_lowering.rs`. Move the identical `EdgeTarget` type into the shared module as `ControlTarget`. Add a cached-value helper that accepts the adapter cache, tree node identity, point metadata, and value kind and returns both the value and whether it was newly inserted; Go uses the insertion flag to attach type identity. Add one callable-resolution-gap helper that maps `CallableTargetResolution` to `SemanticGapKind` and accepts adapter-provided detail strings. Add a common iterative-driver finisher for error conversion, unreachable sealing, and freezing. Extract await suspend/normal-resume/exceptional-resume scaffolding only after proving the C#, JavaScript/TypeScript, Python, and Rust topology is identical; retain Rust executor uncertainty and adapter-specific operand selection outside the helper. Add shared unit tests in `lowering.rs` plus existing language conformance tests, update the plan, and commit.

Milestone 3 creates syntax-free scheduling functions for stable control shapes. Start with conditional branches and pre/post-test loops, then short-circuit expressions and C-style loops. Each helper receives already-extracted nodes or opaque adapter payloads, `ControlTarget`s, scope identifiers, and closures that construct the adapter’s local work items. It must not inspect source text, tree-sitter field names, or node kinds. Migrate the closest language pairs first—C# with Java and Java with JavaScript/TypeScript—then reuse the helper in other adapters only where the topology and evaluation order match. Extend topology-equivalence tests rather than comparing raw row order. Update the plan and commit after focused tests.

Milestone 4 extracts cleanup-route specialization. The shared helper handles direct routing when no cleanup exists, creates or reuses specialized cleanup entries, retains dense point metadata, preserves the destination edge kind, and returns newly created cleanup steps to the adapter. The adapter still decides whether the step is an executable `finally` body or an opaque resource, monitor, fixed, ensure, or context-manager boundary. Migrate compatible C#, Java, Python, Scala, JavaScript/TypeScript, PHP, and Ruby routes incrementally. Do not force Rust RAII or C++ destruction into the generic try model. Validate normal and exceptional relay edge kinds, update the plan, and commit.

Milestone 5 introduces one shared semantic outcome status for direct ICFG input and aggregated summary results, with stable labels, accessors, hashing, ordering, and merge precedence. Retain public aliases or wrappers only where they communicate a distinct API role. Add a `DataflowRequest` operation that performs cancellation check, staged solver charge, a second cancellation check, and commit atomically; use it in tabulation, transfer evaluation, and summary solving. Centralize stable semantic-handle ordering rather than maintaining parallel handwritten rank functions. Run the data-flow test suites and commit.

Milestone 6 validates and publishes. Run `cargo fmt`, focused semantic and data-flow suites, the full `cargo test --features nlp,python`, and `scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings`. Repeat PMD 7.14 CPD with an 80-token floor over `src/analyzer` and compare the exact issue #1159 pair masses and largest clones. Review the complete diff for security, duplication, intent, operations, and architecture; fix all critical and high findings and any bounded lower-severity findings that improve the extraction. Update this plan’s retrospective, commit the final review fixes, push the existing branch, and open a draft pull request targeting `master`.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/2165/bifrost`.

Inspect state before each milestone:

    git status --short --branch
    git diff --stat

Run focused semantic validation during milestones 1 through 4:

    cargo fmt --check
    cargo test --features nlp,python --test semantic_language_conformance
    cargo test --features nlp,python --test semantic_cfg_contract

Run focused data-flow validation during milestone 5:

    cargo test --features nlp,python dataflow
    cargo test --features nlp,python --test dataflow_summary

Use the repository helper for the final isolated clippy gate:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Run the full feature-enabled suite:

    cargo test --features nlp,python

Repeat CPD using PMD 7.14.0:

    pmd cpd --minimum-tokens 80 --language rust --dir src/analyzer --format xml --no-fail-on-violation --no-fail-on-error

Before publication, inspect and stage only files listed in this plan:

    git status --short
    git diff --check
    git diff origin/master...HEAD --stat

Push the current branch and create a draft pull request targeting `master`.

## Validation and Acceptance

Milestone 1 is accepted when all ten adapters use `ProcedureInventoryBuilder`, successful enumeration seeds batch lowering with traversal work only, and interrupted outcomes report identity plus traversal work. A C++ many-procedure test must assert that `work.procedures` equals the number of materialized procedures, and representative wide/no-callable inventories must stop at the configured nested-entry budget.

Milestones 2 through 4 are accepted when existing language conformance snapshots and CFG topology contracts remain unchanged, shared helper unit tests cover success, cancellation, budget, normal/exceptional routing, and insertion behavior, and the corresponding adapter-local copies have been removed.

Milestone 5 is accepted when direct ICFG input and summary aggregation expose the same outcome labels and payload accessors, merge precedence remains traversal-order independent, staged solver work is never committed after cancellation, and all data-flow tests pass.

The full plan is accepted when formatting, clippy, focused tests, and the full `nlp,python` suite pass; the issue’s duplicated-token mass is materially reduced; no language-specific syntax parser has moved into shared code; and a draft PR clearly documents the accounting fix, architecture, validation, and residual deliberate duplication.

## Idempotence and Recovery

All migrations are source-level and can be rerun safely. Each milestone ends in a focused commit, so a failed later milestone can be repaired without disturbing earlier verified work. Do not use destructive git resets. If a test exposes a semantic mismatch, keep the adapter-local path until the helper can express the distinction explicitly; do not add source-text fallbacks or suppress lint.

Use `scripts/with-isolated-cargo-target.sh` for isolated validation so temporary Cargo targets are automatically removed. Bifrost may create `.brokk/bifrost_cache.db`; it is an analysis artifact and must remain untracked and be removed before publication. CPD downloads and reports belong under a unique directory in `/private/tmp` and must be removed after measurements are recorded.

## Artifacts and Notes

The baseline at the start of implementation is current `origin/master` commit `3317217e`. The issue’s original pair masses were 3,364 C#↔Java, 3,265 Java↔JavaScript/TypeScript, 1,721 C#↔Python, 1,711 C#↔Rust, 1,690 C#↔JavaScript/TypeScript, 1,651 Go↔Rust, 1,604 PHP↔Python, 1,584 Go↔Python, and 1,544 C#↔Scala.

The largest baseline clones were the C#/Java C-style loop, Java/JavaScript structured statements, C#/Java try handling, and the C#/JavaScript/Python/Rust await scaffold. These measurements are diagnostic evidence, not acceptance by themselves; semantic graph behavior and work accounting remain the primary contracts.

## Interfaces and Dependencies

In `src/analyzer/semantic/inventory.rs`, define shared types with crate visibility equivalent to:

    pub(crate) struct ProcedureInventoryBuilder<'budget> { ... }

    pub(crate) struct ProcedureIdentity {
        pub id: ProcedureId,
        pub locator: SemanticLocator,
        pub declaration_path: usize,
    }

    impl ProcedureInventoryBuilder<'_> {
        pub fn new(
            file: &ProjectFile,
            dialect: Language,
            root: Node<'_>,
            fallback_file_name: &str,
            budget: &SemanticBudget,
        ) -> Result<Self, SemanticProviderError>;

        pub fn push_container(
            &mut self,
            parent: usize,
            kind: DeclarationSegmentKind,
            name: Option<&str>,
            anchor: SourceAnchor,
        ) -> Result<usize, SemanticProviderError>;

        pub fn allocate_procedure(
            &mut self,
            parent: usize,
            kind: DeclarationSegmentKind,
            name: Option<&str>,
            anchor: SourceAnchor,
        ) -> Result<ProcedureIdentity, ProcedureInventoryError>;

        pub fn charge_traversal(
            &mut self,
            work: SemanticWork,
        ) -> Result<(), ProcedureInventoryError>;

        pub fn observed_work(&self) -> SemanticWork;
        pub fn lowering_seed_work(&self) -> SemanticWork;
    }

The exact language dialect type and error wrapping may follow existing module types, but budget exhaustion must remain a normal semantic outcome rather than an internal provider error.

In `src/analyzer/semantic/lowering.rs` or `src/analyzer/semantic/control_lowering.rs`, define `ControlTarget`, shared cached-value and resolution-gap helpers, and small control-shape scheduling functions. These APIs must be generic over adapter-owned work payloads or closure constructors and must not depend on any language module.

In `src/analyzer/dataflow`, define one semantic outcome status implementation and one cancellation-atomic staging operation on `DataflowRequest`. No new external crate dependencies are expected.

Plan revision note: created on 2026-07-24 after refreshing master and revalidating the issue diagnosis. The plan orders the inventory correction first because duplicated work accounting has already diverged, then proceeds from low-level shared lowering mechanics to higher-risk topology extraction. Updated after Milestones 1 through 5 to record completed shared kernels, bounded topology, cleanup and data-flow invariant extraction, regression coverage, and the host-specific Python extension link failure observed during all-feature validation.
