# Decompose the semantic IR and oracle modules without changing behavior

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The semantic intermediate representation and its workspace-backed oracles already expose the behavior needed by control-flow, dispatch, value-flow, and heap consumers, but three source files now own several independent contracts each. This refactor gives those contracts stable, named module homes so future IFDS/IDE, finite-state, and pushdown analyses can find and extend the relevant seam without growing another multi-thousand-line root module. Users should observe no semantic, schema, adapter-identity, ordering, proof, budget, or cancellation change: the same public `crate::analyzer::semantic::*` imports compile and the same contract tests pass unchanged.

## Progress

- [x] (2026-07-22 16:56Z) Verified issue #1081, fetched `origin`, and confirmed the clean attached issue branch matches its remote at `4037def8`.
- [x] (2026-07-22 16:56Z) Mapped the public and private ownership seams in `oracle.rs`, the original flat `ir.rs`, and `workspace_oracle.rs`, including direct consumers and visibility hazards.
- [x] (2026-07-22 16:56Z) Chose acyclic module boundaries and recorded the implementation and validation sequence in this plan.
- [x] (2026-07-22 17:10Z) Decomposed the language-neutral oracle contracts behind the existing `oracle.rs` facade and preserved the full exported type set.
- [x] (2026-07-22 17:10Z) Decomposed the semantic IR model, artifact, validation, and tests behind the existing IR facade and preserved the full exported type set.
- [x] (2026-07-22 17:10Z) Moved workspace dispatch implementation and its unit tests into `workspace_oracle/dispatch.rs` while retaining the shared root facade and ICFG helper paths.
- [x] (2026-07-22 17:27Z) Ran the unchanged contract tests, formatting, all-target/all-feature checking and Clippy, exact scope checks, and five parallel specialist review lenses; no code findings remained.
- [x] (2026-07-22 18:06Z) Rebased onto `origin/master` at `1584751d`, reconciled upstream's independent `ir/mod.rs` split without losing either side's content, and reran formatting, all-feature checking and Clippy, and all 90 focused contract tests.

## Surprises & Discoveries

- Observation: Bifrost MCP code-intelligence calls fail in this desktop worktree with `Bifrost is not bound to a workspace`, even though the task has an approved filesystem root.
  Evidence: both `get_summaries` and `search_symbols` returned MCP error `-32603`; diagnosis therefore used exact `rg`, `sed`, and git-history inspection as the documented fallback.

- Observation: the six-file oracle example in the issue would create real sibling cycles if relation ownership continued to name heap queries and dispatch boundaries while those result contracts also retained relation handles.
  Evidence: `OracleRelationOwner` stores `AliasQuery` and `StoreAtPoint`, `OracleRelationSubject` stores `DispatchBoundaryKind`, and heap/dispatch result constructors validate `OracleRelationHandle` values.

- Observation: the original inline IR tests inherited capability, ID, budget, `Arc`, and hash-set names through private imports in `ir.rs`; moving the same test body to a sibling file made that implicit dependency visible.
  Evidence: the first all-target compile reported missing test-only names. `ir/tests.rs` now imports those dependencies explicitly, and `cargo check --all-targets --all-features` passes.

- Observation: ICFG production code imports `exact_source_for_procedure` and `semantic_locator_work`, while its unit tests also import callable-identity, candidate-retention, and scoped-gap helpers from the workspace-oracle root.
  Evidence: the first integrated compile resolved the imports in `src/analyzer/semantic/icfg.rs`; the facade now preserves the production paths and gates the three test-only re-exports with `#[cfg(test)]`.

- Observation: the four acceptance suites compile with the Python feature, but their test executables cannot link on this macOS host when PyO3's `extension-module` feature is enabled because the executable has unresolved `_Py*` symbols.
  Evidence: the isolated `cargo test --features nlp,python` run reached the link step and failed only on undefined Python symbols; the helper removed its managed target. This is the repository's previously documented macOS PyO3 test-link limitation, not a refactor compile error. The same unchanged suites passed with `--features nlp`, while all Python-feature Rust code passed all-target checking and Clippy.

- Observation: the shell initially resolved `cargo` and `rustc` from `/Users/dave/.local/bin` but `cargo-clippy` from Homebrew, whose LLVM patch versions are incompatible for isolated compilation.
  Evidence: the first isolated Clippy run reported E0514 with LLVM 22.1.2 versus 22.1.6 metadata. Rerunning with `/opt/homebrew/bin/cargo`, `/opt/homebrew/bin/rustc`, and the matching Homebrew Clippy completed cleanly with warnings denied.

- Observation: while the reviewed branch was being published, `origin/master` gained commit `65ac7f19`, which independently moved the flat IR into `ir/mod.rs`, `ir/validate.rs`, and `ir/tests.rs`.
  Evidence: GitHub reported PR #1090 as conflicting. The rebase retained upstream's module-directory home, replaced its large contract `mod.rs` with the #1081 facade plus `model.rs` and `artifact.rs`, renamed `validate.rs` to `validation.rs`, and kept the merged test body with only sibling-required imports. The rebased incremental IR diff is therefore focused on the deeper ownership split rather than repeating upstream's first-stage code motion.

## Decision Log

- Decision: Keep `src/analyzer/semantic/oracle.rs` as a thin private-child facade and, after rebasing, use upstream's `src/analyzer/semantic/ir/mod.rs` as the equivalent thin IR facade.
  Rationale: The original implementation used Rust's supported sibling directory beneath `ir.rs`. Once upstream established the directory module, retaining `ir/mod.rs` avoids undoing current-master topology while preserving `semantic::oracle::*`, `semantic::ir::*`, and `semantic::*` as single re-export layers.
  Date/Author: 2026-07-22 / Codex

- Decision: Add foundational `oracle/error.rs`, `oracle/model.rs`, and `oracle/traits.rs` modules in addition to the issue's example relation, limits, value-flow, call, heap, and dispatch modules.
  Rationale: errors, query/identity vocabulary, and the three public oracle traits are stable ownership seams. Moving query descriptors below relation removes relation-to-heap and relation-to-dispatch cycles; a dedicated traits leaf depends on completed result contracts without forcing those contracts to depend on one another. `model.rs` contains contract types only and is not a generic utilities module.
  Date/Author: 2026-07-22 / Codex

- Decision: Put `ProcedureSemanticsParts` in `ir/model.rs`, validation-only indexes in `ir/validation.rs`, and immutable procedures/artifacts/scoped handles in `ir/artifact.rs`.
  Rationale: validation consumes construction parts, while artifact publication consumes validated boundaries. This produces the dependency direction model, then validation, then artifact instead of an artifact/validation cycle, and keeps `Arc`-scoped handle identity private to the artifact module.
  Date/Author: 2026-07-22 / Codex

- Decision: Keep `WorkspaceSemanticOracle` in `workspace_oracle.rs` and move all location-first dispatch machinery plus its unit tests to `workspace_oracle/dispatch.rs`.
  Rationale: source, value-flow, and heap submodules all share the facade type, while callable grouping, result projection, gap composition, work accounting, ordering, and cancellation are dispatch-owned. The root will re-export only the existing crate-visible helper required by ICFG tests.
  Date/Author: 2026-07-22 / Codex

- Decision: Keep ICFG helper reachability through narrow workspace-oracle facade re-exports and make relocated IR-test dependencies explicit in `ir/tests.rs`.
  Rationale: this preserves existing consumer paths without making the new child modules public, avoids unused production imports for test-only helpers, and removes accidental reliance on facade implementation imports.
  Date/Author: 2026-07-22 / Codex

## Outcomes & Retrospective

Issue #1081 is complete as a topology-only refactor. `oracle.rs`, `ir/mod.rs`, and `workspace_oracle.rs` are now 27-, 17-, and 55-line facades. Oracle contracts live in focused `call`, `dispatch`, `error`, `heap`, `limits`, `model`, `relation`, `traits`, and `value_flow` children. IR model, validation, immutable artifact, and tests have separate homes. Workspace dispatch implementation and tests now live together under the unchanged shared workspace-oracle facade.

The public oracle and IR type sets match `4037def8` exactly, all existing consumers compile with all features, and the four acceptance test files are byte-for-byte unchanged. Their 90 tests pass with `--features nlp` (25 ICFG, 11 IR, 41 oracle, and 13 value-language tests). Formatting, exact diff checks, and all-target/all-feature Clippy with warnings denied pass. The only incomplete literal form of the requested test command is the known macOS PyO3 executable-link limitation described above; Python-feature compilation remains covered by both `cargo check` and Clippy.

Five independent review lenses found no security, duplication, intent, operational, or architecture findings. In particular, reviewers verified private one-way facades, scoped identity, relation-arena ownership, candidate sealing, ordering, coverage/proof composition, finite-limit guards, work budgets, and cancellation precedence. No follow-up code changes were required after review.

## Context and Orientation

The repository root for every command is `/Users/dave/.codex/worktrees/74bc/bifrost`. `src/analyzer/semantic/mod.rs` is the public semantic facade: it declares `ir`, `oracle`, and the crate-private `workspace_oracle`, then publicly re-exports IR and oracle items. A semantic artifact is an immutable, validated representation of procedures, values, memory, events, gaps, and control-flow. An oracle is a bounded query contract that returns evidence-backed dispatch, value-flow, call-binding, points-to, alias, or update facts. A relation arena is an `Arc`-owned finite table whose handles compare by arena pointer and dense relation ID; preserving that pointer identity is a correctness requirement.

`src/analyzer/semantic/oracle.rs` currently contains the entire oracle contract. Its facade will declare private child modules and publicly re-export their existing public items exactly once. `oracle/model.rs` will own relation-independent query and identity vocabulary such as call contexts, procedure ports, scoped locators, access paths, abstract objects and locations, alias/store queries, object cardinality, and dispatch-boundary kinds. `oracle/relation.rs` will own relation IDs, owners, records, arenas, handles, candidates, sets, coverage, and provenance validation. `oracle/limits.rs`, `value_flow.rs`, `dispatch.rs`, `call.rs`, and `heap.rs` will own their named contracts; `error.rs` will own `OracleContractError`; `traits.rs` will own `DispatchOracle`, `ValueFlowOracle`, and `HeapOracle`.

At the start, `src/analyzer/semantic/ir.rs` mixed public row types, mutable construction parts, immutable artifacts and handles, validation/accounting, and about 2,350 lines of unit tests. Current master independently established `ir/mod.rs`, `ir/validate.rs`, and `ir/tests.rs` before the final rebase. The completed facade at `ir/mod.rs` privately declares `model`, `validation`, `artifact`, and the test module, publicly re-exporting only model and artifact public items. `ir/model.rs` owns validation errors, semantic rows, and `ProcedureSemanticsParts`; `ir/validation.rs` owns private indexes, resource accounting, and exhaustive validators; `ir/artifact.rs` owns artifact build errors, frozen control-flow graphs, immutable procedures and artifacts, and scoped handles; `ir/tests.rs` contains the existing test body with explicit sibling imports.

`src/analyzer/semantic/workspace_oracle.rs` already has `common`, `source`, `value_flow`, and `heap` children but still contains dispatch. It will remain the home of `WorkspaceSemanticOracle` and its constructors. `workspace_oracle/dispatch.rs` will own callable identity grouping, the `DispatchOracle` implementation, dispatch projection and gap helpers, work accounting, deterministic ordering, and the existing dispatch unit tests. `scoped_procedure_dispatch_gap` remains reachable at its current crate path through a crate-visible root re-export because `src/analyzer/semantic/icfg.rs` uses that path in tests.

## Plan of Work

First create the oracle facade and move exact existing item bodies into their ownership modules. Preserve every constructor and validation sequence. Only widen sibling-required internals to `pub(super)`: relation quality/identity checks and arena comparison, model validation helpers, candidate/set fields used by strong-update validation, and dispatch-candidate call validation. Do not make any child module public. Compile before further decomposition so path and privacy errors remain localized.

Next create the IR facade. Move semantic row and construction types into model, frozen graph/artifact/handle types into artifact, and validation indexes/accounting into validation. Expose only the sibling hooks required for construction: semantic error constructors, `measure_artifact_work`, `validate_artifact`, `find_boundaries`, and the returned boundary fields. Move the current test body without rewriting assertions. Preserve artifact publication order exactly: measure work, clone and charge the budget, validate all parts, freeze procedures and indexes, construct the artifact, then publish the charged budget.

Then add the workspace dispatch child. Leave `WorkspaceSemanticOracle` at the root because every oracle implementation uses it. Move dispatch-only types, the trait implementation, helpers, and tests together. Repair relative paths that become one level deeper by importing semantic contract types explicitly. Keep cancellation checks, candidate retention order, proof/coverage composition, budget staging, locator ordering, and relation construction byte-for-byte except for module paths and necessary sibling visibility.

After each topology milestone, run formatting or a focused compile and inspect the diff for accidental body changes. At the end run the issue's four unchanged contract suites with all features enabled, run formatting in check mode, and run full all-target/all-feature Clippy through the repository's isolated-target helper. Finally compare the complete diff to the issue scope and run parallel security, duplication, intent, operational, and architecture reviews. Fix confirmed findings, rerun affected gates, and update this plan with evidence.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/74bc/bifrost`.

Create the oracle child files and facade, then format and compile the library and tests enough to catch module privacy and path errors:

    cargo fmt --all
    scripts/with-isolated-cargo-target.sh cargo check --all-targets --all-features

Create the IR child files and facade, preserving the original test module body, then repeat the focused format/check gate. Move workspace dispatch and repeat it once more.

Run the unchanged acceptance suites together so one isolated build serves all four test binaries:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python \
      --test semantic_ir_contract \
      --test semantic_oracle_contract \
      --test semantic_value_language_contract \
      --test icfg_contract

Run the repository's formatting and lint acceptance gates:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

The expected result for each command is exit status zero. Contract-test counts may evolve, but no test source in those four files is to change as part of this issue. On the current macOS host, the Python-feature test executables have the known PyO3 link limitation documented above; use the `nlp` result plus the all-feature check and Clippy gates as the local evidence boundary.

## Validation and Acceptance

Acceptance is demonstrated when existing consumers compile without import edits and the four named contract suites pass from unchanged source files. `cargo fmt --all -- --check` must produce no diff. Clippy must complete with no warning under `--all-targets --all-features`. The final diff must contain only the ExecPlan, new module files, thin facade edits, relative import changes, and the smallest `pub(super)` visibility adjustments required by sibling ownership. No schema constant, serialized field, adapter identity, constructor validation order, candidate ordering, proof/completeness rule, limit arithmetic, work accounting, or cancellation branch may change.

The review should explicitly verify `Arc::ptr_eq` relation and procedure identity, first-seen provenance deduplication, `limit + 1` overflow detection, dispatch candidate sealing before call bindings, weak-update reason ordering, exact locator comparison, and atomic budget publication.

## Idempotence and Recovery

Formatting, checking, testing, and Clippy commands are safe to rerun. The isolated-target helper creates and removes its own managed Cargo target even on failure, so no manually named `/tmp/bifrost-*` target is allowed. The file move is mechanical and can be retried from the last checkpoint commit. If a compile error reveals a bad boundary, move the affected item to the lower dependency module or add `pub(super)` visibility; do not add public compatibility shims, duplicate implementations, ignore annotations, or source-text fallbacks.

## Artifacts and Notes

Starting state:

    HEAD 4037def8 Fix Scala annotated constructor parsing (#1070)
    branch 1081-decompose-semantic-ir-oracle-contracts-and-workspace-dispatch
    divergence from origin branch: 0 ahead, 0 behind

Relevant origin commit:

    b5b0dc3f Generalize receiver facts into value, dispatch, and heap oracles (#1076)

That commit introduced the oracle and workspace-oracle implementation being decomposed. No behavior from it is intentionally changed here.

Integrated compile evidence after the three moves:

    cargo check --all-targets --all-features
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 23.43s

The exported top-level `pub struct`, `pub enum`, `pub trait`, and `pub type` name sets in both `oracle` and `ir` match commit `4037def8` exactly.

Final validation evidence:

    cargo fmt --all -- --check
    # passed

    cargo check --all-targets --all-features
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 24.61s

    scripts/with-isolated-cargo-target.sh cargo test --features nlp \
      --test semantic_ir_contract \
      --test semantic_oracle_contract \
      --test semantic_value_language_contract \
      --test icfg_contract
    # 90 passed; 0 failed

    RUSTC=/opt/homebrew/bin/rustc scripts/with-isolated-cargo-target.sh \
      /opt/homebrew/bin/cargo clippy --all-targets --all-features -- -D warnings
    # passed; managed target removed

    git diff --quiet origin/master..HEAD -- \
      tests/semantic_ir_contract.rs \
      tests/semantic_oracle_contract.rs \
      tests/semantic_value_language_contract.rs \
      tests/icfg_contract.rs
    # exit 0

    git diff --check origin/master..HEAD
    # passed

## Interfaces and Dependencies

At completion, these facade paths remain valid and unchanged:

    crate::analyzer::semantic::*
    crate::analyzer::semantic::ir::*
    crate::analyzer::semantic::oracle::*
    crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle

The child modules are implementation details and remain private. Public type names, trait signatures, constructors, accessors, derives, and visibility stay unchanged. The only added visibility is `pub(super)` for helpers or fields that were previously private but must now be shared among private sibling modules. No new external crate or Cargo feature is introduced.

Revision note (2026-07-22 16:56Z): Initial self-contained plan created after live issue, branch, dependency, and history inspection. The oracle layout adds explicit foundational contract modules to satisfy the issue's one-direction dependency constraint.

Revision note (2026-07-22 17:10Z): Recorded completion of all three module moves, the implicit IR-test imports and ICFG helper consumers found by the integrated compile, and the successful all-target/all-feature check.

Revision note (2026-07-22 17:27Z): Closed validation and review with exact test, formatting, Clippy, API-parity, and unchanged-source evidence; documented the known macOS PyO3 link boundary and the corrected local toolchain selection.

Revision note (2026-07-22 18:06Z): Recorded the source-aware rebase over upstream's independent first-stage IR split, the resulting `ir/mod.rs` facade decision, and the complete post-rebase validation rerun.
