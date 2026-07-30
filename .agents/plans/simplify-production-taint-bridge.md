# Simplify the production taint policy bridge

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The production taint adapter added by pull request #1343 works, but it duplicates selector compilation and carries several layers of intermediate data that obscure ownership. This refactor keeps every public policy result and every analysis decision unchanged while making shared selector compilation a concrete two-consumer component used by taint and typestate. A maintainer can verify the outcome by running the existing taint adapter, typestate policy, semantic, renderer-parity, formatting, and strict Clippy checks: the same behavior remains covered while the taint bridge becomes smaller and no longer depends on typestate implementation helpers.

## Progress

- [x] (2026-07-30 09:05Z) Verified the worktree was clean, fetched `origin/master`, and detached HEAD at `538a4729e8a740b63135c64fd7e566d9d8c2034d`.
- [x] (2026-07-30 09:12Z) Located PR #1343 and mapped the duplicated selector, semantic-budget, materialization, work-report, evidence, and witness-projection responsibilities.
- [x] (2026-07-30 09:43Z) Extracted neutral semantic identity/location and bounded witness helpers with analysis-specific labels supplied by each caller.
- [x] (2026-07-30 09:28Z) Replaced `PreparedPayload`, consolidated taint endpoint metadata, and made one compilation result own its work report.
- [x] (2026-07-30 09:38Z) Extended `selector_compiler.rs` into `PolicySelectorSession` and migrated taint.
- [x] (2026-07-30 09:42Z) Migrated typestate to `PolicySelectorSession`, retaining analysis-specific bindings outside it.
- [x] (2026-07-30 09:45Z) Kept taint compilation/execution/projection in one file because the shared extractions reduced it substantially and a file split would add module plumbing without clearer ownership.
- [x] (2026-07-30 09:57Z) Ran formatting, 5 focused taint adapter tests, 196 policy tests, 500 semantic tests, and strict all-target/all-feature Clippy. The repository policy MCP check remained unavailable because `list_policies` and `run_policy` were not registered.

## Surprises & Discoveries

- Observation: This worktree began detached at tag `v0.8.15`, not at current master.
  Evidence: `git status --short --branch` reported `HEAD (no branch)` at `6b6c2db9`; fetched `origin/master` is `538a4729`.

- Observation: The installed Bifrost skills are visible but the task has no Bifrost MCP code-intelligence or policy tools.
  Evidence: tool discovery did not expose `search_symbols`, `get_summaries`, `list_policies`, or `run_policy`, so navigation must use repository-native tools and final policy validation cannot be claimed unless the surface appears later.

- Observation: The concrete two-consumer extraction is a net deletion even after adding the neutral session and helpers.
  Evidence: the implementation diff reported 650 inserted lines and 957 deleted lines before final plan updates.

## Decision Log

- Decision: Keep the worktree detached at the exact fetched `origin/master` commit.
  Rationale: The user explicitly requested current `origin/master`, while repository instructions prohibit creating or switching branches unless explicitly asked.
  Date/Author: 2026-07-30 / Codex

- Decision: Make `PolicySelectorSession` concrete and policy-oriented rather than introducing a generic analysis framework.
  Rationale: Only taint and typestate consume the duplicated machinery, and their value/object bindings should remain separate.
  Date/Author: 2026-07-30 / Codex

- Decision: Expose the internal `SummaryWitness` from `TypestateWitness` at crate scope so both analyses use the same bounded public projection.
  Rationale: This preserves the existing public witness-step model without inventing a generic witness trait or collapsing typestate/taint labels.
  Date/Author: 2026-07-30 / Codex

- Decision: Do not split `taint_policy.rs` after the responsibility extraction.
  Rationale: The file lost the duplicated session and witness/identity implementations; splitting the remaining tightly coupled batch preparation and projection flow would add module boundaries without further semantic ownership gains.
  Date/Author: 2026-07-30 / Codex

## Outcomes & Retrospective

The shared ownership refactor is complete. Taint payload and root-plan intermediates were removed, selector compilation is owned by one concrete two-consumer session, semantic identities and witness projection are neutral, and taint no longer calls typestate implementation helpers. The implementation is a net deletion and all requested local validation passed. The only unavailable gate was the Bifrost MCP policy run because its tools were not registered in this task.

## Context and Orientation

`crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs` currently combines policy compilation, coordinator preparation and batched solver execution, and public finding projection. Its `TaintPolicyCompiler` owns query execution limits, cancellation, a semantic work budget, a semantic execution budget, accumulated CodeQuery work, and a per-file semantic artifact cache. `crates/bifrost-analysis/src/analyzer/policy/typestate_policy.rs` owns the same facilities in `TypestatePolicyCompiler`, plus typestate-only syntax trees and formal-parameter caches. `crates/bifrost-analysis/src/analyzer/policy/selector_compiler.rs` is already neutral but currently contains only small conversion helpers.

A selector is a resolved CodeQuery attached to a policy endpoint. Compiling a selector means executing that query under finite row, byte, semantic, materialization, and traversal limits; rejecting cancellation or incomplete results; retaining source-backed selected sites; and charging all work to the policy report. A semantic artifact is the structured per-file control/data-flow model used after selection. The shared session will own these neutral responsibilities. Taint remains responsible for turning selected sites into values and value-flow endpoints. Typestate remains responsible for turning selected sites into abstract objects, protocol events, and formal-name bindings.

The public policy witness type is `BoundedWitness` from `policy/finding.rs`. Both taint and typestate currently translate internal `SummaryWitness` steps into that type while applying analysis-specific labels. The neutral helper must preserve the public CodeQuery witness-step model and accept labels from each analysis rather than deciding them itself.

## Plan of Work

First move stable semantic identity and source-location construction out of `typestate_policy.rs` into a neutral policy module. Move the shared bounded witness projection shape beside those policy projection helpers, parameterized only by the analysis-specific step labels and the existing bounds. Update taint and typestate to use the neutral helpers so no taint code references typestate implementation details.

Next simplify the taint preparation data. Construct `TaintProjectionPayload` directly, remove `PreparedPayload`, consolidate source and sink projection metadata into one compiled root metadata owner, retain origin information only through `TaintOriginFindingEvidence`, and return one compilation result that owns its `PolicyWorkReport` instead of cloning the same report into each root plan.

Then expand `selector_compiler.rs` with `PolicySelectorSession`. It will own the workspace, CodeQuery limits, cancellation token, semantic budget, semantic execution budget, accumulated CodeQuery work, and materialized-artifact cache. It will expose concrete operations for executing a resolved selector into neutral selected sites, calculating remaining query and semantic limits, charging external query semantic work, checking cancellation/execution exhaustion, materializing an artifact once per file, and producing a policy work report with an analysis-specific metric prefix. Error conversion will remain in the two compilers so public completion and diagnostic semantics do not change.

Migrate `TaintPolicyCompiler` to the session and leave value selection, matched-value binding, call-region discovery, and taint plan construction in taint-owned code. Migrate `TypestatePolicyCompiler` next, leaving object/protocol binding, formal-name interpretation, syntax-tree caching, and protocol compilation in typestate-owned code.

Finally split `taint_policy.rs` into sibling compiler, execution, and policy-projection modules if the extracted boundaries produce cohesive modules. The compiler owns resolved-policy lowering and call-region/value-flow plan construction. Execution owns coordinator preparation, shared batch solving, and finite execution budgets. Projection owns policy findings, origins, witnesses, and public taint results. Keep coordinator-wide batching unchanged.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/e2aa/bifrost`.

After each extraction, run:

    cargo fmt --all -- --check
    cargo test --test suite_bench_policy taint_policy_adapter

Run the focused policy and semantic suites identified by the affected harnesses:

    cargo test --test suite_bench_policy
    cargo test --test suite_semantic

Run strict Clippy through the managed isolated-target helper:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Before the all-feature command, check free disk space and do not run another NLP build concurrently.

## Validation and Acceptance

The existing taint adapter tests must continue to prove caller/callee flow, inclusion of unselected common callers, matched-value binding, zero-match clean results, one shared propagation solve, broad fallback classification, bounded evidence, and human/JSON/SARIF parity. Typestate policy tests must continue to prove selector and protocol behavior. The semantic suite must pass without weakened budgets or changed incomplete outcomes.

Source review must show that `PreparedPayload` is gone, compilation work is owned once per policy compilation, compiled source/sink metadata has one owner, taint origins are retained only as `TaintOriginFindingEvidence`, taint has no references to `typestate_policy` implementation helpers, and both compilers construct and use `PolicySelectorSession`.

`cargo fmt --all -- --check` and strict Clippy must pass. If `list_policies` and `run_policy` become callable, run `bifrost.code-smells` together with every executable repository policy root in one request dated `2026-07-30`; otherwise record the missing MCP surface as a validation limitation.

## Idempotence and Recovery

All test and formatting commands are repeatable. The isolated Cargo target helper cleans its temporary target on success, failure, or interruption. Do not stage, commit, push, create a branch, rebase, or open a pull request unless the user asks. Preserve unrelated worktree changes if any appear.

## Artifacts and Notes

Baseline revision:

    538a4729e8a740b63135c64fd7e566d9d8c2034d

PR #1343 merge commit:

    9ce1a3ae Add production taint policy adapter and public projection (#1343)

## Interfaces and Dependencies

`PolicySelectorSession<'a>` will live in `crates/bifrost-analysis/src/analyzer/policy/selector_compiler.rs`. It will use existing `WorkspaceAnalyzer`, `CodeQueryExecutionLimits`, `CancellationToken`, `SemanticBudget`, `SemanticExecutionBudget`, `CodeQueryExecutionWork`, `ProjectFile`, and `SemanticArtifact` types. It must not introduce a trait, generic analysis mode, or policy-specific binding enum.

The neutral selected-site representation will retain `ProjectFile`, byte span, `ProofStatus`, and `EvidenceCompleteness`. Analysis compilers may wrap or consume it but must not duplicate query execution.

Revision note (2026-07-30): Created the initial plan after live remote verification and source mapping. The milestones deliberately migrate taint before typestate so behavior can be checked after each consumer adopts the shared session.

Revision note (2026-07-30): Updated the living sections after completing the implementation and focused validation. Recorded the deliberate no-split decision because the shared extractions already made ownership explicit with a net source deletion.

Revision note (2026-07-30): Marked validation complete after the Homebrew-pinned strict Clippy run avoided a rustup/Homebrew LLVM metadata mismatch and the final post-format policy and semantic reruns passed.
