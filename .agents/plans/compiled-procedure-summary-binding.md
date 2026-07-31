# Bind compiled procedure summaries into reusable data-flow summaries

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, a caller that has already selected one compiled semantic-model procedure-summary family and resolved every selected target to exact mounted semantic declarations can deterministically turn those records into the existing `ExternalSemanticSummarySet`. The binder performs no pack activation, workspace search, source parsing, declaration synthesis, or query-specific carrier binding. Focused semantic-suite tests demonstrate the supported transfer/effect forms, failure cases, dependency closure, recursion, provenance, and order-independent fingerprints.

## Progress

- [x] (2026-07-31 17:10Z) Confirm PR #1410 is merged at the current `63feeb6a` base and inspect its compiled DTOs.
- [x] (2026-07-31 17:10Z) Trace the reusable summary IR, exact target matching, compatibility, evidence, completeness, dependency, SCC, and final-set contracts.
- [x] (2026-07-31 17:32 SAST) Added the activation-neutral binding API and typed errors under `crates/bifrost-analysis/src/analyzer/semantic_model/`.
- [x] (2026-07-31 17:35 SAST) Added behavior-focused semantic-suite coverage for lowering, identity stability, graph determinism, provenance honesty, and fail-closed validation.
- [x] (2026-07-31 18:04 SAST) Completed final validation: formatting, featureless Clippy, 28 focused semantic-model tests, and the full 603-test semantic suite pass; the required policy gate remains failed as unreliable because a repository-wide performance rule exhausts its budget.

## Surprises & Discoveries

- Observation: the existing CFG SCC implementation is already stack-safe and generic over a dense bidirectional graph.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic/cfg_algorithms.rs` implements iterative Kosaraju traversal, and `typestate/production.rs` already reuses it for procedure dependencies.
- Observation: complete external model rows must still be unproven, while model completeness is a separate axis.
  Evidence: `SummaryEvidence` tracks proof and row completeness independently, while `SummaryCompleteness::Partial` has the dedicated `ExternalModelIncomplete` reason.
- Observation: Bifrost MCP code-intelligence calls failed during discovery on the legacy MCP stack.
  Evidence: a parallel `search_symbols`, `get_summaries`, and `find_filenames` batch took 8.99 seconds; searches were cancelled with zero observed files and the other tools returned request-budget errors.
- Observation: the ordinary `cargo clippy` path mixed rustup Cargo/rustc with Homebrew `cargo-clippy`/`clippy-driver`, even though both report Rust 1.96.0.
  Evidence: clean and isolated targets both failed with E0514 for `cc`; `rustup which clippy-driver` resolved under `.rustup`, while `command -v clippy-driver` resolved `/opt/homebrew/bin/clippy-driver`. Invoking the toolchain's exact `cargo-clippy` binary made the featureless gate pass.
- Observation: the required built-in repository policy gate did not establish a reliable result.
  Evidence: the final `run_policy` returned exit 2 with five inconclusive rules. It retained 158 repository-wide review prompts, including six sort-in-loop prompts in changed files. Those six are required canonicalization steps over each procedure or dependency component; removing their stable ordering would violate deterministic summary identity. The MCP failures and timing evidence are tracked in issue #1423.

## Decision Log

- Decision: accept compiled summaries and explicit target-binding values directly, with no dependency on `ResolvedActiveSemanticModels` or `semantic_model/runtime.rs`.
  Rationale: selection and runtime indexing are concurrent work; the binder needs only immutable payload and exact binding facts.
  Date/Author: 2026-07-31 / Codex
- Decision: make each binding carry the exact compiled target value, artifact key, procedure locator, and structured receiver/parameter shape.
  Rationale: equality against the compiled target proves which resolver result is being consumed without parsing its path or symbol strings, while artifact/locator and boundary-shape checks fail closed.
  Date/Author: 2026-07-31 / Codex
- Decision: reuse `strongly_connected_components` with a binder-local dense graph, then emit SCCs through a deterministic dependency-first heap.
  Rationale: this preserves the existing stack-safe algorithm and recursive-group contracts without coupling the binder to production typestate planning.
  Date/Author: 2026-07-31 / Codex
- Decision: derive location/event keys with length-delimited, domain-separated hashing over compiled model, record, and local location/event identities.
  Rationale: record order, workspace roots, source coordinates, dense IDs, and temporary handles cannot affect these model-owned identities.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

The pure binder, portable external identity adjustment, and focused acceptance suite are implemented. Formatting and featureless Clippy pass, all 28 focused semantic-model tests pass, and the full semantic integration suite passes with 583 tests run and 20 ignored. The mandatory policy gate remains honestly failed as unreliable for repository-wide budget/cancellation reasons unrelated to the changed Rust files; issue #1423 owns the MCP failure and latency evidence.

## Context and Orientation

PR #1410 added strict compiled procedure-summary DTOs in `crates/bifrost-analysis/src/analyzer/semantic_model/artifact.rs`. A `CompiledProcedureSummary` contains a stable record ID, model ID, contract version, content SHA-256, authored target, completeness, abstract locations, transfers, and effects. Compilation validates these records but deliberately does not activate or apply them.

The reusable summary IR is in `crates/bifrost-analysis/src/analyzer/dataflow/reusable_summary.rs` and exported from `dataflow/mod.rs`. `SemanticProcedureSummary` owns stable ports, exits, transfers, effects, dependencies, completeness, and a `ProcedureSummaryKey`. `ExternalSemanticSummarySet::try_new` canonicalizes external summaries, verifies one compatibility family, rejects duplicate structured targets, and computes the set fingerprint. Recursive dependencies use `SummaryDependencyKey::Recursive` and a shared `SummaryRecursiveGroupKey`; dependencies outside an SCC use exact complete `ProcedureSummaryKey` values.

An exact target binding in the new module is resolver output, not a resolver. It associates one compiled record ID and its exact `CompiledProcedureTarget` with a `SemanticArtifactKey`, a procedure-role `SemanticLocator`, and an explicit boundary shape. The boundary shape says whether a receiver exists and lists formal parameter ordinals. The binder verifies these facts but never derives declarations from the target's symbol string.

## Plan of Work

Create `crates/bifrost-analysis/src/analyzer/semantic_model/summary_binding.rs` and export its focused API from `semantic_model/mod.rs`. Define structured receiver/parameter metadata, the exact target binding, and `ProcedureSummaryBindingError`. Implement one public pure function accepting a compiled summary slice, exact bindings, and `ExternalSummaryCompatibilityKey`.

Canonicalize records and bindings by stable IDs. Reject missing, duplicate, mismatched, non-procedure, artifact/locator-inconsistent, receiver/parameter-inconsistent, and compatibility-inconsistent bindings. Decode the compiled content digest into `ExternalSummaryOrigin`; use the bound artifact and declaration with the consumer compatibility family to form every `ProcedureSummaryIdentity`.

Resolve every direct and ambiguous callee ID in one batch before constructing summaries. Build canonical dependency adjacency, reuse the iterative CFG SCC helper, and process SCCs dependency-first. Build recursive-group fingerprints from exact member identities, recursive edges, and already-built external dependency keys. Lower ports, exits, transfers, and effects with explicitly unproven model evidence. Partial records additionally carry incomplete row evidence and `SummaryCompleteness::Partial([ExternalModelIncomplete(content_hash)])`.

Construct every `SemanticProcedureSummary`, then call `ExternalSemanticSummarySet::try_new` as the final validator and canonical set builder. Map its compatibility/ambiguity errors into binder errors.

Add `tests/suite_semantic/semantic_model_summary_binding.rs` and register it in `tests/suite_semantic/main.rs`. Use compiled fixtures or compact DTO builders plus exact semantic artifacts/locators. Assert all specified records, origin/evidence/completeness, location/event stability, reordered fingerprints, direct and recursive groups, required closure, and each typed failure.

## Concrete Steps

From `/Users/dave/.codex/worktrees/c00d/bifrost`:

    cargo test --test suite_semantic -- semantic_model_summary_binding::
    cargo fmt --all -- --check
    cargo clippy --all-targets --no-default-features -- -D warnings

After tests pass, run the installed Bifrost policy checker against the built-in `bifrost.code-smells` pack and every executable repository `.rqlp` root discovered in the workspace. A `finding` requires review and an `unreliable` result fails validation.

## Validation and Acceptance

The focused semantic tests must show that parameter-to-return, receiver, exceptional, heap, capture, allocation, escape, unknown-call, direct-call, and ambiguous-call records lower to the matching reusable IR variants. They must show that record and binding reordering preserve the set fingerprint; direct dependency chains and recursive SCC keys are deterministic; model-owned location/event identities are unaffected by mount/root, coordinates, or other runtime handles; complete model rows are complete but unproven; partial model rows and the enclosing summary are incomplete with external-model provenance; and duplicate/missing/ambiguous bindings, compatibility mismatch, unknown callees, invalid recursion, and unsupported location bindings return typed errors.

The existing semantic pack tests must remain green, proving that compilation and artifact bytes are unchanged and the binder remains an additive consumer.

## Idempotence and Recovery

All implementation steps are additive or local exports and can be rerun. Test and formatting commands do not mutate semantic-model artifacts. If a generated or fixture file changes unexpectedly, inspect it rather than sweeping it into the change. Do not edit `semantic_model/runtime.rs`, policies, RQL, solvers, or production plan construction.

## Artifacts and Notes

PR #1410 is merged as commit `63feeb6a9ec4324e3a47f06d8b834d22a42cb3c0`. The active worktree started clean and detached at that commit.

## Interfaces and Dependencies

The new module must expose a narrowly named binding function, exact binding and boundary metadata types, and a typed error. Its only graph dependency is the existing crate-private `DenseBidirectionalGraph`/`strongly_connected_components` API. Its final successful value must come from `ExternalSemanticSummarySet::try_new`. It must not import `ResolvedActiveSemanticModels` or edit `crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs`.

Revision note (2026-07-31): created the initial executable specification after confirming PR #1410 and tracing the compiled and reusable contracts.

Revision note (2026-07-31 17:38 SAST): recorded the implemented binder/tests, external identity portability decision, focused validation, toolchain split, policy unreliability, and issue #1423 evidence while the final gates continue.

Revision note (2026-07-31 18:04 SAST): closed the implementation plan after the toolchain-correct Clippy gate and complete semantic suite passed; retained the policy gate's unreliable result as an explicit failed validation outcome.

Revision note (2026-07-31 18:08 SAST): reviewed all six changed-file policy prompts and documented why the per-procedure and per-component canonical sorts are required for deterministic output; the repository-wide result remains unreliable because five rules are inconclusive.
