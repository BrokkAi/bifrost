# Add rollout evidence for unrecognized-symbol diagnostics

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

Maintain this plan in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost must keep unrecognized-symbol diagnostics optional until evidence proves that they are correct and fast. This work adds a stable report artifact for that evidence. The artifact pins the Bifrost revision, fixture revision, configuration digest, active pack hashes, cache state, activation state, SQL work, and diagnostic results.

The report keeps cold activation separate from cold and warm file diagnostics. It reads the semantic-pack lifecycle measurements that issue #1155 added. It does not add a second activation, hydration, matcher, candidate, retained-byte, or SQL counter. It also reads the structured diagnostic report that issue #1615 added. It does not copy that report or store source text.

A maintainer can serialize samples, aggregate compatible samples, and render a short Markdown report. The result cannot be clean when a report is incomplete or cancelled.

## Progress

- [x] (2026-08-06 07:10Z) Read `AGENTS.md`, `.agents/PLANS.md`, and the related #1155 and #1615 plans.
- [x] (2026-08-06 07:12Z) Verified a clean detached worktree at old `origin/master`, fetched origin, and moved to current `origin/master` at `c628a36cd`.
- [x] (2026-08-06 07:15Z) Verified live issue #1628. Verified PR #1667 and Lane 2 PR #1675 are merged into current master.
- [x] (2026-08-06 07:20Z) Inspected PR #1675 and mapped its production report and activation interfaces.
- [x] (2026-08-06 09:23Z) Milestone 1: added the artifact schema, direct lifecycle adapters, validation, aggregation, Markdown rendering, and seven focused tests.
- [ ] Milestone 2: add the opt-in benchmark collector and separate cold activation, cold diagnostic, warm diagnostic, and refresh samples.
- [ ] Milestone 3: add the pinned real-project campaign and set measured warm p95 review limits.
- [ ] Run the final policy gate and proportionate CI checks for each completed milestone.
- [ ] Review default enablement only after issues #1620 through #1627 and the pinned false-positive campaign are complete.

## Surprises & Discoveries

- Observation: Lane 2 was already merged when this work started.
  Evidence: PR #1675 merged at `dc0ba96f2` on 2026-08-05. Current `origin/master` contains that commit.

- Observation: PR #1667 already supplies all activation phase and resource measurements.
  Evidence: `SemanticModelActivationReport` owns candidate, shard, record, index, working-byte, retained-byte, and phase measurements. `SemanticModelActivationPhaseMeasurements` owns selection, decode or hydration, matcher construction, and catalog SQL values.

- Observation: Release bundle measurement already serializes the same production values.
  Evidence: `ReleasePackMeasurement` includes activation selection, decode or hydration, matcher construction, SQL, candidate, index, retained-byte, and lookup values.

- Observation: The structured diagnostic report has private fields and typed accessors.
  Evidence: `SemanticDiagnosticReport::status`, `diagnostics`, and `outcomes` expose read-only data. Only complete absence can add a diagnostic.

- Observation: `release_bundle` is not part of a normal runtime build.
  Evidence: `brokk-bifrost-semantic-packs` exposes it only through `release-tooling`. The rollout module now uses the same opt-in feature.

- Observation: This host has Rustup and Homebrew Clippy drivers with the same Rust commit but different LLVM builds.
  Evidence: Rustup reports LLVM 22.1.2. Homebrew reports LLVM 22.1.6. An unpinned Clippy run fails with `E0514`. Direct use of the pinned Rustup `cargo-clippy`, `rustc`, and `rustdoc` passes.

- Observation: The policy pack completes but reports repository-wide findings.
  Evidence: All 12 policies completed. The final result has 283 findings. The two findings on a changed file are old sort calls at catalog lines 804 and 809. This milestone changes only the serialization derive near line 86.

## Decision Log

- Decision: Store `SemanticModelActivationReport` directly in the rollout artifact.
  Rationale: The production report owns these measurements. Direct storage prevents a second metric schema and prevents value drift.
  Date/Author: 2026-08-06 / Codex

- Decision: Store `ReleaseBundleMeasurements` directly when release evidence is present.
  Rationale: The release crate already owns its serializable schema and pack lifecycle values.
  Date/Author: 2026-08-06 / Codex

- Decision: Store only counts from `SemanticDiagnosticReport`.
  Rationale: The rollout report needs proof classes and suppression classes. It does not need diagnostic messages, ranges, or source text.
  Date/Author: 2026-08-06 / Codex

- Decision: Make cold activation, cold diagnostic, warm diagnostic, and refresh diagnostic explicit phases.
  Rationale: Activation and diagnostic latency have different owners. Combining them would hide regressions.
  Date/Author: 2026-08-06 / Codex

- Decision: Keep diagnostics optional and keep default enablement outside this milestone.
  Rationale: Issues #1620 through #1627 and the pinned real-project false-positive campaign still block that review.
  Date/Author: 2026-08-06 / Codex

## Outcomes & Retrospective

The plan, interface reconciliation, and instrumentation-alignment milestone are complete. Schema version 1 pins revision, fixture, configuration, pack hash, cache state, activation state, and SQL metadata. It stores the production activation report and release measurements directly. It stores only proof and suppression counts from diagnostic reports.

Seven focused tests pass. They cover round trips, source metric preservation, cold and warm separation, all proof and suppression classes, cancelled activation, refresh rules, and SQL failure status. Featureless `cargo check`, formatting, `git diff --check`, and focused strict Clippy pass.

The final policy run completed all 12 policies with `status=finding`. It has no finding on a changed line. Open issue #1452 already covers the 8.6-second self-repository policy latency. Full issue completion remains blocked by the opt-in collector, ecosystem issues #1620 through #1627, and the pinned real-project campaign.

## Context and Orientation

An unrecognized-symbol diagnostic reports that a reference has no valid declaration. A diagnostic proof class describes the structured result for one checked reference. The classes are resolved, ambiguous, absent, and incomplete. Only absent can emit an error. A suppression class is the typed reason that stopped complete proof, such as cancellation or missing dependency discovery.

`crates/bifrost-core/src/analyzer/model.rs` defines `SemanticDiagnosticReport`, `SemanticDiagnosticOutcome`, `SemanticDiagnosticReportStatus`, and `SemanticDiagnosticIncompleteReason`. These are the production proof types from Lane 2.

`crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs` defines `SemanticModelActivationReport`, `SemanticModelActivationPhaseMeasurements`, `SemanticModelRuntimeLifecycle`, and `SemanticModelRuntimeOutcome`. These are the production activation types from Lane 1 and Lane 2.

`crates/bifrost-semantic-packs/src/release_bundle.rs` defines `ReleaseBundleMeasurements`. It is the release artifact for shipped packs.

`src/benchmark/` contains Bifrost benchmark report and aggregation support. The issue #1628 artifact belongs here. The first milestone adds a library boundary only. It does not start a project scan or enable diagnostics.

The cold activation phase includes dependency discovery, pack preparation, and runtime activation. The host owns the total elapsed value. The production runtime report owns its internal phase measurements. The cold diagnostic phase is the first per-file diagnostic request after activation. The warm diagnostic phase is a repeated request with unchanged revision, configuration, packs, and cache state. The refresh diagnostic phase is the first request after an activation outcome requires a diagnostic refresh.

## Plan of Work

Milestone 1 adds `src/benchmark/semantic_diagnostic_rollout.rs`. Define schema version 1. Add revision, fixture, configuration, active-pack, and cache identity. Add activation and diagnostic sample records. The activation sample stores the production activation report directly. The diagnostic sample converts a production `SemanticDiagnosticReport` to proof and suppression counts.

Add validation before aggregation. Reject missing revisions, malformed SHA-256 values, duplicate active packs, incompatible sample identity, invalid phase and cache combinations, absent counts that do not match error counts, and reports that claim completeness while they contain incomplete outcomes. Require a refresh diagnostic sample to identify an activation that requested refresh.

Add aggregation for compatible samples. Report sample counts, nearest-rank p50 and p95 latency, complete and incomplete report counts, emitted error counts, proof counts, and suppression counts. Keep activation lifecycle values in each source sample. Do not sum retained bytes or candidate counts into a misleading total.

Add a Markdown renderer for the aggregate. It must show pinned identity, phase latency, proof classes, suppression classes, and a final complete or incomplete status. An incomplete or cancelled sample must make the final status incomplete.

Milestone 2 adds an opt-in collector. It runs only when an explicit benchmark command or test environment requests it. It activates dependency packs through `WorkspaceAnalyzer::activate_dependency_packs`. It measures the host-owned total activation time. It then records cold, warm, and refresh diagnostic samples. Diagnostic calls only read the published analyzer snapshot.

Milestone 3 uses checked-in fixture definitions and pinned real-project revisions. It runs enough warm samples to set a reviewed p95 limit. It records zero confirmed false positives before any default-enablement review.

After each milestone, run focused tests, inspect the diff, update this plan, run the repository policy gate, and make one checkpoint commit. Do not push or open a pull request unless the user requests it.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/1009/bifrost`.

For milestone 1, add serialization derives to the production activation report types that the artifact stores. Do not add new measurement fields. Add the rollout module and its exports. Run:

    cargo fmt
    cargo test --features release-tooling benchmark::semantic_diagnostic_rollout
    cargo test benchmark::report::tests::percentile_uses_nearest_rank

Run the built-in `bifrost.code-smells` pack and each executable repository policy root in one MCP request. Treat `unreliable` as failure. Review each finding in changed code.

For strict focused Clippy on this host, use the pinned Rustup tools because Homebrew has a different LLVM build:

    RUSTC=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustc \
    RUSTDOC=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustdoc \
    /Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/cargo-clippy \
      clippy --features release-tooling --lib -- -D warnings

For milestone 2, add focused tests under the existing semantic or LSP suite. Use `InlineTestProject` for small fixtures. Do not add a root `tests/*.rs` binary. Run only featureless tests unless the change needs Python.

For milestone 3, use pinned repositories and exact revisions. Keep a failed sample artifact. Do not download dependencies during ordinary tests.

## Validation and Acceptance

Milestone 1 passes when schema round trips preserve production activation fields and release measurements. Tests must change candidate, retained-byte, SQL, revision, configuration, pack hash, cache state, lifecycle, and refresh values independently. Each change must remain visible or cause the documented validation error.

Diagnostic aggregation must count resolved, ambiguous, absent, and incomplete outcomes. It must count every typed suppression class. A cancelled or incomplete report must render an incomplete final state. No artifact contains diagnostic messages, ranges, or source text.

Cold activation samples must use cold cache state. Warm diagnostic samples must use warm cache state. Refresh diagnostics must point to an activation sample with `diagnostic_refresh_required=true`.

Full #1628 acceptance also needs pinned real-project reports, zero confirmed false positives, complete proof for every error, typed reasons for every suppression, and a measured warm p95 review limit. Default enablement needs a separate explicit review.

## Idempotence and Recovery

The schema, aggregation, rendering, format, and test commands are safe to repeat. Unit tests use in-memory values and temporary JSON strings. They do not scan repositories or download packs.

If a later schema change is incompatible, add a new schema version. Do not silently reinterpret version 1. Do not add a compatibility shim for the temporary Lane 2 branch API.

The worktree is detached by design. A checkpoint commit can remain detached until the user selects its destination. Do not change branches, rebase, push, or open a pull request.

## Artifacts and Notes

Live state at plan creation:

    HEAD af6a0d10f (detached at origin/master)
    #1628 OPEN
    #1667 MERGED as c209007db
    #1675 MERGED as dc0ba96f2

The first artifact schema version is 1. It stores hashes as lowercase hexadecimal SHA-256 strings. It stores times as integer nanoseconds.

## Interfaces and Dependencies

`src/benchmark/semantic_diagnostic_rollout.rs` will expose these main interfaces:

    pub const SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION: u32 = 1;

    pub struct SemanticDiagnosticRolloutArtifact { ... }

    pub struct SemanticDiagnosticActivationSample { ... }

    pub struct SemanticDiagnosticSample { ... }

    pub struct SemanticDiagnosticReportCounts { ... }

    pub struct SemanticDiagnosticRolloutAggregate { ... }

    pub fn aggregate_semantic_diagnostic_rollout(
        artifacts: &[SemanticDiagnosticRolloutArtifact],
    ) -> Result<SemanticDiagnosticRolloutAggregate, SemanticDiagnosticRolloutError>;

    pub fn render_semantic_diagnostic_rollout_markdown(
        aggregate: &SemanticDiagnosticRolloutAggregate,
    ) -> String;

The activation sample stores `brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationReport`. The artifact can store `brokk_bifrost_semantic_packs::release_bundle::ReleaseBundleMeasurements`. The diagnostic adapter accepts `brokk_bifrost_analysis::analyzer::SemanticDiagnosticReport` by reference.

Revision note, 2026-08-06: Created after live master, issue, PR, and production-interface verification. Lane 2 had merged, so the plan uses its production types directly.

Revision note, 2026-08-06 07:45Z: Synced detached HEAD to `af6a0d10f`. Kept the rollout artifact behind the existing release-tooling boundary because `release_bundle` is not a normal runtime API.

Revision note, 2026-08-06 09:23Z: Completed milestone 1. Recorded the schema, direct production adapters, focused validation, policy result, and host toolchain requirement. Left collection and real-project gates for later milestones.
