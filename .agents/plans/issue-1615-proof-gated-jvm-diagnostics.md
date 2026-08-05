# Deliver proof-gated JVM diagnostics for issue 1615

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

Maintain this plan under `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost must report an unrecognized symbol only when structured analysis proves that the symbol is absent. After this work, Java, Kotlin, and Scala diagnostics use one JVM resolution realm. They use workspace declarations and active dependency API packs. Unknown, incomplete, stale, cancelled, ambiguous, generated, or dynamic boundaries suppress errors and retain an exact reason.

A user can verify this behavior with focused semantic and LSP tests. Missing local names produce errors. Known workspace or indexed external names do not. Incomplete external evidence produces a structured suppressed result instead of an error.

## Progress

- [x] (2026-08-05 13:00Z) Read `AGENTS.md` and `.agents/PLANS.md`. Verified a clean detached worktree and `BIFROST_MCP_RMCP=on`.
- [x] (2026-08-05 13:02Z) Fetched origin and moved detached HEAD to `origin/master` at `2bf15296f2b316991efe7732b3d53e04c92af9bd`.
- [x] (2026-08-05 13:04Z) Verified live issues #1615 through #1619 are open and #1600 is closed.
- [x] (2026-08-05 13:06Z) Verified RMCP search, source-reading, usage, and policy tools are available. Initial calls completed within five seconds.
- [x] (2026-08-05 16:14Z) Milestone 1, issue #1616: added the shared semantic diagnostic proof report, migrated all implementations, tested it, and completed the post-milestone review. The checkpoint commit follows this plan update.
- [x] (2026-08-05 16:45Z) Milestone 2, issue #1617: added the host-owned seven-ecosystem activation and evidence lifecycle, tested it, reviewed it, and landed commit `739708573`.
- [x] (2026-08-05 16:45Z) Milestone 3, issue #1618: added the shared proof conformance harness and pinned offline Scala witnesses, tested it, reviewed it, and landed commit `be3c3d66a`.
- [ ] Milestone 4, issue #1619: add the JVM pilot, exact positive and near-miss tests, review it, and commit it.
- [ ] Run the final Bifrost policy gate and appropriate CI-equivalent checks.

## Surprises & Discoveries

- Observation: `IAnalyzer::semantic_diagnostics` has 12 language implementations and returns a bare vector.
  Evidence: RMCP `search_symbols` returned implementations for C++, Go, JavaScript, Kotlin, PHP, Python, Ruby, Rust, Scala, TypeScript, `MultiAnalyzer`, and the trait default.
- Observation: The semantic-model cache already retains dependency discovery evidence and keeps one published overlay.
  Evidence: `SemanticModelRuntimeCache` contains `dependency_evidence` and `overlay`; Python activation leaves the overlay unchanged after cancellation or unavailable preparation.
- Observation: A featureless first build of the shared semantic integration binary took 5 minutes 15 seconds. Subsequent filtered runs took seconds.
  Evidence: The Kotlin and Scala filtered test commands reused the built binary and passed 7 and 6 tests.
- Observation: The required policy result completed all 12 rules but returned 280 repository-wide findings. One finding named a changed file, but its line was unchanged by this milestone.
  Evidence: `bifrost.performance.sort-in-loop` named `crates/bifrost-analysis/src/analyzer/i_analyzer.rs:304`; the milestone diff changes only imports and lines 582 through 592 in that file.
- Observation: The #1617 review found two atomicity defects before landing.
  Evidence: Invalidation used short-circuit `any`, which left later language evidence. In-memory publication occurred before persistent publication could fail. Both orders were corrected.
- Observation: The #1618 review found incomplete checked-domain coverage.
  Evidence: The final harness now tests lexical scope, module, package, type, and member surface domains.
- Observation: One broad JVM `search_symbols` call took 5.18 seconds and returned a large response.
  Evidence: Issue #1668 records the exact request, revision, RMCP state, and result.

## Decision Log

- Decision: Put report and proof vocabulary in `brokk-bifrost-core` next to `SemanticDiagnostic` and reuse `BoundaryStatus`.
  Rationale: The report is a language-neutral model value. Core cannot depend on another Bifrost crate.
  Date/Author: 2026-08-05 / Codex
- Decision: Keep parse diagnostics outside the semantic report conversion.
  Rationale: The LSP already produces parse diagnostics separately. Issue #1616 requires no parse behavior change.
  Date/Author: 2026-08-05 / Codex
- Decision: Complete and commit #1616 before parallel work starts on #1617 and #1618.
  Rationale: Both issues depend on the report contract.
  Date/Author: 2026-08-05 / Codex
- Decision: Keep report status separate from per-reference outcomes.
  Rationale: A report with no diagnostics still needs an explicit complete or incomplete request state. Per-reference outcomes retain exact proof and suppression reasons.
  Date/Author: 2026-08-05 / Codex
- Decision: Reject `Absent` diagnostics at `ExternalDeclaredUnindexed` and `ExternalUnknown` boundaries in the report constructor.
  Rationale: Those boundary states do not provide complete negative evidence. Only workspace-local and indexed-external surfaces can prove absence.
  Date/Author: 2026-08-05 / Codex
- Decision: Publish overlay and discovery evidence under one runtime mutex after persistent publication succeeds.
  Rationale: One analyzer generation must expose one evidence set. A failed replacement cannot discard the prior complete state.
  Date/Author: 2026-08-05 / Codex
- Decision: Keep the shared #1618 matrix report-level and add language execution as each ecosystem integration lands.
  Rationale: The shared proof contract exists now. Only the JVM pilot is in this lane. Other language collectors belong to #1620 through #1627.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. `IAnalyzer::semantic_diagnostics` now returns `SemanticDiagnosticReport`. The report has private diagnostic storage, explicit request status, per-reference outcomes, checked domains, `BoundaryStatus`, and typed incomplete reasons. Only `push_absent` can add an error, and it rejects incomplete boundaries. Existing collectors now return reports without changing parse diagnostics. Discovery evidence and runtime outcomes map to the shared reasons without starting I/O.

Validation passed: five core contract tests, three analysis mapping tests, seven Kotlin tests, six Scala tests, `cargo fmt`, analysis and LSP checks, and `git diff --check`. The policy gate completed all 12 rules with `status=finding`; its only changed-file path was an unchanged pre-existing line. Two RMCP policy calls took 8.33 and 8.57 seconds. Open issue #1452 already records the same complete-result and oversized-output behavior, so no duplicate evidence comment was added.

Milestone 2 is complete. `DependencyPackEcosystem` selects JVM, .NET, npm, Python, Go, Cargo, or Ruby. `WorkspaceAnalyzer::activate_dependency_packs` runs explicit host work outside diagnostic requests. Complete work publishes overlay and discovery evidence atomically for one generation. Cancellation, incomplete preparation, unavailable runtime, or persistence failure retains the prior complete state. Explicit invalidation clears affected proof and requests a diagnostic refresh. LSP watched-file generation changes refresh all published diagnostic URIs.

Milestone 3 is complete for the shared proof layer. The matrix contains all 11 required scenario classes, all five checked domains, exact multi-reason suppression, member-surface completeness, and the LSP diagnostic projection. Ten non-absence cases emit zero errors. One complete workspace absence emits one error. Two offline Scala witnesses are content-pinned. No checked-in pinned Java or Kotlin real-project corpus exists yet; milestone 4 must add JVM-specific executable cases. Other ecosystem real-project rows remain gated by their integration issues #1620 through #1627.

## Context and Orientation

`crates/bifrost-core/src/analyzer/model.rs` contains public analyzer data such as `SemanticDiagnostic`. `crates/bifrost-core/src/analyzer/structural/resolution.rs` contains `BoundaryStatus`, which distinguishes workspace-local, indexed external, declared-but-unindexed external, and unknown external boundaries.

`crates/bifrost-analysis/src/analyzer/i_analyzer.rs` defines `IAnalyzer`. Its `semantic_diagnostics` method currently returns `Vec<SemanticDiagnostic>`. Language adapters implement this method. `crates/bifrost-analysis/src/analyzer/multi_analyzer.rs` selects a language analyzer and gives Kotlin a wider JVM source realm.

`crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs` records dependency discovery results and retained evidence. `crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs` builds and publishes active semantic-model overlays. An overlay is an immutable external declaration index attached to one analyzer generation. `crates/bifrost-analysis/src/analyzer/workspace.rs` contains a Python-only host activation flow that discovery, preparation, and publication use.

`crates/bifrost-lsp/src/lsp/handlers/diagnostic.rs` combines parse and semantic diagnostics. A diagnostic request must only read an existing analyzer snapshot. It must not discover dependencies, download data, build packages, or scan package caches.

The JVM realm is the combined Java, Kotlin, and Scala source and external declaration view. Existing JVM external indexes live under `crates/bifrost-analysis/src/analyzer/jvm/`. Kotlin and Scala have semantic collectors. Java does not.

## Plan of Work

Milestone 1 changes the semantic API from a vector to a report. The report contains diagnostic items and one outcome for each checked reference. Outcomes are resolved, ambiguous, complete absence, or incomplete. Complete absence includes a checked domain and `BoundaryStatus`. Incomplete results use typed reasons for missing discovery, stale generation, cancellation, truncation, unsupported semantics, dynamic behavior, and any runtime unavailable state. Constructors enforce that only complete absence can own an error diagnostic. Existing collectors first wrap their current results with accurate local proof or an incomplete reason. Tests cover construction, conversion, empty reports, and parse separation.

Milestone 2 replaces the Python-only workspace entry point with one explicit host lifecycle for JVM, .NET, npm, Python, Go, Cargo, and Ruby. It retains discovery and activation evidence for one analyzer generation. Publication swaps all overlay state atomically. Cancellation or unavailable preparation keeps the prior complete overlay. Dependency input changes invalidate matching evidence and request diagnostic refresh. Diagnostic handlers only read retained state.

Milestone 3 adds a shared behavior-driven test matrix under the existing semantic and LSP suites. Small projects use `tests/common/inline_project.rs`. The matrix checks known workspace symbols, complete local absence, indexed externals, declared-unindexed dependencies, unknown boundaries, ambiguity, corrupt or partial packs, cancellation, stale evidence, unsupported generated surfaces, dynamic behavior, and same-name near misses. Pinned real-project records state repository revision, toolchain, dependency, and pack versions. Each case checks emitted errors and exact suppressed outcomes.

Milestone 4 adds Java collection and migrates Kotlin and Scala to one JVM proof resolver. Workspace declarations across all three languages and active JDK, Kotlin, Scala, and dependency packs share precedence. Member absence is complete only when the owner surface is complete. Explicit and star imports keep ambiguity. Definition, reference, hover, and diagnostic queries use the same candidate order. External records stay external and never become workspace `CodeUnit` values.

After each milestone, run focused tests, inspect the diff, run a post-milestone review, correct findings, update this plan, and create one multiline checkpoint commit. Stage only files owned by this lane. After all milestones, run `cargo fmt`, the combined Bifrost policy selection, focused suites, and suitable workspace CI checks. Do not enable NLP unless the final CI-equivalent gate requires all features and disk space is sufficient.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/a5f9/bifrost`.

For milestone 1, edit the core model and analyzer trait. Migrate all implementations and direct tests. Run focused commands selected from the affected crates, followed by `cargo fmt --check`.

For milestone 2, edit semantic-model runtime and workspace lifecycle code. Add initial activation, reuse, invalidation, cancellation, recovery, and refresh tests. Run the affected semantic-model and LSP tests.

For milestone 3, add one shared harness inside existing test suites. Do not create a root `tests/*.rs` binary. Run the semantic and LSP conformance tests and record exact case counts.

For milestone 4, edit JVM, Java, Kotlin, Scala, multi-analyzer, and LSP code. Run exact Java, Kotlin, and Scala positive and near-miss tests.

Before final completion, run:

    cargo fmt
    cargo test --test suite_semantic <focused filters>
    cargo test -p brokk-bifrost-lsp <focused filters>

Use `scripts/with-isolated-cargo-target.sh` for a full all-features clippy command. Check disk space first. Run the built-in `bifrost.code-smells` pack and each executable repository policy root in one RMCP request.

## Validation and Acceptance

Issue #1616 passes when every semantic request returns a report, empty reports state why they are empty, and only complete absence creates errors. Tests must cover each typed incomplete reason and keep parse output unchanged.

Issue #1617 passes when all named ecosystems use one lifecycle contract. Tests must show atomic generation publication, prior-complete retention after cancellation, invalidation after dependency changes, recovery, and diagnostic refresh. A diagnostic request must perform no discovery or package I/O.

Issue #1618 passes when the shared matrix checks each required scenario and exact reason. Pinned ecosystem cases must report zero confirmed false positives.

Issue #1619 passes when Java, Kotlin, and Scala use one realm. Cross-language and indexed external symbols must not produce errors. Complete local absence must produce errors. Unknown classpaths, ambiguous imports, incomplete owners, generated surfaces, and dynamic behavior must produce exact suppressed results.

The final policy run must return `clean`. An `unreliable` result fails validation. Review each `finding`, correct in-scope findings, and repeat the same policy request.

## Idempotence and Recovery

All tests and format commands are safe to repeat. Activation tests use temporary projects and local fixtures. They must not download dependencies. If a milestone test fails, keep the current complete overlay and report objects intact while correcting the narrow failure.

Commits are recovery points. Do not reset, rebase, switch branches, push, or open a pull request. Do not stage unrelated files. The current worktree is the dedicated lane.

## Artifacts and Notes

Live state at plan creation:

    HEAD 2bf15296f2b316991efe7732b3d53e04c92af9bd (detached at origin/master)
    #1615 OPEN
    #1616 OPEN
    #1617 OPEN, depends on #1616
    #1618 OPEN, depends on #1616
    #1619 OPEN, depends on #1616, #1617, #1618, #1600
    #1600 CLOSED at 2026-08-05T10:25:48Z
    BIFROST_MCP_RMCP=on

Lane #1155 can supply lifecycle measurement records. This plan emits structured outcomes and activation evidence for measurement. It does not add thresholds or default-enablement policy. Issue #1628 owns those decisions.

## Interfaces and Dependencies

At the end of milestone 1, `brokk-bifrost-core` must expose a semantic diagnostic report, a checked-domain type, an absence proof, a typed incomplete reason, and a per-reference outcome. `IAnalyzer::semantic_diagnostics` must return that report. The report must make invalid error states unrepresentable through its constructors or validation.

At the end of milestone 2, `WorkspaceAnalyzer` must expose one explicit activation entry point that selects an ecosystem adapter without putting ecosystem logic into diagnostics. Runtime state must expose snapshot generation, retained discovery evidence, active overlay evidence, and invalidation state.

At the end of milestone 4, the JVM resolver must accept one realm view and return the shared proof outcome. Java, Kotlin, Scala, definition, reference, hover, and diagnostic clients must consume the same resolution order.

Revision note, 2026-08-05: Created the plan after live issue, worktree, RMCP, and initial code-surface verification.

Revision note, 2026-08-05 16:14Z: Completed issue #1616. Added exact API, test, review, policy, and latency evidence. Recorded the two review corrections that prevent unknown-boundary errors and expose empty-report completeness.

Revision note, 2026-08-05 16:45Z: Landed #1617 and #1618 together after their parallel detached-worktree reviews. Recorded atomic lifecycle behavior, conformance results, pinned-corpus limits, and dogfood latency issue #1668.
