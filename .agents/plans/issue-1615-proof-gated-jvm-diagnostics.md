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
- [x] (2026-08-07) Milestone 4, issue #1619: all three JVM languages answer one proof ladder, diagnostics are read-only, and the cross-language matrix is executable.
- [x] (2026-08-05 17:10Z) Started #1619: added proof-gated Java collection, merged-realm workspace lookup, and three focused tests.
- [x] (2026-08-07) Finished #1619: added `brokk-bifrost-jvm/src/proof.rs`, migrated Kotlin and Scala off `from_workspace_absences`, made every external read peek-only, moved jar building to `warm_query_indexes`, and added Java's active-overlay import tiers.
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
- Observation: Existing Kotlin and Scala collectors still construct complete workspace absences after resolver calls that can initialize JVM external indexes.
  Evidence: Their implementations use `from_workspace_absences`; Kotlin type checks call `external_declaration_index()`.
- Observation: The concern above was worse than recorded. Every JVM external read went through `OnceLock::get_or_init`, and no `.get()` peek existed anywhere. `JvmExternalDeclarationIndex::build_for_project` reads up to 128 artifacts and 512 MiB of jars, and under `JvmDependencyDiscoveryMode::OfflineBuildTools` spawns `mvn -o` or `gradle --offline` with a 30-second timeout each.
  Evidence: Survey of `analyzer/jvm/external.rs:968-1017` and `dependency_discovery.rs:88-226`. No pre-warm caller existed: `warm_query_indexes` was overridden only by `RustAnalyzer`, so the background `IndexWarmer` never touched the JVM index and every build was demand-driven from a request.
- Observation: `JvmExternalType` carries no member information at all.
  Evidence: `analyzer/jvm/external.rs:59-67` holds `fqn`, `package_name`, `short_name`, `kind`, `visibility`, `source`. `class_type` parses a whole `.class` file through `jclassfile` and discards the method and field tables; `apply_java_type_fact` merges only `kind` and `visibility`.
- Observation: The active overlay indexes each symbol under its simple name as well as its qualified name and aliases, so a naive `symbols_named` lookup silently accepted a simple-name match.
  Evidence: `semantic_model/overlay.rs:616-619` posts all three. A Kotlin file spelling a bare `Widget` with no import matched the modelled `com.acme.Widget` until `JvmOverlayModel` was narrowed to qualified spellings.
- Observation: `MultiAnalyzer` routed Kotlin diagnostics to the Kotlin *delegate* and only when `kotlin_realm()` found Java or Scala peers, so a Kotlin-only workspace read an empty overlay. Scala had no arm at all.
  Evidence: `acquire_active_semantic_models` publishes onto the analyzer the host holds; delegates keep their own `snapshot_caches`. Both defects would have made the proof gate permanently inert for those languages.

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
- Decision: A diagnostic peeks at the retained external index and never builds it; `IAnalyzer::warm_query_indexes` builds it instead.
  Rationale: #1615 forbids package I/O inside a request, and building that index reads jars and can spawn build tools. `warm_query_indexes` is the documented off-request, background-safe, idempotent hook, and `IndexWarmer` already drives it. The resolver keeps its eager path, so the diagnostic path's evidence is a strict subset of the resolver's; with less evidence a lookup can only fall toward `Incomplete`, never toward `Absent`, so a diagnostic can never contradict a `get_definition` that resolved the same reference.
  Date/Author: 2026-08-07 / Claude
- Decision: Only a published dependency model makes an external miss provable. A complete jar index answers `ExternalUnknown` on a miss.
  Rationale: This follows the Java pilot rather than widening it. A jar index is complete for the artifacts that happened to resolve on disk, which is not a claim about the classpath the build would use; if JDK discovery had not run, trusting it would report `String` as absent. A published model set is an activated, curated API surface, so missing it is evidence. The visible consequence is recorded under Outcomes.
  Date/Author: 2026-08-07 / Claude
- Decision: Map Scala's former `Uncertain` to `UnsupportedSemantics{detail}`, not to a dependency-state reason.
  Rationale: `Uncertain` meant an import the resolver cannot follow -- a wildcard whose members it does not enumerate, or a target no retained surface holds. Nothing is missing from the dependency surface; the gap is in this resolver. `MissingDependencyDiscovery` would send a reader to configure a classpath that is not the problem. The detail quotes the exact import.
  Date/Author: 2026-08-07 / Claude
- Decision: JVM member-surface absence is not implemented, and is documented as vacuous rather than faked.
  Rationale: `JvmExternalType` carries no member information, so no JVM surface can prove a member absent from a complete owner. `SemanticDiagnosticDomain::MemberSurface` therefore has no JVM producer, and all three collectors diagnose written type and term names only. The shared conformance harness still covers the domain at report level from #1618.
  Date/Author: 2026-08-07 / Claude
- Decision: A conflicted model match is `Ambiguous`, not a miss.
  Rationale: Two dependency models binding one fully-qualified name means the name exists and denotes neither in particular. Treating that as absence would manufacture an error out of an excess of evidence.
  Date/Author: 2026-08-07 / Claude

## Outcomes & Retrospective

Milestone 1 is complete. `IAnalyzer::semantic_diagnostics` now returns `SemanticDiagnosticReport`. The report has private diagnostic storage, explicit request status, per-reference outcomes, checked domains, `BoundaryStatus`, and typed incomplete reasons. Only `push_absent` can add an error, and it rejects incomplete boundaries. Existing collectors now return reports without changing parse diagnostics. Discovery evidence and runtime outcomes map to the shared reasons without starting I/O.

Validation passed: five core contract tests, three analysis mapping tests, seven Kotlin tests, six Scala tests, `cargo fmt`, analysis and LSP checks, and `git diff --check`. The policy gate completed all 12 rules with `status=finding`; its only changed-file path was an unchanged pre-existing line. Two RMCP policy calls took 8.33 and 8.57 seconds. Open issue #1452 already records the same complete-result and oversized-output behavior, so no duplicate evidence comment was added.

Milestone 2 is complete. `DependencyPackEcosystem` selects JVM, .NET, npm, Python, Go, Cargo, or Ruby. `WorkspaceAnalyzer::activate_dependency_packs` runs explicit host work outside diagnostic requests. Complete work publishes overlay and discovery evidence atomically for one generation. Cancellation, incomplete preparation, unavailable runtime, or persistence failure retains the prior complete state. Explicit invalidation clears affected proof and requests a diagnostic refresh. LSP watched-file generation changes refresh all published diagnostic URIs.

Milestone 3 is complete for the shared proof layer. The matrix contains all 11 required scenario classes, all five checked domains, exact multi-reason suppression, member-surface completeness, and the LSP diagnostic projection. Ten non-absence cases emit zero errors. One complete workspace absence emits one error. Two offline Scala witnesses are content-pinned. No checked-in pinned Java or Kotlin real-project corpus exists yet; milestone 4 must add JVM-specific executable cases. Other ecosystem real-project rows remain gated by their integration issues #1620 through #1627.

Milestone 4 has started but is not complete. Java now has a structured collector. It uses the merged JVM workspace definition index in `MultiAnalyzer`, keeps multiple workspace candidates ambiguous, and does not create external `CodeUnit` values. Without retained dependency proof, a missing Java type produces `MissingDependencyDiscovery` and no error. Three Java tests cover workspace resolution, an unproved missing type, and a same-name value near miss. Active overlay lookup must next use Java import tiers. Kotlin and Scala must then stop eager external-index initialization during diagnostics.

Milestone 4 is now complete. `brokk-bifrost-jvm/src/proof.rs` holds the vocabulary all three languages answer: `JvmNameProof`, `JvmProofGap`, `JvmRetainedExternalIndex`, `JvmModelDisposition` and `JvmActiveSemanticModel`. `record_jvm_name_proof` is the only path from a proof to a report entry, so exactly one code path can emit an error and only `JvmNameProof::Absent` reaches it. Kotlin's `kotlin_type_name_proof` replaces a boolean that had collapsed three facts into one bit, and Scala's `simple_type_proof` and `simple_term_proof` replace `ScalaTypeKnownness`, whose `Uncertain` arm had collapsed two more.

Every external read is now a peek. Java, Kotlin and Scala expose `retained_*` members that read the `OnceLock` without initializing it, and all three analyzers implement `warm_query_indexes` so the jar reads happen on the host's background hook instead. Java consults the active model through `java_type_name_candidate_fqns`, which walks the explicit-import, wildcard-import, same-package, default-package and `java.lang` tiers and yields spellings rather than `CodeUnit`s, because an external declaration has none and must never be given a fabricated one.

Validation: 694 semantic-suite tests, 1686 analysis unit tests, 33 JVM crate tests and 198 LSP server tests pass, with featureless workspace clippy clean. `tests/suite_semantic/jvm_diagnostic_proof.rs` runs ten cross-language assertions covering all six acceptance criteria; the per-language files now assert outcomes instead of `Debug` substrings.

Two consequences are deliberate and visible. First, JVM unrecognized-symbol diagnostics no longer fire without an activated dependency model, so a plain LSP session publishes none: the LSP host does not call `activate_dependency_packs`, while the MCP service does activate through `acquire_active_semantic_models`. Wiring LSP activation is host work outside this lane and is what turns positive JVM diagnostics back on. The two LSP opt-in tests were rewritten to pin the new contract -- an enabled pass still publishes nothing it cannot prove -- and they name where the positive case is pinned instead. Second, `SemanticDiagnosticDomain::MemberSurface` has no JVM producer, because `JvmExternalType` carries no member information; this is documented in `proof.rs` and in the Decision Log rather than simulated.

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

Revision note, 2026-08-05 17:10Z: Started #1619 with Java proof-gated collection and focused near-miss tests. Recorded remaining overlay-precedence and read-only migration work.

Revision note, 2026-08-07: Completed #1619. Added the shared JVM proof ladder, migrated Kotlin and Scala onto it, made every external read peek-only and moved jar building to `warm_query_indexes`. Recorded the two routing defects that would have left the gate inert, the simple-name overlay match that would have suppressed real errors, the vacuous member-surface result, and the LSP activation gap that keeps positive JVM diagnostics off until a host activates packs.
