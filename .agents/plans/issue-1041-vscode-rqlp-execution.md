# Add first-class VS Code execution for RQLP policies

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while implementation proceeds. This document follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, a developer editing a `.rqlp` policy in VS Code can run the live, possibly unsaved buffer against Bifrost's already-indexed workspace. A dedicated policy-results view shows the policy identity, its complete, inconclusive, unsupported, or failed state, and navigable findings without confusing endpoint-selector matches for findings. The Explorer also shows a Brokk-helmet policy icon that remains recognizable on light and dark themes.

The behavior is visible by opening a workspace policy, changing it without saving, pressing the editor-title Play button, and observing a structured policy report whose findings open their exact source ranges. Editing the policy or workspace afterward marks the retained report stale.

## Progress

- [x] (2026-07-21 18:08Z) Read issue #1041, inspected the current branch and relevant Rust/TypeScript paths, and completed independent diagnosis and planning passes.
- [x] (2026-07-21 18:08Z) Attached the worktree to the existing `1041-add-first-class-vs-code-execution-and-brokk-branding-for-rqlp-policies` branch.
- [x] (2026-07-21 18:24Z) Milestone 1: refactored policy coordination to accept an existing analyzer, cancellation, and a live root-document overlay; focused tests prove unsaved bytes and endpoint-root diagnostics.
- [ ] Milestone 2: expose overlay evaluation through a cancellable `bifrost/runPolicy` LSP request, with integration tests.
- [ ] Milestone 3: add the typed VS Code policy runner, dedicated results view, navigation, and stale-result lifecycle, with TypeScript tests.
- [ ] Milestone 4: replace the `.rqlp` icon and verify Explorer-size rendering on light and dark themes.
- [ ] Run formatting, clippy, Rust feature tests, VS Code tests, and manual Extension Development Host validation.
- [ ] Run the guided-issue specialist review, address material findings, and complete the retrospective.

## Surprises & Discoveries

- Observation: The missing policy Play experience is intentional, not a regression. `editors/vscode/src/rql_query.ts` rejects `bifrost-rql-policy`, and `src/lsp/server.rs` routes policy validation and hover through source-only handlers.
  Evidence: The existing `runRqlQuery` language guard accepts only `bifrost-rql`, while `ValidatePolicy` carries only a `source` string and has no analyzer or workspace access.

- Observation: The CLI coordinator currently constructs a fresh `FilesystemProject` and `WorkspaceAnalyzer`, so calling it directly from LSP would violate the requirement to reuse the active index.
  Evidence: `evaluate_policy_files_with_limits` builds a new analyzer before constructing `PolicyEvaluationContext`.

- Observation: Endpoint documents do not use the same explicit schema-version field as policies in the current fixture format.
  Evidence: The first endpoint-root test intentionally reached canonical validation failure; adapting it to the checked-in endpoint schema produced `NotExecutableEndpoint` as required.

## Decision Log

- Decision: Reuse the canonical `PolicyReportDocument` wire shape rather than defining a flattened editor-only report.
  Rationale: Completion states, report diagnostics, findings, evidence, and truncation semantics already have one bounded canonical representation. A second shape would drift and could accidentally turn unsupported or failed runs into empty successes.
  Date/Author: 2026-07-21 / Codex

- Decision: Select exactly one capability-confined workspace root from the active document URI and reject ambiguous, mismatched, traversing, or outside-workspace identities.
  Rationale: Policy dependencies must resolve relative to the policy's real workspace without widening access to a common ancestor in a multi-root session.
  Date/Author: 2026-07-21 / Codex

- Decision: Retain stale results with an explicit stale marker rather than clearing them silently.
  Rationale: Old evidence remains useful for inspection, but the UI must not imply it reflects changed policy or workspace state.
  Date/Author: 2026-07-21 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. `evaluate_policy_source` now evaluates editor-provided bytes under their supplied identity with a caller-owned `IAnalyzer` and cancellation token, while shared coordination still builds bounded canonical reports and CLI file evaluation retains its original analyzer-building behavior. The focused unsaved-source and endpoint-root tests pass. LSP request validation and integration remain for Milestone 2.

## Context and Orientation

RQL is Bifrost's structural query language. A `.rql` file is an ad hoc query; a `.rqlp` file is a durable policy or reusable endpoint document. Policy execution loads the root policy and capability-confined dependencies such as referenced `.rql` selectors, endpoint files or directories, exact endpoint references, and catalogs. An endpoint document is a dependency and must produce a clear `not executable` report diagnostic when selected as the run root.

`src/analyzer/policy/coordinator.rs` owns workspace-backed policy loading, evaluation, bounded report construction, and CLI exit-status calculation. Its public `evaluate_policy_files` API currently rereads roots from disk and constructs a new analyzer. `src/analyzer/policy/report.rs` and `src/analyzer/policy/finding.rs` define the canonical serialized policy report, including rule descriptors, runs, completion states, findings, source locations, evidence, and report diagnostics.

`src/lsp/server.rs` owns private Bifrost LSP requests. The existing `bifrost/queryCode` request demonstrates how an expensive workspace query snapshots the active overlay, uses the existing workspace analyzer, runs in a cancellable worker, and returns structured results. Policy validation and hover are intentionally source-only and must remain so; execution needs a new workspace-backed request.

`editors/vscode/src/extension.ts` owns VS Code lifecycle and command wiring. `editors/vscode/src/rql_query.ts` and `rql_results.ts` implement the ordinary RQL Play command and raw query-results tree. Policy execution must have separate models and a separate view because its hierarchy and semantics are policy run, completion, finding, and evidence rather than arbitrary query result items. `editors/vscode/package.json` declares commands, views, menus, languages, and file icons.

## Plan of Work

Milestone 1 introduces an internal coordinator pipeline that separates root input preparation, registry/evaluator/report coordination, and analyzer acquisition. Keep `evaluate_policy_files` unchanged for CLI callers: it canonicalizes the root, opens a `WorkspaceRoot`, reads the requested disk files, and builds one analyzer. Add a single-policy live-source entry point that accepts a validated workspace-relative `PolicySourceIdentity`, source bytes from the editor, an existing analyzer, and optional cancellation. It must register the active bytes under the supplied identity while every dependency continues to load through `PolicyRegistry::new_for_workspace`. Endpoint roots and invalid source must become canonical report diagnostics. Focused tests prove unsaved source overrides disk, dependency loading remains confined and functional, all completion states survive, and the live path does not construct another analyzer.

Milestone 2 defines `bifrost/runPolicy` in `src/lsp/server.rs`. Its parameters carry the document URI, workspace-relative source identity, and live source. Request handling selects the exact active workspace root, validates that URI and identity describe the same in-root path, snapshots the current overlay, and runs the coordinator entry point through the existing cancellable-worker infrastructure. The result is the serialized canonical report plus enough root identity for source navigation. Integration tests in `tests/bifrost_lsp_server.rs` cover saved and unsaved match policies, clean runs, invalid source, endpoint-root rejection, unsupported taint and typestate, dependency forms, range serialization, identity rejection, and multi-root behavior where supported.

Milestone 3 creates `editors/vscode/src/rql_policy.ts` for typed schema-version-one protocol models and the pure run helper, plus `rql_policy_results.ts` for a dedicated tree. The tree groups policy/run metadata above findings, shows exact completion state, severity, message, primary location, and terminal symbol, and exposes detailed evidence through tooltips or secondary expandable nodes. `extension.ts` registers Run Policy and finding navigation, focuses the dedicated view, and marks prior results stale when the active policy, workspace content, workspace folders, or server lifecycle changes. `package.json` contributes the Play button only for `bifrost-rql-policy`, a policy results view, and hidden internal navigation command. TypeScript tests cover request payloads, all states, diagnostics-only reports, rendering, navigation, staleness, and manifest conditions while retaining the test that policies never execute through the ordinary query command.

Milestone 4 replaces the generic shield/check document artwork. New light and dark SVG assets use a simple document silhouette with the checked-in Brokk helmet as the dominant recognizable element and at most a small secondary policy badge. Render both at 16 and 24 pixels on representative VS Code light and dark backgrounds, inspect the images, and iterate until the helmet remains legible.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/4188/bifrost` on `1041-add-first-class-vs-code-execution-and-brokk-branding-for-rqlp-policies`.

For each Rust milestone, run focused tests through the self-cleaning target helper, for example:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_lsp_server run_policy

Run the Rust gates after functional milestones:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Run extension validation from `editors/vscode`:

    npm test

Create checkpoint commits after each completed milestone. Stage only files changed for that milestone. Commit messages must explain both the user-visible result and why the design preserves active-analyzer reuse and capability confinement.

## Validation and Acceptance

Automated acceptance requires focused Rust integration tests, `cargo fmt --check`, clippy with all targets and features and warnings denied, the practical full Rust suite with `nlp,python`, and the VS Code `npm test` suite.

Manual acceptance uses a VS Code Extension Development Host attached to a small test workspace. Open a saved match policy, edit its selector without saving, and press the policy Play button. The dedicated policy view must show the policy ID/name, `complete`, and findings from the unsaved buffer. Selecting a finding must open the exact source range and show a terminal symbol when present. Evidence and provenance must be available without dominating the default tree. Editing the policy or a workspace file must leave the old result visible but labeled stale. An endpoint root must show a clear non-executable diagnostic. Taint and typestate must show `unsupported`, not a successful empty run. Referenced selector files, exact endpoints, endpoint directories, and catalogs must resolve from the chosen workspace root.

Render the new icon at 16 and 24 pixels on both representative theme backgrounds. Acceptance requires the Brokk helmet to be the first recognizable element and the document/policy treatment to remain secondary but sufficient to distinguish `.rqlp` from `.rql`.

## Idempotence and Recovery

All source edits and tests are repeatable. Isolated Cargo targets are removed automatically by `scripts/with-isolated-cargo-target.sh`; do not create manually named target directories. If a checkpoint fails validation, keep the living plan accurate, fix forward on the current issue branch, and rerun the focused command. Do not rebase, switch branches, or discard unrelated user changes. If report schema or policy-loader constraints make the proposed interface unsafe, record the discovery and revised decision here before changing course.

## Artifacts and Notes

The issue branch began clean at `d49a4fe0`, which is also the fetched `origin/master` at task start. The primary foundation is commit `3fdaa719`, which introduced versioned RQLP policy loading, evaluation, editor validation/hover, and the current generic icon. The existing structured RQL request/result precedent was introduced by the July 13 query-execution work.

## Interfaces and Dependencies

The final coordinator interface must provide a public single-root live-source function that accepts the workspace root, a portable `PolicySourceIdentity`, editor source text, the existing analyzer interface used by `PolicyEvaluationContext`, and cancellation where supported. Its result is `PolicyBatchOutcome`, whose report is the canonical `PolicyReportDocument`. The exact Rust signature may adapt to existing trait lifetimes, but it must not build a `WorkspaceAnalyzer` or read the root source from disk.

The final private LSP interface is `bifrost/runPolicy`. Its request contains document URI, workspace-relative source identity, and source text. Its response includes the canonical report without parsing or embedding CLI-rendered text, plus the selected workspace root identity required to turn report paths into file URIs.

The extension must define TypeScript wire types matching canonical schema version 1, a pure `runRqlPolicy` helper suitable for unit testing, and a dedicated `RqlPolicyResultsProvider`. Optional evidence fields may remain loosely typed at the edges where the UI only displays JSON detail, but required rule, run, completion, finding, severity, message, and source-location fields must be validated before rendering.

Revision note (2026-07-21): Created the initial self-contained plan after diagnosis and independent implementation planning. The milestone split isolates active-analyzer/capability-confinement correctness from editor presentation and visual branding so each risk can be validated independently.

Revision note (2026-07-21 18:24Z): Marked Milestone 1 complete after extracting shared coordination, adding the live-source API, threading cancellation into evaluation, and passing focused tests for unsaved analyzer-backed findings and endpoint-root rejection.
