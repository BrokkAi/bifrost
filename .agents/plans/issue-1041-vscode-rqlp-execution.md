# Add first-class VS Code execution for RQLP policies

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while implementation proceeds. This document follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, a developer editing a `.rqlp` policy in VS Code can run the live, possibly unsaved buffer against Bifrost's already-indexed workspace. A dedicated policy-results view shows the policy identity, its complete, inconclusive, unsupported, or failed state, and navigable findings without confusing endpoint-selector matches for findings. The Explorer also shows a Brokk-helmet policy icon that remains recognizable on light and dark themes.

The behavior is visible by opening a workspace policy, changing it without saving, pressing the editor-title Play button, and observing a structured policy report whose findings open their exact source ranges. Editing the policy or workspace afterward marks the retained report stale.

## Progress

- [x] (2026-07-21 18:08Z) Read issue #1041, inspected the current branch and relevant Rust/TypeScript paths, and completed independent diagnosis and planning passes.
- [x] (2026-07-21 18:08Z) Attached the worktree to the existing `1041-add-first-class-vs-code-execution-and-brokk-branding-for-rqlp-policies` branch.
- [x] (2026-07-21 18:24Z) Milestone 1: refactored policy coordination to accept an existing analyzer, cancellation, and a live root-document overlay; focused tests prove unsaved bytes and endpoint-root diagnostics.
- [x] (2026-07-21 18:45Z) Milestone 2: exposed overlay evaluation through a cancellable, identity-validated `bifrost/runPolicy` LSP request; the focused integration test covers findings, parse diagnostics, endpoint rejection, unsupported taint, and invalid identities.
- [x] (2026-07-21 18:57Z) Milestone 3: added the typed VS Code policy runner, dedicated results view, navigation, evidence tooltip, and stale-result lifecycle; the complete 61-test extension suite passes.
- [x] (2026-07-21 19:00Z) Milestone 4: replaced the generic policy artwork with theme-specific Brokk-helmet document icons and inspected 16- and 24-pixel light/dark renders for legibility.
- [x] (2026-07-21 19:35Z) Ran `cargo fmt --check`, strict all-target/all-feature clippy, the complete `nlp,python` Rust test suite, 185 matching LSP integration tests, and all 64 VS Code tests.
- [x] (2026-07-21 20:34Z) Ran a real isolated VS Code Extension Development Host smoke test: executed a `.rqlp` match policy, rendered `complete · 1 finding`, opened the finding at the exact 12-character `eval(source)` span, and compared the policy icon beside Python, JSON, RQL, and Markdown Explorer icons.
- [x] (2026-07-21 19:35Z) Completed the five-specialist guided review, fixed every Critical/High/Medium finding, and received clean senior and architecture re-reviews.

## Surprises & Discoveries

- Observation: The missing policy Play experience is intentional, not a regression. `editors/vscode/src/rql_query.ts` rejects `bifrost-rql-policy`, and `src/lsp/server.rs` routes policy validation and hover through source-only handlers.
  Evidence: The existing `runRqlQuery` language guard accepts only `bifrost-rql`, while `ValidatePolicy` carries only a `source` string and has no analyzer or workspace access.

- Observation: The CLI coordinator currently constructs a fresh `FilesystemProject` and `WorkspaceAnalyzer`, so calling it directly from LSP would violate the requirement to reuse the active index.
  Evidence: `evaluate_policy_files_with_limits` builds a new analyzer before constructing `PolicyEvaluationContext`.

- Observation: Endpoint documents do not use the same explicit schema-version field as policies in the current fixture format.
  Evidence: The first endpoint-root test intentionally reached canonical validation failure; adapting it to the checked-in endpoint schema produced `NotExecutableEndpoint` as required.

- Observation: The VS Code worktree initially had no installed Node dependencies.
  Evidence: `prettier` and `tsc` were missing; `npm ci` installed the locked 431-package dependency graph, after which the full extension test pipeline passed.

- Observation: A detailed generated helmet/document concept lost its silhouette at Explorer sizes.
  Evidence: The simplified SVG keeps the red horned helmet as the dominant shape and the document as a low-detail secondary outline; direct 16- and 24-pixel renders remain recognizable on both theme backgrounds.

- Observation: The shell resolved Homebrew's `clippy-driver` ahead of the repository-pinned rustup toolchain, producing incompatible compiler metadata despite matching version labels.
  Evidence: Reordering `PATH` to put `/Users/dave/.cargo/bin` first aligned Cargo, rustc, and clippy; the strict all-targets/all-features gate then reached source diagnostics and passed after correcting two test-only generic annotations.

- Observation: The canonical run-diagnostic code is a serde-tagged object, and policy source identities and finding paths can inhabit different coordinate systems in a multi-root server.
  Evidence: Review exposed both assumptions before release. The TypeScript decoder now accepts `{ "type": ... }` codes (including nested CodeQuery codes), while the LSP response separately names `policyRootUri` and `reportRootUri`; configured-root and multi-root tests assert both meanings.

- Observation: The feature-complete implementation needed generation tracking in addition to request cancellation.
  Evidence: VS Code cancellation is cooperative, so a superseded server response can still arrive. `PolicyRunTracker` gates publication by run ID and content revision, preventing older results from replacing newer ones and preserving a stale marker when content changes during a run.

- Observation: The first real VS Code run exposed a macOS path-alias boundary that integration tests using canonical temporary roots had hidden.
  Evidence: VS Code sent a `file:///tmp/...` document URI while `FilesystemProject` canonicalized its root to `/private/tmp/...`, so the policy-only resolver rejected a visibly in-workspace document. Reusing the shared allow-missing URI resolver canonicalizes the existing path prefix, and a real-server symlinked-workspace regression test now covers the same class of alias.

## Decision Log

- Decision: Reuse the canonical `PolicyReportDocument` wire shape rather than defining a flattened editor-only report.
  Rationale: Completion states, report diagnostics, findings, evidence, and truncation semantics already have one bounded canonical representation. A second shape would drift and could accidentally turn unsupported or failed runs into empty successes.
  Date/Author: 2026-07-21 / Codex

- Decision: Derive the policy source identity exclusively on the server from the active document URI and its deepest configured root.
  Rationale: Policy dependencies must resolve relative to the policy's real configured root without trusting a client-provided relative identity or widening access to a common ancestor. This also supports absolute configured roots outside the editor's ordinary workspace folders.
  Date/Author: 2026-07-21 / Codex

- Decision: Retain stale results with an explicit stale marker rather than clearing them silently.
  Rationale: Old evidence remains useful for inspection, but the UI must not imply it reflects changed policy or workspace state.
  Date/Author: 2026-07-21 / Codex

- Decision: Return separate `policyRootUri` and `reportRootUri` coordinates from `bifrost/runPolicy`.
  Rationale: Policy diagnostics and dependency identities are relative to the capability-confined policy root, while findings are serialized relative to the analyzer project's report root. Making both explicit prevents incorrect navigation in configured-root and multi-root sessions.
  Date/Author: 2026-07-21 / Codex

- Decision: Generalize cancellable workers to distinguish cancellation from internal failure strings.
  Rationale: Policy coordination can fail before a canonical report exists. Returning that as an internal LSP error is accurate, while treating it as cancellation would hide a real failure and duplicating the worker implementation would drift.
  Date/Author: 2026-07-21 / Codex

- Decision: Keep protocol validation and presentation helpers in a VS Code-independent `rql_policy.ts`, with `rql_policy_results.ts` limited to tree-item construction.
  Rationale: Unsaved request payloads, schema version checks, completion semantics, terminal-symbol extraction, and 1-based-to-0-based ranges can be unit-tested directly. The UI consumes those tested projections without parsing rendered CLI text.
  Date/Author: 2026-07-21 / Codex

- Decision: Ship separate light and dark policy icon assets rather than relying on one neutral asset.
  Rationale: The document outline needs opposing contrast across VS Code themes while the red helmet should remain visually stable and immediately recognizable at 16 pixels.
  Date/Author: 2026-07-21 / Codex

- Decision: Treat cancellation, stale publication, and successful-empty presentation as separate concerns.
  Rationale: Cancellation limits wasted work, generation/revision tracking establishes which response may publish, and completion/diagnostic/truncation checks determine whether zero findings is genuinely clean. Combining these would allow races or unsupported runs to appear successful.
  Date/Author: 2026-07-21 / Codex

- Decision: Render all report-controlled tooltip text through `MarkdownString.appendText` and evidence through `appendCodeblock`.
  Rationale: Findings and policy metadata are untrusted workspace content. Separating escaped data from fixed Markdown prevents command-link or formatting injection while preserving useful structured detail.
  Date/Author: 2026-07-21 / Codex

## Outcomes & Retrospective

All four implementation milestones and automated validation are complete. `evaluate_policy_source` evaluates editor-provided bytes under a server-derived identity with a caller-owned `IAnalyzer`, capability-confined dependencies, and cancellation checks. `bifrost/runPolicy` selects the owning configured root, uses the overlay-snapshot analyzer, and returns the canonical report with explicit policy and report coordinate roots. VS Code now exposes a cancellable policy-only Play command and dedicated results view with exact completion semantics, run/report diagnostics and truncation, safe evidence tooltips, navigable findings, generation-safe publication, and conservative stale-result marking. Theme-specific Brokk-helmet document icons remain legible in inspected 16- and 24-pixel renders.

The five-specialist review found and drove fixes for server-authoritative identity, configured roots outside editor workspaces, multi-root path coordinates, stale response races, user cancellation, unsupported/empty messaging, hidden diagnostics/truncation, canonical tagged diagnostic codes, Markdown injection, and duplicated policy input preparation. Senior and architecture re-reviews found no remaining Critical, High, or Medium issues; security retained only a Low observation that cancellation cannot interrupt one already-running bounded registry load. Formatting, strict clippy, the complete `cargo test --features nlp,python` suite, the LSP integration selection, and all 64 VS Code tests pass.

The final isolated Extension Development Host smoke test found and then verified the fix for `/tmp` versus `/private/tmp` document identity. The successful rerun displayed one complete finding and navigated to the exact `eval(source)` span in `app.py`. In the real dark-theme Explorer, the light-box footprint and perceived height of the red helmet/document policy glyph match the adjacent 16-pixel Python, JSON, ordinary RQL, and Markdown icons without crowding the filename row. All automated and manual acceptance steps are complete.

## Context and Orientation

RQL is Bifrost's structural query language. A `.rql` file is an ad hoc query; a `.rqlp` file is a durable policy or reusable endpoint document. Policy execution loads the root policy and capability-confined dependencies such as referenced `.rql` selectors, endpoint files or directories, exact endpoint references, and catalogs. An endpoint document is a dependency and must produce a clear `not executable` report diagnostic when selected as the run root.

`src/analyzer/policy/coordinator.rs` owns workspace-backed policy loading, evaluation, bounded report construction, and CLI exit-status calculation. Its public `evaluate_policy_files` API currently rereads roots from disk and constructs a new analyzer. `src/analyzer/policy/report.rs` and `src/analyzer/policy/finding.rs` define the canonical serialized policy report, including rule descriptors, runs, completion states, findings, source locations, evidence, and report diagnostics.

`src/lsp/server.rs` owns private Bifrost LSP requests. The existing `bifrost/queryCode` request demonstrates how an expensive workspace query snapshots the active overlay, uses the existing workspace analyzer, runs in a cancellable worker, and returns structured results. Policy validation and hover are intentionally source-only and must remain so; execution needs a new workspace-backed request.

`editors/vscode/src/extension.ts` owns VS Code lifecycle and command wiring. `editors/vscode/src/rql_query.ts` and `rql_results.ts` implement the ordinary RQL Play command and raw query-results tree. Policy execution must have separate models and a separate view because its hierarchy and semantics are policy run, completion, finding, and evidence rather than arbitrary query result items. `editors/vscode/package.json` declares commands, views, menus, languages, and file icons.

## Plan of Work

Milestone 1 introduces an internal coordinator pipeline that separates root input preparation, registry/evaluator/report coordination, and analyzer acquisition. Keep `evaluate_policy_files` unchanged for CLI callers: it canonicalizes the root, opens a `WorkspaceRoot`, reads the requested disk files, and builds one analyzer. Add a single-policy live-source entry point that accepts a validated workspace-relative `PolicySourceIdentity`, source bytes from the editor, an existing analyzer, and optional cancellation. It must register the active bytes under the supplied identity while every dependency continues to load through `PolicyRegistry::new_for_workspace`. Endpoint roots and invalid source must become canonical report diagnostics. Focused tests prove unsaved source overrides disk, dependency loading remains confined and functional, all completion states survive, and the live path does not construct another analyzer.

Milestone 2 defines `bifrost/runPolicy` in `src/lsp/server.rs`. Its parameters carry the document URI and live source. Request handling derives the workspace-relative source identity from the exact owning configured root, snapshots the current overlay, and runs the coordinator entry point through the existing cancellable-worker infrastructure. The result is the serialized canonical report plus explicit policy-root and report-root identities for diagnostic and finding navigation. Integration tests in `tests/bifrost_lsp_server.rs` cover saved and unsaved match policies, clean runs, invalid source, endpoint-root rejection, unsupported taint and typestate, dependency forms, range serialization, configured roots, and multi-root behavior.

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

The final private LSP interface is `bifrost/runPolicy`. Its request contains document URI and source text; the server derives the source identity. Its response includes the canonical report without parsing or embedding CLI-rendered text, `policyRootUri` for policy diagnostics and dependencies, and `reportRootUri` for finding-path navigation.

The extension must define TypeScript wire types matching canonical schema version 1, a pure `runRqlPolicy` helper suitable for unit testing, and a dedicated `RqlPolicyResultsProvider`. Optional evidence fields may remain loosely typed at the edges where the UI only displays JSON detail, but required rule, run, completion, finding, severity, message, and source-location fields must be validated before rendering.

Revision note (2026-07-21): Created the initial self-contained plan after diagnosis and independent implementation planning. The milestone split isolates active-analyzer/capability-confinement correctness from editor presentation and visual branding so each risk can be validated independently.

Revision note (2026-07-21 18:24Z): Marked Milestone 1 complete after extracting shared coordination, adding the live-source API, threading cancellation into evaluation, and passing focused tests for unsaved analyzer-backed findings and endpoint-root rejection.

Revision note (2026-07-21 18:45Z): Marked Milestone 2 complete after adding the cancellable `bifrost/runPolicy` request, authoritative workspace-relative identity validation, structured canonical response, and passing end-to-end LSP coverage.

Revision note (2026-07-21 18:57Z): Marked Milestone 3 complete after adding typed canonical report handling, the dedicated policy-results tree, exact finding navigation, stale lifecycle wiring, manifest contributions, and passing the full VS Code test pipeline.

Revision note (2026-07-21 19:00Z): Marked Milestone 4 complete after replacing the generic icon with separate light/dark Brokk-helmet assets and visually inspecting Explorer-size renders.

Revision note (2026-07-21 19:05Z): Recorded the pinned-toolchain clippy invocation and its clean result after fixing generic annotations in the cancellable-worker unit tests.

Revision note (2026-07-21 19:35Z): Recorded final automated validation and the guided-review fixes for server-derived identity, configured/multi-root coordinates, cancellation and publication races, completion messaging, diagnostic projection, safe Markdown rendering, and canonical tagged diagnostic codes. Senior and architecture re-reviews are clean; only interactive Extension Host validation remains.

Revision note (2026-07-21 20:34Z): Recorded the real VS Code smoke test, the macOS `/tmp` path-alias failure it exposed, the shared-resolver fix and symlink regression test, successful finding navigation, and the final Explorer icon-size comparison.
