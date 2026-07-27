# Add durable policy suppressions and tracked Bifrost project configuration

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`. It implements GitHub issue #1207 on the already checked-out branch `1207-add-durable-policy-finding-suppressions-and-tracked-bifrost-project-configuration`. Do not create or switch branches. Because this is an ExecPlan, finish and review each milestone, then commit only that milestone's files with a multiline message explaining why the change is necessary. Do not push or open a pull request unless the user explicitly asks later.

## Purpose / Big Picture

After this change, a project can commit exploratory queries under `.bifrost/queries/`, recurring policies under `.bifrost/policies/`, and reviewed false-positive decisions in `.bifrost/suppressions.json`. A reviewed suppression names one exact strong policy finding. It survives unrelated line insertions and presentation-only policy edits, but it does not follow changed source bytes, moved files, weak identities, fuzzy paths, regular expressions, or similar-looking findings.

Policy evaluation still runs normally and constructs the same findings, proof, completeness, witnesses, and work report. Bifrost then joins the resulting strong identities to the suppression document. Concise human output and failure thresholds ignore accepted current suppressions, while verbose human output, canonical JSON, and SARIF retain the result and its audit evidence. Invalid suppression configuration makes the report unreliable rather than silently treating every finding as active. Stale, expired, not-evaluated, incomplete-run, and policy-hash-drift states remain visible for review.

The same change separates tracked project configuration from disposable analyzer data. Default generated storage moves from `.bifrost/bifrost_cache.db` to `.bifrost/cache/bifrost_cache.db`; only `.bifrost/cache/` is ignored and filtered from watchers. Existing generated whole-directory ignore files are migrated conservatively so they cannot continue hiding project-owned configuration.

The behavior is observable by running one fixture policy, accepting its strong finding in `.bifrost/suppressions.json`, and rerunning the CLI with the same explicit evaluation date. The canonical report still contains the finding, SARIF contains an external accepted suppression and the original strong fingerprint, concise output reports one suppressed finding without printing it as active, and `--fail-on warning` exits cleanly. Editing the selected source bytes makes the old suppression stale and the new finding active.

## Progress

- [x] (2026-07-27 10:40Z) Reconciled issue #1207 with current `origin/master`, parent issue #1204, closed policy foundation #709, and the existing CLI, library, LSP, MCP, report, and cache surfaces.
- [x] (2026-07-27 10:40Z) Chose the canonical suppression, evaluation-date, cache-migration, and narrow MCP contracts recorded below.
- [x] (2026-07-27 11:47Z) Milestone 1: split tracked `.bifrost` project state from generated cache state; validated exact legacy migration, ignore safety, watcher behavior, linked-worktree sharing, extension provisioning, and affected persistence integrations.
- [ ] Milestone 2: implement the bounded suppression schema, typed parser, capability-confined loader, and identity/date types.
- [ ] Milestone 3: apply suppressions in the shared coordinator and extend the canonical report model without changing analyzer evidence or work.
- [ ] Milestone 4: make human, JSON, SARIF, CLI, and failure-threshold behavior suppression-aware.
- [ ] Milestone 5: thread the same request through LSP/VS Code and add a narrow read-only MCP `run_policy` tool for explicit workspace policies.
- [ ] Milestone 6: update public documentation, run the complete Rust/docs validation gates, perform specialist review, and record final outcomes.

## Surprises & Discoveries

- Observation: Bifrost currently has no MCP policy-evaluation tool. The `extended` toolset exposes `query_code`, and parent issue #1204 explicitly owns built-in policy-pack listing and selection.
  Evidence: `src/mcp_extended.rs` does not register a policy tool, `SearchToolsService::call_tool_output_with_cancellation` has no policy branch, and live issue #1204 lists an MCP policy surface as a future deliverable.

- Observation: commit `5434773f` creates `.bifrost/.gitignore` containing `*`, so changing only the database path would leave existing workspaces' query, policy, and suppression files invisible to Git.
  Evidence: `src/cache_db.rs::ensure_cache_dir_self_ignored` writes `*\n` when the database parent is `.bifrost`.

- Observation: the project watcher currently drops every event whose first relative component is `.bifrost`, not just cache events.
  Evidence: `src/project_watcher.rs::classify_project_path` returns `IgnoredInternal` for any path under the top-level cache-name constant.

- Observation: VS Code provisioning independently appends `.bifrost` to a workspace root `.gitignore` and treats that broad rule as the desired state.
  Evidence: `editors/vscode/src/lifecycle.ts` defines `BIFROST_GITIGNORE_ENTRY = ".bifrost"`; `workspaceGitignoreNeedsBifrostEntry`, `appendBifrostGitignoreEntry`, and provisioning tests all preserve or create the whole-directory rule.

- Observation: broad Bifrost navigation calls were unexpectedly slow in this worktree even though exact-source and summary reads were fast.
  Evidence: one broad `search_symbols` call took roughly ninety seconds; `scan_usages_by_location` and two further broad searches were cancelled after approximately forty to one hundred seconds. This is not part of #1207 and should be reported separately with the exact calls after the feature work is stable.

- Observation: SQLite's `SQLITE_OPEN_NOFOLLOW` rejects a legacy database reached through macOS's `/var` to `/private/var` system symlink even when the database and workspace-owned directories are regular files.
  Evidence: the exact migration test failed to inspect a valid temporary legacy database until the already-validated `.bifrost` directory was canonicalized before opening the old database. The migration still rejects a symlink at the workspace-owned `.bifrost` component before canonicalization.

- Observation: four existing subprocess-based MCP stderr tests fail with `Operation not permitted` under the restricted filesystem/process sandbox, while the same complete library suite passes outside that restriction.
  Evidence: the restricted run passed 1,907 tests and failed only three `benchmark::mcp_session` subprocess tests plus the then-unfixed milestone tests. After the milestone fixes, the approved unrestricted run passed 1,914 tests with six intentional ignores.

## Decision Log

- Decision: Suppression matching uses only the pair `(PolicyId, PolicyFindingId)` and requires the current finding to have `FindingIdentityStability::Strong`.
  Rationale: `PolicyFindingId` already incorporates policy identity, result domain, path, stable semantic owner when available, selected source bytes, and duplicate ordinal. Adding path, line, glob, regex, or fuzzy fallback logic would weaken the conservative identity contract and could suppress changed code.
  Date/Author: 2026-07-27 / Codex

- Decision: Add a strict lower-hex parser for `PolicyFindingId` and a separate `AcceptedPolicyHash` audit type instead of allowing suppression files to mint `PolicySemanticHash` values.
  Rationale: finding IDs are legitimate external join keys. The policy hash at acceptance is provenance only, and keeping it in a distinct type preserves the existing rule that semantic hashes are constructed from canonical policy content rather than trusted from external text.
  Date/Author: 2026-07-27 / Codex

- Decision: Version-one suppression records accept only `identity_stability: "strong"` and `status: "accepted"`. Unknown values, weak records, empty or unsafe reasons, invalid identifiers, duplicate keys, and resource-limit violations invalidate the document.
  Rationale: version one defines an exact durable accepted-decision list, not a general review database. Retaining weak or undefined-status records would suggest that they can safely become suppressions later.
  Date/Author: 2026-07-27 / Codex

- Decision: Core policy evaluation never reads the clock. Hosts pass an explicit UTC calendar date through `PolicyEvaluationOptions`; the CLI offers `--evaluation-date YYYY-MM-DD`, and LSP/MCP requests carry `evaluationDate`. CLI and the VS Code extension may derive today's UTC date at their boundary, but the value must be passed into the coordinator and serialized in the suppression audit so the canonical core is deterministic for identical inputs. Tests always pass a fixed date.
  Rationale: suppression expiration must be useful in ordinary host workflows without making the library coordinator consult ambient wall-clock state.
  Date/Author: 2026-07-27 / Codex

- Decision: The conventional suppression source is `.bifrost/suppressions.json`; hosts may provide one explicit workspace-relative override. A missing conventional or explicit file means no project suppressions only when the actual error is `NotFound`. All other open, classification, size, UTF-8, parse, and validation failures become canonical report diagnostics.
  Rationale: this matches existing capability-rooted policy loading and prevents permission, symlink, or malformed-input failures from degrading to unsuppressed success.
  Date/Author: 2026-07-27 / Codex

- Decision: Bump `PolicyReportDocument::SCHEMA_VERSION` from 1 to 2.
  Rationale: findings gain typed suppression state and reports gain a suppression audit collection and evaluation context. This is a material canonical-schema change, and repository policy explicitly does not require backward compatibility yet.
  Date/Author: 2026-07-27 / Codex

- Decision: Store active suppression metadata on each suppressed `PolicyFinding` and store one normalized `PolicySuppressionReview` for every loaded suppression record at report level. A review has three orthogonal typed states: match state (`strong_finding`, `current_finding_not_strong`, `finding_absent`, `policy_not_evaluated`, or `policy_incomplete`), temporal state (`current` or `expired`), and policy-hash state (`matching`, `drifted`, or `unknown`). `applied` and `stale` are derived predicates, not competing enum variants.
  Rationale: JSON and SARIF consumers need the reason and provenance directly on the retained result, while stale, expired, and unprovable records have no result on which to attach their audit state. A record can be both expired and stale or both expired and drifted, so a single mutually-exclusive disposition would lose audit information.
  Date/Author: 2026-07-27 / Codex

- Decision: Only a complete policy run can prove that an unmatched suppression is stale. An unsupported, failed, inconclusive, omitted, or unexecuted policy produces an unproven review disposition instead.
  Rationale: absence is evidence only when the run could enumerate the relevant findings completely. Report-retention omission must not be mistaken for analyzer absence, so the join runs on evaluator-produced findings before builder retention.
  Date/Author: 2026-07-27 / Codex

- Decision: Invalid suppression input produces a typed report diagnostic, applies no suppressions from that document, still evaluates the requested policies normally, and therefore exits with `POLICY_EXIT_UNRELIABLE`.
  Rationale: users still receive analyzer evidence for diagnosis, but no malformed partial list can silently suppress a subset or convert invalid configuration into clean success.
  Date/Author: 2026-07-27 / Codex

- Decision: Suppression loading and retention failures are bounded batch-level `PolicyReportDiagnostic` values, never duplicated into individual `PolicyRun::diagnostics`. Schema-2 JSON serializes them through the existing report diagnostic collection, and SARIF projects them through invocation notifications and run properties like other report diagnostics.
  Rationale: one suppression file governs the batch rather than one rule. Duplicating its failure across runs would make output depend on the number of selected policies and would waste the report budget.
  Date/Author: 2026-07-27 / Codex

- Decision: Compute threshold projection from the complete pre-retention finding set after the suppression join. `PolicyReportBuilder` retains applied suppressed findings before ordinary findings because the canonical audit contract requires the suppressed result. If a mandatory applied result or review still cannot fit, mark that review `result_omitted`, add a report-level `SuppressionAuditRetentionExceeded` diagnostic, preserve ordinary omitted-finding accounting, and return unreliable status.
  Rationale: builder retention must not turn an active finding into false clean success or leave an `applied` review pointing at a missing canonical result. Prioritizing applied results satisfies the normal contract; explicit omission plus unreliability handles impossible budgets honestly.
  Date/Author: 2026-07-27 / Codex

- Decision: Add a narrow read-only MCP `run_policy` tool to the `extended` toolset for explicit workspace-relative `.rqlp` files. It uses the active immutable analyzer snapshot and the same `PolicyEvaluationOptions`. Built-in pack discovery and selection remain owned by #1204 and will extend this request rather than add another evaluator.
  Rationale: #1207 explicitly requires CLI/MCP/LSP/library parity, while #1204 confirms that no current MCP call site exists. A small explicit-file surface satisfies this issue without pulling the built-in pack into scope.
  Date/Author: 2026-07-27 / Codex

- Decision: Rename the workspace-owned directory concept separately from its generated cache subdirectory. Default cache helpers resolve `.bifrost/cache/bifrost_cache.db`; `BIFROST_CACHE_DIR` continues to mean an explicit cache directory and still resolves `$BIFROST_CACHE_DIR/bifrost_cache.db`.
  Rationale: changing the environment-variable meaning would break its safety boundary and create a surprising extra nested directory. Client-root MCP sessions must continue using the exact approved root rather than the primary checkout.
  Date/Author: 2026-07-27 / Codex

- Decision: On a default-layout open, migrate only the exact generated legacy state: `.bifrost/.gitignore` whose bytes are exactly `*\n` and the known old `bifrost_cache.db`, `-wal`, `-shm`, and journal files. Never alter a user-modified `.bifrost/.gitignore`. If a legacy generated file cannot be safely removed, return an actionable cache-initialization error rather than leaving tracked project configuration hidden.
  Rationale: the cache is explicitly disposable, but user-authored ignore rules are not. Exact-name, exact-content migration avoids broad deletion and handles Windows live-file failures honestly.
  Date/Author: 2026-07-27 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. Generated state now defaults to `.bifrost/cache/bifrost_cache.db`; `.bifrost/cache/.gitignore` hides the live database and sidecars while `.bifrost/queries`, `.bifrost/policies`, and `.bifrost/suppressions.json` remain ordinary watched project paths. Primary-checkout cache sharing and exact client-worktree confinement are preserved, and an explicit `BIFROST_CACHE_DIR` retains its existing directory semantics.

The legacy upgrade removes only an exact generated `.bifrost/.gitignore` and the known old unified database/sidecars after proving the database is idle. User-authored narrow ignore files survive byte-for-byte; modified whole-directory rules, symlinked ignore state, live/unsafe legacy files, or cache rules that expose generated files fail actionably. VS Code now offers an explicit replacement for an exact root `.bifrost` ignore and otherwise adds only `.bifrost/cache/`, preserving comments, negations, line endings, and non-exact patterns.

Validation for this checkpoint: `cargo fmt --all`; all 39 `cache_db` tests; all six `project_watcher` tests; linked-worktree path tests; the complete library suite outside the subprocess restriction (1,914 passed, 6 ignored); 45 analyzer persistence tests, 8 store-reconcile tests, and 3 structural-facts persistence tests; VS Code Prettier, both TypeScript type checks, ESLint, and all 74 extension unit tests. The `unified_cache` integration target correctly compiled but contains zero default-feature tests because its cases are gated by `nlp`; it remains part of the final `--features nlp,python` gate. Suppression semantics and host/report integration remain for milestones 2 through 5. The slow broad-navigation observation has not yet been filed.

## Context and Orientation

The policy subsystem lives in `src/analyzer/policy/`. A policy is a versioned `.rqlp` document that gives an analysis stable identity, severity, message, and reporting semantics. `src/analyzer/policy/coordinator.rs` loads explicit policy files, builds or receives an analyzer snapshot, invokes `DefaultPolicyEvaluator`, assembles `PolicyRun` values, retains their `PolicyFinding` values through `PolicyReportBuilder`, and computes the process exit status. A strong finding ID is a 32-byte digest rendered as sixty-four lowercase hexadecimal characters. It intentionally excludes line and column coordinates, message, severity, and other presentation metadata.

`PolicyReportDocument` in `src/analyzer/policy/report.rs` is the sole canonical input to all renderers. JSON uses its serializer directly. `src/analyzer/policy/render/human.rs` produces concise or verbose terminal-safe text. `src/analyzer/policy/render/sarif.rs` produces SARIF 2.1.0 and already emits the strong finding ID as `partialFingerprints["bifrostFinding/v1"]`. `report_exit_status` in the coordinator currently considers every retained finding active.

Workspace documents are read through `WorkspaceRoot` and `read_workspace_document` in `src/workspace_document.rs`. These functions retain one directory capability, validate portable relative paths, confine symlink resolution, classify the opened handle as a regular file, enforce a byte limit, and decode UTF-8. The suppression loader must reuse this authority boundary. It must not call `std::fs::read_to_string` on an independently canonicalized path and must not add source-text or fuzzy matching.

The CLI entry point is `src/bin/bifrost.rs::run_policy_mode`. LSP policy execution is `src/lsp/server.rs::handle_run_rql_policy_request`, used by `editors/vscode/src/rql_policy.ts`. MCP tool schemas for the `extended` toolset are declared in `src/mcp_extended.rs`; calls execute through `SearchToolsService::call_tool_output_with_cancellation` in `src/searchtools_service.rs`. The new MCP tool must use the already-acquired immutable workspace snapshot rather than constructing an unrelated analyzer.

Generated analyzer and semantic-search data currently resolves through `src/gitblob.rs::cache_db_path` to `.bifrost/bifrost_cache.db` for explicit roots. `src/searchtools_service.rs::client_cache_db_path` deliberately keeps client-root sessions under the exact approved worktree. `src/cache_db.rs::prepare_cache_db_path` creates the database parent and currently writes a whole-directory `.gitignore`. `src/project_watcher.rs::classify_project_path` currently filters the entire `.bifrost` tree. All four seams must agree on `.bifrost/cache` while leaving `.bifrost/queries`, `.bifrost/policies`, and `.bifrost/suppressions.json` visible.

An accepted suppression is active only when its policy ID and finding ID exactly match a current strong finding and its expiration date is absent or later than or equal to the explicit evaluation date. Policy-hash drift does not deactivate it. An expired record remains auditable but does not suppress. A stale record is one whose policy completed in the current batch but produced no matching strong finding. A policy not selected or not complete cannot prove staleness.

## Plan of Work

### Milestone 1: establish tracked project state and isolated generated cache state

Introduce distinct constants in `src/gitblob.rs` for the project directory `.bifrost` and the generated subdirectory `cache`. Change the default explicit-root resolver to append `cache/bifrost_cache.db`, while preserving the primary-repository behavior and the current `BIFROST_CACHE_DIR` contract. Change `src/searchtools_service.rs::client_cache_db_path` to append the same subdirectory under the exact approved client root.

In `src/cache_db.rs`, replace `ensure_cache_dir_self_ignored` with a helper that recognizes only the default `.bifrost/cache` layout and writes `*\n` to `.bifrost/cache/.gitignore`. Add an exact legacy migration before opening the new database. It may remove only the known old database and SQLite sidecar names and may remove `.bifrost/.gitignore` only when its content is exactly the generated `*\n`. Missing files are success. A user-authored ignore file is left untouched, and any failure that would leave the exact generated whole-directory ignore in place is reported with an actionable error. Explicit `BIFROST_CACHE_DIR` paths remain outside this migration and do not receive project-layout ignore files.

Narrow `src/project_watcher.rs::classify_project_path` so only descendants of `.bifrost/cache` are `IgnoredInternal`; project-owned query, policy, and suppression paths must become ordinary project files. Remove the root `.bifrost/` rule from this repository's `.gitignore`.

Update `editors/vscode/src/lifecycle.ts` so new provisioning writes `.bifrost/cache/`, not `.bifrost`. Replace the current boolean detector with a classification that distinguishes a correct cache-only rule, a missing rule, and legacy broad standalone spellings such as `.bifrost` or `/.bifrost/`. Do not silently delete a legacy line from a user-owned root `.gitignore`; surface it as a migration action and replace only the exact standalone rule after explicit user confirmation. A user-authored compound, negated, commented, or otherwise different rule is never rewritten. Update `editors/vscode/test/provisioning.test.ts` to prove cache-only creation, legacy detection/confirmed replacement, and conservative preservation.

Update focused tests in `tests/unified_cache.rs`, `src/cache_db.rs`, `src/searchtools_service.rs`, `src/project_watcher.rs`, and any persistence tests whose observable path is part of the contract. Prove primary-checkout sharing, exact-root client storage, environment override behavior, generated self-ignore behavior, conservative migration, Windows-friendly error behavior, and watcher visibility.

At milestone completion, run the focused cache and watcher tests, inspect `git diff --check`, review only this milestone's diff, update this ExecPlan, and commit the plan plus the cache-layout files with a multiline checkpoint message.

### Milestone 2: define and safely load version-one suppression documents

Create `src/analyzer/policy/suppression.rs` and export its public host/report types from `src/analyzer/policy/mod.rs`. Define `DEFAULT_POLICY_SUPPRESSION_PATH`, a bounded wire document with `schema_version: 1`, normalized domain records, `PolicyEvaluationDate`, `AcceptedPolicyHash`, `PolicySuppressionSource`, `PolicySuppressionOptions`, and typed load/validation errors. Reuse `PolicyId`, `PolicyFindingId`, and `FindingIdentityStability`; implement `FromStr` for the finding ID with an exact sixty-four-character lowercase-hex contract and focused round-trip/invalid-input tests in `src/analyzer/policy/finding_identity.rs`.

Use Serde only for JSON syntax decoding. Normalize and validate explicitly after decoding: reject unknown schema versions and fields, reject more than the documented maximum records or bytes, require non-empty safe bounded `reason`, validate optional `accepted_by`, parse `accepted_at` and `expires_at` as ISO `YYYY-MM-DD`, reject expiration before acceptance, validate optional policy-hash provenance, and sort by `(policy_id, finding_id)` before detecting identical duplicates or conflicting records. Do not allow weak stability or any status other than accepted in schema version one. Tighten retained strings/vectors after normalization.

Load the conventional or explicit workspace-relative path through the existing `WorkspaceRoot` capability and `read_workspace_document`, allowing only `.json`, regular files, bounded UTF-8, and confined paths. Distinguish only a true missing file from every other failure. Add `tests/policy_suppression_loading.rs` using `InlineTestProject` where a small project suffices. Cover missing, valid, reordered-equivalent, unknown-field, schema-version, duplicate/conflict, uppercase or malformed hash, weak identity, unsafe text, count/byte limit, directory/FIFO where platform-supported, symlink escape, and explicit-path confinement behavior.

At milestone completion, run the finding-identity and suppression-loading tests, review the public types for minimality and retained-size safety, update this ExecPlan, and commit the milestone.

### Milestone 3: join suppressions into the canonical report

Refactor `src/analyzer/policy/coordinator.rs` around a public `PolicyEvaluationOptions` value used by file, live-source, and snapshot-backed evaluation. It contains the existing schema-version and fail-threshold choices plus the suppression source and explicit evaluation date. Add a file-evaluation entry point that accepts a host-supplied `IAnalyzer`; the new MCP path will use it, while the existing CLI convenience path may still build one persisted-independent workspace analyzer snapshot.

Load suppression configuration once per batch but do not let it affect registry construction, query execution, evaluator budgets, proof, completion, witnesses, or work. After every evaluator `PolicyRun` exists and before `PolicyReportBuilder` can omit findings for retention, build deterministic lookups over policy runs and current strong finding IDs. For each normalized record, compute one `PolicySuppressionReview`. Apply only current, strong, accepted, unexpired exact matches by cloning or mutating only the finding's new suppression metadata. Compare an optional `AcceptedPolicyHash` to the current `PolicySemanticHash` solely to set a drift flag. Classify unmatched entries as stale only for a complete selected policy run; otherwise record the appropriate unproven disposition.

Extend `PolicyFinding` in `src/analyzer/policy/finding.rs` with `Option<AppliedPolicySuppression>` plus validation and retained-size accounting. The identity constructor and evaluator adapters must remain unchanged. Extend `PolicyReportDocument` and `PolicyReportBuilder` in `src/analyzer/policy/report.rs` with a sorted, bounded suppression audit and bump the report schema to 2. Add suppression-specific `PolicyReportDiagnosticCode` variants. A malformed document creates one bounded report-level diagnostic, applies no records, still retains ordinary findings, and never copies that diagnostic into policy runs. The existing report diagnostic serializer carries it in JSON; the existing SARIF invocation-notification and run-property projections carry it in SARIF.

Compute match, temporal, and policy-hash state independently for every review. A record is applied only when its match state is `strong_finding` and its temporal state is `current`. It is stale when the selected policy completed and its match state is `finding_absent`, even if it is also expired; hash drift is reported whenever the current policy hash is knowable, not only for applied records.

Compute failure-threshold projection from the evaluator-produced finding set after this join and before report retention. Change `PolicyReportBuilder` to retain applied suppressed findings and their reviews before ordinary findings. Existing omission accounting remains authoritative for ordinary retention. If a mandatory applied result or review cannot fit, set `result_omitted` on the review when representable, register one `SuppressionAuditRetentionExceeded` report diagnostic, and make the batch unreliable; never leave a successful applied review with no canonical finding. Ensure report budgets account for suppression metadata without altering evaluator work counters.

Change `report_exit_status` so accepted active suppressions are excluded from the threshold projection but all existing unreliable checks still win. Add behavior-focused coordinator/report tests proving line-shift and presentation stability, source-edit staleness, path/owner/ordinal conservatism, weak-finding rejection, drift visibility without reactivation, expiration at fixed dates, ordering independence, incomplete-run non-staleness, invalid-document unreliability, and unchanged proof/completion/witness/work values before and after the join.

At milestone completion, run `tests/policy_match_evaluation.rs`, the new suppression coordinator tests, and report unit tests; compare canonical JSON before and after suppression to prove that only suppression/report fields and exit projection changed. Review and commit the milestone.

### Milestone 4: render and expose suppression behavior through the CLI

In `src/analyzer/policy/render/human.rs`, make concise mode skip applied suppressed findings while counting them. Its summary must distinguish active and suppressed counts and must report the orthogonal stale, expired, drifted, unproven, and result-omitted counts without dumping full reasons. Verbose mode prints every finding and adds the suppression reason, acceptance provenance, evaluation/expiration dates, and policy-hash drift state; it also prints full non-applied review records for cleanup. All new text must use the existing terminal escaping and bounded writer.

Canonical JSON comes from report schema 2 and retains the full finding plus typed suppression metadata and report audit. In `src/analyzer/policy/render/sarif.rs`, retain every result, preserve the existing strong partial fingerprint, and add `suppressions: [{"kind":"external","status":"accepted","justification":...}]` for an applied decision. Put accepted-by/date/hash/drift fields in the suppression property bag. Add the report-level review collection to SARIF run properties so stale, expired, and unproven records are not lost when no result exists. Validate output against `tests/fixtures/sarif/sarif-schema-2.1.0.json`.

In `src/bin/bifrost.rs`, add policy-mode-only `--suppressions-file PATH` and `--evaluation-date YYYY-MM-DD`. The default suppression source is conventional. If no date is supplied, the CLI resolves today's UTC date once at its host boundary and passes it explicitly to the core. Update help text and argument-conflict tests. The CLI must not load or interpret suppression JSON itself.

Extend `tests/policy_rendering.rs`, `tests/policy_sarif_rendering.rs`, and `tests/bifrost_policy_cli.rs`. Prove canonical result retention, concise hiding and counts, verbose provenance, accepted external SARIF, strong fingerprint retention, stale/expired reporting, invalid-input exit 2, active-finding exit 1, suppressed-finding exit 0, output-file atomicity, and deterministic output under a fixed date.

At milestone completion, run the focused renderer and CLI suites, validate representative SARIF against the offline schema, review all user-facing wording and schema changes, update this ExecPlan, and commit the milestone.

### Milestone 5: provide LSP, VS Code, and MCP parity

Extend `RunRqlPolicyParams` in `src/lsp/server.rs` with a workspace-relative optional suppression path and required explicit evaluation date. `handle_run_rql_policy_request` passes both to the shared coordinator alongside the live analyzer snapshot. It must not read the document twice or resolve paths outside the policy workspace root. Extend `editors/vscode/src/rql_policy.ts` so the client sends today's UTC date explicitly, accepts schema-2 finding/report fields, hides applied suppressed findings from the ordinary active tree by default, and adds bounded summary/audit nodes so suppressed, stale, expired, and drifted decisions remain visible. Update `editors/vscode/src/rql_policy_results.ts` and TypeScript tests without adding a separate suppression engine.

Add `run_policy` to `EXTENDED_TOOL_NAMES` and `extended_tool_descriptors()` in `src/mcp_extended.rs`. Its schema accepts one or more explicit workspace-relative `.rqlp` paths, an optional workspace-relative suppression file override, a required `evaluation_date`, and `fail_on` for parity even though MCP does not map it to a process exit. In `SearchToolsService::call_tool_output_with_cancellation`, decode the bounded request, acquire the normal immutable query snapshot, and call the shared file evaluator with that snapshot and cancellation token. Return the canonical schema-2 `PolicyReportDocument` plus the computed policy status as structured output. Do not add built-in pack names, categories, ambient discovery, or automatic `.bifrost/policies` execution; #1204 owns those selectors.

Extend `tests/bifrost_lsp_server.rs`, `editors/vscode/test/rql-policy.test.ts`, the descriptor tests in `src/mcp_extended.rs`, and `tests/bifrost_mcp_server.rs`. Using the same fixture, policy files, suppression file, and fixed evaluation date, assert that library, CLI JSON, LSP, and MCP return equivalent rule/run/finding IDs, completion, suppression disposition, and work. Also prove missing/invalid suppression behavior, active-root confinement, callable tool exposure, cancellation, and that the MCP result comes from the active worktree snapshot.

At milestone completion, run the LSP, VS Code, and MCP focused suites, perform one real stdio MCP smoke against the current worktree, review the cross-host contract, update this ExecPlan, and commit the milestone.

### Milestone 6: document, validate, and review the complete feature

Update `docs/src/content/docs/static-analysis-policies.md` with the `.rql` exploration to `.rqlp` recurring-policy to exact suppression lifecycle, the version-one suppression schema, strong identity boundary, stale/expired/drift behavior, and CLI examples. Update `docs/src/content/docs/cli.md` for the new options and exit behavior. Update `docs/src/content/docs/rql-vscode.md` for editor presentation. Update `docs/src/content/docs/data-boundaries.md`, `docs/src/content/docs/semantic-search.md`, `docs/src/content/docs/evaluation-evidence.md`, and `docs/src/content/docs/reproduce-analysis.md` from the old database path to `.bifrost/cache/bifrost_cache.db`, while preserving the primary-repository, exact client-root, and `BIFROST_CACHE_DIR` distinctions.

Run formatting, focused tests, the full feature-enabled Rust suite, Clippy, and the docs check/build using isolated Cargo targets where appropriate. Inspect the rendered documentation preview rather than relying only on the build. Then execute the guided-issue review phase with security, duplication, intent, operational, and architecture specialist reviews over the complete diff. Fix all valid critical/high findings and any selected lower-severity findings, rerun affected gates, update this plan's decision/progress/outcome sections, and make the final reviewed checkpoint commit. Do not push or open a pull request without explicit user direction.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/0be1/bifrost`.

Before each milestone, confirm the branch and preserve unrelated work:

    git status --short --branch
    git rev-parse --abbrev-ref HEAD

Use focused validation as the implementation grows:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test unified_cache
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test policy_suppression_loading
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test policy_match_evaluation
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test policy_rendering
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test policy_sarif_rendering
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_policy_cli
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_lsp_server
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_mcp_server

Run the VS Code tests using the package's existing test command after confirming the script name in `editors/vscode/package.json`. Run documentation validation with:

    npm --prefix docs run check
    npm --prefix docs run build

The final Rust gates are:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    git diff --check

For the end-to-end demonstration, create or use a temporary inline fixture rather than adding generated cache state to this worktree. Run a warning policy once as canonical JSON, copy its strong finding ID into `.bifrost/suppressions.json`, and rerun with a fixed date:

    bifrost --root <fixture> --policy-file .bifrost/policies/example.rqlp --evaluation-date 2026-07-27 --format json --fail-on warning
    bifrost --root <fixture> --policy-file .bifrost/policies/example.rqlp --evaluation-date 2026-07-27 --format sarif --fail-on warning

The second run should exit 0, retain the finding in JSON/SARIF, mark it externally accepted in SARIF, keep `bifrostFinding/v1`, and report one suppressed finding in concise human output. After editing the exact selected expression, the old record should be stale, the new finding ID should differ, and `--fail-on warning` should exit 1. Inserting unrelated preceding lines should leave the accepted ID and clean exit unchanged.

After each milestone, update this plan, review the file list with `git status`, stage only the milestone files explicitly, and commit a multiline checkpoint. Never use `git add -A`.

## Validation and Acceptance

The feature is accepted only when all of the following observable behaviors hold.

A checked-in `.bifrost/queries/example.rql`, `.bifrost/policies/example.rqlp`, and `.bifrost/suppressions.json` appear in ordinary Git status and file walking, while `.bifrost/cache/bifrost_cache.db` and its SQLite sidecars do not. Watcher tests show that editing a tracked policy or suppression file triggers project handling and writing the cache does not.

A strong finding accepted by exact ID stays suppressed after unrelated preceding lines or a message/severity change. Editing the selected source bytes, moving the file, changing the semantic owner, or changing identical-occurrence ordering follows the documented conservative identity contract and never invokes fuzzy rebinding. A weak current finding is never suppressed.

Missing suppression configuration means no project suppressions. Invalid, unsafe, oversized, escaping, duplicate, or conflicting configuration yields typed canonical diagnostics and policy exit 2, not clean unsuppressed success. Reordering valid records leaves canonical output unchanged.

Applied suppressions do not change analyzer certainty, completeness, proof, evidence, witnesses, or work. They remain in JSON and SARIF, concise output omits them as active and reports the suppressed count, verbose output explains them, and `--fail-on` excludes them. SARIF validates offline, uses standard external accepted suppression fields, and retains the strong fingerprint.

Staleness is reported only after a complete selected policy produced no matching strong finding. Unselected, unsupported, failed, inconclusive, truncated, and retention-limited runs do not claim staleness. Expiration uses the host-supplied date, remains auditable, and reactivates the finding. Policy-hash drift is visible but does not reactivate a matching ID.

Library, CLI JSON, LSP, and MCP evaluations over identical inputs and a fixed date agree on rule, run, finding, suppression, completion, and work values. MCP exposes a callable read-only explicit-policy tool against the active root, but it does not discover or execute every project policy automatically.

The path migration retains existing primary-checkout sharing for explicit roots, exact worktree confinement for client-root sessions, and the existing explicit `BIFROST_CACHE_DIR` boundary. Exact generated legacy state can be rebuilt, user-authored ignore files are not overwritten, VS Code no longer creates broad ignore rules, and both a live generated ignore failure and a user-owned legacy root rule are visible and actionable.

All focused tests, the full `--features nlp,python` suite, Clippy with all targets/features and denied warnings, docs checks/build, rendered docs inspection, and final specialist review pass.

## Idempotence and Recovery

All source edits and test commands are repeatable. Isolated Cargo targets are created and removed by `scripts/with-isolated-cargo-target.sh`; do not create manually named `/tmp/bifrost-*` targets. Suppression tests use temporary projects and fixed dates, so they do not depend on the wall clock or write `.bifrost` state into the repository.

Cache migration is intentionally narrow. It may remove only exact generated legacy cache filenames and the exact generated `*\n` ignore file. It must be safe to retry after partial completion: missing old files are success, an already-created new cache directory is reused, and a user-modified ignore file is left unchanged. If Windows reports a live handle, stop the old Bifrost process and retry; do not broaden deletion or overwrite the file.

If a milestone fails, leave its changes unstaged, record the failure and evidence in `Surprises & Discoveries`, and resume from the last committed checkpoint. Do not reset, delete unrelated files, or alter user-owned `.bifrost` configuration. If a schema or host-contract decision changes during implementation, update every affected section of this plan and append a revision note before proceeding.

## Artifacts and Notes

The representative version-one project document is:

    {
      "schema_version": 1,
      "suppressions": [
        {
          "policy_id": "bifrost.performance.file-read-in-nested-loop",
          "finding_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "identity_stability": "strong",
          "status": "accepted",
          "reason": "The receiver is an in-memory virtual filesystem",
          "policy_hash_at_acceptance": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
          "accepted_by": "review-agent",
          "accepted_at": "2026-07-27",
          "expires_at": null
        }
      ]
    }

The canonical evaluation sequence must remain:

    policy and dependency loading
      -> analyzer snapshot and ordinary policy evaluation
      -> canonical finding identity and completion construction
      -> exact strong suppression join using explicit evaluation date
      -> canonical report retention
      -> human, JSON, SARIF, and fail-threshold projection

The desired workspace layout is:

    .bifrost/
      queries/
      policies/
      suppressions.json
      cache/
        .gitignore
        bifrost_cache.db

## Interfaces and Dependencies

Use the existing `serde`/`serde_json` dependencies for strict wire decoding, `chrono::NaiveDate` for calendar dates, `WorkspaceRoot` and `read_workspace_document` for filesystem authority, and the existing retained-size and terminal-safety helpers. Do not add a date, path-walking, fuzzy-matching, or regular-expression dependency.

In `src/analyzer/policy/finding_identity.rs`, provide strict external parsing:

    impl FromStr for PolicyFindingId {
        type Err = PolicyFindingIdParseError;
        // Accept exactly 64 lowercase hexadecimal characters.
    }

In `src/analyzer/policy/suppression.rs`, define the host and canonical types with names equivalent to:

    pub const DEFAULT_POLICY_SUPPRESSION_PATH: &str = ".bifrost/suppressions.json";

    pub struct PolicyEvaluationDate(NaiveDate);

    pub enum PolicySuppressionSource {
        Conventional,
        Explicit(PathBuf),
        Disabled,
    }

    pub struct PolicySuppressionOptions {
        source: PolicySuppressionSource,
        evaluation_date: PolicyEvaluationDate,
    }

    pub struct AppliedPolicySuppression {
        // Exact record provenance plus policy_hash_drifted.
    }

    pub enum PolicySuppressionMatchState {
        StrongFinding,
        CurrentFindingNotStrong,
        FindingAbsent,
        PolicyNotEvaluated,
        PolicyIncomplete,
    }

    pub enum PolicySuppressionTemporalState {
        Current,
        Expired,
    }

    pub enum PolicySuppressionHashState {
        Matching,
        Drifted,
        Unknown,
    }

    pub struct PolicySuppressionReview {
        // Normalized record, orthogonal states, and result_omitted.
    }

Names may be refined during implementation, but there must be one typed source/options model, one finding-attached applied model, and one report-level review model with orthogonal match, temporal, and hash states. Do not represent these states or identity stability with free-form strings internally.

In `src/analyzer/policy/coordinator.rs`, converge public evaluation around:

    pub struct PolicyEvaluationOptions {
        pub require_explicit_schema_versions: bool,
        pub fail_on: PolicyFailOn,
        pub suppressions: PolicySuppressionOptions,
    }

    pub fn evaluate_policy_files(
        root: impl AsRef<Path>,
        policy_files: &[PathBuf],
        options: PolicyEvaluationOptions,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError>;

    pub fn evaluate_policy_files_with_analyzer(
        root: impl AsRef<Path>,
        policy_files: &[PathBuf],
        analyzer: &dyn IAnalyzer,
        options: PolicyEvaluationOptions,
        cancellation: Option<&CancellationToken>,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError>;

    pub fn evaluate_policy_source(
        root: impl AsRef<Path>,
        source_identity: PolicySourceIdentity,
        source: &str,
        analyzer: &dyn IAnalyzer,
        options: PolicyEvaluationOptions,
        cancellation: Option<&CancellationToken>,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError>;

The exact argument order may follow local style, but all hosts must call the same internal join and no renderer may load suppression configuration.

In `src/mcp_extended.rs`, advertise `run_policy` as a read-only tool with bounded `policy_files`, optional `suppressions_file`, required `evaluation_date`, and optional `fail_on`. In `src/searchtools_service.rs`, return a structured object containing the canonical report and computed status. Reuse the active `WorkspaceQueryScope` analyzer and cancellation token.

Revision note, 2026-07-27 / Codex: Initial plan created after live issue reconciliation and repository diagnosis. It resolves the previously open evaluation-date and MCP ownership decisions, adds conservative legacy-ignore migration, and makes canonical report schema 2 the shared host contract.

Revision note, 2026-07-27 / Codex: Post-planning specialist review added the overlooked VS Code provisioning seam, made suppression failures explicitly batch-level, defined pre-retention threshold and mandatory applied-result retention behavior, and replaced an ambiguous mutually-exclusive review disposition with orthogonal match, temporal, and policy-hash states.
