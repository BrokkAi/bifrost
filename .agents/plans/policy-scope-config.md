# Directory-scoped policy exclusions via .bifrost/policy-scope.json

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Bifrost's policy gate (`run_policy` over the built-in `bifrost.code-smells` pack) currently has exactly one mechanism for accepting a finding: a per-finding record in `.bifrost/suppressions.json`, keyed by the finding's stable identity hash. That is the right grain for individual accepted findings in product code, but the wrong grain for whole directories whose findings are categorically not defects. Two concrete cases exist in this repository today: `tests/fixtures/` contains corpora that *intentionally* embed code smells (they are the positive fixtures the policy tests run against), and test code under `tests/` is not performance-sensitive, so the performance-category review prompts (sleep-in-loop, parsing-in-loop, and so on) are noise there. Suppressing those per finding means every new fixture or test re-dirties the gate and forces a new suppression commit.

Note that the analyzer-level ignore file `.bifrostignore` is not the right lever: it removes files from analysis entirely (navigation, search, usages), and we absolutely want fixtures and tests analyzed — we only want policy findings from them pre-accepted.

After this change, a repository can check in a second reviewed document, `.bifrost/policy-scope.json`, that lists workspace-relative directories (each with a mandatory human reason, and optionally restricted to specific policy ids or policy categories). Findings whose primary location falls inside a scoped directory are retained in the canonical report with an attached scope decision — auditable, never silent — but no longer count toward the failure status. Concretely: after writing a scope file covering `tests/fixtures` and the `performance` category under `tests`, `run_policy` on this repository reports those findings as scoped, the per-finding suppressions they previously required can be deleted, and the run still exits 0.

## Progress

- [x] (2026-08-04) Researched the existing suppression pipeline (`crates/bifrost-policy/src/suppression.rs`, `coordinator.rs`, `report.rs`) and the MCP/CLI surfaces that would carry the new option.
- [x] (2026-08-04) Authored this plan.
- [x] (2026-08-04) Milestone 1: scope document model, parsing, validation (`crates/bifrost-policy/src/scope.rs`) with unit tests (5 passing; `WorkspaceRelativePath` needed a field-level `serialize_with` because it does not implement `Serialize`).
- [x] (2026-08-04) Milestone 2: coordinator loading + application, report plumbing (`scope` audit array, per-finding scope attachment, status exclusion, schema_version 2 -> 3), human/JSON render, and behavior tests in `tests/suite_bench_policy/policy_scope_evaluation.rs` (component-wise prefix, selector gating, invalid-document unreliability, suppression precedence).
- [x] (2026-08-04) Milestone 3: MCP `scope_file` parameter and CLI `--scope-file` flag with schema/help/tests, both threading `PolicyScopeOptions` through `PolicyEvaluationOptions::with_scope`.
- [x] (2026-08-04) Milestone 4: dogfooding — this repo's `.bifrost/policy-scope.json` (3 entries) replaced 90 of the 284 per-finding suppressions; the locally built CLI reports exit 0 with all entries applied (1+87+2 findings) and 194 suppressions, and pointing `--scope-file` at a missing path brings the 90 findings back with exit 1.

## Surprises & Discoveries

- Observation: 284 pre-existing findings on this repository were triaged on 2026-08-04 and all were false positives or accepted patterns; 89 of them sit under `tests/` and 3 under `tests/fixtures/` corpora. This is the motivating corpus for the feature.
  Evidence: commit "Suppress triaged pre-existing policy-gate findings" (fdf1a132b) and its 284-record suppression file.
- Observation: `report_storage_size`/`new_with_suppression_audit` implement a byte-budget preflight that drops the suppression audit when it would exceed the retained-report budget; the scope audit must participate in the same preflight or large scope files could silently blow the budget. Implemented by treating suppressions+scope as one droppable audit block behind the existing `SuppressionAuditPreflightExceeded` recovery.
  Evidence: `crates/bifrost-policy/src/report.rs` around `new_with_suppression_audit` (`preflight_without_suppressions` branch, line ~1980).
- Observation: policy categories are a built-in pack manifest concept (`BuiltInPolicyManifestEntry::category`), not part of loaded `.rqlp` metadata (`PolicyMetadata` has no categories field). Scope entries with `policy_categories` therefore only ever match built-in policies; repository policies are reachable via `policy_ids` or unrestricted entries, and the behavior test pins this down.
  Evidence: E0609 on `metadata.categories` during Milestone 2; `crates/bifrost-policy/src/builtin.rs:89`.

## Decision Log

- Decision: Scope is applied *after* evaluation, by matching each finding's primary location path, rather than by excluding files from evaluation.
  Rationale: Policies may use scoped files as evidence for findings anchored elsewhere (cross-file taint, hierarchy); pre-evaluation exclusion would change rule semantics, not just reporting. Post-evaluation filtering also keeps the report honest (scoped findings remain visible with their decision attached) and reuses the shape of the proven suppression pipeline. The compute cost of evaluating scoped files is accepted; performance of self-repository runs is owned by issue #1452, not this plan.
  Date/Author: 2026-08-04, session with dbakereffendi.
- Decision: Matching is component-wise workspace-relative directory prefix, forward slashes, no globs in v1.
  Rationale: The known use cases are directories ("ignore certain directories from the scan" was the user's framing). Globs add matching and validation complexity and an ambiguity surface (`*` vs `**`) that nothing currently needs; a later version can add them behind the same schema_version gate. Component-wise comparison prevents `tests` from matching `tests_extra`.
  Date/Author: 2026-08-04, session with dbakereffendi.
- Decision: An entry may optionally restrict itself to exact `policy_ids` and/or `policy_categories` (union of the two); omitted means all policies.
  Rationale: The dogfood case needs it immediately: `tests/` should be scoped for the `performance` category only — correctness and security findings in tests still matter. Category names mirror the `run_policy` selector vocabulary, so no new concept is introduced.
  Date/Author: 2026-08-04, session with dbakereffendi.
- Decision: File lives at `.bifrost/policy-scope.json` by default, overridable via a `scope_file` parameter on MCP `run_policy` and a `--scope-file` CLI flag, exactly parallel to `suppression_file`.
  Rationale: Symmetry with the existing suppression source keeps the mental model and the plumbing identical; JSON rather than YAML because the sibling document is JSON and the crate already depends on serde_json only.
  Date/Author: 2026-08-04, session with dbakereffendi.
- Decision: Scoped findings are retained in the report with a `scope` attachment and excluded from status computation; the report grows a top-level `scope` audit array and the canonical report `schema_version` bumps from 2 to 3.
  Rationale: Silent removal would make the gate unauditable; the schema bump is honest because consumers assert the version (tests assert `schema_version == 2` today) and additive fields still change the canonical shape. Backwards compatibility is explicitly not a goal in this repository.
  Date/Author: 2026-08-04, session with dbakereffendi.
- Decision: Scope entries have no expiry and no per-entry acceptance hash.
  Rationale: Unlike a per-finding suppression, a directory scope is a standing statement about a directory's nature (fixture corpus, test tree), not about one finding of one rule version. Entries that match zero findings are reported as unmatched (parallel to stale suppressions) so dead entries stay visible.
  Date/Author: 2026-08-04, session with dbakereffendi.

## Outcomes & Retrospective

Complete (2026-08-04). All four milestones landed in sequence: the scope document model, the coordinator/report application with the schema 2 -> 3 bump, the MCP/CLI surfaces, and the dogfood configuration. The repository gate now runs with a 3-entry scope file and 194 per-finding suppressions (down from 284); the locally built `bifrost --policy-pack bifrost.code-smells` exits 0 with 90 scoped findings visible in the audit and exits 1 again when the scope file is absent, proving the mechanism is live rather than cosmetic.

One transition caveat: the *installed* Bifrost plugin predates this feature, so its MCP `run_policy` does not read `.bifrost/policy-scope.json` and will report the 90 scope-covered findings as active until a release containing this change ships. That is expected and self-healing at the next release; do not re-add the per-finding suppressions to paper over it.

Lessons: the suppression pipeline's shape (wire struct, normalize, review, attach, audit, byte-budget preflight) transplanted cleanly to scope; the two genuine design discoveries were that policy categories exist only in the built-in pack manifest, and that an invalid governance document must make the run unreliable rather than merely non-clean, both now pinned by behavior tests.

## Context and Orientation

All policy evaluation lives in the `brokk-bifrost-policy` crate at `crates/bifrost-policy/`. The pieces this plan touches:

- `crates/bifrost-policy/src/suppression.rs` is the model to imitate. It defines the wire format of `.bifrost/suppressions.json` (`WireSuppressionDocument`, `schema_version: 1`, `deny_unknown_fields`), strict normalization (`normalize_wire_record` rejects blank reasons, non-`strong` identity, duplicate/conflicting records), the loaded `PolicySuppressionDocument`, the per-record review produced during application (`PolicySuppressionReview` with `match_state` / `temporal_state` / `policy_hash_state`), and the decision attached to a finding (`PolicyFindingSuppression`). `load_policy_suppressions_from_root` resolves the conventional path against the workspace root.
- `crates/bifrost-policy/src/coordinator.rs` orchestrates a run. Around line 681 it loads the suppression document (missing file → `NotFound`, parse failure → a `SuppressionLoadFailed` diagnostic plus `Invalid` state — the run continues but the report records the failure). After all policy runs complete, `apply_policy_suppressions` (line ~1205) joins records to findings by `(policy_id, finding_id)`, builds reviews, and attaches decisions via `finding.attach_suppression`. The reviews then flow into `PolicyReportBuilder::new_with_suppression_audit`.
- `crates/bifrost-policy/src/report.rs` owns the canonical schema-2 report: top-level fields `schema_version`, `evaluation`, `execution`, `rules`, `runs`, `diagnostics`, `suppressions`, plus truncation bookkeeping. `new_with_suppression_audit` sorts and validates the reviews, and a byte-budget preflight may drop the audit (clearing per-finding attachments) when the retained report would exceed budget. Status/exit computation treats findings with an applied suppression as non-failing.
- `crates/bifrost-policy/src/render/` renders the report for humans (and JSON passthrough). The human renderer summarizes applied/stale suppressions; scope needs the same treatment.
- MCP surface: `crates/bifrost-mcp/src/mcp_extended.rs` declares the `run_policy` tool schema (the `suppression_file` property, line ~575); `crates/bifrost-mcp/src/searchtools_service.rs` (line ~3164) converts `params.suppression_file` into `PolicySuppressionSource::explicit_portable` and builds `PolicyEvaluationOptions::with_suppressions`.
- CLI surface: `src/bin/bifrost.rs` `run_policy_mode` (line ~700) receives a `PolicySuppressionOptions` parsed from `--suppression-file` and forwards it into the same options type.

"Primary location" means `finding.primary.path`: the workspace-relative, forward-slash path carried by every policy finding (visible in the JSON report as `runs[].findings[].primary.path`).

## Plan of Work

Milestone 1 — the scope document. Create `crates/bifrost-policy/src/scope.rs` (registered in `lib.rs`) defining the wire format and validation. The document is JSON:

    {
      "schema_version": 1,
      "scopes": [
        {
          "path": "tests/fixtures",
          "reason": "Intentional smell corpus used as policy test fixtures.",
          "policy_ids": null,
          "policy_categories": null
        },
        {
          "path": "tests",
          "reason": "Test code is not performance-sensitive.",
          "policy_ids": null,
          "policy_categories": ["performance"]
        }
      ]
    }

Define `PolicyScopeDocument`, `PolicyScopeEntry`, `PolicyScopeSource` (conventional `.bifrost/policy-scope.json` vs explicit path), `PolicyScopeOptions`, and `load_policy_scope_from_root`, all shaped after their suppression counterparts. Validation must reject: unknown fields, a `schema_version` other than 1, more than 256 entries, blank or over-long reasons (reuse the suppression text limits), absolute paths, backslashes, `.`/`..` components, empty or trailing-slash paths, empty `policy_ids`/`policy_categories` arrays (omit or null instead), invalid policy ids, duplicate entries (same path and same selector set). Matching helper: `entry.matches(path: &str, policy_id: &PolicyId, category: &str) -> bool` implementing component-wise prefix on the path and union selector semantics. Unit tests live in the module.

Milestone 2 — application and report. In `coordinator.rs`, load the scope document next to the suppression document with identical error posture (missing → `NotFound` state; invalid → new diagnostic code `ScopeLoadFailed` + `Invalid` state; the run continues). After `apply_policy_suppressions`, add `apply_policy_scope`: for each run and finding without an applied suppression, test each scope entry against the finding's primary path and the policy's id/category (category comes from the registry metadata); on first match attach a `PolicyFindingScope { entry_index, reason }` to the finding and increment that entry's matched count. Produce one `PolicyScopeReview` per entry (path, selectors, reason, matched finding count — zero means unmatched, reported but not fatal). In `report.rs`, bump `SCHEMA_VERSION` to 3, add the `scope` array and document state to the serialized report and to `report_storage_size`/retained-size accounting, include the scope audit in the same byte-budget preflight that can drop the suppression audit, and exclude scope-attached findings from status/exit computation exactly like suppressed ones. Update the human renderer to print a scope summary line (entries, matched counts, unmatched entries). Update every test that asserts `schema_version == 2`.

Milestone 3 — surfaces. MCP: add `scope_file` (optional string, same length cap as `suppression_file`) to the `run_policy` schema in `mcp_extended.rs` and thread it through `searchtools_service.rs` into `PolicyEvaluationOptions` (which grows a `with_scope` constructor or a builder method carrying `PolicyScopeOptions`). CLI: add `--scope-file` to the `run-policy` argument parser in `src/bin/bifrost.rs` and pass it through `run_policy_mode`. Both default to the conventional path. Because both MCP hosts must stay in lockstep while `mcp_common.rs` exists, confirm the parameter flows through the shared `build_server_spec*`/tool-descriptor path rather than being duplicated per host; the schema lives in the shared spec, so one edit should serve both.

Milestone 4 — dogfooding. Write this repository's `.bifrost/policy-scope.json` with the two entries shown above plus `scripts` restricted to the performance category if review agrees scripts are utility code. Regenerate `.bifrost/suppressions.json` retaining only findings not covered by scope (the prod-code performance findings and the voyage sidecar dynamic-evaluation acceptance). Rerun the pack via MCP `run_policy` with `evaluation_date` set to today and confirm: status `clean`, exit 0, scoped findings visible in the `scope` audit, no unmatched entries, remaining suppressions all `strong_finding`/`matching`/`current`.

## Concrete Steps

Work from the repository root. After each milestone run the focused tests, then the shared gate before pushing:

    cargo test -p brokk-bifrost-policy
    cargo test --test suite_bench_policy
    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets --all-features -- -D warnings

For milestone 3 also run the MCP surface tests:

    cargo test -p brokk-bifrost-mcp

For milestone 4, run the gate through the live MCP tool (`run_policy` with `{"policy_packs": ["bifrost.code-smells"], "evaluation_date": "<today>"}`) and inspect `status`, `report.scope`, and `report.suppressions` in the JSON result.

## Validation and Acceptance

Acceptance is behavioral. With no scope file present, every existing policy test passes unchanged apart from the schema-version literal. With the dogfood scope file present, `run_policy` on this repository returns `status: "clean"`, its report lists each scope entry with a non-zero matched count and each remaining suppression as applied, and deleting one scope entry makes the previously scoped findings reappear as failures (demonstrating the mechanism is live, not cosmetic). A malformed scope file (for example `"path": "/abs"`) must not abort the run: the report carries a `ScopeLoadFailed` diagnostic, the document state is `invalid`, and the run exits unreliable (exit 2) exactly like an invalid suppression document, so nothing is silently accepted.

## Idempotence and Recovery

All steps are additive and re-runnable. The scope module lands before anything consumes it; the report schema bump is a single constant plus its assertions, revertable in one commit. Regenerating this repository's suppression file is deterministic from the canonical report, so it can be rebuilt at any time by re-running the pack and re-applying the triage reasons recorded in the 2026-08-04 suppression commit.

## Artifacts and Notes

The 284-finding triage that motivates this feature is recorded in commit fdf1a132b ("Suppress triaged pre-existing policy-gate findings"); its message contains the per-rule breakdown. The suppression wire format that this plan mirrors is defined by `WireSuppressionDocument`/`WireSuppressionRecord` in `crates/bifrost-policy/src/suppression.rs` (lines ~854-872).

## Interfaces and Dependencies

No new external dependencies. In `crates/bifrost-policy/src/scope.rs`, define (names final, signatures indicative):

    pub struct PolicyScopeEntry { /* path, reason, policy_ids, policy_categories */ }
    pub struct PolicyScopeDocument { /* schema_version, entries */ }
    pub enum PolicyScopeSource { Conventional, Explicit(Box<str>) }
    pub struct PolicyScopeOptions { /* source */ }
    pub fn load_policy_scope_from_root(root: &Path, options: &PolicyScopeOptions)
        -> Result<Option<PolicyScopeDocument>, PolicyScopeLoadError>;
    impl PolicyScopeEntry {
        pub fn matches(&self, primary_path: &str, policy_id: &PolicyId, category: &str) -> bool;
    }

`PolicyEvaluationOptions` in `coordinator.rs` gains a `scope: PolicyScopeOptions` field with a `with_scope(...)` builder method; `PolicyReportBuilder` gains the scope-review parameter alongside the suppression reviews. All types implement `RetainedSize` following the file-local pattern.
