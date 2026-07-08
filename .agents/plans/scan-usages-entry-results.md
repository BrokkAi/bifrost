# Refactor scan_usages to ordered per-request entries

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agents/PLANS.md` from the repository root. It is self-contained so a contributor can continue the work without prior conversation context.

## Purpose / Big Picture

`scan_usages` is a public JSON tool that answers "where is this requested definition used?" Today it returns five parallel top-level arrays: `usages`, `not_found`, `failures`, `ambiguous`, and `too_many_callsites`. Those arrays make it easy for a requested item to disappear from the response and make some zero-hit cases render as the misleading text `No usages found.` After this change, every requested symbol and every requested location target produces exactly one ordered entry in a single `results` array. Callers can map each response back to the original input, distinguish authoritative zero-hit scans from inconclusive zero-hit scans, and retry ambiguous or target-based requests from structured payloads.

The behavior is visible by calling `scan_usages` with mixed `symbols` and `targets`: the JSON contains `results` in parameter order, each entry echoes the original input, and rendered text lists each requested member with its status. A resolved zero-hit query renders as `verified_absent` or `unverified_absent` instead of the old generic fallback.

## Progress

- [x] (2026-07-08T17:09Z) Read `.agents/PLANS.md` and the current `scan_usages` model in `src/searchtools.rs`, `src/searchtools_render.rs`, benchmark validation, and MCP registry references.
- [x] (2026-07-08T17:09Z) Created this ExecPlan with the requested result shape, decision table, consumer impact, and validation strategy.
- [x] (2026-07-08T17:43Z) Replaced `ScanUsagesResult` top-level arrays with `results: Vec<ScanUsagesEntry>` and a compact `summary`.
- [x] (2026-07-08T17:43Z) Carried request indexes and original symbol/target inputs through resolution, scanning, render-budget demotion, and classification.
- [x] (2026-07-08T17:43Z) Centralized entry classification after render-budget convergence and added unit tests for the decision table rows.
- [x] (2026-07-08T17:43Z) Updated rendered text to drive directly from `results` in entry order and removed the "No usages found." fallback for non-empty requests.
- [x] (2026-07-08T17:43Z) Updated benchmark validation, MCP description/docs, affected Rust tests, and the Python consumer in `../brokkbench` without scanning `clones/`.
- [x] (2026-07-08T17:43Z) Ran formatting, focused tests, `cargo clippy-no-cuda`, Brokkbench focused Python tests, and the full `cargo test` suite.

## Surprises & Discoveries

- Observation: The current budget loop measures the whole legacy result shape, including `summary.symbols` and warning arrays.
  Evidence: `render_scan_usages_with_budget` builds a temporary `ScanUsagesResult` with `usages`, `not_found`, `failures`, `ambiguous`, and `too_many_callsites`, then serializes it on each loop iteration.

- Observation: Target requests currently lose their original structured object immediately after resolution.
  Evidence: `resolve_scan_usages_target` returns a display `symbol` label such as `path:line:column`; the old arrays have no field that preserves the original `{path, line, column, start_byte, end_byte}` object.

- Observation: Several later full-suite failures were stale test expectations that still read old `usages`, `ambiguous`, `failures`, or `summary.symbols` fields.
  Evidence: `usage_graph_identity_test`, `usages_csharp_graph_test`, and `usages_python_graph_test` failed after the focused scan_usages tests passed; the actual tool output already contained the correct `results` entries.

- Observation: The Brokkbench Python repo has a very dirty working tree unrelated to this refactor.
  Evidence: `git -C /home/jonathan/Projects/brokkbench status --short` produced thousands of existing modified/untracked files, so only the known consumer files were edited and no broad staging command was used.

## Decision Log

- Decision: The new public shape has one top-level `results: Vec<ScanUsagesEntry>` plus `summary`.
  Rationale: A single ordered list is the only shape that guarantees one response per input and removes precedence issues among parallel arrays.
  Date/Author: 2026-07-08 / Codex

- Decision: Entry order is symbols in the order provided, then targets in the order provided.
  Rationale: This matches `ScanUsagesParams` declaration order and gives callers a stable mapping without sorting by status.
  Date/Author: 2026-07-08 / Codex

- Decision: Status is only the outcome axis; `complete: false` carries incompleteness from candidate truncation, rendering demotion/summarization, or callsite caps.
  Rationale: `unproven_matches`, `candidate_files_truncated`, and `reference_only_siblings` can co-occur, so they belong in `absence_caveats` or payload fields instead of competing statuses.
  Date/Author: 2026-07-08 / Codex

- Decision: `truncated_zero_hit_failure` is removed as a failure classification and becomes `unverified_absent` with `candidate_files_truncated`.
  Rationale: The scan completed against a truncated candidate set; the result is inconclusive absence, not an analyzer or graph failure.
  Date/Author: 2026-07-08 / Codex

## Outcomes & Retrospective

Implemented the public `scan_usages` JSON refactor. The service now emits one `results` entry per request, in canonical symbol-then-target order, with status and completeness separated. Zero-hit scans classify as `verified_absent` or `unverified_absent`; truncated zero-hit scans no longer become failures. Ambiguous entries keep structured retry payloads, and too-many-callsite results are represented as one incomplete entry.

Rendering, benchmark validation, MCP tool description text, and Rust tests were updated to the new entry shape. The Brokkbench Python consumers were also updated to read only the new `results` shape, with no old-shape fallback.

Validation completed:

- `cargo fmt`
- `cargo clippy-no-cuda`
- `BIFROST_SEMANTIC_INDEX=off cargo test scan_usages_classif`
- `BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_service -- scan_usages`
- `BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_fuzzy_symbol_lookup --test usages_php_graph_test --test go_canonical_fqn_test`
- `cargo test --quiet`
- `PYTHONPATH=. uv run pytest tests/test_prefilter.py tests/test_contextagent.py` in `/home/jonathan/Projects/brokkbench`

The Brokkbench full Python test suite was not run because importing the suite through `python -m pytest` failed on an existing missing `pygit2` dependency from `p2t/conftest.py`. The focused consumer tests passed under `uv run`.

## Context and Orientation

Bifrost is a Rust code-analysis server. The `scan_usages` tool is implemented in `src/searchtools.rs` and exposed through service/tool plumbing elsewhere. A caller passes `ScanUsagesParams`, which currently has optional `symbols`, structured `targets`, optional `paths`, and `include_tests`. `symbols` are strings such as a fully qualified function name or a file-anchored selector like `src/foo.ts#Foo`. `targets` are structured location selectors with `path`, optional `line` and `column`, and optional `start_byte` and `end_byte`.

The old public response type is `ScanUsagesResult` in `src/searchtools.rs`. It has a `summary`, then five status arrays: `usages` for successes, `not_found` for unresolved inputs, `failures` for analyzer failures, `ambiguous` for multiple declarations, and `too_many_callsites` for high-fanout symbols. `src/searchtools_render.rs` renders those arrays in category order, which loses request order and can produce `No usages found.` when a request resolved but had no returned usage block. `src/benchmark/runner.rs` currently validates benchmark output by reading `structured["usages"]` and `structured["too_many_callsites"]`.

The render-budget loop uses `SymbolUsageRenderState`. It first records full hit rows, then repeatedly demotes the largest symbol from full snippets to line clusters to per-file summaries until the serialized JSON fits `SCAN_USAGES_RESPONSE_BUDGET_BYTES`. Because final rendering state determines `complete`, classification must happen after this loop converges.

Definitions used in this plan:

- A "request" is one element from `symbols` or one element from `targets`.
- A "proven hit" is a usage site that the usage graph structurally resolved to the requested declaration.
- An "unproven match" is a structurally plausible usage site where the graph could not prove the receiver or target identity.
- "Candidate file truncation" means the usage finder capped the set of files it scanned, so zero hits are not authoritative.
- A "reference-only sibling caveat" means the workspace contains related file types, such as templates, that can reference code but are not analyzed for usage hits.

## Result Shape and Classification

Replace the five top-level arrays in `ScanUsagesResult` with:

    pub struct ScanUsagesResult {
        pub summary: ScanUsagesSummary,
        pub results: Vec<ScanUsagesEntry>,
    }

Each `ScanUsagesEntry` carries:

- `input`: an echo of the original request. For symbols, serialize the string exactly as supplied after blank-symbol filtering. For targets, serialize the original `ScanUsagesTarget` object, not a display label, so an agent can re-issue it verbatim.
- `input_kind`: `symbol` or `target`.
- `status`: one of `found`, `verified_absent`, `unverified_absent`, `not_found`, `ambiguous`, `failure`, or `too_many_callsites`.
- `complete: bool`, serialized only when false. Complete is false when the candidate file set was truncated, rendering was demoted or summarized, output file groups were truncated, or the callsite cap was hit.
- Status-specific payload fields.

The status taxonomy is outcome-only:

- `found`: proven hits exist. Payload includes `hits` as the old rendered `SymbolUsages` fields without duplicating `symbol`, plus unproven matches when present and truncation details when `complete: false`.
- `verified_absent`: scan ran, zero proven hits, no unproven matches, complete coverage, and no reference-only sibling caveat.
- `unverified_absent`: scan ran, zero proven hits, but absence is not authoritative. Payload includes `absence_caveats` with values such as `unproven_matches`, `candidate_files_truncated`, and `reference_only_siblings`; it also includes `unproven_files` and `candidate_files_sample` when relevant.
- `not_found`: input did not resolve to any declaration. Payload includes a human `message`.
- `ambiguous`: input resolved to multiple distinct declarations. Payload keeps `candidate_targets`, `candidate_details` with `scan_usages_target` objects, per-candidate `total_hits`, and a human `message`.
- `failure`: analyzer or graph failure only, such as `no_graph_seed`. Payload includes `reason_kind`, `fq_name`, `strategy`, `candidate_files_sample`, and a conservative human `message`.
- `too_many_callsites`: the callsite cap was exceeded. Payload includes sample hits, `total_callsites`, `limit`, and `complete: false`.

Decision table for the classification function:

| Scan outcome | Status | complete |
| --- | --- | --- |
| proven hits, full coverage | `found` | true |
| proven hits, candidate set truncated | `found` | false |
| zero proven, zero unproven, full coverage, no sibling caveat | `verified_absent` | true |
| zero proven, unproven exist (any coverage) | `unverified_absent` with `unproven_matches` and maybe `candidate_files_truncated` | per coverage |
| zero proven, zero unproven, truncated | `unverified_absent` with `candidate_files_truncated` | false |
| zero proven, full coverage, sibling caveat | `unverified_absent` with `reference_only_siblings` | true |
| callsite cap hit | `too_many_callsites` | false |
| graph failure | `failure` | false if candidate files were truncated, otherwise true |

The summary is intentionally small:

- `requested`: count of non-empty symbol requests plus target requests.
- `resolved`: count whose input resolved to a declaration and was scanned: `found`, `verified_absent`, `unverified_absent`, and `too_many_callsites`.
- `total_hits`: sum of proven hits from `found` entries and sample-proven hits for `too_many_callsites` only if the existing surface counted them that way; otherwise keep this as proven returned hits for found entries.
- `partial`: true if any entry has `complete: false`.

Do not serialize `status_counts` or a per-symbol summary. Render text can derive per-entry details directly from `results`.

## Plan of Work

First, replace the public Rust types in `src/searchtools.rs`. Add `ScanUsagesInput`, `ScanUsagesInputKind`, `ScanUsagesStatus`, `ScanUsagesEntry`, and a compact `ScanUsagesSummary`. Keep existing helper structs such as `UsageFileGroup`, `UsageLocation`, `AmbiguousUsageSymbol`, `UsageFailureInfo`, and `ScanUsagesCandidateFilesSample` where they are still useful as nested payloads, but stop exposing them as top-level arrays. Remove separate hint fields from new entries; use one `message` for non-success entries and `notes` for success or zero-hit entries. Keep `reason_kind` for machine-readable failure classification.

Second, introduce an internal request accumulator. Assign a stable index before resolution. Use an enum with the original input and input kind. Resolve targets first only for parameter-order semantics if necessary, but the final vector must always be sorted by the assigned canonical order: symbols first, targets second. Every resolution path must produce an internal outcome at the same index: resolved scan input, not found, ambiguous, failure, too many callsites, or render state.

Third, scan resolved requests and preserve their index. For `FuzzyResult::Success`, always create a `SymbolUsageRenderState` even when there are zero hits and no unproven matches. Do not synthesize `truncated_zero_hit_failure`; leave the render state with candidate truncation metadata for classification. For `FuzzyResult::TooManyCallsites`, create one entry carrying the sample render state and total cap metadata. For `FuzzyResult::Failure`, classify as failure only.

Fourth, change `render_scan_usages_with_budget` so it receives the full indexed outcomes and measures serialized size over the new `ScanUsagesResult { summary, results }` shape. After convergence, call one shared classification function that consumes each final rendered usage and creates `ScanUsagesEntry`. Add unit tests for each decision-table row. Unit tests may construct minimal `SymbolUsages` values directly instead of building ad hoc projects when classification alone is under test.

Fifth, update `src/searchtools_render.rs` so `RenderText for ScanUsagesResult` iterates `results` in order. A single positive result can render compactly as before. Mixed batches should show each requested member explicitly with its status. Empty `results` is the only case that may render a generic empty-request message.

Sixth, update consumers and descriptions. In `src/benchmark/runner.rs`, validate `structured["results"]` and accept `found` and `too_many_callsites` as positive usage-producing statuses. In the MCP tool description/docs for `scan_usages`, describe the `results` entry shape. Update tests, especially `tests/searchtools_service.rs` and the per-language `usages_*_graph_test.rs` files that assert heavily on the old parallel arrays. Prefer behavior-focused updates: list a tool and successfully call it, assert exactly one entry per request, assert status and payload, and assert order.

Brokkbench follow-up completed for the local Python consumer under `/home/jonathan/Projects/brokkbench`: `prefilter.py`, `tests/test_prefilter.py`, `tests/test_contextagent.py`, `oneoffs/ca_prefilter.py`, and `p2t/eval/extract_scan_usages.py` now read the new `results` shape only. Searches used `rg --glob '!clones/**'` so cloned repositories were not scanned.

`src/symbol_rename.rs` is unaffected because its not-found handling uses internal usage APIs rather than the public `scan_usages` JSON shape.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

1. Inspect status and avoid unrelated files:

       git status --short

2. Edit `src/searchtools.rs` for type changes, request accumulation, scanning, budget classification, and summary building.

3. Edit `src/searchtools_render.rs` for per-entry rendering.

4. Edit `src/benchmark/runner.rs` to consume `results`.

5. Search for legacy public fields and update tests/descriptions:

       rg '\"usages\"|\"too_many_callsites\"|\"failures\"|\"ambiguous\"|\"not_found\"|summary\\[\"symbols\"\\]|ScanUsagesResult' src tests

6. Run formatting and focused tests:

       cargo fmt
       BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_service -- scan_usages

7. Run a broader check appropriate for this machine:

       cargo clippy-no-cuda

If `cargo clippy-no-cuda` is not available, run the repository's non-CUDA equivalent shown in `Cargo.toml` or `.cargo/config.toml`.

## Validation and Acceptance

Acceptance requires all of these observable behaviors:

- A `scan_usages` call with two symbols and one target returns exactly three `results` entries in symbol-then-target order.
- A not-found input has `status: "not_found"` and does not disappear into a warning.
- A resolved zero-hit complete scan has `status: "verified_absent"` and `complete` omitted or true.
- A resolved zero-hit scan with candidate truncation has `status: "unverified_absent"`, `complete: false`, `absence_caveats` containing `candidate_files_truncated`, and `candidate_files_sample` when available.
- A zero-proven scan with unproven matches has `status: "unverified_absent"` and `absence_caveats` containing `unproven_matches`.
- Ambiguous results keep structured retry payloads, including `candidate_targets` and `candidate_details[*].scan_usages_target`.
- Too-many-callsite results are one entry with `status: "too_many_callsites"`, sample hits, `total_callsites`, `limit`, and `complete: false`.
- Rendered text names each requested entry and status in mixed batches, and `No usages found.` no longer appears for non-empty zero-hit requests.

Focused validation should include the classification unit tests, all `searchtools_service scan_usages` tests, and any per-language usage tests changed by this refactor. Final validation should include `cargo fmt` and non-CUDA clippy when practical.

## Idempotence and Recovery

The refactor is source-only and can be retried safely. Do not use `git add -A`; stage only files touched for this plan. If tests reveal a behavior mismatch, update this plan's `Surprises & Discoveries` and `Decision Log` before changing direction. Existing untracked files under `.agents/docs/` and `.brokk/` predate this plan and must remain untouched unless the user asks otherwise.

## Artifacts and Notes

Initial search evidence:

    rg found the old result arrays in src/searchtools.rs, rendering in src/searchtools_render.rs, benchmark validation in src/benchmark/runner.rs, and many scan_usages assertions in tests/searchtools_service.rs and language usage tests.

The old false-positive empty render path is:

    impl RenderText for ScanUsagesResult
        let mut blocks = self.usages.iter().map(render_symbol_usages_text).collect()
        ...
        if blocks.is_empty() { return "No usages found.".to_string(); }

## Interfaces and Dependencies

In `src/searchtools.rs`, define these public serialized types:

    pub struct ScanUsagesResult {
        pub summary: ScanUsagesSummary,
        pub results: Vec<ScanUsagesEntry>,
    }

    pub struct ScanUsagesSummary {
        pub requested: usize,
        pub resolved: usize,
        pub total_hits: usize,
        pub partial: bool,
    }

    pub struct ScanUsagesEntry {
        pub input: ScanUsagesInput,
        pub input_kind: ScanUsagesInputKind,
        pub status: ScanUsagesStatus,
        #[serde(skip_serializing_if = "std::ops::Not::not", default)]
        pub complete: bool,
        ... status-specific optional payload fields ...
    }

Use `#[serde(rename_all = "snake_case")]` for enums. Because `complete` should serialize only when false, implement it as `incomplete: bool` renamed to `complete` only if the existing serde pattern cannot skip true; otherwise use a helper predicate such as `is_true` with `#[serde(skip_serializing_if = "is_true", default = "default_true")]`.

The classification function should be shared and testable. A concrete shape is:

    fn classify_scan_usage_entry(input: ScanUsageRequestInput, outcome: FinalScanUsageOutcome) -> ScanUsagesEntry

`FinalScanUsageOutcome` should contain post-budget `SymbolUsages` for scanned results, plus original candidate file sample, callsite cap metadata, ambiguity payload, not-found message, or failure data as appropriate.

## Revision Notes

- 2026-07-08T17:09Z: Initial plan created because the refactor changes a public JSON shape, rendering, benchmark validation, and many tests. The plan records the requested status taxonomy and implementation sequencing so future work can continue without relying on conversation memory.
- 2026-07-08T17:43Z: Implementation completed and validated. Additional full-suite failures were fixed by migrating remaining stale tests to the new `results` shape.
