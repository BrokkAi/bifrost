# Remove scan_usages recommended_next_call

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agents/PLANS.md` from the repository root. It is self-contained so a future contributor can continue the work without relying on conversation context.

## Purpose / Big Picture

`scan_usages` currently has a `summary.recommended_next_call` field that sometimes tells callers to run another `scan_usages` call. This is inconsistent with the rest of the tool surface, where failures and partial results carry local notes or hints. The high-fanout `too_many_callsites` branch is especially misleading because its recommended arguments repeat the same symbol without adding a path or more specific selector, so a caller that follows it literally can loop.

After this change, `scan_usages` will no longer emit `recommended_next_call`. Summary-mode and too-many-callsite cases will continue to carry useful, local guidance through the existing `note`, `warnings`, and failure `hint` fields. A user can observe the change by running the focused `searchtools_service` tests and seeing that high-hit summary output has no recommendation field while still explaining how to narrow the query.

## Progress

- [x] (2026-07-06T22:10Z) Inspected the `recommended_next_call` generator and confirmed it is only produced by `src/searchtools.rs`.
- [x] (2026-07-06T22:10Z) Confirmed the only in-tree test assertion for the field is in `tests/searchtools_service.rs`.
- [x] (2026-07-06T22:10Z) Removed the serialized field, helper type, helper function, and assignment from `src/searchtools.rs`.
- [x] (2026-07-06T22:10Z) Improved local notes for summary and `too_many_callsites` results so callers still get actionable guidance.
- [x] (2026-07-06T22:10Z) Updated the high-hit summary test to assert absence of `recommended_next_call` and presence of useful path-narrowing guidance.
- [x] (2026-07-06T22:12Z) Ran `cargo fmt`, the focused summary regression, all `searchtools_service scan_usages` tests, and `cargo check`; all passed.
- [ ] Commit, push, and close GitHub issue #505.

## Surprises & Discoveries

- Observation: `too_many_callsites` is not just a leftover renderer artifact. The `FuzzyResult::TooManyCallsites` variant is still used by usage graph strategies, rename safety checks, and dead-code analysis.
  Evidence: `rg too_many_callsites` shows matches in `src/symbol_rename.rs`, `src/code_quality/dead_code_smells.rs`, language graph strategy tests, and `src/searchtools.rs`.

## Decision Log

- Decision: Remove only the public `summary.recommended_next_call` surface, not the internal `FuzzyResult::TooManyCallsites` variant.
  Rationale: The recommendation field can over-steer callers and is inconsistent with the rest of the tool output, but high-fanout guardrails still matter for editing and analysis workflows.
  Date/Author: 2026-07-06 / Codex.

- Decision: Keep recovery guidance attached to the affected result through existing notes and hints.
  Rationale: The repository already uses local error and partial-result messages. A local note is visible without asking the model to obey a directive next-call object.
  Date/Author: 2026-07-06 / Codex.

## Outcomes & Retrospective

Implementation and validation are complete. The remaining work is to commit, push, and close GitHub issue #505.

Validation completed on 2026-07-06T22:12Z:

    cargo fmt
    cargo test --test searchtools_service scan_usages_demotes_large_result_to_summary_within_budget
    cargo test --test searchtools_service scan_usages
    cargo check

The focused summary regression passed with the new output shape, and the broader `scan_usages` service suite passed 28 tests.

## Context and Orientation

The public `scan_usages` implementation lives in `src/searchtools.rs`. The result type is `ScanUsagesResult`, which contains a `summary` field of type `ScanUsagesSummary`. Before this plan, `ScanUsagesSummary` had an optional `recommended_next_call` field with a `tool`, `arguments`, and `reason`. The helper `recommended_scan_usages_next_call` produced that field for summary-mode results and for `too_many_callsites`.

The phrase `too_many_callsites` means the analyzer found more call sites than the configured cap for a symbol. In `scan_usages`, that cap is `SCAN_USAGES_MAX_CALLSITES`, currently equal to `DEFAULT_MAX_USAGES`, which is 1000. For huge utility symbols such as a logger method in a large project, returning every call site can be expensive and low-signal, so keeping a high-fanout diagnostic is reasonable. What should go away is the directive follow-up object that tells callers to retry the same symbol.

The main regression tests for this public surface are in `tests/searchtools_service.rs`. The test `scan_usages_demotes_large_result_to_summary_within_budget` creates a Java project with many callers and previously asserted that `recommended_next_call.tool == "scan_usages"`.

## Plan of Work

Edit `src/searchtools.rs` to remove `ScanUsagesSummary::recommended_next_call`, remove the `ScanUsagesRecommendedNextCall` struct, remove the `recommended_scan_usages_next_call` helper, and stop computing or assigning the field in `scan_usages_summary`.

Keep the existing `TooManyCallsitesInfo::note` field, but make `too_many_callsites_note` more explicit that the current query is too high-fanout for exhaustive output and that callers should choose narrower `paths` or a more specific symbol. Keep summary-mode notes in `render_symbol_usages` actionable. Do not introduce a new replacement directive field.

Update `tests/searchtools_service.rs` so the high-hit summary test asserts that `recommended_next_call` is absent and that the summary/note fields remain useful. If there is no dedicated `too_many_callsites` service-level test, add a small inline Java test that forces the cap only if the public API exposes a way to do so; otherwise rely on existing language-strategy unit tests for the internal high-fanout variant and update only public summary behavior.

## Concrete Steps

Run commands from `/home/jonathan/Projects/bifrost`.

First, search for the field:

    rg -n "recommended_next_call|ScanUsagesRecommendedNextCall|recommended_scan_usages_next_call" src tests

Then edit `src/searchtools.rs` and `tests/searchtools_service.rs`. After editing, run:

    cargo fmt
    cargo test --test searchtools_service scan_usages_demotes_large_result_to_summary_within_budget
    cargo test --test searchtools_service scan_usages
    cargo check

If tests pass, stage only the changed files and commit on the current branch:

    git add src/searchtools.rs tests/searchtools_service.rs .agents/plans/remove-scan-usages-recommended-next-call.md
    git commit -m "Remove scan_usages recommended next call" -m "..."
    git push

Finally, close issue #505 with a comment explaining that the directive recommendation field was removed in favor of local notes and hints.

## Validation and Acceptance

The change is accepted when `scan_usages` summary JSON no longer contains `recommended_next_call`, high-hit summary responses still include actionable notes, all focused `scan_usages` tests pass, `cargo check` passes, and GitHub issue #505 is closed as completed.

## Idempotence and Recovery

The edits are ordinary Rust source and test changes. Re-running `cargo fmt` and the tests is safe. If a test fails because it still expects `recommended_next_call`, update that test to assert the new contract instead of restoring the removed field. Do not use destructive git commands; inspect diffs and patch forward.

## Artifacts and Notes

Important original locations that were edited or removed:

    src/searchtools.rs:588    ScanUsagesSummary::recommended_next_call, removed
    src/searchtools.rs:619    ScanUsagesRecommendedNextCall, removed
    src/searchtools.rs:3861   recommended_scan_usages_next_call call site, removed
    src/searchtools.rs:3916   recommended_scan_usages_next_call helper, removed
    src/searchtools.rs:4289   too_many_callsites_note
    tests/searchtools_service.rs:3079 summary recommended_next_call absence assertion

Revision note, 2026-07-06T22:10Z: Updated progress and artifact notes after removing the public recommendation field and replacing the test expectation with an absence assertion plus local note validation.

Revision note, 2026-07-06T22:12Z: Recorded successful formatting and focused validation before committing.

## Interfaces and Dependencies

At completion, `ScanUsagesSummary` in `src/searchtools.rs` must have this public shape:

    pub struct ScanUsagesSummary {
        pub requested_symbols: usize,
        pub resolved_symbols: usize,
        pub total_hits: usize,
        pub partial: bool,
        pub symbols: Vec<ScanUsagesSymbolSummary>,
        pub warnings: Vec<String>,
    }

No new dependencies are required.
