# Per-file assertion row batching with per-file completion accounting (#1642)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

An "assertion policy" is a policy whose findings come from proving or refuting typed claims (asserts) about captured source positions, rather than from a plain structural match. The specialized assertion evaluator lives in `crates/bifrost-policy/src/evaluator/assertion.rs`, function `evaluate_assertion_policy`.

Today that evaluator runs one subject query, then one query per row family (occurrences, resolution candidates, reaching bindings, lexical scopes, generation sites), each seeded with the entire subject-file list, and joins all materialized rows in memory. Row volume therefore scales with the total size of every subject file, and one shared `max_pipeline_rows` budget covers the whole run. Measured on this repository (issue #1642): the candidate loop-invariance rule has ~60 subject files, several over 10k lines; the row queries exhaust the budget and the run ends `Inconclusive` with reasons `pipeline_row_budget` + `partial_discovery` no matter how long it runs. This blocks promoting the loop-invariance sort rule into the built-in `bifrost.code-smells` pack (issue #1598).

After this change, the evaluator runs the row-family queries once per subject file and accounts for completion per file. A file whose rows blow the budget (or whose asserts cannot conclude) degrades only that file's verdict: its subjects contribute no findings, the run reports which files could not be concluded, and every other file's verdict stands. Row budgets then bound memory per file rather than correctness of the whole run. On a workspace where every file individually fits the budget, the run concludes `Complete` where it previously could not conclude at all.

Observable outcome: a two-file test project where one file fits a deliberately tiny row budget and the other does not produces a run that (a) reports the fitting file's true-positive finding, (b) has completion `Inconclusive { reasons: [PipelineRowBudget, ...] }`, and (c) carries a diagnostic naming exactly the file that could not be concluded. Before this change the same setup reports zero findings. And the existing 22-test loop-invariant suite plus all assertion conformance suites pass unchanged.

## Progress

- [x] (2026-08-07) Studied `evaluate_assertion_policy`, the query builders, `PolicyRunCompletion`, `PolicyRun::try_new`, the eager-index execution helper, and the prototype suite harness.
- [x] (2026-08-07) Authored this plan.
- [x] (2026-08-07) Milestone 1: restructured `evaluate_assertion_policy` into a per-file loop with per-file completion accounting; added the missing non-empty-path assert to `assertion_generation_query`. `cargo test -p brokk-bifrost-policy` (294 tests) and the 22-test `policy_loop_invariant` suite pass unchanged.
- [x] (2026-08-07) Milestone 2: four behavior tests in `tests/suite_bench_policy/policy_assertion_per_file_completion.rs` (degradation, multi-file Complete, per-file capability gap, vacuous empty), registered in `main.rs` and the harness manifest. Written by an Opus subagent, reviewed and tightened (helper renamed to say what it asserts; the widened-rule `replace` now asserts it actually changed the fixture text).
- [x] (2026-08-07) Milestone 3: full `suite_bench_policy` (321 passed), `cargo test -p brokk-bifrost-policy` (294 passed), fmt, and featureless `cargo clippy --workspace --all-targets -- -D warnings` clean. All-features clippy runs before push.
- [ ] Milestone 4: workspace-scale measurement on this repository (release build), recorded here; decides whether latency needs follow-up work beyond conclusiveness.

## Surprises & Discoveries

- Observation: the generation-site query construction (`assertion_generation_query`) was not guarded by `!paths.is_empty()` like the other row families, and `GenerationSiteSeed::for_exact_paths` with an empty path list produces empty `where_globs` - an *unrestricted* seed. A subject-less policy with a generation assert would scan every file in the workspace, the exact defect class fixed for the other families in PR #1643.
  Evidence: `crates/bifrost-policy/src/evaluator/assertion.rs` line 211 (pre-change) vs the `!paths.is_empty()` guards at lines 154/162/175; `exact_path_globs` in `crates/bifrost-analysis/src/analyzer/structural/query/ir.rs`. The per-file restructure removes the hazard structurally (queries are only built inside the per-file loop); the constructor should also assert non-empty paths like its siblings.
- Observation: `execute_code_query_detailed_eager_index` builds the snapshot structural index on first use and shares it across queries, so a per-file loop (up to 5 queries per file) does not pay a per-query index rebuild. The lexical environment cache, however, is per pipeline execution - unchanged from today, where the candidates and reaching queries were already separate executions over the same files.
  Evidence: `crates/bifrost-analysis/src/analyzer/structural/search/mod.rs:2100` and the `environment_cache` parameter threading in `search/pipeline.rs`.
- Observation: `PolicyRun::try_new` permits findings alongside a non-reliable completion (the `Failed` path already attaches findings), so "findings from concluded files + `Inconclusive` verdict" needs no new run type.
  Evidence: `crates/bifrost-policy/src/finding.rs:2416` validation; `failed_policy_run_with_reason` in `evaluator.rs`.
- Observation (Milestone 2): the planned degradation fixture (many small sort-in-loop subjects in the big file) cannot exhaust a per-file budget before the run-level subject query does - the subject query spans both files and uses the same `max_pipeline_rows`, so there was no budget window at all. The working fixture keeps the big file at *one* subject and makes it expensive in scopes instead (80 filler functions of nested blocks): the family that then exhausts first is the per-file lexical scope seed ("lexical environment seed reached its N-row cap"), with a wide calibration window (degradation holds from 40 to ~400 rows; everything Complete by 600; the test pins 200).
  Evidence: calibration record in `tests/suite_bench_policy/policy_assertion_per_file_completion.rs`.
- Observation (Milestone 2): widening the rule's receiver for the capability-gap test uses a bare `(capture "target")` pattern - `(expression ...)` is not a normalized RQL kind and fails to load. The bare capture matches both an identifier receiver (file A keeps its finding) and an array-literal receiver, which carries no receiver-position occurrence and so produces exactly the per-file `CapabilityIncomplete`.
  Evidence: `per_file_capability_gaps_do_not_block_other_files` in the new suite.

## Decision Log

- Decision: batch per file, not per bounded batch of files.
  Rationale: per-file is the smallest unit that gives exact blame attribution ("this file could not be concluded") and per-file budget reset. Bounded batches would smear one oversized file's exhaustion across its batch mates and complicate the accounting for no measured win - the expensive per-query work (snapshot index) is already shared via the eager-index helper. YAGNI.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: a file that cannot be concluded contributes zero findings, and the run completion becomes `Inconclusive` (union of the per-file reasons) while retaining the findings from concluded files, plus one diagnostic naming the complete set of unconcluded files with their reasons.
  Rationale: findings from a file whose row set is incomplete could be wrong in either direction, so they are discarded wholesale, per file - the existing soundness rules 1 and 3 applied at file granularity instead of run granularity. The run must not claim `Complete` (unobserved rows can falsify a clean claim) and must not launder an unplanned budget exhaustion into `ProvenSubset`, whose meaning here is an omission the *query itself* declared as non-exhaustive by design. `Inconclusive` keeps `is_reliable()` false, so a gate is still honest about the degraded file, but the operator now sees exactly which file to split, scope out, or budget up - and every healthy file's findings.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: subject-query incompleteness stays run-level (zero findings, `Inconclusive`), exactly as today.
  Rationale: if subject discovery itself is incomplete, the evaluator does not even know which files it failed to consider, so per-file attribution is impossible by construction.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: `late_incomplete` (soundness rule 3: an assert that cannot conclude over the stated rows) and `captures_without_ast_id` (a capture with no occurrence identity) become per-file as well.
  Rationale: both are properties of one subject in one file. The #1598 history shows the run-level version in action: expression receivers in `scripts/*.mjs` made the whole workspace run inconclusive, which had to be worked around by narrowing the rule. Per-file accounting makes such a file degrade itself only.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: query failure reasons (`Invalid` completions -> `InvalidExecutionPlan`) and the unbound-capture authoring errors keep failing the whole run.
  Rationale: they indicate the plan or the policy is wrong, which is not a per-file property.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: the relational assertion path (`evaluate_relational_assertion_policy`) is out of scope.
  Rationale: relational plans join rows across files by design, so "per-file completion" has no well-defined meaning there; #1642 names the specialized families. If relational plans hit the same wall, that is a separate issue with its own semantics.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: do not add a lexical-environment cache shared across the per-file queries in this change; measure first (Milestone 4).
  Rationale: #1642's second ask ("per-file derivation cost understood and bounded") starts with a measurement. The candidates and reaching queries were already separate pipeline executions before this change, so the restructure does not regress caching; whether a shared cache is needed is exactly what the Milestone 4 probes tell us.
  Date/Author: 2026-08-07, session with dbakereffendi.

## Outcomes & Retrospective

To be written as milestones complete.

## Context and Orientation

All paths are repository-relative. The work happens in the `brokk-bifrost-policy` crate.

- `crates/bifrost-policy/src/evaluator/assertion.rs` - `evaluate_assertion_policy` (the function to restructure, roughly lines 47-746 pre-change) plus the query builders `assertion_occurrence_query`, `assertion_scope_query`, `assertion_generation_query` near the bottom of the file.
- `crates/bifrost-policy/src/evaluator.rs` - shared run-assembly helpers: `incomplete_reasons`, `failure_reasons`, `inconclusive_policy_run_many`, `failed_policy_run_with_reason`, `finish_assembled_run`, `work_report`.
- `crates/bifrost-policy/src/finding.rs` - `PolicyRunCompletion` (Complete / ProvenSubset / Inconclusive / Unsupported / Failed), `PolicyIncompleteReason` (includes `PipelineRowBudget`, `PartialDiscovery`, `CapabilityIncomplete`), `PolicyDiagnostic`, `PolicyRun::try_new`.
- `crates/bifrost-policy/src/budget.rs` - `PolicyBudget`, `PolicyBudgetBuilder::with_query_limits` (how a test injects a small `max_pipeline_rows`).
- `crates/bifrost-analysis/src/analyzer/structural/search/mod.rs:2100` - `execute_code_query_detailed_eager_index`, the batch-friendly execution entry the evaluator already uses.
- `tests/suite_bench_policy/policy_loop_invariant_sort.rs` - the harness pattern to copy for new tests: `InlineTestProject` + `PolicyRegistry::new_without_workspace` + `DefaultPolicyEvaluator::evaluate` with an explicit `PolicyBudget`.
- `tests/fixtures/policies/loop-invariant-receiver.rqlp` - the candidate rule; its `assert-reaching` makes it exercise the occurrence + reaching + scope families, which is what the new tests reuse.

Terms. A "row family" is one kind of evidence row the evaluator joins to captures: occurrence rows (a token playing a role, e.g. `receiver_position`), resolution-candidate rows, reaching-binding rows (which declaration is in effect for a name at a position), lexical-scope rows, generation-site rows, and locally derived declaration-state rows. A "subject" is one match of the policy's subject selector: a file path, a location, and named captures with AST identities. "Completion accounting" is the typed verdict on whether the evaluator observed every row it needed: `Complete`, or `Inconclusive` with reasons like `PipelineRowBudget` (a row query hit `max_pipeline_rows`).

Pre-change control flow of `evaluate_assertion_policy`, so the restructure is unambiguous: (1) run the subject query; (2) collect subjects; (3) compute the union of asserted roles; (4) build one query per needed row family seeded with *all* subject paths; (5) execute them, folding every query's incomplete/failure reasons into run-level `run_incomplete`/`run_failures`; (6) bucket all rows into hash maps keyed by AST id (path-qualified where needed); (7) if `run_incomplete` is non-empty, return an inconclusive run with zero findings; (8) otherwise evaluate every assert for every subject, pushing findings, with `late_incomplete` collecting asserts that could not conclude; (9) if `late_incomplete` is non-empty, return inconclusive with zero findings; (10) otherwise assemble Complete/ProvenSubset.

## Plan of Work

Milestone 1 - the per-file loop. In `crates/bifrost-policy/src/evaluator/assertion.rs`, restructure `evaluate_assertion_policy`:

Keep steps 1-3 (subject query, subject collection, role computation) unchanged. Subject-query failure reasons still fail the run; subject-query incompleteness (including truncation) still returns run-level inconclusive with zero findings before any row work - this preserves the "no subjects means vacuous verdict from the subject query" behavior and its tests.

Hoist the presentation preparation (message, classification, severity, `identity_support`, `EdgeAssertContext`) above the row work, since findings are now assembled inside the loop. These preparations can still fail the run as before.

Group subjects by path (the paths list is already sorted and deduplicated; keep that order for determinism). For each file, in order: build the row-family queries exactly as today but seeded with only that file's path - occurrence roles query, candidates query, reaching + scope queries, generation query (each only when the corresponding asserts exist, as today), and the per-file declaration-state materialization which already iterates paths. Execute them with `execute_code_query_detailed_eager_index`. Collect the file's rows into the same hash-map shapes as today (they can stay function-local per file; cross-file AST-id collisions between identical-content files then become structurally impossible, though the path-qualified binding join stays). Fold each query's diagnostics and work into the run accumulators. Fold `failure_reasons` into `run_failures` and abort the loop into the existing failed-run path if any appear. Fold `incomplete_reasons` into a per-file reason list instead of `run_incomplete`.

If the file's reason list is non-empty, record the file as unconcluded (path + reasons) and skip assert evaluation for its subjects entirely. Otherwise evaluate all asserts for the file's subjects exactly as the existing loop does, but into a per-file findings buffer with a per-file `late_incomplete`, and treat a subject capture without an AST id (`captures_without_ast_id`) as a per-file `CapabilityIncomplete` instead of a run-level one. If per-file `late_incomplete` ends non-empty, discard the file's findings buffer and record the file as unconcluded with those reasons; otherwise append the buffer to the run findings. The authoring-error paths inside the assert loop (unbound `:at` and friends) keep returning failed runs immediately.

Final assembly: if any file is unconcluded, build the run with completion `Inconclusive` over the sorted, deduplicated union of all per-file reasons, the retained findings, and one additional `PolicyDiagnostic` (code `EvaluationFailure`, impact `RunIncomplete`) whose message names every unconcluded file with its reasons (the complete collection, Debug-formatted, per the repository logging rule; if the diagnostic prose cap forces truncation, keep the typed reasons complete and say how many paths were omitted). Use `finish_assembled_run` so budget-driven retention still applies. If no file is unconcluded, keep today's Complete/ProvenSubset selection, scanning the per-file row-query completions for `ProvenSubset` exactly as the old `row_completions` scan did.

Also add the missing non-empty assert to `assertion_generation_query`, matching its siblings; after the restructure it is only ever called with exactly one path.

Milestone 2 - behavior tests. New suite member `tests/suite_bench_policy/policy_assertion_per_file_completion.rs` plus a `mod` line in `tests/suite_bench_policy/main.rs` (per the analyzer test guidance; also record it in `.agents/docs/test-harness-consolidation-2026-07.md` if that manifest lists members). Reuse the loop-invariant harness pattern with a two-file Rust `InlineTestProject` and the checked-in candidate rule via `include_str!`:

- `a_file_over_budget_degrades_only_itself`: file A is the known true-positive shape (a `Vec` declared outside a `while`, sorted inside); file B contains enough distinct sort-in-loop subjects to push its row queries past a tiny `max_pipeline_rows` injected through `PolicyBudgetBuilder::with_query_limits`, while file A's largest per-file query (likely the scope query - every scope in the file) stays under it. Assert: exactly file A's finding is reported; completion is `Inconclusive` and its reasons include `PipelineRowBudget`; some diagnostic message contains file B's path and no diagnostic implicates file A.
- `all_files_fitting_conclude_complete`: same two-file shape with the default budget; completion `Complete`, findings from both files - proving per-file batching preserves multi-file evaluation.
- `per_file_capability_gaps_do_not_block_other_files`: file A the true positive, file B a subject whose captured receiver has no occurrence identity (an expression receiver shape, with a rule variant that does not constrain the receiver to identifiers - inline a widened copy of the rule in the test so the shipped fixture stays untouched). Assert: file A's finding survives, run inconclusive, diagnostic names file B. If constructing an identity-less capture proves brittle across grammar changes, fall back to a `late_incomplete`-driven variant with the same acceptance shape, and record the swap here.
- `no_subjects_stay_vacuously_complete`: a subject-less workspace still yields `Complete` with zero findings fast (guards the empty-seed regression, now including the generation family structurally).

The degradation test must fail before Milestone 1 (whole-run inconclusive, zero findings) and pass after.

Milestone 3 - validation. Run the focused suites and the crate: `cargo test --test suite_bench_policy policy_loop_invariant`, `cargo test --test suite_bench_policy policy_assertion_per_file`, `cargo test -p brokk-bifrost-policy`, then the broader `cargo test --test suite_bench_policy` and `cargo test --test suite_cross_language` (check whether assertion conformance actually lives there; adjust to the suites that cover assertion policies), then `cargo fmt` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` (via `scripts/with-isolated-cargo-target.sh` if disk pressure warrants). Every pre-existing test must pass unchanged.

Milestone 4 - measure at workspace scale (the #1642 acceptance evidence). Build release and re-run the #1642 probes on this repository: the single candidate rule against `--root crates/bifrost-core` (previously 6s debug), and the full `bifrost.code-smells` pack against the whole repository with the candidate rule loaded the way the #1598 gate ran it (previously 68m49s release, inconclusive). Record wall time and the rule's completion here. Success for #1642 is: the rule concludes (Complete, or Inconclusive naming specific files rather than the whole run), and per-file row budgets are not exhausted on this repository. If the latency remains far outside the naive rules' envelope, the remaining cost is the per-file lexical derivation; measure which files dominate and record the numbers - bounding that cost (caching environments alongside structural facts, or restricting derivation to subject regions) is the follow-up this milestone quantifies, not necessarily implements. The pack flip itself stays in #1598's plan (`.agents/plans/issue-1598-loop-invariance-promotion.md`, recipe commit `f95b4ebfc`).

## Concrete Steps

Work from the repository root. The worktree branch is `dave/stale-issue-check-9c5ce9`; commits go to the current branch per repository rules.

    cargo test --test suite_bench_policy policy_assertion_per_file
    cargo test --test suite_bench_policy policy_loop_invariant
    cargo test -p brokk-bifrost-policy
    cargo test --test suite_bench_policy
    cargo fmt
    cargo clippy --workspace --all-targets --all-features -- -D warnings

Milestone 4, release measurement (long; do not run concurrently with other builds):

    cargo build --release --bin bifrost
    time ./target/release/bifrost --policy-pack bifrost.code-smells --evaluation-date 2026-08-07 --fail-on warning --format json --output <scratchpad>/gate.json

## Validation and Acceptance

Acceptance is behavioral. (1) The new degradation test proves findings and per-file blame coexist: with a tiny row budget, the fitting file's finding is reported, the run is `Inconclusive` with `PipelineRowBudget` among its reasons, and a diagnostic names the oversized file only; this test fails before Milestone 1 and passes after. (2) The multi-file Complete test proves no regression in the common case. (3) `cargo test -p brokk-bifrost-policy` and the full `suite_bench_policy` pass unchanged - in particular the 22-test loop-invariant suite. (4) Milestone 4's measurement shows the candidate rule concluding on this repository, which is the #1642 acceptance and unblocks the #1598 pack flip.

## Idempotence and Recovery

The restructure is a single-function rewrite guarded by an unusually dense behavior suite; if it goes wrong mid-way, `git checkout -- crates/bifrost-policy/src/evaluator/assertion.rs` returns to the known-good whole-run semantics and the new tests simply fail. All test steps are re-runnable. The release measurement writes only to the scratchpad. No schema, manifest, or pack content changes in this plan, so nothing needs rollback coordination.

## Artifacts and Notes

The blocking measurement being fixed, from issue #1642: release-build pack run 68m49s wall / 2808s user, exit 2, rule `inconclusive` with `pipeline_row_budget` + `partial_discovery`, "assertion evaluation could not observe a complete row set"; per-crate probes 6s (debug, single rule, `crates/bifrost-core`) vs 2.3s for the naive rules. Milestone 4 records the post-change numbers here.

## Interfaces and Dependencies

No public interface changes. `evaluate_assertion_policy` keeps its signature; the restructure is internal. The only behavioral surface change is run composition in the degraded case: findings may now accompany a `PolicyRunCompletion::Inconclusive`, which `PolicyRun::try_new` already validates and serializes (`finding.rs`). Consumers that treated "inconclusive implies zero findings" as an invariant would be wrong already for `Failed` runs; none are known - `is_reliable()` remains the gate contract. The new test file depends only on existing test-harness pieces: `InlineTestProject`, `PolicyRegistry::new_without_workspace`, `DefaultPolicyEvaluator`, `PolicyBudgetBuilder`.

Revision note (2026-08-07): initial version.
