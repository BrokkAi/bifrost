# Second-chance retry for starved set-operation branches, and workspace-scaled policy scan budgets (#1766)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

A CodeQuery whose plan is a `union` (or `intersect`/`except`) of seed scans divides its execution budget across the branches with a forward waterfall: branch N's cap is computed from what branches 0..N actually used, so only later branches inherit unused shares, and the *first* branch's cap is fixed at `1/branch_count` of the whole budget before anything has run. On a workspace whose volume is concentrated in the first-listed branch - a five-language policy selector with Rust first, on this mostly-Rust repository - the first branch exhausts its 1/5 share (~403k of 2M fact nodes), the query reports `execution_budget_exhausted`, and every policy built on it is `inconclusive` with `partial_discovery`. Five naive built-in `bifrost.code-smells` rules and the #1598 loop-invariance candidate are all unconcludable on this repository today because of it. That is issue #1766.

There is a second, independent gap that #1766's measurement exposed: even *alone*, with the full 2M fact-node budget, the Rust branch of the candidate rule's selector exhausts the budget at 675 of 1309 Rust files (21.3MB of 37.6MB scanned). A whole-workspace policy subject scan is Theta(workspace facts) by design, so a fixed 2M-fact default cannot serve a workspace of this size no matter how fairly it is divided. This plan files that as its own issue and fixes it for the policy gate by scaling the policy budget's scan lanes with the workspace's measured source volume.

After this change: on a two-language test workspace where nearly all volume is in the first-listed language, a union query that previously truncated its first branch concludes complete within the same total budget; and on this repository, the release-build `bifrost.code-smells` gate plus the candidate rule concludes every rule (`complete`), which is the #1598 promotion precondition.

## Progress

- [x] (2026-08-07) Diagnosed the actual mechanism (sequential set-op waterfall, not the parallel coordinator; see Surprises), measured the single-branch budget shortfall, authored this plan.
- [x] (2026-08-07) Milestone 1: second-chance retry pass in the sequential set-op executor, with two behavior tests in `crates/bifrost-analysis/src/analyzer/structural/search/tests/execution.rs`. Implemented by an Opus subagent; reviewed. Three empirical deviations from this plan's first draft, all recorded in Surprises and the Decision Log: the retry precondition is `starved` (truncated with `execution_budget_exhausted`) plus whole-budget headroom plus a raised *scan* lane, not "any lane strictly larger"; truncated seed-cache entries must be evicted before the retry or it replays the cached frontier verbatim; and a retry that is still truncated with no more rows than the first attempt is discarded. Validation: bifrost-analysis 1683 passed, suite_bench_policy 321, suite_smells 149, suite_issues 335, crate clippy clean.
- [x] (2026-08-07) Milestone 2: parallel coordinator parity *deferred* - production `Auto` never selects the parallel path (explicitly gated 2-branch experiment, recorded no-crossover A/B in `select_parallel_union`), so the divergence is unreachable in production; the sequential retry semantics should settle before the experiment mirrors them. To be recorded on #1766 at PR time.
- [x] (2026-08-07) Milestone 3: budget-scaling follow-up filed as #1771; `PolicyBudget::scaled_for_workspace` implemented (Opus subagent, reviewed) with separate 16x hard-cap constants for the three scan lanes (the old constants doubled as builder hard caps and would have rejected scaled values), applied once in the coordinator's shared inner path (`evaluate_prepared_policy_inputs`), which serves both the CLI gate and MCP `run_policy`. On this repository only the fact-node lane rises (2M -> ~6.27M against the measured ~3.6M need). Policy crate 297 passed, suite_bench_policy 321 passed, crate clippy clean.
- [ ] Milestone 4: gate re-measurement on this repository; record numbers here; comment on #1766 and #1598.

## Surprises & Discoveries

- Observation: the production path for this failure is *sequential*, not the parallel coordinator the issue text described. `select_parallel_union` (search/mod.rs) only returns a parallel plan for an explicit `UnionExecutionStrategy::Parallel` with exactly two seed branches; production `Auto` stays sequential. The sequential set-op arm in `execute_plan` (crates/bifrost-analysis/src/analyzer/structural/search/execution.rs, `SequentialUnion | SequentialIntersection | SequentialExcept`) applies the same waterfall via `fair_branch_limits(&state.budget, limits, dependencies.len() - index)` (crates/bifrost-analysis/src/analyzer/structural/search/pipeline.rs:420): branch 0's cap is `(max - used)/branch_count` computed before any branch has run. The parallel `FairSeedBudgetCoordinator` has the same forward-only shape (its rejection condition `state.finished[..branch].iter().all(finished)` is vacuously true for branch 0), but it is not what production executes.
  Evidence: the union subject query exhausts at 403,158 facts = ceil((2,000,000 - base)/5); `--query-file` diagnostic "execution budget exhausted after scanning 174 files, 4481510 bytes, 403158 facts".
- Observation: a retry of a truncated branch is nearly free for the work already done. The sequential `SeedScanLedger` on `QueryExecutionState` admits each file's `scanned_files`/`scanned_source_bytes`/full-fact charges once per execution, and extracted facts live in the provider memory cache - so re-executing a branch whose first attempt charged N files does not re-charge those N files and re-matches them from cached facts. A retry against the post-first-pass budget therefore effectively *resumes* the scan at the truncation frontier, deterministically.
  Evidence: `SeedScanLedger` doc comment ("later visits skip the already-admitted per-file charges"), search/mod.rs:1306.
- Observation (Milestone 1): "retry when any lane's limit is strictly larger" is wrong twice over. Unused lanes always grow once the budget has been consumed, so the condition fires for branches a bigger share cannot help (row caps, relation limits, missing analysis) - and the row lanes are re-charged on every visit (the ledger dedupes only per-file scan charges), so a rescan against a spent row budget can return *fewer* rows than the first attempt. The landed condition: retry only branches that truncated with `execution_budget_exhausted`, only while every parent lane has headroom, and only when a scan lane (files/bytes/facts) is raised; plus a survivor check that keeps the first attempt if the retry is still truncated with no more rows.
  Evidence: two pre-existing profile tests (`profile_marks_truncated_seed_materialization_and_replay_incomplete`, `profile_preserves_incomplete_reference_cache_state_for_a_sibling`) failed under the naive condition and pass untouched under the landed one.
- Observation (Milestone 1): a truncated seed scan is cached in `state.seed_cache` and replayed verbatim, so a retry without cache eviction re-observes its own truncation frontier (verified: retry with cap 2885 vs 1443 returned the identical 48 rows). The retry pass evicts only truncated entries (`retain(|_, cached| !cached.truncated)`), keeping complete-seed sharing intact.
- Observation (Milestone 1): the behavior tests must run under `StructuralAccessMode::ScanOnly` - under `Auto` an earlier query builds the posting index and later queries charge only candidate facts (101 vs 2885), making scan budgets non-binding and the starvation unreproducible.
- Observation: the single-branch shortfall. The candidate rule's Rust branch alone, with the full default budget: `execution_budget_exhausted` after 675 files / 21,269,821 bytes / 2,007,515 facts; the workspace has 1309 Rust files / 37.6MB. The measured density is ~0.094 fact nodes per source byte (~1 fact per 10.6 bytes), so this workspace needs roughly 3.6M facts for one full Rust scan.

## Decision Log

- Decision: fix the sequential path with a second-chance retry pass rather than reordering branch execution by estimated volume.
  Rationale: reordering needs a per-branch volume estimator (language and glob filters against the file inventory) that is workspace-shape-dependent and wrong exactly when languages share files or globs cut across languages; and it still starves when *two* branches are large. The retry pass needs no estimate, handles any skew, is strictly after-the-fact deterministic (retry limits depend only on all other branches' final actuals), and the ledger makes the re-execution resume-cheap. First-pass semantics for non-starved branches are byte-identical to today.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: retry at most once per branch, only for children that ended `truncated && !cancelled` under first-pass limits strictly below what the retry pass can offer, in declared branch order.
  Rationale: one pass is enough - after it, every branch has seen the true leftovers, so a second retry cannot offer more; the strict-increase condition guarantees termination and skips branches that truncated against the *parent* limits (a genuine global exhaustion, rescanning cannot help).
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: a retried branch's first-pass rows and diagnostics are discarded wholesale and replaced by the retry's.
  Rationale: the first attempt's rows are a prefix of the retry's deterministic re-derivation (same seed order, cached facts); keeping both would duplicate rows, and keeping the first `execution_budget_exhausted` diagnostic would report an exhaustion that no longer describes the run.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: apply the retry to all three sequential set operators, not only union.
  Rationale: `intersect`/`except` consume the same waterfall; a truncated branch poisons their results identically. One retry helper, three set operators' worth of correctness.
  Date/Author: 2026-08-07, session with dbakereffendi.
- Decision: scale the policy budget's scan lanes (`max_scanned_files`, `max_scanned_source_bytes`, `max_fact_nodes`) with the workspace's total analyzed source volume - the maximum of the fixed default and a density-derived value with headroom (see Milestone 3), capped by the existing hard caps. Keep `max_pipeline_rows` fixed. Interactive `query_code` keeps its fixed budget.
  Rationale: a policy subject scan is Theta(workspace facts) *by design*; a fixed scan budget makes the gate's correctness depend on repository size - the same conflation of work-bound and correctness that #1642 removed for row budgets. The scan lanes bound cost, and cost legitimately scales with the workspace being audited; the row lanes bound per-query memory and stay fixed. Latency for interactive queries is the product contract (#1452), and the gate is batch.
  Date/Author: 2026-08-07, session with dbakereffendi.

## Outcomes & Retrospective

To be written as milestones complete.

## Context and Orientation

All paths repository-relative. The work spans two crates: `brokk-bifrost-analysis` (query execution) and `brokk-bifrost-policy` (budgets).

- `crates/bifrost-analysis/src/analyzer/structural/search/execution.rs` - `execute_plan`'s sequential set-op arm (search for `SequentialUnion`): iterates `dependencies` (the branch subplans), computes per-branch limits with `fair_branch_limits`, executes each with the shared `state` (one cumulative `state.budget`, one `SeedScanLedger`), prefixes each branch's rows and diagnostics with the branch index (`prefix_branch_rows`, `prefix_branch_diagnostics`), and combines with `combine_set_rows`. This is where the retry pass goes.
- `crates/bifrost-analysis/src/analyzer/structural/search/pipeline.rs:420` - `fair_branch_limits(budget, parent, remaining_branches)`: per-lane cap = `current + (max - current)/remaining`. Unchanged by this plan; the retry simply calls it again after the first pass, when `remaining` counts only the branches being retried. Note `fair_cap` adds the share to *current* usage, so "what limits did this branch run under" must be captured at execution time, not recomputed later.
- `crates/bifrost-analysis/src/analyzer/structural/search/mod.rs` - `FairSeedBudgetCoordinator` (the parallel 2-branch experiment, Milestone 2's parity target) and the `SeedScanLedger` whose once-per-file charging makes retries resume-cheap.
- `crates/bifrost-policy/src/budget.rs` - `PolicyBudget`, its fixed lane constants and hard caps; Milestone 3 adds the scaled constructor.
- Policy entrypoints that construct the budget: the CLI policy runner and the MCP `run_policy` service (find with `PolicyBudget::default()` call sites under `crates/bifrost-mcp` and the facade binary).

Terms. A "seed scan" walks candidate files, extracts normalized structural facts per file, and matches the branch's pattern; its cost is metered per file against four budget lanes (scanned files, scanned source bytes, fact nodes, pipeline rows). "Truncated" on a child execution means the branch stopped early because a lane hit its limit. The "waterfall" is `fair_branch_limits`' forward-only redistribution described above.

## Plan of Work

Milestone 1 - the retry pass. In the sequential set-op arm of `execute_plan`: record, for each branch, its first-pass limits, its diagnostic span, whether it truncated, and its rows (already collected in `branch_rows`). After the first pass over all branches (unchanged semantics), if no child was cancelled and at least one child is `truncated`, run a retry pass: for the truncated branches in declared order, recompute `fair_branch_limits(&state.budget, limits, remaining_retry_count)`; if the recomputed limits are not strictly larger than that branch's first-pass limits in at least one lane, keep the first attempt (it truncated against a bound retrying cannot lift). Otherwise re-execute the branch subplan with the shared state, replace that branch's rows, drop its first-pass diagnostics, append the retry's (branch-prefixed), and recompute the set op's `truncated` flag from the surviving children. Beware index-shift bugs when removing diagnostic spans - rebuild the vector once from retained spans rather than removing ranges in place. Cancellation during retry behaves exactly like cancellation during the first pass. Behavior tests live wherever the sequential set-op execution is already tested (find existing union execution tests in bifrost-analysis; follow their harness), covering: the skewed two-language workspace that truncates before and completes after (rows identical to the per-branch queries' union), and the genuine-exhaustion case that still truncates without looping.

Milestone 2 - parallel parity. Decide: mirror the retry semantics in `execute_parallel_seed_union` (rejected branches re-run sequentially against final leftovers after all leases finish), or defer with a recorded rationale (production `Auto` never selects the parallel path; it is a gated 2-branch experiment with a recorded no-crossover A/B). Either way, record the decision here and on #1766 so sequential/parallel semantics divergence is visible.

Milestone 3 - workspace-scaled policy budgets. First file the follow-up issue (per repository policy) recording the single-branch measurement above, the density estimate, and the proposed scaling; link it here once it exists. Then, in `crates/bifrost-policy/src/budget.rs`, add a constructor that scales the three scan lanes from the workspace's total analyzed source bytes and file count (max of fixed default and density-derived value with ~2x headroom; clamped to the hard caps), with unit tests for the formula, the clamp, and the small-workspace identity (a workspace below the fixed defaults changes nothing). Thread it through the CLI policy runner and MCP `run_policy` where the budget is constructed, summing analyzed-file sizes from the workspace snapshot already in hand.

Milestone 4 - measurement. Rebuild release; re-run the #1766 reproducers: the union selector via `--query-file` (expect: no `execution_budget_exhausted`), and the full pack + candidate rule gate (expect: every run `complete`, exit reflecting findings only). Record numbers here; comment on #1766 and #1598.

## Concrete Steps

Work from the repository root on branch `dave/issue-1766-union-branch-retry` (stacked on `dave/stale-issue-check-9c5ce9`, PR #1767).

    cargo test -p brokk-bifrost-analysis
    cargo test -p brokk-bifrost-policy
    cargo test --test suite_bench_policy
    cargo fmt
    cargo clippy --workspace --all-targets -- -D warnings
    cargo build --release --bin bifrost
    ./target/release/bifrost --policy-pack bifrost.code-smells --policy-file tests/fixtures/policies/loop-invariant-receiver.rqlp --evaluation-date 2026-08-07 --fail-on warning --format json --output <scratchpad>/gate2.json

## Validation and Acceptance

(1) A new behavior test builds a two-language workspace with ~all volume in the first-listed union branch and a budget sized so the first branch's 1/branch_count share truncates but the whole-workspace scan fits the total: before the retry pass the query is truncated with `execution_budget_exhausted`; after, it is complete with rows identical to the single-branch queries' union. (2) A second test proves the no-lift case: a budget the whole scan genuinely exceeds still truncates (retry does not loop or inflate). (3) Policy budget scaling has unit tests for formula, clamp, and identity. (4) On this repository, the release gate concludes every pack rule and the candidate rule; the union reproducer emits no `execution_budget_exhausted`. (5) Full existing suites pass unchanged.

## Idempotence and Recovery

All steps re-runnable; the retry pass is additive inside one match arm, revert-safe by `git checkout` of the touched source files. The budget scaling is a pure function plus call-site changes. Release measurement writes only to the scratchpad.

## Artifacts and Notes

Reproducers and baseline numbers (2026-08-07, release, at `387cae65a`):

    union selector via --query-file:  execution_budget_exhausted after 174 files / 4.48MB / 403,158 facts (= ceil of 1/5 share)
    rust branch alone, full budget:   execution_budget_exhausted after 675 files / 21.27MB / 2,007,515 facts (repo: 1309 rs files / 37.6MB)
    gate (pack + candidate):          28.4s, exit 2; candidate + 5 naive rules inconclusive [partial_discovery]

Post-change numbers to be recorded by Milestone 4.

## Interfaces and Dependencies

No public API changes in bifrost-analysis: the retry is internal to `execute_plan`'s sequential set-op arm. In bifrost-policy, one new scaled-budget constructor (same visibility as `PolicyBudget::default`), used by the CLI policy runner and MCP `run_policy`. Tests use the existing harnesses only.

Revision note (2026-08-07): initial version.
