# Share structural seed scan charges across union branches (issue #1246)

This plan makes release-bundled multi-language match policies complete on large mixed-language
repositories instead of reporting `execution_budget_exhausted`. After this change, a policy whose
RQL selector is a `union` of several language-bounded branches (the natural shape for "same smell,
different API per language" rules) charges the expensive part of its structural scan — reading a
file and materializing its normalized fact nodes — once per query execution instead of once per
union branch. Nothing about result rows, ordering, deduplication, cancellation, or the hard budget
caps changes; only the double-counting of identical per-file work disappears. The observable
outcome is that `target/debug/bifrost --root <bifrost-checkout> --policy-category performance
--fail-on never --format json` (with a fresh private `BIFROST_CACHE_DIR`) stops reporting
`execution_budget_exhausted` for the five policies listed in issue #1246 while every global policy
hard cap in `crates/bifrost-analysis/src/analyzer/policy/budget.rs` stays unchanged.

## Background a novice needs

Definitions used throughout:

- A *CodeQuery* is Bifrost's structural query IR (`crates/bifrost-analysis/src/analyzer/structural/query/ir.rs`).
  Both JSON and RQL parse into it. A query plan is a tree whose leaves are *seeds*
  (`CodeQuerySeed`: a root pattern plus optional containment patterns, a language filter, and file
  globs) and whose interior nodes are set operations (`union`, `intersect`, `except`) and typed
  pipeline steps.
- The *executor* lives in `crates/bifrost-analysis/src/analyzer/structural/search/mod.rs`. A seed
  executes in `execute_seed`: it lists candidate files per language provider, then for each file
  either uses *Indexed* access (a snapshot posting index supplies a small candidate fact set) or
  *Scan* access (the file's full normalized fact list is materialized and the matcher walks all of
  it). `SeedStructuralAccess` is the enum for those two modes.
- Work is metered by `CodeQueryExecutionBudget` accumulated in `QueryExecutionState::budget` with
  four "fair lanes": `scanned_files`, `scanned_source_bytes`, `fact_nodes` (plus
  `examined_references` in the same lane), and `pipeline_rows`. `CodeQueryExecutionLimits` caps
  each lane; for policies the caps come from `PolicyBudget` in
  `crates/bifrost-analysis/src/analyzer/policy/budget.rs` (`MAX_FACT_NODES = 2_000_000`,
  `MAX_SCANNED_SOURCE_BYTES = 128 MiB`, `MAX_SCANNED_FILES = 20_000`). Exceeding a cap pushes an
  `ExecutionBudgetExhausted` diagnostic, marks the seed truncated, and the policy reports
  inconclusive ("unreliable") completion.
- A `union` with N branches executes each branch with the shared `QueryExecutionState`
  (sequential strategy, `PhysicalQueryOperator::SequentialUnion`) or, for exactly two pure seed
  branches, concurrently (`ParallelUnion`) under a `FairSeedBudgetCoordinator` that admits budget
  deltas per branch under a mutex and merges committed budgets afterwards.
- Identical seeds are already deduplicated: `execute_seed` keys a per-execution
  `state.seed_cache` by `CodeQuerySeed::canonical_cache_key()` and replays cached rows without
  re-charging file or fact work (test
  `sequential_profile_replays_a_shared_seed_for_each_union_branch` in
  `crates/bifrost-analysis/src/analyzer/structural/search/tests.rs`).

The gap: branches that are *compatible but not identical* — same language and file scope,
different match predicates, e.g. the three `(language rust (inside-decl (loop) (call ...)))`
branches of `bifrost.performance.parsing-in-loop` in
`crates/bifrost-analysis/policy-packs/bifrost.code-smells/policies/parsing-in-loop.rqlp` — have
distinct cache keys, so each branch re-charges `scanned_files`, `scanned_source_bytes`, and (under
Scan access) the *entire fact count of every scoped file* even though the `FileFacts` for those
files were materialized once and served from the provider memory cache for every later branch
(`load_seed_facts` / `StructuralFactsCacheOutcome::MemoryHit`). On the Bifrost checkout itself the
Rust corpus is large enough that a handful of same-language branches exhausts the two-million
fact-node cap, which is exactly what issue #1246 reports for the five performance policies.

## Design

Introduce a per-query-execution *seed scan ledger* that records, per `(Language, ProjectFile)`
key, which per-file charges have already been admitted against this execution's budget:

- `scanned`: the file's `scanned_files` / `scanned_source_bytes` charge was admitted. Later seed
  scans that visit the same file skip that charge (the bytes were read and the source snapshot
  reused; re-charging meters the same bytes twice).
- `fully_charged`: the file's complete fact-node count was admitted by a Scan-access seed. Later
  Scan-access seeds over the same file skip the fact-node charge entirely (the extraction happened
  once; replaying cached facts through a different matcher predicate is the cheap part).

What deliberately keeps charging per branch, so accounting stays honest for genuinely distinct
work:

- Indexed-access charges (`candidate_facts` selected by posting terms, plus the verifier-walk
  overage) are branch-specific and stay as they are, in both directions: an Indexed branch never
  marks a file `fully_charged`, and a file already `fully_charged` by a Scan branch does not
  discount a later Indexed branch's candidate charges (they are small by construction).
- Files never visited by an earlier branch (different language or globs) pay full price.
- `pipeline_rows`, `examined_references`, semantic, typestate, value-flow, and taint accounting
  are untouched.

Placement:

- Sequential execution: a new field on `QueryExecutionState` (a small struct with two
  `HashSet<(Language, ProjectFile)>` members). Sequential union branches share the state, so the
  ledger naturally spans branches; it also spans sibling seeds anywhere in one query plan, which
  is sound for the same reason.
- Parallel union: the two branch states are disjoint by design, so the ledger must live on the
  `FairSeedBudgetCoordinator`, guarded by its existing mutex, and the check-admit-mark step must
  be atomic under that lock so two branches racing on the same file cannot both charge it. The
  committed total then matches the sequential strategy's total for the same query, preserving
  strategy parity for budgets. Per-branch attribution of a shared file's charge is
  first-comer-wins and therefore scheduling-dependent in the parallel strategy; totals, results,
  and truncation behavior remain deterministic.

Ordering discipline inside `execute_seed` (the only place the four charge sites exist): consult
the ledger, then admit the projected budget, then mark the ledger — never mark before a
successful admission, so a rejected admission leaves the ledger unmarked and a later branch still
pays for work that was never admitted.

Cache-completeness, truncation, diagnostics, and the seed result cache are unchanged; branches
that previously truncated mid-scan now simply get further before hitting caps, which is the
intended user-visible effect. Profile honesty: the existing
`seed_structural_facts` cache profile already distinguishes extractions from memory replays, and
`admitted_fact_nodes` in the access-path profile reports what was actually admitted; if a
reconciliation test demands it, add explicit `shared_*` counters rather than inflating admitted
work.

## Milestones

Milestone 1 — reproduction and regression fixture. Build the debug binary, run the performance
category against this checkout with a fresh `BIFROST_CACHE_DIR`, and capture the per-policy
`execution_budget_exhausted` diagnostics (their messages embed the cumulative
files/bytes/facts/references counters). Then write a source-backed unit regression in
`crates/bifrost-analysis/src/analyzer/structural/search/tests.rs`: a project with one file whose
fact count is known, `CodeQueryExecutionLimits` whose `max_fact_nodes` admits roughly one full
scan but not two, and a two-branch union with different Scan-access predicates. Before the fix the
execution reports `ExecutionBudgetExhausted` and truncates; this failing assertion is the
regression anchor.

Milestone 2 — sequential ledger. Add the ledger struct and `QueryExecutionState` field, thread it
through the four charge sites in `execute_seed`, and make the Milestone 1 regression pass. Add a
counter-test proving disjoint-file branches still accumulate full charges, and confirm
`sequential_profile_replays_a_shared_seed_for_each_union_branch` plus the profile reconciliation
assertions still hold.

Milestone 3 — parallel parity. Move the ledger behind a shared handle the
`FairSeedBudgetCoordinator` owns for parallel branches, implement the atomic
check-admit-mark path in the lease, and add a parity test: the same overlapping two-branch seed
union under tight limits executed with both union strategies yields identical rows, identical
final budget totals, and the same truncation/diagnostic outcome.

Milestone 4 — dogfood validation. Re-run the Milestone 1 reproduction command; all five policies
from issue #1246 must complete without `execution_budget_exhausted` and with unchanged global
caps. Run the focused featureless test suites for the touched crate, `cargo fmt`, and the
workspace clippy command from CLAUDE.md.

## Progress

- [x] (2026-08-03) Read the executor, budget, coordinator, planner, and policy-pack sources;
  confirmed identical-seed caching exists and the gap is compatible-but-distinct branches.
- [x] (2026-08-03) Reproduced on the Bifrost checkout: with a fresh private cache, the
  performance category run reproduces the issue only when auto structural index admission
  defers the first snapshot build (fresh session ScanOnly windows) or under `--structural-access scan`;
  see Surprises for measured counters.
- [x] (2026-08-03) Milestone 1 regression test:
  `sequential_union_charges_shared_scan_file_extraction_once` in
  `crates/bifrost-analysis/src/analyzer/structural/search/tests.rs` probes one file's Scan
  extraction cost, caps `max_fact_nodes` at twice-minus-one that cost, and asserts a two-branch
  kind-only union completes with exactly one extraction's worth of charged work.
- [x] (2026-08-03) Milestone 2 sequential ledger: `SeedScanLedger` on `QueryExecutionState`,
  threaded through the scanned-files/bytes and full-fact charge sites in `execute_seed`;
  `sequential_union_still_charges_distinct_files_fully` proves disjoint-file branches keep
  accumulating full charges.
- [x] (2026-08-03) Milestone 3 parallel parity: the ledger lives in `FairSeedBudgetState` behind
  the coordinator mutex; `FairSeedBudgetLease::admit_shared` does atomic check-admit-mark per
  `SeedChargeLane`; `parallel_seed_union_matches_serial_shared_scan_charges` asserts equal
  results, work, and completion across both strategies under the tight cap.
- [x] (2026-08-03) Milestone 4 dogfood + gates. Fail-before verification: with only
  `search/mod.rs` reverted, `sequential_union_charges_shared_scan_file_extraction_once` and
  `parallel_seed_union_matches_serial_shared_scan_charges` fail with
  `ExecutionBudgetExhausted` on branch `[1]` ("scanning 2 files, 100 bytes, 8 facts") while the
  distinct-files honesty test passes both before and after. Gates: full crate unit suite 2040
  passed, featureless `cargo clippy --workspace --all-targets -- -D warnings` clean. Dogfood
  no-regression: fresh-cache performance-category runs with the pre- and post-change binaries
  both report all ten policies `complete` with identical finding counts (file-read 27, network 1,
  parsing 47, regex-compile 4, serialization 11, sleep 31, sort 161, subprocess/database/nested 0)
  and zero diagnostics; global policy caps untouched.

## Surprises & Discoveries

- (2026-08-03) The issue's CLI reproduction no longer reproduces on master. A fresh-cache run of
  `BIFROST_CACHE_DIR=<fresh> target/debug/bifrost --root <this-checkout> --policy-category
  performance --evaluation-date 2026-08-03 --fail-on never --format json` reports all ten
  performance policies `complete` (sort-in-loop: 161 findings) with zero diagnostics. Commit
  `002968fd9` (PR #1461, merged 2026-08-02, "Fixes #1398") removed the four causes that pushed
  these policies onto repeated full scans: a bigger structural index cache share, `EagerAuto`
  access for policy batches, candidate-count (not full-file) charging for indexed files, and
  posting terms for anchored `name/regex` alternations. That PR states "Scan charging is
  unchanged", and #1246 stayed open: the union-branch replay this plan addresses still exists
  whenever Scan access serves a seed — index construction over budget, providers without a
  snapshot index cache, selectors with no sound posting terms (kind-only patterns, opaque
  regexes), or `scan_only` benchmark mode. Validation therefore anchors on the source-backed
  unit regression (acceptance criterion one) rather than the CLI dogfood, and the dogfood run is
  kept as a no-regression check.

## Decision Log

- Decision (2026-08-03): Share charges at per-file granularity keyed by `(Language, ProjectFile)`
  rather than trying to prove whole-seed compatibility. Rationale: partial overlaps (differing
  globs) are handled for free, the soundness argument is local to one file, and no new notion of
  "compatible seed" needs a definition or a cache key.
- Decision (2026-08-03): Do not discount Indexed-access candidate charges against a prior full
  Scan charge, and do not let Indexed branches mark files fully charged. Rationale: candidate
  charges are small and branch-specific; keeping them per-branch keeps accounting honest for
  genuinely distinct scans, which the issue explicitly requires.
- Decision (2026-08-03): Automatic factoring only; do not add the alternative RQL sharing form
  from the issue. Rationale: the issue prefers automatic factoring, and a new surface form would
  require schema registry, grammar, and documentation work with no additional power.

## Outcomes & Retrospective

- (2026-08-03) Implemented and validated in one session. What was achieved: a per-execution
  `SeedScanLedger` shares per-file scanned-bytes and Scan-access full-fact charges across
  compatible seed scans, sequentially on `QueryExecutionState` and for parallel unions
  atomically inside `FairSeedBudgetState` via `FairSeedBudgetLease::admit_shared`; three
  behavior-focused tests pin the sharing, the honesty for disjoint files, and
  sequential/parallel parity for results, work, and completion. What changed relative to the
  plan as filed: the issue's CLI acceptance run already passed on master because PR #1461 fixed
  the indexed path, so validation anchored on the source-backed regressions and the dogfood
  became a no-regression check (identical findings, zero diagnostics, unchanged caps). One
  accounting semantics change worth knowing: `admitted_fact_nodes` in the access-path profile
  is now recorded only for admitted charges; a rejected final file no longer inflates it. No
  test depended on the old semantics. Lesson: dated issues in this repo can be half-fixed by
  adjacent work within days; re-reproduce before implementing, but check whether the underlying
  mechanism the issue names is still unaddressed (here Scan-access replay was, exactly as the
  issue's "Desired behavior" described).
