# Stop the watcher's .git event feedback loop

This ExecPlan is a living document maintained per `.agents/PLANS.md`. Sections `Progress`,
`Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current.

STATUS: APPROVED, IMPLEMENTING (Milestone 1). Milestone 2 stays behind its own approval gate.

## Purpose / Big Picture

Bifrost's file watcher feeds a feedback loop that turns any watched session on a git workspace
into a permanent whole-tree-walk generator. Measured at runtime (2026-08-08, investigation
checked in as `.agents/docs/` companion to issue #1848): one `echo >> file.rs` into an
otherwise idle watched server produced 50-56 whole-tree walks per second, sustained indefinitely
with no further stimulus; a single one-shot `bifrost --tool usage_graph` call produced 1,863
walks in 50 seconds, because the one-shot CLI installs the watcher too. Each walk shells out to
`git status`. On large trees this is the constant ~2.2 walks/second measured throughout the
kill-gate benchmarks, stealing I/O and CPU from every query.

The mechanism, confirmed end to end by an independent inotify observer and a counterfactual run:
`git status` creates and removes `.git/index.lock` on every invocation (3 inotify events);
`handle_event` invalidates the workspace listing for any non-`.bifrost/cache` path -- `.git` is
not exempt (`project_watcher.rs:121-128`); classification then calls `is_bifrostignored`, whose
first act is an unconditional `all_files()` (`project_watcher.rs:187` -> `project.rs:723-733`)
on the listing cache it just dropped -- a whole-tree walk plus another `git status`, which emits
the next `.git/index.lock` events. A linked worktree whose gitdir lives outside the root shows
2 events and no loop. The loop is metastable: idle servers stay quiet until the first
post-watcher listing, then loop forever.

Two secondary harms are part of this defect: `.git/index.lock` (deleted by classification time)
falls through to `PathDisposition::ProjectFile` and is drained into `snapshot.update()`, which
discards the `global_usage_definition_index` `OnceLock` -- so the loop also forces constant
rebuilds of the resident definition index (issue #1847; fixing this loop is sequenced BEFORE
that issue's plan so the remaining rebuild pain can be measured honestly). And pre-existing
`.git` files (`HEAD`, refs) classify as gitignored -> `RefreshFallback` -> `requires_full_refresh`
-> full re-analysis; that route is the ONE legitimate `.git` consumer (verified: nothing else in
`crates/` reads `.git/HEAD`, refs, or packed-refs, and no gitblob/generation code subscribes to
watcher events), pinned by two tests at `project_watcher.rs:587-640`.

After this change: `.git`-internal churn produces zero listing invalidations, zero walks, zero
classification work; HEAD/ref changes still trigger the full-refresh path exactly as the two
pinning tests demand. Observable outcome: the runtime reproduction (file touch into a watched
server on a git repo) shows the triggered walks for the touch itself and then silence.

## Progress

- [x] (2026-08-08) Runtime confirmation, mechanism chain, counterfactual, consumer census, and
  option analysis completed (investigation report; issue #1848).
- [x] (2026-08-08) Milestone 1: `.git`-internal event exemption in the watcher, with the loop
  reproduced in a test and pinned by a walk counter. Owner approved, implemented, validated.
- [ ] Milestone 2 (evidence-gated, separate approval): path-rule classification that does not
  materialize the listing.

## Surprises & Discoveries

- Observation: the loop's rate is walk-duration-bound (18.5 ms/walk on the probe repo -> 54/s;
  the rustc tree's slower walk -> the 2.2/s seen in benchmarks). Debounce therefore cannot break
  the loop, only set its frequency: `notify` already coalesces 3 events to 1 walk and the system
  still loops. Recorded so nobody re-proposes debounce.
- Observation: the unconditional `all_files()` is in `is_bifrostignored`, not `is_gitignored` as
  issue #1848's initial text guessed; the issue was corrected by the investigation.
- (2026-08-08, Milestone 1) The loop reproduces on a **two-file** repository, and faster than on
  the investigation's clone: one external `git status` into a watched two-file temp repo produced
  **156 whole-workspace walks in 500 ms** and was still climbing when the assertion read the
  counter (`git_bookkeeping_in_a_watched_repository_never_walks_the_workspace`, run against HEAD
  in a scratch worktree). Walk-bound as predicted -- the smaller the tree, the faster the loop.
- (2026-08-08, Milestone 1) The loop also *fights the user's own git*. The first fail-before run
  drove `git status` and then `git add -A`; the `git add` aborted with "Unable to create
  `.git/index.lock`: File exists", because the watcher thread was inside its own `git status` at
  that moment. So the defect is not only wasted I/O: a watched session can make ordinary git
  commands fail. Not previously recorded anywhere.
- (2026-08-08, Milestone 1) The two existing `.git/HEAD` tests pass unchanged, but note what they
  do *not* pin: neither asserts a listing invalidation, so the new "ref state skips the listing"
  behavior is invisible to them. The new `git_ref_state_events_refresh_the_workspace_without_walking_it`
  is what holds that half.

## Decision Log

- Decision: exempt `.git` internals at the watcher (Option 1) as Milestone 1; treat path-rule
  classification (Option 2) as a separately-approved Milestone 2.
  Rationale: Option 1's sufficiency is proven by the counterfactual run (gitdir outside root =
  no loop) and it is the smallest diff on an existing exemption hook. Option 2 removes the
  residual walk-per-legitimate-event by replacing listing-membership tests with path-only ignore
  rules, but that is a real semantic change (index+status membership differs from gitignore
  rules for tracked-but-ignored files) needing its own equivalence pin -- bigger blast radius,
  independent value, separate review.
  Date/Author: 2026-08-08 / Fable.
- Decision: the exemption set is "all of `.git/**` never invalidates the listing and never
  classifies as a project file", with a whitelist (`HEAD`, `refs/**`, `packed-refs`,
  `MERGE_HEAD`, `ORIG_HEAD`) routed ONLY to the `requires_full_refresh` decision.
  Rationale: the consumer census found exactly one legitimate `.git` consumer (full-refresh on
  HEAD movement), pinned by two tests. `index`/`index.lock` are pure churn. The walker already
  refuses to descend `.git` with the comment "VCS internals, never source" (`project.rs:992-999`),
  so the project-file universe cannot contain `.git` paths by construction -- the watcher
  claiming otherwise is the inconsistency.
  Date/Author: 2026-08-08 / Fable.
- Decision: the `.git` boundary is *any* directory component named `.git`, not only
  `<root>/.git`. Rationale: match the workspace walk exactly. `collect_workspace_files`'s
  `filter_entry` refuses to descend every entry named `.git` at any depth, so a vendored
  sub-repository's internals are already outside the project-file universe; a watcher rule that
  exempted only the root repository would keep classifying paths that can never be listed. A
  nested `HEAD` therefore also reaches the full-refresh decision, which is what the pre-change
  code did for it (via `RefreshFallback`). Comparison is per path component, so `.github` is
  untouched -- pinned by
  `nested_repository_internals_follow_the_same_boundary_as_the_workspace_walk`.
  Date/Author: 2026-08-08 / Opus (Milestone 1).
- Decision: the bare `.git` entry itself (the directory, or the file in a linked worktree) is
  churn, not ref state. Rationale: a repository appearing or disappearing also creates or removes
  its `HEAD`, which *is* ref state, so the parent-entry event carries nothing of its own; routing
  it to ref state would instead risk a full refresh on every backend that reports a parent-
  directory modification alongside `index.lock` churn -- which is the loop again, one level up.
  Date/Author: 2026-08-08 / Opus (Milestone 1).
- Decision: keep the plan's "ref state skips listing invalidation", considered and confirmed.
  Rationale: the concern is a `requires_full_refresh` that then re-analyzes against a stale
  cached listing. It cannot bite: the listing's membership can only differ if working-tree files
  differ, and those files produce their own (non-`.git`) events, which do invalidate. Invalidating
  on ref state would also have been safe (nothing writes `HEAD` during a listing, so it cannot
  loop), so this is a cost decision, not a correctness one, and it is revisitable in isolation.
  Date/Author: 2026-08-08 / Opus (Milestone 1).

## Outcomes & Retrospective

Milestone 1 landed 2026-08-08 (`.git` split in `handle_event`,
`crates/bifrost-mcp/src/project_watcher.rs`).

What the change is: `handle_event` partitions the event batch through
`git_internal_disposition` before the listing invalidation. `GitInternalPath::Churn` paths are
dropped outright; `GitInternalPath::RefState` paths (`GIT_REF_STATE_FILE_NAMES` = `HEAD`,
`packed-refs`, `MERGE_HEAD`, `ORIG_HEAD`, plus everything under `refs/`) mark
`requires_full_refresh` on the same event kinds as before and are then dropped. The surviving
paths take the pre-change route unchanged. The refresh-kind test both sites share is now
`triggers_refresh_fallback`.

Evidence, fail-before measured at HEAD in a scratch worktree carrying only the new tests
(`git worktree add`, never a stash -- a second agent held uncommitted work in this checkout):
5 of the 6 new tests failed, and the sixth (`source_events_still_invalidate_the_listing_and_classify`)
passed before and after, which is exactly its job. The live loop test read 156 walks in 500 ms
before, 0 after. The service-level #1847 pin failed with "Git bookkeeping must not replace the
session snapshot" before, passes after.

Residual, unchanged by this milestone and the subject of Milestone 2: a *legitimate* single-file
event still costs one whole-tree walk plus one `git status` on the watcher thread, because
`classify_project_path` still answers "is this ignored" by materializing the listing. What is
gone is the feedback: that walk's `git status` no longer produces the next event.

Not measured here: the resident-index rebuild rate in a real session now that the loop no longer
drives `snapshot.update`. That is the #1847 plan's baseline, and taking it was the reason for
sequencing this milestone first.

## Context and Orientation

The watcher lives in `crates/bifrost-mcp/src/project_watcher.rs` (verify path with
`rg -l handle_event crates/`). `handle_event` receives batched `notify` events, currently
exempts only `EventKind::Access` and `<root>/.bifrost/cache/**`, invalidates the
`WorkspaceFileListingCache` for anything else, and classifies each path via
`classify_project_path` -> `is_bifrostignored` (unconditional `all_files()`) then `is_gitignored`.
Dispositions: `ProjectFile` paths drain into `snapshot.update(&changed_files)`;
gitignored-but-relevant paths can return `RefreshFallback`, and `requires_full_refresh`
(`searchtools_service.rs:3115-3125`) decides whole-workspace re-analysis -- `.git/HEAD` movement
must keep reaching it (tests at `project_watcher.rs:587-640` encode this).

## Plan of Work

### Milestone 1: the exemption

In `handle_event`, before listing invalidation: paths under `<root>/.git/` are split by the
whitelist. Non-whitelisted `.git` paths (notably `index`, `index.lock`, and lock/tmp churn) are
dropped entirely -- no listing invalidation, no classification, no snapshot update. Whitelisted
paths (`HEAD`, `refs/**`, `packed-refs`, `MERGE_HEAD`, `ORIG_HEAD`) skip listing invalidation
and project-file classification but still feed the full-refresh decision exactly as today.
Root-relative containment must be correct for nested-repo layouts: only the workspace's own
`.git` is exempt; a vendored sub-repository's `.git` inside the tree follows the same rule
relative to itself only if the walker also skips it (it does; match that boundary).

As built (2026-08-08): the split is `git_internal_disposition(project, path)` in
`project_watcher.rs`, called from `handle_event` before the listing invalidation. It strips the
project root, finds the first path component named `.git` (the walker's boundary, so nested
repositories are covered), and reads the remainder: `refs` and the four names in
`GIT_REF_STATE_FILE_NAMES` are `RefState`, the bare `.git` entry and everything else are `Churn`.
`RefState` marks `requires_full_refresh` through the shared `triggers_refresh_fallback` kind test
that the existing `RefreshFallback` route also uses, so the refresh semantics are literally the
same predicate. Paths outside the root are not `.git`-internal and keep feeding the refresh
fallback, as before.

Tests, fail-before mandatory:
1. Loop reproduction: a watched service on a temp git repo; drive `git status` (or synthesize
   the three `index.lock` events); assert via the existing `workspace_file_listing_count` that
   zero additional walks occur. Before the fix this test measurably loops (bound the assertion
   window; the investigation's reproduction gives the shape).
2. The two existing `.git/HEAD` full-refresh tests pass unchanged.
3. A source-file event still invalidates and classifies (non-regression).
4. `.git/index.lock` no longer reaches `snapshot.update` (pin: the definition-index `OnceLock`
   survives a `git status` in a watched session -- this is the #1847 coupling made testable).

As built (2026-08-08), in `project_watcher.rs` unless noted:
1. `git_bookkeeping_in_a_watched_repository_never_walks_the_workspace` -- a real
   `ProjectChangeWatcher` over a real two-file repository, driven only by `git status` and
   `git add -A`; asserts zero walks and an empty `ChangeDelta`. Fail-before: 156 walks in 500 ms.
2. Unchanged, plus `git_ref_state_events_refresh_the_workspace_without_walking_it` for the half
   they do not cover (`HEAD`, `ORIG_HEAD`, `MERGE_HEAD`, `packed-refs`, `refs/heads/main`:
   refresh, no walk, no project file) and `git_churn_events_neither_walk_the_workspace_nor_update_the_project`
   for `index`, `index.lock`, an object, a reflog, and the bare `.git` entry.
3. `source_events_still_invalidate_the_listing_and_classify` -- the only new test that passes
   before the change, which is what makes it the non-regression pin. Boundary non-regression
   (`.github`, nested repositories) is in
   `nested_repository_internals_follow_the_same_boundary_as_the_workspace_walk`.
4. `git_bookkeeping_in_a_watched_session_keeps_the_definition_index`
   (`searchtools_service.rs`, `watcher_startup_tests`): warms the index in a watched session,
   drives Git bookkeeping, then asserts the session snapshot is the same `Arc` and the index was
   not rebuilt. Snapshot identity is the observable form of "the `OnceLock` survived": `update`
   allocates a fresh one, a query's `clone` shares it.

### Milestone 2 (separate approval): classify without the listing

Replace the listing-membership tests in `is_bifrostignored`/`is_gitignored` with path-only rule
evaluation so a legitimate single-file event costs rule matching, not a whole-tree walk. Needs
an equivalence pin over tracked-but-ignored and untracked-but-not-ignored shapes, and a decision
about listing invalidation granularity. Not scoped further here; approval gate after Milestone 1
lands and its residual cost is measured.

## Validation and Acceptance

Standard ladder (fmt; check -p brokk-bifrost-mcp -p brokk-bifrost-core; nextest -p both;
workspace watcher/service selections; featureless clippy --workspace --all-targets -- -D
warnings). Documented pre-existing failures per the existing plans; stash-verify new ones.
Acceptance is behavioral: the loop-reproduction test fails before and passes after; the HEAD
whitelist tests hold; the #1847-coupling pin holds.

Milestone 1 results (2026-08-08): `cargo fmt`; `cargo check -p brokk-bifrost-mcp
-p brokk-bifrost-core --all-targets` clean; `cargo nextest run -p brokk-bifrost-mcp` 165 tests,
164 pass, the one failure being `bifrost_searchtools_server_speaks_mcp_stdio`, verified failing
at HEAD in the scratch worktree too; the workspace selection
`-E 'test(/watcher|project_watcher|searchtools_service/)'` 261 tests, 260 pass, the one failure
being `manual_service_sees_change_after_explicit_update_paths` (which this plan recorded as
"documented"; it was in fact a regression, fixed on 2026-08-08 by stat-validating the memoized
working-tree scan in `Liveness::oids_for_files` -- see `.agents/plans/rust-usage-index-v2.md`
Surprises -- and this selection is now expected to be fully green);
`cargo clippy -p brokk-bifrost-mcp -p brokk-bifrost-core --all-targets -- -D warnings` clean.
The full `--workspace` clippy could not be scored for this change: a concurrent unrelated change
to `brokk-bifrost-analysis` was uncommitted in the same checkout and failed four lints of its own
(`usages/rust_graph.rs` doc lints); nothing in `bifrost-mcp` or `bifrost-core` was reported.
Re-run the full gate once that work lands. Verification used `git worktree add` at HEAD, never
`git stash`, because a stash would have swept that concurrent work.

## Idempotence and Recovery

Milestone 1 is one focused change plus tests; revert by commit. No schema, no cache, no
persisted state. The runtime reproduction harness stays in the investigation artifacts, not in
the tree.

## Artifacts and Notes

Investigation: `.agents/docs/fenced-followups-investigation-2026-08.md` (checked in with the
plans) and the session's `followup-evidence/` (inotify event log, counterfactual). Issue #1848
carries the summary. Rate arithmetic: 156 events/s / 3 per status = 52 walks/s observed; 2,611
of 2,613 events were `.git/index.lock`. Milestone 1's own reproduction lives in the tree as a
test, so it needs no external harness.

## Interfaces and Dependencies

No new types expected; the change extends the existing exemption logic in `handle_event` and the
disposition routing. The whitelist is one constant list next to it. Sequencing: this plan lands
BEFORE the #1847 retirement plan so that plan's baseline measurements exclude loop-driven
rebuilds.

As built (2026-08-08): one private enum (`GitInternalPath`), one private function
(`git_internal_disposition`), one extracted predicate (`triggers_refresh_fallback`), and three
constants, all in `project_watcher.rs`. No public API and no cross-crate change. The exemption
did *not* extend `is_internal_state_rel_path` as Option 1 first sketched: that hook answers one
question ("analyzer-owned state, do not invalidate the listing") and `.git` needs two answers,
one of which still has to reach the full-refresh decision. A separate classifier keeps both
readable.

## Revision note

2026-08-08 (Opus, Milestone 1 implementation): status flipped to APPROVED, IMPLEMENTING and then
Milestone 1 checked off in `Progress`; added the as-built descriptions of the split and of the
six tests to `Plan of Work`; added three decisions (the `.git` boundary is any component named
`.git`, the bare `.git` entry is churn, and ref state keeps skipping listing invalidation --
confirmed rather than changed) to the `Decision Log`; added three findings to `Surprises &
Discoveries` (the loop is faster on small trees at 156 walks / 500 ms, it can make a user's own
`git add` fail on the lock, and the two pre-existing HEAD tests never pinned listing
invalidation); recorded results in `Validation and Acceptance` and wrote `Outcomes &
Retrospective`; corrected the investigation's filename in `Artifacts and Notes`, which named a
scratchpad file that was checked in under a different name. Reason: the plan must be restartable
from itself, and the boundary and bare-entry decisions were choices the plan text left open.
