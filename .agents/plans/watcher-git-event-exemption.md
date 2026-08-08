# Stop the watcher's .git event feedback loop

This ExecPlan is a living document maintained per `.agents/PLANS.md`. Sections `Progress`,
`Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current.

STATUS: PLAN FOR OWNER REVIEW. Do not implement until approved.

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
- [ ] Milestone 1: `.git`-internal event exemption in the watcher, with the loop reproduced in a
  test and pinned by a walk counter.
- [ ] Milestone 2 (evidence-gated, separate approval): path-rule classification that does not
  materialize the listing.

## Surprises & Discoveries

- Observation: the loop's rate is walk-duration-bound (18.5 ms/walk on the probe repo -> 54/s;
  the rustc tree's slower walk -> the 2.2/s seen in benchmarks). Debounce therefore cannot break
  the loop, only set its frequency: `notify` already coalesces 3 events to 1 walk and the system
  still loops. Recorded so nobody re-proposes debounce.
- Observation: the unconditional `all_files()` is in `is_bifrostignored`, not `is_gitignored` as
  issue #1848's initial text guessed; the issue was corrected by the investigation.

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

## Outcomes & Retrospective

(To be written at milestone completion.)

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

Tests, fail-before mandatory:
1. Loop reproduction: a watched service on a temp git repo; drive `git status` (or synthesize
   the three `index.lock` events); assert via the existing `workspace_file_listing_count` that
   zero additional walks occur. Before the fix this test measurably loops (bound the assertion
   window; the investigation's reproduction gives the shape).
2. The two existing `.git/HEAD` full-refresh tests pass unchanged.
3. A source-file event still invalidates and classifies (non-regression).
4. `.git/index.lock` no longer reaches `snapshot.update` (pin: the definition-index `OnceLock`
   survives a `git status` in a watched session -- this is the #1847 coupling made testable).

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

## Idempotence and Recovery

Milestone 1 is one focused change plus tests; revert by commit. No schema, no cache, no
persisted state. The runtime reproduction harness stays in the investigation artifacts, not in
the tree.

## Artifacts and Notes

Investigation: `fenced-followups-investigation-v1.md` (session scratchpad; check into
`.agents/docs/` with Milestone 1's first commit) and `followup-evidence/` (inotify event log,
counterfactual). Issue #1848 carries the summary. Rate arithmetic: 156 events/s / 3 per status
= 52 walks/s observed; 2,611 of 2,613 events were `.git/index.lock`.

## Interfaces and Dependencies

No new types expected; the change extends the existing exemption logic in `handle_event` and the
disposition routing. The whitelist is one constant list next to it. Sequencing: this plan lands
BEFORE the #1847 retirement plan so that plan's baseline measurements exclude loop-driven
rebuilds.
