# Reuse C++ linkage classification across visibility roots

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` current while work proceeds.
Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The authoritative C++ inverse path currently builds one request-wide visibility
index, but still traverses and materializes overlapping include visibility for
every candidate root before any target query can start. On ESPHome's 1,000-file
reference differential this serial setup takes roughly 65–72 minutes, while
the following 1,000 target queries finish in about 20 seconds.

After this change, the root-independent linkage classification for each
declaration is reused across every root projection in the authoritative batch.
Root-specific visible-source filtering, include cycles, cancellation, exact
declaration identity, and authoritative candidate isolation remain unchanged.
Long authoritative visibility construction also reports explicit
start/completion progress instead of appearing hung.

## Progress

- [x] (2026-07-27) Reproduced the long post-forward interval on the clean
  persisted ESPHome top-ten replay and verified the process remains CPU-bound
  at niceness 10.
- [x] (2026-07-27) Compared three prior successful persisted runs: each was
  silent for 3,891–4,323 seconds before completing all 1,000 inverse targets in
  17–23 seconds.
- [x] (2026-07-27) Traced the silent path to
  `CppAuthoritativeUsageBatch::new` and `VisibilityIndex::build`, after the
  union include graph is shared but before inverse workers start.
- [x] (2026-07-27) Searched the full issue tracker. Closed #854 and #859 cover
  union adjacency hydration and cross-target batch sharing, but no issue owns
  the remaining per-root projection cost.
- [x] (2026-07-27) Created `FIRD:` issue #1215 assigned to `jbellis` before
  implementation.
- [x] (2026-07-27) Narrowed the regression to `b4419a37`: the correct
  anonymous-namespace filter resets a root-independent internal-linkage cache
  inside every root projection and can repeat an all-declarations peer scan
  hundreds of times.
- [x] (2026-07-27) Shared root-independent linkage classification across the batch while
  retaining the root-specific visible-source filter, and add behavior-focused
  reuse coverage.
- [x] (2026-07-27) Added observable start/completion progress around
  authoritative visibility construction, including root and target-group
  counts in CLI output.
- [x] (2026-07-27) Passed the once-per-batch work-count regression, engine and
  CLI progress-order regressions, and all 12 #1184 internal/external-linkage
  behavior tests outside the sandbox at niceness 10.
- [x] (2026-07-27) The unchanged old-binary persisted top-ten replay completed
  all ten clean envelopes in 1:45:23. Its ESPHome visibility barrier cleared
  at 5,743.2 seconds, 4,341.8 seconds after forward completion, then the 1,000
  target queries completed rapidly. This independently confirms the diagnosed
  pre-target bottleneck.
- [x] (2026-07-27) Benchmarked the same-limits persisted ESPHome production
  boundary on clean runner `dc8d2765`: the 477-root / 1,000-target visibility
  barrier fell from 4,341.8 seconds to 562.7 seconds (7.72x), total repository
  time fell from 5,770.7 seconds to 2,231.8 seconds, and the complete report
  remained byte-for-byte equivalent in summary counts with zero missing.
- [x] (2026-07-27) Merged origin/master at `18346d74` without overlap and
  passed formatting, diff checks, all-target/all-feature Clippy, and the complete
  `cargo test --features nlp,python` matrix before publication.

## Surprises & Discoveries

- Observation: the long gap precedes even `InverseTargetStarted`.
  Evidence: `compare_inverse` constructs `CppAuthoritativeUsageBatch` before
  entering the parallel target loop; the current and historical logs stop
  immediately after `ForwardResolution`.

- Observation: persisted analyzer startup is not the bottleneck.
  Evidence: the current ESPHome workspace completed in 18.4 seconds and
  forward resolution completed at 1,401.4 seconds. The subsequent silent
  visibility build accounts for the historical hour-long interval.

- Observation: more target workers cannot accelerate the current design.
  Evidence: visibility construction is serial and completes before
  `prepared.par_iter()` begins.

- Observation: exact visible-source-set interning is not the first fix.
  Evidence: `b4419a37` moved internal-linkage filtering into
  `build_visible_identifier_index` and placed its cache inside the per-root
  loop. The saved timing changes from a roughly one-second gap before that
  commit range to 65–72 minutes afterward.

- Observation: the unchanged production run reproduced the saved timing almost
  exactly.
  Evidence: forward completed at 1,401.4 seconds and inverse targets started at
  5,743.2 seconds, a 4,341.8-second barrier. The previous maximum was 4,322.8
  seconds.

- Observation: sharing the classification cache removes most, but not all, of
  the visibility cost.
  Evidence: the clean corrected runner completed the same 477-root visibility
  build in 562.7 seconds, then completed all 1,000 inverse queries in 17.3
  seconds. The remaining setup time is no longer multiplied by the root count
  and is separable from this issue's regression.

## Decision Log

- Decision: let the already-running authoritative replay finish unchanged.
  Rationale: a loaded binary cannot adopt source changes, the process is
  healthy, and the user explicitly asked not to cancel existing work.
  Date/Author: 2026-07-27 / Codex

- Decision: optimize exact projection reuse rather than lowering
  `max_files`, `max_targets`, or `max_usage_files`.
  Rationale: reducing those limits would make the campaign faster by weakening
  its evidence; issue #1215 is a product scaling defect in the symbols path.
  Date/Author: 2026-07-27 / Codex

- Decision: first hoist only the root-independent internal-linkage
  classification cache across the batch; leave visible declaration and
  identifier projections root-specific.
  Rationale: this directly removes the measured multiplier while preserving
  the root-specific source-visibility predicate. Broader projection interning
  is unnecessary unless production evidence still shows material setup cost.
  Date/Author: 2026-07-27 / Codex

- Decision: accept the narrow fix after the same-limits production replay
  demonstrated a 7.72x visibility speedup with identical semantic output.
  Track any further improvement to the now-exposed one-time classification
  cost separately rather than broadening this ticket after its measured root
  multiplier is removed.
  Date/Author: 2026-07-27 / Codex

## Outcomes & Retrospective

The fix changed no reference classifications on the same ESPHome commit and
run fingerprint: both old and new reports audited 1,000 files / 10,000 sites,
queried 1,000 targets, and produced 1,127 consistent, 80 editor-only, 153
unproven, 8,640 inconclusive, and zero missing classifications with no file or
candidate-limit errors.

The measured visibility interval fell from 4,341.8 seconds to 562.7 seconds,
removing 3,779.1 seconds (62.99 minutes) from the critical path. End-to-end
repository time fell from 5,770.7 seconds to 2,231.8 seconds despite the new
run sharing the machine with the all-feature Cargo gates. The explicit
visibility progress events make any remaining setup cost observable.

## Context and Orientation

`src/reference_differential/mod.rs::compare_inverse` prepares target groups,
unions their C++ candidate roots, and constructs one
`CppAuthoritativeUsageBatch`. `src/analyzer/usages/cpp_graph/shared.rs`
constructs that batch by calling
`src/analyzer/usages/cpp_graph/resolver.rs::VisibilityIndex::build`.

`build_visibility_data` already constructs one request-local `IncludeGraph` and
hydrates declarations once for every file in its union. It then calls
`collect_visible_declarations` independently for every root, retaining both
the visible declaration set and visited source set.
`build_visible_identifier_index` subsequently rebuilds a name index from every
root's visible declaration set. Exact visible-source-set equivalence is the
candidate reuse boundary; internal-linkage filtering must still be evaluated
with the consumer root identity where required.

## Plan of Work

First, move the `CodeUnit -> internal linkage` cache outside the per-root loop
in `build_visible_identifier_index`. Keep the decision to omit an
internal-linkage candidate inside the root loop because it depends on that
root's exact visible source set. Keep public and query-facing behavior
unchanged.

Second, add an inline multi-root C++ fixture with overlapping closures, a
file-local declaration, a cycle, and an unrelated root. Assert exact visible
resolution and candidate isolation. Add a test-only work counter that proves a
shared declaration's linkage is classified once for the entire batch, without
asserting registry-shaped implementation lists.

Third, extend reference-differential progress with start/completion or bounded
subphase events for C++ authoritative visibility setup. Preserve existing CLI
progress compatibility and add a production-routed test that observes the new
events.

Finally, run focused C++ usage and differential suites. Build the release
runner from normal repository Cargo storage outside the sandbox at niceness 10
and compare a bounded ESPHome replay against the recorded boundary. After
review, run formatting, `git diff --check`, all-target/all-feature Clippy with
warnings denied, and the complete feature-enabled test matrix at niceness 10.

## Validation and Acceptance

Acceptance requires exact shared-batch and independent-query results for roots
with overlapping but non-identical visibility, no cross-root internal-linkage
leakage, deterministic results under root insertion order, preserved
cancellation, and a counter proving equivalent projections are built once.

The runner must report that authoritative C++ visibility construction has
started before doing the expensive work and report completion/root counts
afterward. Existing progress events remain valid.

The bounded ESPHome production proof must materially reduce the pre-inverse
wall time without reducing files, sites, target groups, usage files, or
candidate limits. All Cargo and Bifrost commands run outside the sandbox at
niceness 10 with the normal repository target. The accepted proof reduced the
477-root / 1,000-target visibility interval from 4,341.8 to 562.7 seconds while
preserving the complete report summary.

## Idempotence and Recovery

The active replay uses an already-loaded release binary and is independent of
source edits. Do not cancel it. Source changes are ordinary reversible edits;
stage only files owned by this issue. Do not create a manual Cargo target under
`/tmp`. Keep raw benchmark output under
`/mnt/optane/tmp/bifrost-fird/` at unique paths.

## Artifacts and Notes

Live issue: <https://github.com/BrokkAi/bifrost/issues/1215>

Current authoritative log:
`/mnt/optane/tmp/bifrost-fird/cpp-task-top10-003a2be4.log`.

The historical post-forward gaps were approximately 3,890.8, 4,056.9, and
4,322.8 seconds. These are the production boundary the optimization must
improve.

Accepted production artifact:
`/mnt/optane/tmp/bifrost-fird/cpp-esphome-issue1215-dc8d2765.jsonl`,
SHA-256
`0b26b435937a2d5ac3c2a0c29a7242d642d3be0f45afa2899563ef78ba055210`.
