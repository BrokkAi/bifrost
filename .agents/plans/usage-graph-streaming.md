# Make the Rust usage-graph phase answer per site and stream its results

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

The rules for this document are in `.agents/PLANS.md` from the repository root. Maintain this
document in accordance with that file.

The approved design this plan executes is `.agents/docs/usage-graph-streaming-design-2026-08.md`
(components D1 through D4). The read-only investigation behind it, with every file and line the
design cites, is `.agents/docs/graph-phase-investigation-2026-08.md`. This plan repeats every fact
it depends on, so a reader who has only this file can still do the work.

## Purpose / Big Picture

Today, asking Bifrost "where is this Rust symbol used?" in a large workspace can take many minutes
and tens of gigabytes of memory. On the `rustc` source tree a single `scan_usages` call spent
1,034 seconds in the usage-graph phase and peaked at 23.4 GB of resident memory. Almost all of that
time is one function: `RustAnalyzer::build_reference_context`, which ran 1,115 times for 1,062
seconds of thread time.

That function builds a per-file "reference context": a bundle of hash maps that say what every name
written in that file could mean. It is built for every candidate file before the file is scanned,
and it is only ever *read* when the fast, fact-backed prover cannot answer a site. In other words,
Bifrost precomputes the answer to every question a file could ask, and then asks almost none of
them.

After this change, a Rust usage query answers each unresolved site as a separate small question,
using data the analyzer already stores. The user-visible outcome is that `scan_usages` on a large
Rust workspace returns in a time proportional to the number of genuinely unresolved sites, rather
than to the number of candidate files, and that its memory does not grow with the size of the
imported export surface. A second user-visible outcome is that the 1,000-callsite cap stops work
instead of merely trimming the answer, so a query on a very common symbol returns promptly.

You can see it working two ways. First, the new counter pins in the test suite prove that a scan
which used to canonicalize every exported name of every namespace-imported module now canonicalizes
only the handful of names actually written at unresolved sites, and that a scan which hits the
callsite cap stops opening candidate files. Second, on a large tree such as `rustc`, the
`usages::graph_find_usages` profiling span shrinks from ~1,034 s to seconds. The large-tree
measurement is a separate task run after review; it is not part of this plan's acceptance.

## Progress

- [x] (2026-08-08 12:00Z) Read the approved design, the investigation, and the code it cites.
- [x] (2026-08-08 12:40Z) Wrote this ExecPlan; set the design document's status to
      `APPROVED, IMPLEMENTING`.
- [ ] Milestone 1: freeze the current closure-based resolution under `#[cfg(test)]` and add the
      equivalence fixture.
- [ ] Milestone 2: add the three counters and their pins, observed failing before the rewrite.
- [ ] Milestone 3 (D1 + D3): replace `RustReferenceContext` with a lazy per-site resolver; delete
      the eager builders, the two analyzer caches, and the mis-weighing weigher.
- [ ] Milestone 4 (D2): check the callsite cap before dispatching each candidate; bound
      `sample_hits`.
- [ ] Milestone 5: full multi-language parity run and featureless clippy.

## Surprises & Discoveries

- Observation: the forward reference context is built *during a scan*, not only by
  `get_definition`. `resolver.rs::lexical_import_fqn` calls
  `support.forward_reference_context(rust, file)` and is reached from macro token-tree resolution
  inside the scan. This is why the investigation counted n=1,115 context builds against a
  1,000-file candidate cap: forward and reverse contexts are both built per file.
  Evidence: `crates/bifrost-analysis/src/analyzer/usages/rust_graph/resolver.rs:422-437`, reached
  from `resolve_token_path_segment_fqn` (`:349-420`) and `hits.rs:236`.

- Observation: `local_impl_target_importer_files`
  (`crates/bifrost-analysis/src/analyzer/usages/rust_graph/resolver.rs:1256-1275`) calls
  `rust.reference_context_of(file)` for *every analyzed file in the workspace*, before the scan and
  with no cancellation. It is called from `RustQueryResolver::find_usages` whenever the graph seed
  is a local declaration. This is a third eager whole-workspace context build that the
  investigation did not name, and it disappears with the same change.

## Decision Log

- Decision: keep the public type name `RustReferenceContext` and its four resolution methods
  (`resolve_bare`, `resolve_scoped`, `resolve_scoped_owner`, `bare_names_resolving_to`), and change
  the type from an eagerly filled bundle of maps into a lazy per-file resolver that borrows the
  analyzer and answers one name at a time.
  Rationale: the design's D1 says to delete the eager builders and the `scoped`/`glob` closure maps.
  Those maps have about forty read sites spread across `get_definition/rust.rs`,
  `rust_graph/resolver.rs`, `rust_graph/inverted.rs`, `rust_graph/extractor.rs`, and
  `rust/diagnostics.rs`. Deleting the fields outright would delete resolution capability from
  `get_definition`, which the design does not authorize. Making the same questions lazy deletes the
  precomputation, which is the actual defect, while every consumer keeps working and the frozen
  equivalence pin (D4) can compare old answers against new ones name by name.
  Date/Author: 2026-08-08, Opus.

- Decision: delete the two analyzer-level caches `reference_contexts` and
  `forward_reference_contexts`, and with them `weight_reference_context`.
  Rationale: a lazy resolver borrows `&RustAnalyzer`, so it cannot be stored in a cache owned by
  that same analyzer. This is also exactly what D3 asks for: the weigher omitted the two unbounded
  maps (`crates/bifrost-analysis/src/analyzer/rust/cache.rs:9-23`), so the caches believed they were
  32 MiB each while holding gigabytes. Removing the maps and the caches makes the weight defect
  moot by removal rather than by correction.
  Date/Author: 2026-08-08, Opus.

- Decision: `bare_names_resolving_to(target_fqn)` is answered by generating a candidate name set
  filtered on the target's terminal identifier and then resolving each candidate, rather than by
  materializing every binding in the file.
  Rationale: it is an inverse query ("which local names in this file bind this fqn"). Every binding
  that resolves to `target_fqn` ends at a declaration whose identifier is the last dotted segment of
  `target_fqn`, so a candidate whose imported name, module tail, exported name, or declaration name
  is not that terminal cannot resolve to it. The one case this filter can miss is a chain that
  renames on the way (`pub use inner::Real as Alias;` re-exported and then imported as `Alias`); the
  equivalence fixture covers that case explicitly, and the fact-backed `usage_binding_names` path
  already contributes such aliases to the scan's name gate independently.
  Date/Author: 2026-08-08, Opus.

- Decision: keep the per-site memo inside one `RustReferenceContext` value (a `RefCell` map living
  for one file for one query), and do not add an analyzer-level `(file, name)` cache.
  Rationale: the design permits a `(file, name)` memo only when a counter shows repeated identical
  site slices, and asks for honest weights if one is added. A memo that dies with the query needs no
  weight and cannot grow with workspace size, so it is strictly safer than what the design permits.
  The counter added in Milestone 2 reports how many resolutions the memo serves.
  Date/Author: 2026-08-08, Opus.

## Outcomes & Retrospective

To be written at completion.

## Context and Orientation

Everything in this section is current behavior before the change.

A **usage query** is `scan_usages`: given a symbol, find where it is used. For Rust it runs
`UsageFinder::query_with_provider_and_source_budget`
(`crates/bifrost-analysis/src/analyzer/usages/finder.rs:146`), which first performs *candidate
discovery* (which files could mention this symbol), then opens the profiling span
`usages::graph_find_usages` and hands the candidates to
`RustQueryResolver::find_usages` (`crates/bifrost-analysis/src/analyzer/usages/rust_graph.rs:100`).

That resolver picks one of two scans in
`crates/bifrost-analysis/src/analyzer/usages/rust_graph/extractor.rs`:
`scan_files_for_target` (line 89) for a free item, or `scan_files_for_member_target` (line 1115) for
a method, field, or associated item. Both iterate the candidate files with rayon's `par_iter` and
merge each file's hits into one shared `Mutex<BTreeSet<UsageHit>>`.

A **hit** is proven per site by `RustAnalyzer::usage_reference_at`
(`crates/bifrost-analysis/src/analyzer/rust/usage.rs:1140`). That function reads persisted fact
tables: `rust_module_scopes` (which module encloses a byte offset), `rust_import_targets` (the
file's import bindings, with owner module, visibility, and the byte extent over which the binding is
live), and `rust_exports` (re-exports and globs). When it answers `Exact`, the scan is done with
that site.

The **reference context** is the fallback used when `usage_reference_at` does not answer `Exact`.
It is `RustReferenceContext` in
`crates/bifrost-analysis/src/analyzer/rust/graph_support.rs:37-53`, a struct of six fields:

- `package` and `crate_package`: two short strings from path arithmetic.
- `named`: local name to fully qualified name, for `use path::Item;` bindings, plus one entry for
  every name this file itself re-exports (`insert_reexport_reference_bindings`, line 765).
- `namespace`: local alias to package, for `use crate::util;` bindings.
- `scoped`: the string `"local::Name"` to a canonical declaration fqn, filled by
  `insert_namespace_export_bindings` (line 708) for *every export name of every namespace-imported
  module*, following `pub use *` transitively.
- `glob`: name to fqn for unambiguous `use path::*;` imports, filled by
  `collect_glob_reference_bindings` (line 737) the same way.
- `same_file`: identifier to fqn for items declared in this file.

`scoped` and `glob` are the unbounded fields. On `rustc` a single `use rustc_middle::ty;` makes
thousands of `scoped` entries, each one requiring a separate re-export walk through
`canonical_export_fqn_from_files` (line 659), which itself calls `export_index_of` per reachable
file and issues declaration lookups. That is the 1,062 seconds.

The context is built by `build_reference_context_with_progress` (line 556) and cached twice per
file: `reference_contexts` (reverse) and `forward_reference_contexts` (forward), on the analyzer
(`crates/bifrost-analysis/src/analyzer/rust/mod.rs:77-78`). "Forward" and "reverse" differ only in
which direction re-export chains are walked (`forward: bool`, used at line 666).

Three places build it eagerly, before knowing whether it is needed:

1. `extractor.rs:130`, once per candidate file in `scan_files_for_target`.
2. `extractor.rs:1160`, once per candidate file in `scan_files_for_member_target`.
3. `resolver.rs:1256-1275` (`local_impl_target_importer_files`), once per *analyzed file in the
   workspace*, when the graph seed is a local declaration.

A fourth, `resolver.rs:422-437` (`lexical_import_fqn`), builds the *forward* context lazily but
still whole, from inside the scan.

Two defects follow. `weight_reference_context`
(`crates/bifrost-analysis/src/analyzer/rust/cache.rs:9-23`) sums only `named`, `namespace`, and
`same_file`, so the caches under-report by exactly the two unbounded fields. And
`reference_context_of` (`graph_support.rs:505`) passes `&|| true` as its keep-going predicate, so a
scan-driven build never polls for cancellation and is uninterruptible from start to finish.

Finally, the **cap**. `RustQueryResolver::find_usages` collects every hit from every candidate,
filters, counts the external ones, and only then compares against `max_usages` (which is 1,000,
`SCAN_USAGES_MAX_CALLSITES` in `crates/bifrost-analysis/src/searchtools/mod.rs`). When the count
exceeds the cap it returns `FuzzyResult::TooManyCallsites` carrying the *entire* hit set as
`sample_hits` (`rust_graph.rs:186-197`). So contexts are built, and files scanned, for results the
cap then discards.

## Plan of Work

### Milestone 1: freeze the current algorithm for equivalence

Add a `#[cfg(test)]` module `frozen` at the bottom of
`crates/bifrost-analysis/src/analyzer/rust/graph_support.rs` holding a verbatim copy of today's
resolution: a `FrozenReferenceContext` struct with the six fields, a
`build_frozen_reference_context(rust, file, forward)` function copied from
`build_reference_context_with_progress` with the progress checks removed, and copies of
`resolve_bare`, `resolve_scoped`, `resolve_scoped_owner`, and `bare_names_resolving_to`. This is the
house idiom used by the frozen Cargo-route algorithm for issues #1793 and #1817 in
`crates/bifrost-analysis/src/analyzer/rust/cargo_routes.rs`: keep the old algorithm alive only for
tests so a rewrite can be pinned against it.

Add the equivalence fixture and test in the same file's `mod tests`. The fixture must contain, per
the design: a named import, an aliased import, a namespace import, a glob import, a re-export chain
that includes a cycle, a macro whose visibility gates its use, and a same-file shadow of an imported
name. The test enumerates, for every file in the fixture and both directions, a probe set of every
identifier and every two-segment path spelled anywhere in the fixture, and asserts the live
resolver's answer equals the frozen answer for `resolve_bare`, `resolve_scoped_owner`,
`resolve_scoped`, and `bare_names_resolving_to`.

At this milestone the live resolver *is* the frozen algorithm, so the test passes trivially. Its
value is realized in Milestone 3.

### Milestone 2: counters and pins, failing first

Add three counters to `RustAnalyzer` following the existing per-instance counter idiom
(`module_file_resolution_count`, `crates/bifrost-analysis/src/analyzer/rust/mod.rs:88-95` and its
`#[doc(hidden)]` reset/read pair at `:287-296`): an `Arc<AtomicUsize>` shared by `Clone`, reset only
by the analyzer that owns it, never process-global.

1. `export_name_canonicalization_count`, incremented at the top of
   `canonical_export_fqn_from_files`. This is the per-name re-export walk that the eager builders
   run once per export name of every namespace- and glob-imported module. It is the direct measure
   of the design's central claim.
2. `scanned_candidate_file_count`, incremented once per candidate file that a scan actually opens
   in `scan_files_for_target` and `scan_files_for_member_target`.
3. `reference_resolution_memo_hits` / `reference_resolution_count`, reported by the per-context memo
   so the Decision Log's memo justification is evidence-backed.

Add the pins as tests. Write them before the rewrite and record their failing output in
`Artifacts and Notes`:

- `usage_scan_does_not_canonicalize_the_whole_namespace_export_surface`: a fixture whose module
  `wide` exports twenty names, a consumer file with `use crate::wide;` that writes `wide::target()`,
  and a scan for `target`. Assert the canonicalization count stays small. Before the change it is at
  least twenty per context per file.
- `usage_scan_stops_opening_candidates_once_the_callsite_cap_is_proven`: a fixture with many files
  each containing hits, scanned with a small `max_usages`. Assert the scanned-file count is below
  the candidate count. Before the change every candidate is opened.
- `cancelled_usage_scan_stops_inside_reference_resolution`: the same wide-export fixture scanned
  with a cancellation token that trips partway. Assert the canonicalization count stays bounded.
  Before the change the in-flight context build cannot be interrupted.

### Milestone 3 (D1 and D3): the lazy per-site resolver

Change `RustReferenceContext` in `graph_support.rs` to:

    pub struct RustReferenceContext<'a> {
        rust: &'a RustAnalyzer,
        file: ProjectFile,
        forward: bool,
        progress: Box<dyn Fn() -> bool + 'a>,
        package: String,
        crate_package: String,
        binder: ImportBinder,
        same_file: HashMap<String, String>,
        memo: RefCell<HashMap<RustReferenceQuery, Option<String>>>,
    }

Construction keeps only what is genuinely cheap: two path-arithmetic strings, the import binder
(one store round trip through `import_info_of`), and the same-file declaration map (one declaration
read). Nothing walks an export surface at construction time.

Each method answers one name:

- `resolve_bare(name) -> Option<String>` tries, in order, the named binding for `name`, the
  namespace binding for `name`, the same-file declaration, and the glob resolution. The named
  binding is the binder's `Named` entry for `name` resolved through
  `canonical_export_fqn_from_files` for that one imported name; if there is no such binder entry, it
  is this file's own re-export of that name, and failing that this file's star-re-export closure
  containing that name. The glob resolution asks each `Glob` binding's module closure whether it
  exports `name` and canonicalizes only that name, keeping the answer only when exactly one glob
  binding produces one fqn. This reproduces the eager `glob` map's "unambiguous only" rule for one
  name.
- `resolve_scoped_owner(path)` tries the scoped resolution for `path` (split `path` into
  `local::name`, require `local` to be a `Namespace` binding and `name` to be in that module's
  export closure, then canonicalize only `name`), then recurses on the path prefix, then the
  namespace binding, then rooted path arithmetic, then named, same-file, and glob, in exactly the
  order `resolve_scoped_owner` uses today.
- `resolve_scoped(path, name)` is unchanged: `resolve_scoped_owner(path)` joined with `name`.
- `bare_names_resolving_to(target_fqn)` builds the terminal-filtered candidate set described in the
  Decision Log and keeps candidates whose `resolve_bare` equals `target_fqn`.

`resolve_bare` changes its return type from `Option<&str>` to `Option<String>`, because a lazily
computed answer cannot be borrowed out of the struct. Update every call site; most of them already
called `.map(str::to_string)`.

Thread cancellation (D3): the `progress` closure is polled at the top of each loop in the per-site
walks, and a resolution that is interrupted returns `None` rather than a partial answer. There are
no cache writes left to gate, because the caches are gone.

Delete: `build_reference_context_with_progress`, `insert_namespace_export_bindings`,
`collect_glob_reference_bindings`, `insert_reexport_reference_bindings` (its logic moves into the
per-name named resolution), `single_rust_target_fqn`'s eager callers, the
`reference_contexts` and `forward_reference_contexts` caches and their four construction sites in
`mod.rs`, `weight_reference_context` in `cache.rs`, `reference_context_built_for_test`,
`RustAnalyzer::warm_usage_reference_contexts`, `AnalyzerWorkspace::warm_rust_usage_reference_contexts`,
and the `BIFROST_WARM_USAGE_ANALYSIS` gate in
`crates/bifrost-mcp/src/searchtools_service.rs` that exists only to switch that warm off.

Three existing tests in `graph_support.rs` pin the caches rather than the answers:
`forward_reference_context_is_reused_within_analyzer_generation`,
`issue_1228_interrupted_forward_reference_context_is_not_cached`, and
`issue_1304_interrupted_inverted_reference_context_is_not_cached`. With no cache, "an interrupted
build publishes nothing" is true by construction. Replace them with tests that pin the surviving
invariant: an interrupted resolution answers `None`, and an uninterrupted one answers the same fqn
the old tests asserted (`exports.Alias`, `exports.helper`). Record the replacement here.

### Milestone 4 (D2): stop at the cap

Give both scans a stop condition. Pass `max_usages` into `scan_files_for_target` and
`scan_files_for_member_target`. Keep a shared `AtomicUsize` of proven external hits, where
"external" means the same predicate `RustQueryResolver::find_usages` applies today
(`hit.enclosing != target` and `hit.kind.included_in(UsageHitSurface::ExternalUsages)`). Each rayon
task returns immediately if the stop flag is already set, so no candidate past the stop is opened,
parsed, or resolved. After a task merges its hits it adds its external count and sets the stop flag
once the total reaches `max_usages + 1` -- the cap plus the one hit needed to *prove* the cap is
exceeded.

In `RustQueryResolver::find_usages`, bound `sample_hits` to `max_usages` entries instead of carrying
the entire set. `total_callsites` becomes the count at the stop, which is still greater than the
limit, so every consumer's "too many, evidence inconclusive" message stays true.
`crates/bifrost-analysis/src/analyzer/structural/search/expansions.rs:704-707` already truncates the
sample to `limit`, so bounding the carrier changes nothing downstream.

### Milestone 5: parity

`rust_graph.rs` result assembly is the orchestration every language's scan suite exercises through
shared machinery, so the whole scan surface is the bar.

## Concrete Steps

Run all commands from `/mnt/optane/bifrost-nlp`.

Focused iteration during Milestones 1 to 4:

    cargo nextest run -p brokk-bifrost-analysis -E 'test(/reference_context|graph_support/)'

Full selections for Milestone 5:

    cargo nextest run --workspace -E 'test(/scan_usages|usages|rust_graph|searchtools/)'
    cargo nextest run -p brokk-bifrost-analysis

Lint gate:

    cargo fmt
    cargo clippy --workspace --all-targets -- -D warnings

Do not enable the `nlp` feature: this change does not touch semantic search, and an `nlp` build can
use tens of gigabytes per worktree. Do not run large-tree benchmarks from this plan; the design's
`rustc` measurement is a separate task after review.

## Validation and Acceptance

Acceptance is behavioral and is carried by five things.

First, the equivalence pin: `reference_resolution_matches_the_frozen_closure_algorithm` in
`crates/bifrost-analysis/src/analyzer/rust/graph_support.rs` must pass after Milestone 3, comparing
the lazy per-site answers against the frozen eager algorithm over the fixture, for named, aliased,
namespace, and glob imports, a re-export chain containing a cycle, macro-visibility gating, and
same-file shadowing.

Second, the three counter pins from Milestone 2: each must fail before its milestone and pass after,
with the before and after numbers recorded in `Artifacts and Notes`.

Third, the unchanged contracts. These must pass without modification:
`issue_1416_late_cancellation_keeps_the_hits_the_graph_scan_already_proved` and
`issue_1228_cancellation_after_candidate_discovery_is_not_reported_as_empty_success` in
`crates/bifrost-analysis/src/analyzer/usages/finder.rs`; the suite
`tests/suite_issues/issue_1230_rust_scan_complexity.rs`; and
`tests/issue_1175_scan_usages_reparse.rs`.

Fourth, the `debug_assert!` at `extractor.rs:497` -- that the cheap name gate never skips an
identifier which would resolve to the target -- must still hold. It runs in every debug test build,
so a violation surfaces as a panic in the suites above. If the per-site rewrite makes an equivalent
invariant more appropriate, the replacement and its reason go in the Decision Log.

Fifth, the full multi-language selections and featureless clippy from `Concrete Steps`, with any
new failure verified against a clean stash of the working tree before it is accepted as
pre-existing.

## Idempotence and Recovery

Every step is an ordinary source edit under version control, and each milestone is a separate
commit on the branch `bifrost-nlp-ft`. Nothing writes outside the repository, creates persistent
temporary directories, or changes stored analyzer data: the two deleted caches are in-memory only
and retire with the analyzer generation, so no migration and no cache invalidation is needed. To
abandon the work, reset to the commit before the first milestone.

## Artifacts and Notes

Fail-before and after evidence for the counter pins is recorded here as each milestone lands.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/rust/graph_support.rs`, at the end of Milestone 3:

    pub struct RustReferenceContext<'a> { /* fields as above */ }

    impl<'a> RustReferenceContext<'a> {
        pub fn resolve_bare(&self, name: &str) -> Option<String>;
        pub fn resolve_scoped(&self, path: &str, name: &str) -> Option<String>;
        pub fn resolve_scoped_owner(&self, path: &str) -> Option<String>;
        pub(crate) fn bare_names_resolving_to(&self, target_fqn: &str) -> HashSet<String>;
    }

    impl RustAnalyzer {
        pub fn reference_context_of(&self, file: &ProjectFile) -> RustReferenceContext<'_>;
        pub(crate) fn reference_context_of_while<'a>(
            &'a self,
            file: &ProjectFile,
            keep_going: impl Fn() -> bool + 'a,
        ) -> RustReferenceContext<'a>;
        pub(crate) fn forward_reference_context_of(&self, file: &ProjectFile)
            -> RustReferenceContext<'_>;
        pub(crate) fn forward_reference_context_of_while<'a>(
            &'a self,
            file: &ProjectFile,
            keep_going: impl Fn() -> bool + 'a,
        ) -> RustReferenceContext<'a>;
    }

In `crates/bifrost-analysis/src/analyzer/usages/rust_graph/resolver.rs`, the provider hook keeps its
name and gains a borrow lifetime so it can return a resolver that borrows the analyzer:

    fn forward_reference_context<'r>(
        &self,
        rust: &'r RustAnalyzer,
        file: &ProjectFile,
    ) -> Option<Arc<RustReferenceContext<'r>>>;

A method that is generic only over a lifetime keeps the trait object safe, and
`dyn RustDefinitionProvider` is used throughout the Rust resolution paths.

In `crates/bifrost-analysis/src/analyzer/usages/rust_graph/extractor.rs`, both scans take the cap:

    pub(super) fn scan_files_for_target(
        analyzer: &dyn IAnalyzer,
        rust: &RustAnalyzer,
        files: HashSet<ProjectFile>,
        target: &CodeUnit,
        seeds: Option<&RustBindingSeeds>,
        cancellation: Option<&CancellationToken>,
        max_usages: usize,
    ) -> BTreeSet<UsageHit>;
