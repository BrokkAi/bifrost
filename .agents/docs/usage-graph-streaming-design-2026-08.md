# Design: usage-graph result assembly as per-site queries with streaming

Status: DESIGN FOR OWNER REVIEW. Do not implement until approved. Author: Fable, 2026-08-08.
Substrate: `graph-phase-investigation-v1.md` (session artifact; key findings restated here so this
document stands alone) and `.agents/docs/intellij-indexing-research-2026-08.md` sections 3.2-3.5.

## The problem, precisely

Kill-gate run 3 (plan record `96577182`): past candidate discovery, `usages::graph_find_usages`
costs 1,034 s with 1,115 `build_reference_context` calls, and the answering regime peaks at
23.42 GB RSS. Investigation attribution corrects one earlier claim: ~15.5 GB of that RSS accrues
in candidate discovery before the graph phase (dominated by `global_usage_definition_index`, an
unbounded whole-workspace RAM index in a `OnceLock`); the graph phase's marginal cost is ~8 GB.

The 1,034 s is almost entirely `build_reference_context`: 1,062.51 s across n=1,115 (~0.95 s
each; n exceeds the 1,000-candidate cap because forward and reverse contexts duplicate per file).

## Why the owner's prior is correct (findings, cited to the investigation)

1. The scan proves each hit with the v2 fact-backed `usage_reference_at`; `RustReferenceContext`
   is consulted ONLY when that returns non-Exact (`extractor.rs:486-505`, `:558-596`). It is a
   fallback.
2. Yet `reference_context_of(file)` runs unconditionally, once per candidate, BEFORE that file's
   scan (`extractor.rs:130`, `:1160`).
3. Its expensive fields (`scoped`, `glob`) eagerly enumerate and canonically resolve the entire
   export surface of every namespace- and glob-imported module, transitively through `pub use *`
   (`graph_support.rs:708-763`, `:876-945`). Unbounded: |glob imports| x |export closure|.
4. Its cheap fields are already rows: `named`/`namespace` are `rust_import_targets` +
   `rust_exports` (and `RustUsageWalks::origin_routes_of` composes the same relation with domain
   and byte-extent gating the flat maps cannot express); `same_file` is `code_units` via the
   memoized `RustDeclarationFacts`; `package` is path arithmetic.
5. Two latent defects: `weight_reference_context` (`rust/cache.rs:9-23`) omits exactly the two
   unbounded maps, so the two context caches enforce a 32 MiB budget while holding gigabytes;
   and construction passes `&|| true` as its keep-going predicate (`graph_support.rs:505-508`),
   so one build is uninterruptible end to end.
6. Result assembly accumulates: all hits into one `Mutex<BTreeSet<UsageHit>>`, the `max_usages`
   cap (1,000) applied only after every candidate finishes (`rust_graph.rs:177-197`), and
   `TooManyCallsites` carries the ENTIRE hit set as `sample_hits`. Contexts are built for results
   the cap then discards.

IntelliJ's answers to the same phase (researched, cited in the investigation): a `Processor`
early-out protocol threaded through every layer; the usage limit pauses candidate processing
BEFORE each next file; per-candidate ASTs held by weak references in batch mode so GC bounds
memory; results are pointers (offset + smart pointer), never contexts; verification is text-first
with the AST walked only at matching offsets. They never precompute a per-file import closure.

## The design

Four components. No new persistence. No new workspace-sized structure, in RAM or in the store.

### D1. Demote the reference context: from eager-per-file to lazy per-unresolved-site

Delete the eager `reference_context_of` call from the scan path. When `usage_reference_at`
returns non-Exact for a site, answer THAT site's question with per-site queries over existing
data: the site's module scope at its byte offset (`rust_module_scopes`), its file's import
bindings (`rust_import_targets` rows), and - only when the site's name must be traced through a
namespace or glob import - a bounded `origin_routes_of` / export-chain walk (CycleWalk-backed,
575c2ffb) for that ONE name, instead of enumerating whole export surfaces for every possible
name. The flat `scoped`/`glob` closure maps are deleted with the eager build; the forward/reverse
duplication disappears with them.

If measurement during implementation shows a file's non-Exact sites repeatedly need the same
narrow slice, memoize per (file, name) in the existing weighted-cache mechanism with HONEST
weights. That is the only caching this design permits, and it is an optimization to be justified
by a counter, not a default.

### D2. Streaming with early-out (the Processor lesson)

Check the `max_usages` cap before dispatching each next candidate, not after all finish; stop
dispatch once the cap plus the proof threshold is reached. `TooManyCallsites.sample_hits`
carries a bounded prefix (existing rendering already truncates; make the carrier honest too).
No per-site fallback work runs for candidates past the stop. The partial-on-cancel contract
(the two issue-1416 "interrupted context is not published" tests) and the issue-1230 complexity
pins must pass unchanged; the `debug_assert!` at `extractor.rs:497` (the name gate never skips a
resolving path) is the invariant the per-site rewrite must preserve.

### D3. Cancellation and honest weights

The per-site path takes the scan's keep-going predicate (the 575c2ffb rule: loops poll, cache
writes gate on not-cancelled). If any transitional stage keeps a context map alive,
`weight_reference_context` must count `scoped` and `glob` - but the end state deletes the maps,
making the weight bug moot by removal.

### D4. Equivalence and gate

The current closure-based resolution is frozen under `#[cfg(test)]` (the house idiom from
#1793/#1817) and the per-site answers are pinned against it over a fixture covering: named,
aliased, namespace, and glob imports; re-export chains including a cycle; macro-visibility
gating; same-file shadowing. Measured gate on the rustc tree, same cells as run 3: graph phase
from 1,034 s to seconds (target: proportional to non-Exact site count, which the investigation
shows is the small minority); marginal RSS of the graph phase from ~8 GB to O(bounded caches).

## Explicitly out of scope (each needs its own decision)

- `global_usage_definition_index`: the ~15.5 GB discovery-phase resident index. Same disease,
  different organ, shared across languages - needs its own investigation and design. Will be
  filed as an issue when this design is approved.
- The listing loop (~2.2 whole-tree walks/s): the investigation traced it (inferred, spans lack
  parents) to watcher feedback - `handle_event` invalidates the listing for any non-cache path
  including `.git`, then `classify_project_path` calls `is_gitignored` which calls `all_files()`,
  walk plus `git status`, possibly generating the next event. A watcher bug, not a query-path
  design question. Filed separately on approval.
- The ~87 s candidate walk (`edges_binding_identity` computing forward edges per mentioning
  file): the same per-site-vs-precompute question one stage earlier. Excluded from this cut to
  keep the change reviewable; the per-site machinery D1 builds is the natural second application,
  and the design should be re-visited for it once D1's shape is proven.

## Expected outcomes

Graph phase cost proportional to non-Exact sites (small minority) instead of candidate count;
~8 GB marginal RSS replaced by bounded caches; cap and cancellation honest end to end; net code
deletion (the closure builders and their two cache maps go away). First-query latency for the
answering regime on rustc: dominated by discovery (~87 s, out of scope here) instead of
1,034 s of assembly.

## Risks

1. A pathological file with many non-Exact sites pays per-site walks where one closure build
   amortized; mitigated by the (file, name) memo escape hatch, justified by counters.
2. Per-site glob resolution must equal closure enumeration semantically; carried by the frozen
   equivalence pin, which is the same mechanism that caught the inline_by_name and Scala-sigil
   regressions in earlier milestones.
3. The streaming change touches shared scan orchestration (`rust_graph.rs` accumulation); other
   languages' scan paths must stay at parity - the full multi-language scan suites are the bar.
