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
- [x] (2026-08-08 14:10Z) Milestone 1: froze the closure-based resolution under `#[cfg(test)]` and
      added the equivalence fixture and pin (commit `02e221a0`).
- [x] (2026-08-08 14:55Z) Milestone 2: added the two counters and observed all three pins failing
      before the rewrite; numbers in `Artifacts and Notes`. The pins themselves land with the
      milestone that makes each one pass, so the tree stays green at every commit.
- [x] (2026-08-08 18:20Z) Milestone 3 (D1 + D3): `RustReferenceContext` is a lazy per-site
      resolver; the eager builders, both analyzer caches, the mis-weighing weigher and the
      reference-context warm are deleted; the equivalence pin and the two D1/D3 counter pins pass
      (commit `48e6e9f1`).
- [x] (2026-08-08 18:45Z) Milestone 4 (D2): the callsite cap is checked before each candidate is
      opened and `sample_hits` is a bounded prefix; the D2 counter pin passes (commit `5cb4f4c2`).
- [x] (2026-08-08 19:30Z) Milestone 5: parity selections and featureless clippy run; every failure
      reproduced at the branch tip before this work. Results in `Validation and Acceptance`.
- [x] (2026-08-08) **D4 large-tree gate measured on rustc. SPLIT RESULT: the marginal-RSS target
      passes, the graph-phase latency target FAILS.** Report:
      `usage-graph-d4-gate-v1.md` (session scratchpad). Measured at `9263e2a5`
      (source-identical to `96e86c4e`) against run 3's `5c33701b` binary, on the same tree and
      cells. **This plan should not be treated as closed** -- see `Outcomes & Retrospective`.
- [x] (2026-08-08) **D4's one open correctness question is closed: the 11 -> 8 hit change is a
      wall-clock deadline artifact, not a per-site resolver difference.** Report:
      `hit-delta-triage-v1.md` (session scratchpad). Under non-truncated (narrowed-`paths`)
      sweeps, HEAD `38800fe5` and the run-3 comparator `5c33701b` return the identical 11-hit set,
      twice each. Across three matched full-scope pairs the answers are nested prefixes of that
      same 11 -- 4/4, 10/8 and 8/8 -- so the count tracks work done, not lineage, and in the one
      pair that separates them it is HEAD that finds *more*.
      See `Outcomes & Retrospective` for the evidence and for the 300 s budget ceiling it exposed.
- [x] (2026-08-08) **D4 re-measured after the stampede fix (`1272c7d7`). The verdict is unchanged
      and better understood: the marginal-RSS target passes with more margin, the graph-phase
      latency target still FAILS.** Report: `usage-graph-d4-remeasure-v1.md` (session scratchpad).
      Measured at `37540fb3` at loadavg 22-58, the quietest large-tree run since run 3. The fix
      reaches the theoretical minimum -- **100,890 store reads for 100,847 distinct keys** -- and
      `usages::graph_find_usages` is still **90.9% of the backend**, because the duplicated work it
      removed was concurrent rather than serial. The dominant term is now the per-read cost of a
      hot short name (5-11 s each) times a 100,847-distinct-name fan-out. See
      `Outcomes & Retrospective`.

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

- Observation: the equivalence pin earned its keep twice, and both times against
  `bare_names_resolving_to`.
  Evidence, first failure: `bare_names_resolving_to disagreed: file=src/consumer.rs forward=false
  target=wide.Gadget / left: ["Alias"] / right: ["Alias", "Renamed"]`. The candidate filter kept
  only names carrying the target's terminal identifier, and `use crate::barrel::Renamed;` binds
  `wide.Gadget` through a renaming re-export, sharing no spelling with it. Second failure:
  `target=cyclic_a.AlphaItem / left: [] / right: ["AlphaItem"]`. The frozen algorithm reports a name
  bound by *any* of the four map kinds, not by the winner of their precedence, and `consumer.rs`
  both declares `AlphaItem` and glob-imports `cyclic_a::AlphaItem`. Neither was visible from reading
  the code; both were caught by a fixture written before the rewrite.

- Observation: the per-site design removes a cache that a repeated query used to ride for free. The
  old contexts were cached per analyzer generation, so a second scan of the same file resolved
  nothing. This showed up while tuning the cancellation pin: with a warmed analyzer, every
  cancellation budget from 1 to 23 gave zero canonicalizations, because the context was already
  built. The pin therefore requires a cold analyzer. In production the trade is the intended one --
  a bounded per-question cost every time, instead of an unbounded precomputation once -- but it is
  a real difference in repeat-query behavior and worth naming.

- Resolution (2026-08-08) of the three update-visibility failures this plan listed below as "beyond
  the documented set": `issue_1450_cross_request_prepared_syntax`,
  `issue_1451_cross_request_import_infos` and
  `searchtools_service::manual_service_sees_change_after_explicit_update_paths` were REGRESSIONS,
  not stale pins, and all three are now green. One root cause, one fix, in
  `crates/bifrost-analysis/src/analyzer/store/liveness.rs`: `Liveness::oids_for_files` memoized the
  batched working-tree scan for the lifetime of the repository handle and served it to every later
  caller, so `TreeSitterAnalyzer::resolve_live_oids` re-registered the *pre-edit* blob oid for an
  edited file. `reconcile_file_states` then found that blob already parsed
  (`missing={}`) and skipped the re-parse, and the new generation's `LivePathMap` entry paired the
  stale oid with the *post-edit* stat, so every later blob-keyed read served the old file. The scan
  is now stat-validated per path: a path whose file has moved since it was last resolved is
  re-hashed from the working tree.
  Evidence: instrumented run at `8f6eb602` showed `resolve_live_oids` returning oid
  `b3490886` for `src/callers.rs` both before and after `update_paths`, and
  `reconcile files=["src/callers.rs"] missing={}`; after the fix the second resolution returns
  `f5668bc1` and the file is re-parsed. The same instrumentation at the last green commit
  `c1b08f54` also printed the stale `b3490886`, which proves the stale registration predates both
  first-bad commits: `48f8cc20` (#1757) and `d4a82ef4` (#1793) did not introduce it, they removed
  the downstream re-read-from-disk that had been masking it. The failure being language-agnostic
  (the Java `get_summaries` sibling shares it) is the tell that it never belonged to the Rust usage
  work at all.

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

- Decision: `bare_names_resolving_to(target_fqn)` asks every explicit binder binding, and applies
  the terminal-identifier filter only to the names this file itself exports.
  Rationale: this replaces an earlier decision, and the replacement was forced by the equivalence
  pin. The first version filtered every candidate on the target's terminal identifier -- the last
  dotted segment of `target_fqn` -- on the argument that a binding resolving to the target must end
  at a declaration with that identifier. That argument is sound about the *declaration* and wrong
  about the *binding*: `barrel` re-exports `wide::Gadget as Renamed`, so `use crate::barrel::Renamed;`
  binds `wide.Gadget` under a name sharing no spelling with it, and the fixture caught exactly that.
  There is no cheap test for a chain that renames, so every binder binding is resolved; the count is
  bounded by the file's import list, which is what the old `named` map already cost. The filter is
  kept for this file's own export names because a barrel module can re-export thousands of them and
  resolving all of them per candidate file is the cost this design exists to remove. The residual
  gap is a re-export of this file renaming at a hop deeper than the first.
  Date/Author: 2026-08-08, Opus.

- Decision: a candidate counts when *any* of the four binding kinds binds it to the target, not when
  the winner of their precedence does.
  Rationale: also forced by the pin. `resolve_bare` collapses named, namespace, same-file and glob
  into one answer by precedence, but the eager maps were four separate maps and the inverse query
  read all four. A file that declares `AlphaItem` and also glob-imports `cyclic_a::AlphaItem` binds
  the name twice, and the scan's name gate wants to hear about both -- narrowing to the shadowing
  declaration would drop the glob-imported target's hits.
  Date/Author: 2026-08-08, Opus.

- Decision: `issue_1230_rust_scan_complexity`'s module-file-resolution pin reads its counter after
  the two resolution questions rather than after constructing the context.
  Rationale: the task asked for this suite to pass unchanged. It cannot pass literally unchanged --
  `resolve_bare` returns `Option<String>` now, so `.map(str::to_string)` does not compile -- and
  leaving the counter read where it was would make the assertion vacuous, because constructing a
  resolver resolves no module files at all and the test would pin zero against zero. The claim in
  the assertion message is unchanged and now measures the answering work directly: what those two
  questions cost must not grow with the number of names the imported module exports.
  Date/Author: 2026-08-08, Opus.

- Decision: the `debug_assert!` at `extractor.rs:497` survives unchanged, with no equivalent
  substituted.
  Rationale: it asserts that the cheap name gate never skips an identifier that would resolve to the
  target, and it is written in terms of `matches_resolved_identifier`, which is unchanged. What that
  function resolves *through* changed; what it answers did not, which is what the equivalence pin
  establishes. The assertion runs in every debug test build, so the whole Rust usage suite exercises
  it, including `tests/suite_usages/issue_1416_scan_name_gate.rs`, which exists to walk it.
  Date/Author: 2026-08-08, Opus.

- Decision: keep the per-site memo inside one `RustReferenceContext` value (a `RefCell` map living
  for one file for one query), and do not add an analyzer-level `(file, name)` cache.
  Rationale: the design permits a `(file, name)` memo only when a counter shows repeated identical
  site slices, and asks for honest weights if one is added. A memo that dies with the query needs no
  weight and cannot grow with workspace size, so it is strictly safer than what the design permits.
  The counter added in Milestone 2 reports how many resolutions the memo serves.
  Date/Author: 2026-08-08, Opus.

## Outcomes & Retrospective

All four design components landed. The usage-graph phase no longer precomputes what a file could
mean; it answers what a site wrote. The reference context went from a bundle of eagerly filled maps
cached twice per file on the analyzer to a query-scoped view that borrows the analyzer, derives two
path strings at construction, and computes each answer when it is asked. The two unbounded maps and
their two mis-weighed caches are gone rather than corrected, which is what D3 asked for. The
callsite cap became a stop condition. The keep-going predicate is the caller's and is polled inside
the walks, where the entry point the scan used could not be interrupted at all.

The numbers, all from the counter pins:

- One site behind a namespace import of a module exporting 21 names: 21 export-name
  canonicalizations before, 0 after. Zero, not one, because the fact-backed prover answers that
  site `Exact` and the resolver is never consulted -- which is the design's thesis stated as a
  measurement.
- The same scan under a cancellation token tripping on its fourth check: 21 before, 0 after.
- A 24-candidate scan with the cap at one: 24 of 24 candidates opened before, 2 of 24 after.

What remains. The three exclusions the design fenced off are untouched:
`global_usage_definition_index`, the watcher listing loop, and the ~87 s candidate walk in
`edges_binding_identity`. The per-site machinery this built is the natural second application for
the third of those, as the design says.

### The D4 large-tree gate, measured (2026-08-08)

The measurement this section previously deferred has now been run on rustc, at `9263e2a5`, against
run 3's `5c33701b` binary, same tree and same cells. Full report:
`usage-graph-d4-gate-v1.md` in the session scratchpad. **It is the first large-tree measurement
taken after the watcher `.git` exemption (`0bdfc37c`), so it is also the first one not carrying the
~2.2 whole-tree-walks-per-second parasite that contaminated runs 1-3.**

**D4 target "marginal RSS of the graph phase from ~8 GB to O(bounded caches)": PASS.** Answering-cell
peak RSS fell from 23.42 GB to 17.49 GB timed / **15.58 GB untimed**, and RSS is flat through the
graph phase -- **+0.75 GB across 880 s** (17.2 GB at t=244 s, 17.95 GB at t=1,124 s). The
unbounded-context memory cost is genuinely gone.

**D4 target "graph phase from 1,034 s to seconds": FAIL, by about two orders of magnitude.**
`usages::graph_find_usages` measures **1,321.77 s** (v4) and 1,388.01 s (v4i), still **90% of the
scan backend** -- the same share it held in run 3. The host was heavily loaded (per-cell 1-min
loadavg 84-486 against run 3's 3.8-4.7), so the wall clocks are not a controlled comparison; but no
load factor explains "seconds" versus 1,322 s.

The deletion itself is verified: `RustAnalyzer::build_reference_context` is **absent from the
binary by symbol** and from every span log, where run 3 charged it n=1,115 at 1,062.51 s.

**What now dominates is a cache stampede, and it is shared and pre-existing, not created here.**
`sql_definition_candidates.rows[*]` fires n=146,678, thread-summed 1,070.9 s -- but the span opens
before the per-request memo is consulted, and **68.5% of those calls return in under 0.1 ms**. The
damage is a tail: **the slowest 1% (1,466 calls) carry 87.8% of the time**. Sorting individual
durations shows eight-plus *concurrent* 9-11 s reads of the *same* short name (`foo` n=53/126.7 s,
`Foo` n=96/125.6 s, `Bar` n=62/90.0 s). Many workers miss the memo simultaneously and all perform
the same expensive store read. Run 3's v3 charged n=98,553 of these at a *higher* 24.7 ms mean, so
the defect predates D1; it became dominant only because the eager build that used to dominate was
deleted.

Consequence for this plan's own risk register: **Risk 1's named mitigation is the wrong lever.** A
`(file, name)` memo is already implemented (`graph_support.rs:79`), the per-request
`QueryReadCache::definition_candidate_rows` memo sits underneath it, and two thirds of lookups are
already free. The fix indicated is single-flight de-duplication of *concurrent* misses, which is
local to `definition_candidate_rows` and targets ~940 s of a 1,322 s phase. That is a separate
change and wants its own issue (search first; adjacent to #1748/#1774, but the concurrency angle is
new).

Two further results worth carrying:

- **Gate cell (b) went from 653.78 s to 5.34 s (122x)** and its whole-workspace listing count from
  1,487 to 12 -- **that is the watcher fix, not this plan.** Cell (a) warm and cell (c) edited are
  at parity with run 3 (5.72 s vs 5.51 s; 6.42 s vs 6.91 s). Listing counts are 11-12 per query
  against run 3's 11-15 for the cells that were never looping: the loop is gone, the startup floor
  remains.
- **The answering cell returned 8 hits where run 3 returned 11**, reproduced on both v4 and v4i.
  Both runs are `complete=false`, so this may only be where the deadline truncated the sweep under
  far heavier load -- but it may be a per-site resolver difference at a scale the fixture-based
  equivalence pin cannot reach. **This wants a load-matched rerun and, if it survives, triage
  before the per-site resolver is considered settled.** It is the one open question here that could
  be correctness rather than performance.

  **CLOSED (2026-08-08, triaged): deadline artifact, not behavior. The per-site resolver is not
  implicated.** Report: `hit-delta-triage-v1.md` (session scratchpad). Two independent lines,
  both comparing hit *sets* rather than counts. **(1) When the sweep is not truncated, the two
  lineages return the identical set, and it is the full 11.** Narrowing `paths` to the six files
  that carry the hits collapses the graph phase, so the query completes (`partial=false`, no
  `incomplete_reason`); four such runs -- HEAD `38800fe5` and the run-3 comparator `5c33701b`, two
  matched repetitions each -- all return **11 hits, byte-identical to each other and to run 3's
  set**, including all three sites run 4 "lost" (`rustc_codegen_llvm/src/abi.rs:99:49`,
  `codegen_fn_attrs.rs:249:19`, `:255:26`). Narrowing to just those two files returns all three on
  both binaries, twice. **(2) Under matched full-scope conditions the sets are nested prefixes of
  that same 11, and the sign of the original delta reverses.** Three pairs, each with both
  binaries started at the same instant: pair 1 (loadavg 85) returned the *identical* 4 hits on
  both, at 7,850 CPU-seconds (HEAD side) against 10,734 (comparator); pair 2 (loadavg 14)
  returned **10 on HEAD and 8 on the comparator**, at 7,287 against 8,751 CPU-seconds, with exact
  containment `v3(8) < v6(10) < complete(11)`; pair 3 (loadavg 12) returned the *identical* 8 on
  both, at 6,326 against 8,796 CPU-seconds. **The comparator reproduced run 4's "regressed" 8 in
  two pairs, and in the one pair that separates the lineages it is HEAD that finds more.** Every
  answer this campaign has recorded is a prefix of one deterministic sweep -- 4 <= 8 <= 10 <= 11
  -- so the answer size is a property of how much work fitted inside the wall-clock deadline, not
  of the lineage. Run 4's "reproducible 8" was three runs sharing one load regime (loadavg
  84-486); run 3's 11 was one run at loadavg 3.8-4.7.

  Three things this leaves behind for the record. **`max_duration_secs` is clamped to 300 s**
  (`SCAN_USAGES_MAX_DURATION_CEILING`, `scan_usages.rs:772`), so every "600 s budget" cell in runs
  3, 4 and 5 ran a 300 s deadline and no budget override can buy a longer sweep. **`paths` is
  applied after candidate discovery** (`finder.rs`, `candidates.retain(...)` follows
  `find_default_candidates_with_cancellation`), so it collapses the graph phase but does not
  shorten discovery -- which is why the narrow cells complete in ~170 s of wall where the
  full-scope cells run half an hour and still truncate. And **hit counts from truncated cells must
  not be quoted as a behavior signal**: compare sets from completing queries, or compare at equal
  CPU-seconds consumed, never at equal wall-clock budgets on a shared host.

  Incidental, measured in the same matched pairs: **`1272c7d7` (single-flight for the
  definition-candidate row read) costs 1.7-2.1x less CPU** on the completing cell -- 277.2 and
  284.7 CPU-seconds at HEAD against 474.5 and 488.8 on the comparator, for the identical 11-hit
  answer. That is the first CPU-normalized confirmation of the stampede fix at rustc scale.

### The D4 gate re-measured after the stampede fix (run 6, 2026-08-08)

Run 4 identified a cache stampede in `definition_candidate_rows` and estimated ~940 s of a 1,322 s
graph phase as recoverable. `1272c7d7` single-flighted that read. This is the clean-conditions
re-measure the fix's own issue comment queued. Measured at `37540fb3`, on the same rustc tree and
the same cells, at **loadavg 22-58** -- the quietest large-tree run since run 3 (3.8-4.7) and far
better than run 4 (84-486). Full report: `usage-graph-d4-remeasure-v1.md` in the session scratchpad.
Verdicts are read off CPU time, span proportions, RSS and counts; wall clock is context only.

**The fix works exactly as specified, and the graph phase did not move.** A probe binary counting
every store read inside `definition_candidate_rows` charges **100,890 reads for 100,847 distinct
keys -- 1.0004 reads per key, the theoretical minimum.** In-flight duplication is gone.
`usages::graph_find_usages` nevertheless measures **1,271.99 s, 90.9% of the scan backend**, the
same share it held in run 3 (90.3%) and run 4 (90.3%).

**D4 target "graph phase from 1,034 s to seconds": still FAIL, by two orders of magnitude** -- but
now for a diagnosed reason rather than a suspected one.

**D4 target "marginal RSS to O(bounded caches)": PASS, with more margin.** Peak RSS **10.69 GB**
untimed (11.74 timed) against run 4's 15.58/17.49 and run 3's 23.42. Most of the further drop is
`37540fb3`, which stopped copying the definition index into a normalized twin.

**Why the ~940 s did not materialise, measured.** Of the 1,255.1 s of
`sql_definition_candidates.rows[*]` span time, **at most 664.3 s (52.9%) is real read time and at
least 590.8 s (47.1%) is followers parked on a leader** (per-name maxima bound the leader from
above; the span opens before the memo, so a follower's span *is* its park time). The duplicated
work was **concurrent, not serial**: eight threads running the same 10 s read finish in about 10 s
of wall, and one thread running it while seven wait also finishes in about 10 s. The fix recovers
CPU and store I/O -- the parallel triage measures **1.7-2.1x less CPU on a completing cell** -- and
recovers no wall clock on the truncated one.

**Run 4's reading of the duration histogram needs one correction.** It called the sub-0.1 ms bucket
(68.5%) "memo hits". It cannot be: there are 100,847 *distinct* keys against 146,212 calls, so at
least 69% of all calls are a key's first ask and must read. That bucket is overwhelmingly **fast
reads of rare names**. This is why "more memoization" was never the lever, and why the lever that
was pulled could not pay what was estimated.

**The new dominant term is per-read cost and name volume, not duplication.** One read of a hot short
name genuinely costs 5-11 s (`foo` 11.16 s, `main` 10.97 s, `bar` 10.15 s), and one query reads
**100,847 distinct short names**. The slowest 1% of names carry **74.1%** of all real read time; the
slowest 0.1% carry 41.8%. Two separable follow-ups: the cost of a single
`declaration_order_candidate_rows_by_short_name_for_langs` on a high-cardinality short name, and the
name volume the scan generates. Both want their own issue; both are adjacent to #1748/#1774 without
being what those describe.

**`workspace_module_walk` is not implicated at this scale.** It carries no span, but it is reached
from candidate discovery, and `usages::candidate_discovery` is **119.26 s, 8.5% of the backend**
(down from 9.4-9.5%). There is no room inside 8.5% for a term that explains a 1,272 s graph phase.
Inference from the share, not proof. The second-largest named item inside the phase is
`RustAnalyzer::export_index_of_declarations`, n=3,076 / 533.85 s / 38.1%; its call count is flat
across runs 3, 4 and 6 while its thread-summed time is not, so one sample should not be read as a
regression, but it is now the largest item after the row reads.

**Gate cells, on a CPU-adjusted reading.** Cell (a) warm 5.31 s wall / **4.21 s user CPU**, against
4.69 s (run 4) and 4.93 s (run 3): user CPU is flat to falling, so the work has not changed and run
3's quiet-host verdict carries -- **gate 1(a) still FAILS its 5 s bar, by about 6%**. Cell (b) warm
5.31 s, listing count 12: the watcher fix holds (run 3: 653.78 s, 1,487 listings), **gate 1(b) fails
the same 5 s bar by the same ~6%**. Cell (c) edited 6.11 s / 4.41 s user CPU: **gate 2 PASSES** at
39% inside its 10 s bar, and no load factor can flip it. Gate cell peak RSS 0.43-0.74 GB: **gate 3
PASSES at the gate budget**, and still fails in the answering regime at 10.69 GB. All eight gate
cells return `resolved=0 failure=1 time_budget`, for the fifth run running: the gate table measures
how fast the pipeline gives up, not answering latency. `workspace_file_listing_count` is 11 cold /
12 warm, identical to run 4.

**Method note worth carrying: on this host, user CPU is load-independent and system CPU is not.**
Run 6's gate cells charge 7.5-9.1 s of sys against run 3's 2.9-3.7 s while user CPU is flat; the
difference tracks host memory pressure and background I/O, not the query.

**Independent corroboration of the closed hit flag.** The probe binary's answering run returned
**eleven hits, run 3's set entry for entry**, on an ordinary full-scope truncated sweep with no
`paths` narrowing -- while the unprobed binary returned eight twice, a strict subset. That is a
third line of evidence for the deadline-artifact conclusion already recorded above, and the only one
that did not need a narrowed query to reach the full set.

Two lessons. First, the frozen equivalence pin was not ceremony: it caught two behavioral
differences in `bare_names_resolving_to` that reading the code did not reveal, and both would have
silently narrowed the scan's name gate. A fixture written before the rewrite, probing every name
against every path prefix over every file in both directions, is worth more than a set of
hand-picked assertions. Second, writing counter pins before the change and recording their failing
output made the difference between "the design says this should be cheaper" and "21 became 0".

A third, from run 6: **an estimate built from span time is an estimate of waiting, not of work.**
The ~940 s figure came from summing the durations of concurrent same-key spans. Those durations
overlapped, and the span opened before the memo, so the sum measured neither the duplicated work nor
the phase's critical path. The counter that settled it -- reads per distinct key -- cost two lines
of instrumentation and should have been the first measurement, not the last.

## Note on revisions

2026-08-08, after Milestone 3: the `bare_names_resolving_to` decision in the Decision Log was
replaced. The original filtered every candidate name on the target's terminal identifier; the
equivalence pin showed that a renaming re-export binds a target under a name sharing no spelling
with it, so every explicit binder binding is now resolved and the filter applies only to this file's
own export names. A second decision was added for the same method, because the frozen algorithm
reports a name bound by any of the four binding kinds rather than by the winner of their precedence.
Two further decisions were added: one recording why the `issue_1230` pin reads its counter after the
questions instead of after construction, and one recording that the `extractor.rs` name-gate
`debug_assert!` survives unchanged. `Surprises & Discoveries` gained the two pin failures with their
exact output, and the note that the per-site design gives up a free repeat query in exchange for a
bounded first one.

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

Results as of Milestone 5, at commit `5cb4f4c2`.

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
new failure verified against a clean checkout before it is accepted as pre-existing.

What was run, and what it produced:

`cargo nextest run --workspace -E 'test(/scan_usages|usages|rust_graph|searchtools/)'`: 2,096 tests,
2,090 passed, 6 failed. `cargo nextest run -p brokk-bifrost-analysis`: 1,837 tests, 1,834 passed,
3 failed. `cargo nextest run -p brokk-bifrost --test suite_issues --test suite_usages --test
issue_1175_scan_usages_reparse --test suite_lsp_parity --test suite_cross_language`: 2,230 tests,
2,227 passed, 3 failed. `cargo clippy --workspace --all-targets -- -D warnings`: clean.

Every one of those twelve failures was reproduced in a detached worktree at the branch tip and again
at commit `9a7f2269`, which is this plan's own Milestone 2 and predates any behavior change here.
They are:

In `brokk-bifrost-analysis`, `analyzer::jvm::java_artifact::tests::
source_and_class_jars_share_declaration_ids_and_keep_distinct_origins`, and the two live-oid
rendezvous tests `analyzer::tree_sitter_analyzer::tests::
live_oid_resolution_hashes_two_overlays_concurrently` and
`..._reports_first_input_error_after_parallel_planning`. These three are the documented
pre-existing set.

In `suite_symbols`, `searchtools_fuzzy_symbol_lookup::
scan_usages_resolves_public_typescript_static_method_symbol` (also documented),
`searchtools_definition_selectors::csharp_generic_type_resolves_without_arity_spelling`,
`..._summaries_route_file_anchored_selector_with_extension_like_symbol_member`,
`..._summaries_and_ancestors_accept_js_file_anchored_selectors`, and
`searchtools_service::manual_service_sees_change_after_explicit_update_paths`.

In `suite_cross_language`, `code_query_resolution_conformance::
an_unindexed_declared_dependency_is_a_boundary_row_rather_than_an_empty_answer`. In `suite_usages`,
`issue_1450_cross_request_prepared_syntax::
an_edited_file_is_rescanned_rather_than_served_from_the_retained_tree` and
`issue_1451_cross_request_import_infos::
a_rewritten_import_is_rehydrated_rather_than_served_from_the_retained_infos`. In
`brokk-bifrost-mcp`, `bifrost_mcp_server::bifrost_searchtools_server_speaks_mcp_stdio`.

The last eight are beyond the documented set and are not caused by this work. They are worth their
own triage; `issue_1450` and `issue_1451` in particular are named in the investigation as behavioral
coverage of the Rust scan, so their being red on the branch means that coverage is currently not
protecting anything.

Update (2026-08-08): that triage happened. `issue_1450`, `issue_1451` and
`manual_service_sees_change_after_explicit_update_paths` were one regression with one root cause
(the memoized working-tree scan in `Liveness::oids_for_files`; see the Surprises entry of the same
date) and are green again. They are removed from every "documented pre-existing" list. The
remaining tolerated failures for this plan's selections are the JVM artifact test needing
`javac`/`jar`, the two `live_oid_resolution_*` rendezvous tests, and
`scan_usages_resolves_public_typescript_static_method_symbol`.

Update (2026-08-08, second): the same treatment reached the four selector tests, so none of them
is tolerated any more either. Bisected in
`.agents/docs/selector-failures-bisection-2026-08.md` to two adjacent commits of 2026-08-06:
`6da767e9` for `summaries_route_file_anchored_selector_with_extension_like_symbol_member` and
`summaries_and_ancestors_accept_js_file_anchored_selectors`, and `7e7ac9ee` for
`csharp_generic_type_resolves_without_arity_spelling` and
`scan_usages_resolves_public_typescript_static_method_symbol` (the last of which had been on this
plan's list since the start). Fixed by `7a22bf53` and `8a27e0cd`; both original commits' latency
fast paths survive and are pinned. The tolerated set for this plan's selections is now the JVM
artifact test and the two `live_oid_resolution_*` rendezvous tests.

## Idempotence and Recovery

Every step is an ordinary source edit under version control, and each milestone is a separate
commit on the branch `bifrost-nlp-ft`. Nothing writes outside the repository, creates persistent
temporary directories, or changes stored analyzer data: the two deleted caches are in-memory only
and retire with the analyzer generation, so no migration and no cache invalidation is needed. To
abandon the work, reset to the commit before the first milestone.

## Artifacts and Notes

Fail-before and after evidence for the counter pins is recorded here as each milestone lands.

Fail-before, all three pins, at commit `02e221a0` plus the Milestone 2 counters, from
`cargo test -p brokk-bifrost-analysis --lib analyzer::usages::rust_graph::tests::`:

    a scan of one site behind one namespace import canonicalized 21 export names;
      the module exports 21 and only one is written
    a cancelled scan canonicalized 21 export names
    the scan opened 24 of 24 candidates after the cap was proven

The first number is exact and diagnostic: 21 canonicalizations for a module with 21 exports, from a
consumer that writes one of them. The cancellation budget of four was found by sweeping budgets one
through twenty-three against a cold analyzer; the counts are 0, 0, 0, then 21 from four upward,
which locates the boundary precisely. At three checks the scan bails before the candidate's context
would be built; at four the token is already cancelled and the build runs to completion anyway,
which is the investigation's "a single build is uninterruptible end to end", measured.

After, at commit `5cb4f4c2`, same three pins, same fixtures:

    a scan of one site behind one namespace import canonicalized 0 export names
    a cancelled scan canonicalized 0 export names
    the scan opened 2 of 24 candidates after the cap was proven

The two zeros are the strongest form of the result: not "fewer walks" but none, because the
fact-backed prover answers that site `Exact` and the reference resolver is never consulted at all.
The 2 of 24 is the two-thread pool's one-task overshoot on top of the first candidate, which is the
floor for a rayon fan-out that stops.

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
