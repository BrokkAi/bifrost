# Retire global_usage_definition_index: bounded lookups over store rows

This ExecPlan is a living document maintained per `.agents/PLANS.md`. Sections `Progress`,
`Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current.

STATUS: DEMOTED TO HYGIENE TRACK, SEQUENCED BEHIND THE SCHEMA CLEANUP (owner decision,
2026-08-08, after Milestone 0 corrected the memory case by ~44x). The consumer-migration
cohorts fold into the view-based query surface that the store schema cleanup
(`.agents/docs/store-relational-schema-design-2026-08.md`) builds, rather than preceding it.
Memory-motivated milestones are suspended: Milestone 3's premise is broken (usage_facts_index
never builds on the scan path) and Milestone 4's gate targets ~2% of peak RSS; whether any
memory milestone returns is decided by the RSS attribution investigation now in flight, not by
this plan. The watcher-plan sequencing note below is satisfied (0bdfc37c landed).

## Purpose / Big Picture

`global_usage_definition_index` (`crates/bifrost-analysis/src/analyzer/global_usage_definition_index.rs`)
is the last large whole-workspace RAM materialization on the scan path: eleven maps per language
shard (fqn, normalized fqn, identifier, file-identifier, two direct-children maps, a
types-by-package map, and a four-map package catalog), holding owned key strings and keeping
every `CodeUnitInner` alive. It is built lazily into a `OnceLock`, has no weight, no budget,
and no in-place invalidation: any non-empty `update()` allocates a fresh `OnceLock`, so a
one-file edit discards everything and the next consumer pays a full rebuild. On the rustc tree
it is the dominant driver of the ~15.5 GB resident footprint that accrues before the usage-graph
phase (issue #1847; attribution inferred from the RSS ladder, to be confirmed by this plan's
baseline). Two amplifiers are part of the defect: `MultiAnalyzer::global_usage_definition_index`
flat-maps every delegate, so one Rust-only question builds every language's shard (12 build
spans observed in a single `usage_graph` call); and `usage_facts_index` is a second chained
whole-workspace materialization built FROM this index (`usage_facts.rs:70`).

The disease is the one this campaign has now cured four times (RustUsageIndex, cargo routes,
reference contexts, suffix scans), and the cure is already half-shipped: the investigation's
decisive finding is that `AnalyzerDefinitionLookup` implementing `BoundedDefinitionLookup` over
store-backed queries ALREADY EXISTS AND SHIPS for forward `get_definition` /
`get_type_by_location` dispatch. Five of the index's operations have production-proven bounded
equivalents today. After this plan, every consumer asks a bounded question against `code_units`
rows and its five existing indexes (plus one new narrow package-catalog relation), nothing
workspace-sized lives in heap for definition lookup, and a file edit invalidates nothing beyond
the store's normal per-blob row replacement.

## Progress

- [x] (2026-08-08) Investigation complete: anatomy (11 maps), lifecycle (OnceLock, discard on
  update), amplifiers (MultiAnalyzer flat-map; chained usage_facts_index), consumer census
  (~80 sites: ~55 in usages/*_graph, 4 diagnostics, the rest scattered), and the
  replaceability table (5 operations already bounded in production; 5 more backed by existing
  store methods or existing schema indexes; package catalog needs one new relation;
  `package_types()` full enumeration needs an owner decision - 4 callers).
- [x] (2026-08-08) Milestone 0: baseline measured on rustc with the watcher fix landed. Report:
  `global-index-m0-baseline-v1.md` (session scratchpad). **The ~15.5 GB inference is CORRECTED:
  the index costs ~350 MB and 3.35 s, about 44x less than inferred.** Five shards build (not 12),
  each exactly once; `usage_facts_index` never builds on this path at all. Answering-regime peak
  RSS is 15.58 GB untimed / 17.49 GB timed, of which the index is ~2%. See
  `Surprises & Discoveries` for the corrections and Milestone 4 for the revised gate.
- [x] (2026-08-08, pre-M1, taken independently) The duplicate normalized maps are gone: the
  normalized views are now materialized only after a declaration actually renames, so an
  identity-normalizing shard reads them off the exact maps. Removes the measured 54.6 MB of
  the 185 MB Rust shard (30%) with no change to C#/Java/Scala lookup semantics.
- [x] (2026-08-08) RSS attribution investigation complete - the pass the STATUS line names as
  deciding whether any memory milestone returns. Report: `memory-attribution-v1.md` (session
  scratchpad). **The ~7 GB remainder is per-connection SQLite reader state (mmap of the cache DB
  plus page cache), scaled by host CPU count, not by anything the analyzer owns; and 1.3x-3.5x of
  the headline peak is RSS double-counting one mmap'd file.** See `Surprises & Discoveries` for
  the top-consumers table, the knob ladder, and the phase boundaries. The finding is recorded
  here as measurement; what the memory milestones become is an owner decision, not this pass's.
- [ ] Milestone 1: the package-catalog relation.
- [ ] Milestone 2: consumer migration, cohort by cohort.
- [ ] Milestone 3: `usage_facts_index` - same treatment or explicit retention decision.
- [ ] Milestone 4: delete the index; RSS/latency gate.

## Surprises & Discoveries

- Observation: the composition seam is already correct - per-language shards merged at query
  time (`DefinitionIndexHandle::Merged`); shards never overlap. The problem is one level down
  (each shard is a workspace materialization), which means migration can proceed per operation
  without touching cross-language composition.
- Observation (trap, preserved behavior): `direct_children_by_fqn` deliberately uses naive
  `rsplit_once('.')` rather than `default_parent_fq_name`; changing it regresses
  `csharp_issue701_...` (comment at `global_usage_definition_index.rs:410-425`). The bounded
  `direct_children_limited` path must be verified to match this semantics for the migrated
  callers.
- Observation (Rust caveat, measured): `exact_fqn`, `normalized_fqn`, and `content_qualifier`
  are empty/NULL for every Rust row; Rust identity lives in `fq_segments` + `short_name`. The
  package-catalog relation must not assume `content_qualifier` for Rust.

- **Correction (Milestone 0, measured 2026-08-08): the ~15.5 GB attribution is wrong by ~44x.**
  On the rustc tree (35,370 files) the whole index costs **~350 MB resident and 3.35 s** to build.
  Two independent methods agree: `/proc/self/statm` deltas measured around each shard build sum to
  350 MB, and a structural walk of all eleven maps sums to 197 MB (the ~1.8x gap is the shared
  `CodeUnitInner` payload the structural walk deliberately excludes to avoid double counting).
  The decisive datum is `rss_before_kb=9753404` on the first shard build: **the process is already
  resident at 9.3 GB before the index exists**, so an index contributing 350 MB cannot drive a
  15.58-17.49 GB peak. The Purpose section's "dominant driver of the ~15.5 GB resident footprint"
  should be read as retracted; it was flagged there as inferred and is now measured.

- **Correction: five shards build, not twelve.** The `MultiAnalyzer` flat-map amplifier is real (a
  Rust-only question does build four foreign shards) but it is bounded by workspace content, not by
  the analyzer registry: Cpp, JavaScript, TypeScript, Python, Rust. Those four foreign shards cost
  **36 ms and 1.3 MB in total**. The amplifier is a cleanliness argument, not a performance one.

- **Correction: no rebuild churn.** Every shard reports `build_count=1`. The discard-on-update
  defect is still in the code, but with the watcher loop fixed it is not being triggered
  constantly, which is precisely why this plan sequenced Milestone 0 after the watcher plan.

- **Correction: `usage_facts_index` never builds on the scan path.** Zero builds across an entire
  answering-regime `scan_usages` query, instrumented at the sole `OnceLock` init
  (`try_usage_facts_index_handle`), so absence means absence of a build, not a missed span. It
  contributes no time and no memory here. **Milestone 3's premise needs re-checking against a query
  shape that actually reaches it** before work is planned around it.

- **Discovery: 30% of the Rust shard is duplicate maps.** `by_fqn` and `by_normalized_fqn` have
  identical key counts and identical byte totals (266,834 keys / 45,895,885 bytes each), as do
  `direct_children_by_fqn` and `direct_children_by_normalized_fqn` (44,948 / 8,713,422). For Rust
  `normalize_full_name(fqn) == fqn`, so **54.6 MB of the 185 MB shard is pure duplication**. This is
  a smaller, faster, lower-risk change than the retirement and can be taken independently of it.

- **RESOLVED (2026-08-08, measured): the unattributed ~7 GB is SQLite reader state, and most of
  it is not real memory.** Report: `memory-attribution-v1.md` (session scratchpad). This entry
  replaces the earlier "Open: the memory is somewhere else" item, which asked for exactly this
  pass. The decisive observation is one line of `/proc/<pid>/maps` from a live answering-regime
  process: **`db_mappings=124 db_rss_MB=12318`** - 124 separate mappings of the same 848 MB
  `bifrost_cache.v17.db`, contributing 12.3 GB of RSS between them. `ReaderPool::new`
  (`store/mod.rs`) sizes each of the three reader pools at `available_parallelism()` (120 on the
  measurement host), and `configure_readonly_page_cache` (`cache_db.rs:414-424`) gives every
  pooled connection `mmap_size = 256 MiB` and `cache_size = -65536` (64 MiB). Top consumers of an
  8.17 GB peak on the rustc tree, established by a knob ladder that varies only those three
  values:

  | # | consumer | size at peak | growth phase | bounded or scaled by |
  | ---: | --- | ---: | --- | --- |
  | 1 | SQLite `mmap` of the cache DB, one mapping per pooled reader connection | **5.55 GB** (12.3 GB observed) | candidate discovery | `min(mmap_size, db size) x connections`; connections = host CPU count. **Shared, clean, reclaimable - RSS multiply-counts it** |
  | 2 | SQLite per-connection page cache | **1.32-2.82 GB** | discovery, then graph phase | `64 MiB x connections` -> 7.68 GB ceiling at 120 CPUs. Host-CPU-scaled, genuinely private |
  | 3 | Rust analyzer heap, everything else | 1.30 GB (120 s cell) to ~3.5 GB (300 s cell) | graph phase | workspace-scaled, modest |
  | 4 | `global_usage_definition_index`, all 5 shards | **0.354 GB** | graph phase, t=250-259 s | reproduces Milestone 0's 0.349 GB from a second probe |
  | 5 | binary, 123 thread stacks, loader | ~0.05 GB | startup | bounded |
  | - | `usage_facts_index` | 0.00 GB | never built | - |

  Knob ladder (same cell, same binary, peak RSS from `/usr/bin/time -v`): defaults **8.17 GB**;
  `cache_size` 2 MiB **5.16 GB**; `mmap_size` 0 **2.62 GB**; pool capacity 8 **4.12 GB**; all
  three **1.30 GB**. So **6.87 GB of the 8.17 GB peak is per-connection SQLite state**, and the
  analyzer owns the remaining 1.30 GB.

- **Correction: peak RSS is the wrong meter for this workload, by 1.3x-3.5x.** Measured
  simultaneously on live processes: v3 at its mmap peak is **17.30 GB RSS against 4.88 GB PSS**
  (the DB mapping alone is 12.37 GB RSS but only 38.9 MB private); HEAD at the same instant is
  11.67 GB RSS against 3.26 GB PSS. The campaign's 15.58/17.49 GB headline figures are dominated
  by one file counted once per mapping. **Milestone 4's RSS gate must be restated in PSS or
  Private_Dirty**, or it will move by far more than its own 0.35 GB margin purely from the host's
  core count and from when the kernel reclaims clean pages.

- **Correction: startup is not where the memory is, and the index builds after discovery, not
  before it.** Phase-boundary marks in a full answering-regime run: analyzer construction for six
  languages ends at t=6.2 s with **0.14 GB** resident; `candidate_discovery` runs t=14.7 -> 223.3 s
  and takes RSS 0.46 -> 2.67 GB with SQLite heap 0.08 -> 1.44 GB; the five `gudi_shard` builds fire
  at t=250-259 s, *inside* the graph phase, for +354 MB. Milestone 0's "9.3 GB already resident
  before the first shard build" was therefore not a startup cost and not a floor: it was
  per-connection SQLite state accrued during discovery, and it is transient (the mmap component
  peaks at t=400 s and is back to 0.13 GB by the end of the same run).

- **Correction: `max_duration_secs` is clamped to 300 s**
  (`SCAN_USAGES_MAX_DURATION_CEILING`, `scan_usages.rs:772`). Every "600 s budget" cell in
  Milestone 0, in the D4 gate, and in this pass ran a **300 s** deadline. Both lineages were
  always clamped identically, so no prior comparison is invalidated, but the label is wrong
  wherever it appears and no budget override can buy a longer sweep.

## Decision Log

- Decision: migrate consumers onto bounded lookups; do not persist the index and do not add a
  new resident structure. The package catalog is the only new store relation.
  Rationale: owner's data-in-DB principle; five operations already run bounded in production;
  IntelliJ ships no "all declarations" heap structure at all (research doc sections 4.2-4.3,
  6.3) - `code_units` + its indexes already are the stub-index level.
  Date/Author: 2026-08-08 / Fable (from the investigation; pending owner approval).
- Decision (OWNER, 2026-08-08, supersedes the cohort targets below where they conflict): the
  schema and its views are the store's interface. Consumers migrate onto call-site SQL against
  views, NOT onto more wrapper methods -- "prefer SQL to DAL" and "create a view as soon as a
  query shape has more than one client" are now recorded in AGENTS.md (section "SQL and the
  analyzer store"). Concretely for this plan: Milestone 1 additionally ships the liveness/
  generation views (live_code_units and siblings) that encode the invariants every query
  needs; cohort migrations write their queries at the call site against those views, reusing
  only shape-level row mappers; new pins are EXPLAIN QUERY PLAN assertions rather than Rust
  scan counters. Where a bounded wrapper method already exists and already serves (the five
  in-production operations), re-pointing onto it remains acceptable for cohort 1 -- the rule
  governs NEW query surface, and those methods may themselves be dissolved into view queries
  opportunistically.
  Rationale: the wrapper tax is measured (one query change touched 13 wrappers plus a trait in
  2ba5dda4; the 366cb82e and 3d57cafd reports both cite wrapper plumbing as a design
  constraint), the database is in-process so there is no boundary to mediate, and invariants
  belong in the schema -- views make call-site SQL unable to forget them.
  Date/Author: 2026-08-08 / Jonathan (direction), Fable (recorded).
- Decision: milestones ship per-operation cohorts, not per-consumer big-bang. Cohort 1 is the
  five operations whose bounded equivalents already ship (mechanical re-pointing + parity
  tests); cohort 2 the five rows-backed ones (store methods/indexes exist, call paths need
  plumbing); cohort 3 the package catalog; `package_types()` last, behind its own decision.
  Rationale: each cohort is independently revertable and independently testable against the
  live index while it still exists (the frozen-equivalence idiom applies: the resident index IS
  the frozen reference until Milestone 4 deletes it).
  Date/Author: 2026-08-08 / Fable.

## Outcomes & Retrospective

(To be written at milestone completions.)

## Context and Orientation

Key files: `global_usage_definition_index.rs` (the index; build at
`tree_sitter_analyzer.rs:5603-5684`; discard-on-update at `:2415` pinned by
`shared_usage_indices_reuse_generation_allocations_and_reset_on_update`),
`multi_analyzer.rs:773-785` (the every-delegate amplifier), `usage_facts.rs` (the chained
second index), the `BoundedDefinitionLookup` trait and `AnalyzerDefinitionLookup` (find with
`rg BoundedDefinitionLookup crates/`), and the store methods named in the replaceability table
(`sql_bounded_definitions_vec`, `direct_children_for_unit_limited`,
`declaration_rows_by_package_for_langs`, `declaration_rows_by_package_prefix_page`,
`declaration_candidate_rows_by_identifier_for_langs`,
`declaration_member_rows_for_owner_for_langs{,_limited}`, plus schema indexes
`idx_code_units_lang_normalized_fqn_declarations` and
`idx_code_units_lang_package_simple_type_declarations`). The full consumer census and the
operation-by-operation table are in the investigation report (check into `.agents/docs/` with
Milestone 0's first commit).

## Plan of Work

Milestone 0 - baseline (measurement only): DONE, 2026-08-08. Report
`global-index-m0-baseline-v1.md`. Measured on rustc (35,370 files) in an answering-regime
`scan_usages`, at `9263e2a5`, with the watcher fix landed:

| shard | builds | build time | RSS delta | structural | live blobs | units |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Rust | 1 | 3,317.4 ms | 349 MB | 185.4 MB | 34,935 | 316,099 |
| Cpp | 1 | 15.9 ms | 0.72 MB | 1.44 MB | 101 | 3,036 |
| Python | 1 | 9.8 ms | 0.25 MB | 0.60 MB | 33 | 990 |
| JavaScript | 1 | 6.2 ms | 0.22 MB | 0.38 MB | 156 | 771 |
| TypeScript | 1 | 4.4 ms | 0.13 MB | 0.41 MB | 27 | 795 |
| **TOTAL** | **5** | **3.35 s** | **~350 MB** | **~188 MB** | 35,252 | 321,691 |

`usage_facts_index`: **0 builds**. Answering-regime peak RSS: **15.58 GB untimed / 17.49 GB
timed**, of which 9.3 GB is already resident before the first shard build. It did NOT confirm the
#1847 attribution; it corrected it (see `Surprises & Discoveries`).

**This result should be taken back to the owner before Milestone 1 starts.** The plan's
justification rests on a footprint claim that is now measured at ~2% of the answering-regime peak.
The design argument for retirement stands on its own (an unweighted, unbudgeted, whole-workspace
`OnceLock` with no in-place invalidation is a real defect, and five operations already have
production-proven bounded equivalents), but the expected payoff is ~350 MB and ~3.4 s, not
~15.5 GB. Two cheaper items surfaced that may deserve priority: the 54.6 MB of duplicate Rust maps,
and whatever owns the unattributed ~7 GB.

Milestone 1 - package catalog relation: the four catalog maps (`packages`, `files_by_package`,
`package_languages`, `child_packages_by_parent`) answer bounded questions
(`package_container_exists`, `child_packages`, `package_languages`, `package_files`) that today
force the whole index into RAM (`summaries.rs:422` asks four of them for ONE package). Design a
narrow ancestor relation derivable from existing rows at persistence time or query time -
`content_qualifier`-based for the languages that populate it, `fq_segments`-derived for Rust
(the measured caveat). Smallest correct shape wins; follow the migration-0016/0017 conventions
if rows are added (schema bump, epoch salt, cost accounting, content-stability).

Milestone 2 - consumer migration in cohorts (see Decision Log): each cohort re-points its
consumers, adds parity pins against the still-live index, and keeps behavior byte-identical
(notably the `rsplit_once('.')` children semantics). The MultiAnalyzer amplifier dissolves as
consumers stop asking for merged handles; if any cohort still needs the handle transitionally,
make the merge lazy per-language as an interim (recorded, small).

Milestone 3 - `usage_facts_index`: enumerate its consumers the same way; either migrate onto the
same bounded surface or, if its content is genuinely derived-and-small, keep it with honest
bounds. Its build must stop consuming the definition index either way.

Milestone 4 - delete the index and the `OnceLock` lifecycle, update the reuse/reset test, and
gate. **Gate numbers, now set by the Milestone 0 baseline rather than left abstract:**

- Answering-regime peak RSS on the rustc tree **at or below 15.23 GB untimed** (baseline 15.58 GB
  minus the measured 0.35 GB of shards), same cell and same process model as Milestone 0.
- **No scan-path latency regression** on the standard cells: cell (a) warm <= 5.7 s, cell (b) warm
  <= 5.4 s, cell (c) edited <= 6.5 s, all at comparable host load, and index build time (3.35 s)
  removed rather than relocated.
- The two banned symbols absent from the tree.

Two cautions carried from Milestone 0. First, **this gate is modest by construction** -- it is 2%
of the peak, and it will be hard to distinguish from host noise unless the run is on a quiet box;
budget for repetitions and a load-matched comparator. Second, the baseline was taken on a heavily
loaded host (1-min loadavg 84-486), so the *latency* figures above should be re-taken quietly
before they are used as a pass/fail bar; the RSS and count figures are load-insensitive and stand.
On gate failure, stop and report per house rule.

Three corrections from the 2026-08-08 RSS attribution pass, recorded here because they land on
this gate specifically (see `Surprises & Discoveries`). **(a) The RSS bar as written is not
measurable to its own precision.** Peak RSS on this workload is 1.3x-3.5x the process's unique
footprint, because 100-124 reader connections each map the same 848 MB cache DB and RSS counts
those pages once per mapping; the multiplier varies with the host's core count and with when the
kernel reclaims clean pages, which is far more than the 0.35 GB the gate is trying to detect. A
usable bar must be stated in **PSS or Private_Dirty**. **(b) The 15.58 GB baseline is not a
constant of the workload**; the same cell measured 8.17-11.89 GB peak in this pass, on the same
tree, differing only in host load and reader-connection count. **(c) The latency bar's budget
label is wrong**: `max_duration_secs` is clamped to 300 s
(`SCAN_USAGES_MAX_DURATION_CEILING`), and the deadline is wall-clock, so under load the same
budget buys different amounts of work; per the owner's 2026-08-08 directive, comparisons should
be stated in CPU-seconds (user+sys) with loadavg as a label.

## Validation and Acceptance

Standard ladder per milestone (fmt, check, nextest analysis + workspace usages/searchtools
selections, featureless clippy); comprehensive all-features clippy at the final push checkpoint.
Documented pre-existing failures; stash-verify new ones. Every parity pin demonstrated
fail-before (against a deliberately broken re-pointing). Acceptance is the Milestone 4 gate plus
suite-wide parity throughout.

## Idempotence and Recovery

Cohorts are independently revertable; the index remains live (and authoritative for parity)
until Milestone 4. Any store relation added in Milestone 1 follows the additive-migration
pattern. Measurement milestones write only reports.

## Artifacts and Notes

Investigation: `fenced-followups-investigation-v1.md` + `followup-evidence/` (session
scratchpad; check in at Milestone 0). Measured density (this repo, warm): Rust shard 1,106
blobs -> 62,489 units, 468.6 ms build, 38,849 distinct identifiers. Issue #1847. Related
history: usage-v2 plan (`rust-usage-index-v2.md`) - this plan is its direct sequel and reuses
its idioms (frozen reference, counter pins, cohort migration, kill-gate discipline).

## Interfaces and Dependencies

End state: no `global_usage_definition_index`, no merged resident handle; consumers hold
`BoundedDefinitionLookup`-shaped access or direct store queries; one narrow package-catalog
relation; `usage_facts_index` either retired or honestly bounded. The `package_types()`
full-enumeration API (4 callers) is resolved per the owner's Milestone-2-time decision: paged
store enumeration, per-question redesign of the callers, or explicit retention with bounds.
