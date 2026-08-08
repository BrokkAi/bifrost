# Retire global_usage_definition_index: bounded lookups over store rows

This ExecPlan is a living document maintained per `.agents/PLANS.md`. Sections `Progress`,
`Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current.

STATUS: PLAN FOR OWNER REVIEW. Do not implement until approved. Sequenced AFTER the watcher
plan (`watcher-git-event-exemption.md`): the watcher loop currently discards this index
constantly, so honest baselines require the loop fixed first.

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
- [ ] Milestone 0: baseline. With the watcher fix landed, measure build count, build time, and
  resident size per shard on a large tree (confirm or correct the ~15.5 GB inference).
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

## Decision Log

- Decision: migrate consumers onto bounded lookups; do not persist the index and do not add a
  new resident structure. The package catalog is the only new store relation.
  Rationale: owner's data-in-DB principle; five operations already run bounded in production;
  IntelliJ ships no "all declarations" heap structure at all (research doc sections 4.2-4.3,
  6.3) - `code_units` + its indexes already are the stub-index level.
  Date/Author: 2026-08-08 / Fable (from the investigation; pending owner approval).
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

Milestone 0 - baseline (measurement only): with the watcher fix landed, one large-tree session;
record shard build counts/times/sizes and answering-regime RSS. This confirms the #1847
attribution and sets the Milestone 4 gate numbers.

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
gate: answering-regime RSS on the large tree at or below the Milestone 0 baseline minus the
measured shard sizes; no scan-path latency regression on the standard cells; the two banned
symbols absent from the tree. On gate failure, stop and report per house rule.

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
