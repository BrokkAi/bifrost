# Rust usage index v2: per-file facts in the store, composition at query time

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Bifrost's Rust usage analysis today is powered by `RustUsageIndex` (`crates/bifrost-analysis/src/analyzer/rust/usage_index.rs`), a single struct of seventeen workspace-wide `HashMap`s (exports, importer reverse edges, identity maps, module routing, macro ranges) built wholesale into process heap. On a Firefox-scale workspace this build costs minutes and about 10.8 GB of resident memory, and `RustAnalyzer::update` / `update_all` drop the entire index on any file change, so the next query pays a full rebuild. Issue #1758 measured all of this; the owner rejected both "keep it but schedule it better" and "persist the monolith to SQLite", because a persisted monolith still rebuilds as a monolith.

After this change, there is no Rust usage index to build at all. Per-file facts (what a file exports, imports, declares as modules, and which identifiers occur in it) are rows in the per-workspace SQLite store, written by the same pass that already writes `code_units`, keyed by content hash (`blob_oid`) like everything else in the store. Usage questions are answered at query time by indexed lookups over those rows plus short, memoized cross-file walks. A single-file change costs one re-parse and a handful of row inserts -- the old blob's rows simply orphan for the existing GC -- plus clearing a few bounded in-memory caches. Nothing whole-workspace is ever rebuilt, and nothing workspace-sized lives in heap.

The design transliterates IntelliJ's indexing architecture, verified against `/home/jonathan/Projects/intellij-community` at commit `277409ac3905ece64efd598bfeada8fc69fdb4f0` and written up with code citations in the research report (see Artifacts). The rule taken from there: anything that grows with workspace size lives on disk; anything in heap is bounded or soft. You can see v2 working by running the new behavior tests (a usage query answers correctly from a cold store with no build step; a file edit invalidates only that file's contribution), and by the Milestone 4 benchmark showing a large-workspace update-then-query cycle completing in seconds where v1 took minutes.

## Progress

- [x] (2026-08-07) Root cause and measurements recorded on issue #1758; owner rejected monolith persistence and directed an IntelliJ-style redesign.
- [x] (2026-08-07) IntelliJ mechanism research completed with code citations; synthesis mapped each `RustUsageIndex` product to per-file, inverted-derivable, or genuinely cross-file (report in Artifacts).
- [x] (2026-08-07 12:05Z) Research report copied to `.agents/docs/intellij-indexing-research-2026-08.md`; Artifacts pointer updated so the plan no longer depends on a session-temporary path.
- [x] (2026-08-07 14:10Z) Milestone 1: per-file Rust usage fact tables in the store, written at analysis time. Migration `0016-rust-usage-facts.sql`, cache schema version 15 -> 16, extraction in `parse_rust_file`, both store write paths, reader plus inverted lookups, ten tests.
- [x] (2026-08-07 17:40Z) Milestone 2a: `RustUsageQueries` exists and is the store-backed query layer -- per-file fact reads behind one bounded `(generation, blob)`-keyed cache, the three inverted lookups, locality bucketing, and early-out. Two products migrated onto it end to end: `module_at_byte` (the `module_extents` map is gone from `RustUsageIndex`, and the build no longer opens a syntax tree for it) and the re-export half of `export_index_of_declarations`. Seven tests, including two equivalence pins against the syntax-tree projection.
- [x] (2026-08-07 21:30Z) Milestone 2b: `identities_by_name` is gone from `RustUsageIndex`. The per-file declaration-identity derivation is now one shared function that both the v1 build and the query layer call, and the workspace-wide name bucket is replaced by the store's indexed short-name lookup plus per-candidate verification. `module_importers` and `importer_reverse` did NOT move; the Decision Log records why they cannot until 2c exists.
- [x] (2026-08-07 23:55Z) Milestone 2c: migrate the cross-file group (`module_files`, `module_aliases`, `physical_owners`, `actual_crate_roots`, export chains) to memoized bounded walks, add the `module_resolution` / `export_chain` / `resolve` caches, and finish the consumer switch so `RustUsageIndex` is unused. Now also carries `module_importers` and `importer_reverse`, whose verification step IS the forward-edge computation 2c introduces. Decomposition and dependency order recorded in the Decision Log.
- [x] (2026-08-08 02:40Z) Milestone 3: invalidation and readiness. The v1 warm is gone from every path: `warm_usage_index` is deleted, `warm_query_indexes` and the MCP `StartupIndexWarm` thread run the new per-file fact catch-up instead, and `usage_index_ready` reports the catch-up set rather than the unread index. Catch-up policy implemented with the threshold constant (20), inline below it and on the dedicated build pool at or above it. `update` / `update_all` audited: they already rotate every v2 cache correctly, and the pinning test proves it.
- [ ] Milestone 4: kill-gate benchmark on a large Rust workspace; gates defined below must pass. RUN 1 (2026-08-07): all three gates FAIL for v2, and fail identically for v1. The failure is not attributable to v2 -- `RustAnalyzer::build_cargo_routes` consumes 87-97% of every cell. RUN 2 (2026-08-08, after both prerequisites landed): gates 1 and 2 still FAIL; gate 3 passes as measured but the measurement is not load-bearing. The gate cells still do not reach either usage layer, because `build_cargo_routes` is still 87-91% of the scan -- now 9-19 s of Cargo-topology orchestration rather than 34-44 s of parsing. Supplementary runs at a raised budget DID reach both layers and produced the first direct comparison: `RustUsageIndex::build` 83.68 s against `rust_fact_catch_up` 0.20 s. They also found a new v2-specific defect: at a 60 s or 120 s budget the v2 scan does not terminate where v1 does. RUN 3 (2026-08-08, after 575c2ffb and 13bb6263): gate 2 PASSES (6.91 s vs 10 s); gate 1(a) fails by 10 percent (5.51 s vs 5 s, at 2.5x better than the comparator); every other failure is proven shared and pre-existing (#1839 uncancellable fuzzy-resolve storm at 653-749 s on both lineages, the graph_find_usages phase at 23.42 GB in the only run that ever resolved). GATE RESOLVED BY OWNER DECISION (2026-08-08): the gate is split -- the usage-layer comparison is declared answered and Milestone 5 is UNBLOCKED; the shared scan-pipeline walls move to their own tracked stream (#1839, #1748, the graph phase) ahead of the next benchmark campaign. See the Decision Log entry of the same date.
  - [x] (2026-08-08) Milestone 4 prerequisite, issue #1793: `RustCargoRouteIndex` no longer hydrates and parses every analyzed Rust file. The three things the build read out of each file's tree are per-blob rows written at analysis time (migration `0017-rust-module-routes.sql`, cache schema 16 -> 17, four tables, extraction in `parse_rust_file`), and the build is one batched read of them plus the Cargo manifests, which measurement showed are cheap. Cargo manifests stay on disk. The rerun of the gate itself is a separate task.
  - [x] (2026-08-08) Milestone 4 follow-up, issue #1809: the v2-specific non-termination the rerun found is diagnosed and fixed, and the two candidate causes it recorded were BOTH real. The cost cause is #1809 and the mechanism is exponential, not superlinear: the 2c cycle handling answered a re-entry from the value so far and then iterated THAT frame to a local fixed point while keeping the result out of the analyzer cache, so in a cycle every member iterated over every other member's whole subtree and none of them was ever memoized. `bindings_at` is now one chaotic iteration over everything the outermost frame reaches -- one computation per key per round, iterate until a round changes nothing, then memoize every key that round settled. The cancellation cause is independent and was fixed unconditionally: `RustUsageWalks` now carries the request's `keep_going` predicate, nine loops poll it, and every one of the nine analyzer caches is gated on it so a truncated answer cannot be memoized for the generation. Measured on the synthetic cyclic fixture, one `bindings_at` at four neighbours per module: 3.05 s before and 0.017 s after at eight modules, 69.4 s before at ten, no result in 420 s before at twelve, 0.081 s after at twenty-four. The gate rerun remains a separate decision.
  - [x] (2026-08-08) Milestone 4 prerequisite, issues #1748 and #1774: the `sql_definition_candidates` half of the shared candidate-discovery storm is gone, and the #1774 live-path scan is memoized per request. Three changes, all in shared code and all language neutral: `definitions(fq_name)` is memoized for the life of an `AnalyzerQueryScope`; the whole-workspace live-path walk that every non-persisted declaration scan re-took is materialized at most once per request, with the narrowing `keep` predicate deliberately left outside the memo; and `ImportAnalysisProvider` gained a `prefetch_import_targets` hook so the workspace-wide importer walk resolves every import target it will ask about in one chunked `IN` seek instead of one point lookup per `use` statement. On the counter-pinned fixture a warm Rust usage query charges 1 batched read and 1 point lookup where 32 import statements previously charged one each. The other measured multiplicity, `project::collect_workspace_files` running 64-137 times, is NOT fixed here and is not attributed; see Surprises. The gate rerun remains a separate task.
  - [x] (2026-08-08) Milestone 4 prerequisite, issue #1817: the Cargo-topology orchestration the rerun measured at 9-19 s is decomposed and no longer grows with the workspace's crate and target count. The profile located the cost as a product rather than a sum -- at a constant 832 files, 4 crates and 16 targets cost 0.074 s while 128 crates and 512 targets cost 0.493 s -- and named four loops: the per-crate search of the whole file list for that crate's target roots, the per-crate rebuild of the analyzed-file set inside the membership walk, the per-target sweep of the whole file list for macro visibility and its twin in the passthrough fixed point, and the per-(file, root, target) scan of every route entry in the workspace. The manifest topology is now discovered once instead of once per membership pass, files are grouped under the manifest directories that could auto-discover them instead of being searched per crate, one membership walk is seeded from every target root at once, the per-target stages iterate the inverse of the membership map, reachable-root expansion is computed per root, and a gate-free file's module edges are resolved once per (file, is_crate_root). Same four stages, same answers: the pre-#1817 orchestration is frozen under `#[cfg(test)]` and all seven products are compared against it. Measured on the synthetic fixture, 1,792 files with 512 targets: 1.156 s before, 0.078 s after.
  - [ ] (2026-08-08) Milestone 4, RUN 3, after all four fixes. **Gate 1(a) FAILS narrowly (5.51 s median against 5 s). Gate 1(b) FAILS by 130x, on a cause proven shared and pre-existing. Gate 2 PASSES on its stated bar (6.61 s median against 10 s), the first gate this plan has passed. Gate 3 passes at the gate budget and fails at any budget that lets the query answer. Milestone 5 stays BLOCKED.** Both post-run-2 fixes are verified at rustc scale: `build_cargo_routes` falls from 10.14-11.90 s (87-90% of the scan backend) on the frozen V1P comparator to 0.61-0.78 s (0.1-21%) on HEAD, and run 2's non-termination is gone -- every budget from 30 s to 600 s terminates, paired against V1P at each. Both proof spans fire in the supplementary runs, so the two usage layers were compared for the first time, and the comparison corrects run 2's headline: the query work moved from `RustUsageIndex::build` (88.42 s) to `usage_candidate_files_while` (86.84-87.77 s), a wash, while `rust_fact_catch_up` (0.07-0.18 s) replaces the warm rather than the build. At a 600 s budget HEAD **answered the query** -- `resolved=1`, 11 hits, partial -- which no lineage had ever done in runs 1 or 2. Numbers and decomposition in Outcomes; the plan stops here.
- [ ] Milestone 5: delete v1 (the seventeen-map struct and its warm machinery), close out issues and docs. BLOCKED by the Milestone 4 gate.

## Surprises & Discoveries

- Observation: Bifrost's store is already most of the IntelliJ shape. `code_units` plus `idx_code_units_lang_short_name` is an inverted name-to-blob index (the `IdIndex` analogue at declaration granularity); `import_statements` / `import_details` already persist per-file import facts; and content-hash keying makes the per-file up-to-date check free, where IntelliJ needs `IndexingStamp` plus a VFS flag. The genuinely missing piece is one inverted table: identifier occurrences.
  Evidence: `crates/bifrost-core/migrations/cache/0001-current-baseline.sql` and the research report sections 7.2-7.5.
- Observation (Milestone 1): the export projection has two halves with different natures. `export_index_of_declarations` (`rust/graph_support.rs`, around line 285) builds `ExportEntry::Local` entries from the file's declarations, which needs `export_visible_declarations` and `is_module_export_candidate` -- analyzer state that does not exist inside `parse_file`, where the tree lives. Its second half, the re-export entries, is purely syntactic: root-level `use_declaration` nodes with non-private visibility. Only the second half is a new fact; `Local` exports are `code_units` rows plus a visibility question. `rust_exports` therefore persists re-exports only.
  Evidence: `crates/bifrost-analysis/src/analyzer/rust/graph_support.rs` lines 285-360; `extract_exports` in `crates/bifrost-analysis/src/analyzer/rust/facts.rs`.
- Observation (Milestone 1): `rust_exports` rows are a filtered projection of the same `use` declarations that produce `rust_import_targets` rows, so the two tables overlap. Keeping them separate is deliberate, not an oversight: "which files export the name X" and "which files import the module M" are different questions with different keys, and a narrow table plus its own index makes each one indexed lookup instead of a scan-and-filter over the wider table. That is the IntelliJ shape (one index per question).
- Observation (Milestone 1): the store's blob rows are content-hash keyed, so nothing persisted in these tables may be path-derived. `rust_module_extents` and `rust_import_projection` both take a `base_module` argument that is normally `rust_package_name(file)` -- a path-derived string. Passing the empty base at extraction time yields names relative to the file root, which is the content-stable form the reader recomposes, exactly as `code_units.content_qualifier` already works. The test `rust_fact_rows_are_stable_across_a_re_analysis_of_the_same_content` pins this by analyzing identical bytes at two different paths and asserting identical rows.
  Evidence: `crates/bifrost-analysis/src/analyzer/rust/imports.rs` `rust_module_extents`; the named test in `crates/bifrost-analysis/src/analyzer/store/mod.rs`.
- Observation (Milestone 2a): the plan's classification is right about WHAT is cross-file, but it understates the coupling. The three cross-file products are not independent walks over per-file rows: `importer_reverse` needs `module_aliases` and `physical_owners` to turn one importer's `use` list into edges, `module_aliases` is built from every file's imports, and `physical_owners` is built from `module_files` plus every file's declaration identities. So `binding_seeds` -- the entry point every consumer reaches -- transitively needs all three. Migrating them one product at a time is possible only for the per-file group; the cross-file group has to move as one piece.
  Evidence: `build_importer_reverse` (`rust/usage_index.rs`) takes `module_files`, `module_aliases` and `physical_owners` as parameters; `RustPhysicalOwnerIndex::build` takes `module_files`, `physical_roots`, `declaration_identities` and `actual_crate_roots`.
- Observation (Milestone 2a): `importer_reverse` is keyed by TARGET file, and the persisted inverted key is the module path AS WRITTEN. Those do not match: one target module is written `crate::a::b`, `super::b`, `self::b`, `mycrate::a::b`, or through an alias, so "which files import target T" cannot be a `rust_import_targets` lookup. It has to become the IntelliJ shape -- candidates are the files whose text mentions the target's NAME (`rust_identifier_occurrences`), then each candidate's own forward edges are computed and filtered. That is exactly why the identifier-occurrence table is the load-bearing one, and it is a rewrite of `binding_seeds` rather than a re-pointing of it.
- Observation (Milestone 2a): the store-backed path works without a git repository. `resolve_live_oids` (`tree_sitter_analyzer.rs`) falls back to hashing files directly when `store_context.liveness` is `None`, and publishes the result into `store_context.live_paths` either way, so `LiveSnapshot` answers both blob-to-files and file-to-blob in a plain directory too. That removes the availability risk that store-backed usage analysis would silently degrade outside git checkouts.
- Observation (Milestone 2b): two of the three `identities_by_name` call sites in `usage_reference_at` were per-file questions wearing a name-search costume. Both took the workspace-wide bucket for a name and then filtered it by `identity.file == <a file the caller already holds>` -- the reference's own file in one case, the resolved target file in the other. Only the third, which knows the resolved MODULE but not which file declares the terminal, is a genuine name search. Applying the filter first turns two workspace-wide map probes into one per-file read each, and it is exactly equivalent because the filter was already there.
  Evidence: `usage_reference_at` in `rust/usage_index.rs`, the three former `index.identities_by_name.get(...)` sites.
- Observation (Milestone 2b): the candidate false positive that matters here is not a prose mention. `identities_named`'s candidate source is the store's short-name index over `code_units`, which only ever offers declarations, so a comment or string can never produce one. The real false positive is a declaration whose structural parent is not a module -- an associated function in an `impl` block -- which the v1 derivation skipped (`Some(_) => continue`) and which therefore has no identity and no domain. Verification is what rejects it; the regression test `a_candidate_file_without_a_module_scope_identity_is_rejected` fails when that skip is removed (demonstrated).
- Observation (Milestone 2b): `module_importers` is no more independently movable than `importer_reverse`. It looks like a separate product, but it is derived from `importer_reverse` in the v1 build, and its verification question -- "does this candidate file have an import edge whose target module is M" -- is answered only by computing that candidate's forward edges, which needs alias routes plus module-file resolution. Its consumer, `importers_of_seeds`, produces a candidate file set, so an unverified superset would still be correct; that shortcut was rejected because it changes the number of files the forward scan visits, and nothing in the current suites would catch the resulting latency regression on a large workspace.
- Observation (Milestone 2c design, the sequencing constraint): 2c cannot land in pieces, and the reason is a performance regression rather than a correctness one. Every cross-file structure is consumed from inside another structure's EAGER build: `module_files.resolve_segments` is called from the `build_module_alias_routes` fixed point (which iterates every import up to `import_count` times) and again from `build_importer_reverse` (twice per named import). Today those calls are `HashMap` probes against prebuilt maps. Replace one of them with a memoized lazy walk while the eager builds remain, and the fixed point pays a moka probe plus, on a miss, an indexed store query per iteration -- inside the loop that already dominates the build. The interim state would therefore be slower than either endpoint, with no Milestone 4 benchmark yet in place to catch it. So the cross-file group and the eager build it feeds have to be removed in the same commit.
  Evidence: `usage_index.rs` lines 2938 and 2990 (`routes.resolve_segments(module_files, ...)` inside the `for _ in 0..=import_count` fixed point) and 3068/3122 (`module_aliases.resolve_segments(module_files, ...)` per import in `build_importer_reverse`).
- Observation (Milestone 2c design): the module-file half of the cross-file group needs no new index at all -- the two maps it is built from already exist in indexed form elsewhere in the analyzer. `RustModuleFiles::by_package` is `RustPackageFileIndex::files_in_package` (`graph_support.rs`, a path-only `OnceLock` built from the same `get_analyzed_files()` set), and `RustModuleFiles::inline_by_name` -- keyed by `declaration.fq_name()` for every `declaration.is_module()` -- is `analyzer.definitions(&package).filter(CodeUnit::is_module)`, an indexed `code_units` lookup by fq name. Confidence: verified by reading both constructions, not yet by test. One trap: `graph_support::resolve_module_files` looks like the same function and is NOT -- it additionally filters `is_external_module_declaration` and disambiguates rooted-path collisions by Cargo target relation, so it must not be substituted for `RustModuleFiles::resolve`.
- Observation (Milestone 2c design): three of the cross-file products are not walks at all once the maps are gone. `physical_roots` is the pure function `ModuleKey::new(file, &rust_package_name(file))` gated on analyzed membership. `actual_crate_roots` is the per-file predicate `rust_package_name(file) == rust_crate_root_package(file) || cargo_routes.target_roots_for_file(file).contains(file)`. And `RustPhysicalOwnerIndex::inferred_crates_by_file`, which looks workspace-wide, reduces to "does any file in package C satisfy that predicate" -- one indexed package lookup, because an actual crate root is by definition a file whose package IS its crate root.
- Observation (Milestone 2c implementation): the 2c design observation about module-file resolution was half right and half wrong, and the wrong half was load-bearing. `RustModuleFiles::by_package` is indeed `RustPackageFileIndex::files_in_package`. `inline_by_name` is NOT `analyzer.definitions(&package).filter(is_module)`: `definitions(fq_name)` keeps ONE declaration per fq name, and two files legitimately declare the same module path -- a `pub mod messenger;` in `lib.rs` and a `pub mod messenger { ... }` inside another file both have fq name `messenger`. Substituting it silently dropped one backing file per collided module, which made `crate::tracing_bridge` resolve to two files instead of three and made `module_domains` answer `None` for every module declared only by the losing file. The correct replacement is the store's short-name index filtered by `is_module() && fq_name() == package`, which is what `identities_named` already uses in 2b.
  Evidence: probe output on the `scan_usages_by_reference_finds_exact_fully_qualified_rust_type_owners` fixture -- `definitions("tracing_bridge")` returned only `unrelated.rs`, `lookup_candidates_by_identifier("tracing_bridge")` returned `lib.rs` and `unrelated.rs`.
- Observation (Milestone 2c implementation): the downward physical-owner walk has two halves and only one of them inverts through an index. The module half ("the files backing `M` whose own physical root IS `M`") inverts to one indexed lookup over `files_for_module(parent(M))`. The path half derives children from the DECLARING file's path (`rust_module_files_from_segments`), so there is nothing to look up; it is inverted by trying every prefix of the child's own module path as the declaring file's module root, which yields four candidate declaring files per directory level (`P/lib.rs`, `P/main.rs`, `P/mod.rs`, `P.rs`), and verifying each against its real child set. A superset plus verification is safe; a missed candidate would silently disconnect a file from its crate.
- Observation (Milestone 2c implementation): the v1 alias fixed point does not compute the least fixed point of the lazy recursion. `by_alias` only ever grows, and `resolve_segments` is called at every stage of the iteration, so the map accumulates routes computed against PARTIAL alias knowledge as well as the converged ones -- and which partial states occur depends on file iteration order. The lazy recursion computes only the converged value. The difference can only show up where an import path's first segment is both a real submodule and an alias, and no case in the Rust usage suites distinguishes them. Recorded as a known, untested-either-way divergence rather than a claim of exact parity.
  Evidence: `build_module_alias_routes` writes into `routes.by_alias` inside the `for _ in 0..=import_count` loop and reads through `routes.resolve_segments` in the same iteration.
- Observation (Milestone 2c implementation): the cycle that actually breaks the export-chain recursion is length one, not the mutual re-export everyone designs for. A module that republishes a name declared beside it -- `pub(crate) use target_macro;` next to the `macro_rules! target_macro` it renames -- makes `bindings_at(file, module)` re-enter itself through its own import edge. The v1 worklist never noticed, because it seeded every declaration in the workspace before propagating anything. Answering the cycle with nothing loses the `pub(crate)` visibility upgrade, so the macro stays module-private and every cross-module invocation disappears. Two mechanisms fix it and either one suffices in isolation: seeding the cycle answer with the module's declared bindings, and iterating the frame to a local fixed point when a cycle was hit. Both are kept, because the mutual case needs the iteration and the self case is cheaper with the seed.
  Evidence: `rust_graph_tracks_bare_macro_invocations_through_structured_visibility` failed with the plain recursion and passed once the frame iterated.
- Observation (Milestone 2c implementation): nine inline `moka::sync::Cache` handles made `RustAnalyzer` large enough to trip clippy's `large_enum_variant` on `AnalyzerDelegate`. The caches now live in one `Arc<RustWalkCaches>`, which is both smaller and the natural place to document the three cache concerns together.
- Observation (Milestone 3): the staleness bug this milestone was told to look for is not there, and the reason is worth pinning rather than assuming. `RustAnalyzer::update` and `update_all` do not mutate in place: each constructs a whole new `Self` with a fresh `RustWalkCaches`, a fresh `declaration_facts`, a fresh `rust_usage_facts` and fresh `cargo_routes` / `package_file_index` cells, so the 2c claim that the analyzer instance IS the generation holds for the real update path. The new test edits a file through `analyzer.update(...)` after a query has populated every walk cache with the pre-edit answer; it passes on HEAD, and it fails (`the edited import must bind the target`) the moment `update` is made to carry `walk_caches` across, which is the probe that proves it is a guard rather than a restatement.
  Evidence: `rust/mod.rs` `update` / `update_all`; `a_single_file_edit_is_reflected_by_the_next_usage_query` and the `Arc::clone(&self.walk_caches)` probe.
- Observation (Milestone 3): the gap that does exist is invisibility, not staleness, and it is worse than slowness. Every v2 answer is composed from the fact rows of live blobs, and the inverted lookups go blob-to-file, so a live file whose blob has no rows is not answered slowly -- it is silently absent from the result. That is what makes the catch-up a correctness mechanism rather than a latency one, and it is why the hook sits at the walk constructor, before any candidate set is formed.
- Observation (Milestone 3): byte-identical files share one blob, and the persistence layer treats two prepared blobs with the same key in one batch as a hard error ("duplicate prepared blob key in reconcile batch", an assert). A catch-up batch is a set of FILES, so it must pick one representative per blob key exactly as `reconcile_file_states` does with `representative_by_blob_key`. Found by a fixture whose twenty-one files had identical bodies -- an artificial case that models a real one (generated modules, re-exported stubs).
- Observation (Milestone 3): a catch-up must not persist a file whose disk bytes no longer hash to its live oid. Blob rows are content-addressed and shared, so filing the new content's facts under the old blob would corrupt the answer for every file that ever had those bytes; a missing row is recoverable, a lying row is not. The catch-up therefore skips those files and leaves them to the next `update`, which resolves their real oid anyway. Note this case cannot arise from an edit alone: an edited file's live oid still has its old rows, so it is never IN the catch-up set.
- Observation (Milestone 3): the v1 probe conflated two questions that v2 has to separate. "Is the index built" answered both "has the background preparation happened" and "would a query wait", because for a build they are the same event. Under v2 there is no build: a freshly opened workspace would wait for nothing, so it is READY, but it has not WARMED. `usage_index_ready` (the tool field) is the wait question; `rust_usage_facts_warm` is the warm question that `query_indexes_warm` and the one-shot-service test need.
- Observation (Milestone 3, out of scope but load-bearing for Milestone 4): after this milestone the Rust usage path still drops and rebuilds one workspace-sized structure on every file change, and it is not a usage structure. `update` resets `cargo_routes`, and `RustCargoRouteIndex::build_while` hydrates and parses EVERY analyzed Rust file (its own comment says "hydrating and parsing every workspace file dominates this build"). Every usage walk needs it -- `RustUsageWalks::new` cannot start without it -- so Milestone 4's cell (c), a single-file edit followed immediately by a query, measures the Cargo-route rebuild rather than anything this plan changed. The type-hierarchy index (issue #1772) is the same shape. Neither is in this plan's scope; both must be read off the cell (c) number before it is attributed to v2.
  Evidence: `rust/mod.rs` `update` (`cargo_routes: Arc::new(PoolSafeMemo::new())`); `cargo_routes.rs` `build_while` lines 197-218.
- Observation (Milestone 4): the Milestone 3 prediction about `cargo_routes` was right in kind and wrong in scope. It does not dominate cell (c); it dominates EVERY cell. `RustAnalyzer::build_cargo_routes` costs 34-44 s on the 35k-file rustc tree in each of (a) cold, (a) warm, (b) cold, (b) warm and (c) -- an untouched warm workspace pays it exactly as an edited one does, because `RustCargoRouteIndex` is not persisted and every process rebuilds it. Worse, it is charged INSIDE `searchtools.scan_usages_backend`, which sets the 3 s `SCAN_USAGES_MAX_DURATION` deadline at entry, and `RustUsageWalks::new` cannot return without it. So the deadline is 11-15x expired before any usage question is asked, and every cell of the benchmark returns `status=failure`, `incomplete_reason=time_budget`, `resolved=0`.
  Evidence: v2i cell (a) warm, `build_cargo_routes` 41.914 s of a 43.456 s scan backend (96%); cell (c) 34.160 s of 35.488 s (96%); `ScanUsagesExecutionContext::with_cancellation_and_max_duration` in `searchtools/scan_usages.rs`.
- Observation (Milestone 4): the benchmark did not compare v1's index against v2's walks, and the absent spans are how you can tell. `RustUsageIndex::build` never appears in any v1 run, and `RustAnalyzer::rust_fact_catch_up` never appears in any v2 run. Neither implementation's usage layer was reached; both runs measured the same shared Cargo-route rebuild. Any future attempt to attribute a Milestone 4 number to this plan has to check for those two spans first -- their absence means the number says nothing about v1 versus v2.
- Observation (Milestone 4): the costs sitting behind `cargo_routes` are shared machinery, not v2's, and the naive reading of the evidence gets this backwards. With the budget raised to 120 s, the largest span in all four binaries is `usages::candidate_discovery` (`usages/finder.rs:173`, byte-identical at `b86e575a` and HEAD) at 75-92 s, inside which `project::collect_workspace_files` -- a whole-workspace listing -- runs 64 to 137 times in a single query and `sql_definition_candidates.rows` runs 397k to 662k times. Seeing the repeated listing on v2 first invites blaming repeated `RustUsageWalks` construction, since the Milestone 3 Decision Log notes that the walk constructor lists the workspace for `RustPackageFileIndex`. The v1 runs refute that: v1 has no `RustUsageWalks` and re-lists MORE often (137 versus 64). Peak RSS also tracks how long the scan is allowed to run -- 14 GB at the 3 s default, 26-27 GB at 120 s, on both implementations -- so the gate-3 figure is not a plateau.
- Observation (#1793): the Cargo-route build reads exactly three things out of a file's syntax tree, and everything else it does is Cargo manifest topology. The three are the lexical scopes that `mod` items are written in (their names, their `#[path]` attributes, and the `#[macro_use]` chain that reaches them), the external `mod name;` declarations themselves (name, own `#[path]`, visibility, `#[macro_use]`, bare `#[cfg(test)]`, and the declaration's byte extent), and the `macro_rules!` definitions at item positions with their visibility windows and their replay verdict. Nothing else in `RustCargoRouteIndex` touches a tree. That is what made the whole build persistable as four narrow tables.
  Evidence: `rust_external_module_child_edges` and `rust_rules_item_macro_definitions` were the only two tree consumers in `cargo_routes.rs`; the frozen copies of both are still in the file under `#[cfg(test)]` for the equivalence pin.
- Observation (#1793): one of those three is NOT a function of the file's bytes, and it is the reason the row shape has a gate table. An item macro can expand to `mod name;`, but whether the invoked name resolves to a macro that replays its item parameters verbatim depends on the `#[macro_use]` graph across files -- exactly the fixed point the route build computes. Extraction therefore expands EVERY item-position macro invocation optimistically and records, per produced route, the chain of invocations it came out of; the reader keeps the route only when every gate resolves, at its recorded byte, to a proven passthrough definition. The alternative -- persisting the fragment text and expanding at query time -- would have put a parse back on the query path for the same files, which is what this change exists to remove.
- Observation (#1793): a `#[path]` chain cannot be collapsed into one stored directory string, and the reason is symbolic links. `workspace_relative_path` normalizes `..` lexically but then calls `canonicalize` on the result, so resolving `a/../b` in one step and in two steps differ whenever `a` is a symlink whose target sits in another directory -- and this file has a test that specifically requires symlinked paths to be rejected. The rows therefore carry a scope TREE (`rust_module_scopes`, parent pointer plus own `#[path]`) and the reader walks it step by step, reproducing the syntax walk's own sequence of resolutions.
- Observation (#1793): the manifest half of the build is measured cheap, so it stays on disk. The rustc tree has 347 `Cargo.toml` files totalling 207 KB, which read and TOML-parse in 4.9 ms warm (89 ms on a cold page cache), against 35,370 `.rs` files whose hydration and parsing cost 34-44 s. The build parses the manifest set about three times (`discover_cargo_manifest_directories` plus two `build_from_module_children_while` passes), so the whole manifest cost is on the order of 15 ms. Persisting manifests would have added a table keyed by a hash of a file that is not an analyzed blob, for no measurable gain.
  Evidence: measured with the workspace's own `toml` crate over `/mnt/T9/repo-clones/.codescale-sources/rust--01f6ddf7`, read-only, three repetitions.
- Observation (#1793): byte-identical files share one blob, and that shows up immediately in the new read. The structural-pin fixture has sixteen files but only three distinct blobs, because most of its module files have identical bodies. The batched read is therefore keyed by oid and fanned back out to files by the live snapshot, and "no rows for this blob" is the only missing-data case there is.
- Observation (Milestone 4, run 2): #1793 did exactly what it claimed and the wall moved rather than fell. Sub-span instrumentation inside `RustAnalyzer::build_cargo_routes` (13.23 s total on the rustc tree) splits it as `cargo_routes.facts_read` **0.18 s**, `manifests` 0.30 s, `physical_routes` 4.15 s, `macro_visibility` 3.79 s, `passthrough_fixpoint` 0.18 s, `final_routes` 4.59 s. The per-blob row read that replaced hydrating and parsing every file is 1.4% of the build; the other 12.5 s is `RustCargoRouteIndex::build_while`'s Cargo-topology orchestration -- two whole-workspace `build_from_module_children_while` passes plus a per-Cargo-target sweep that iterates every file again -- which #1793 did not touch and which the 34-44 s of parsing used to hide. It is still charged inside the scan's own 3 s budget, so the gate cells still never reach a usage layer.
  Evidence: binary v2s (HEAD plus six `profiling::scope` calls in `build_cargo_routes` and nothing else), cell (a) warm; `cargo_routes.rs:194` `build_while`, the per-target loop at `cargo_routes.rs:242-278`.
- Observation (Milestone 4, run 2): the two prerequisites, not v2, are what moved every number the first run reported. V1P -- `b86e575a` with `d4a82ef4` and `366cb82e` cherry-picked, so the v1 usage implementation with the v2 prerequisites -- measures 0.45-0.56 GB peak RSS and 16-24 s per cell, against unmodified v1's 14.22-14.35 GB and 31-80 s. So the 14 GB run 1 charged to the gate was never `RustUsageIndex`; it was the Cargo-route build parsing every file plus the candidate-discovery storm. In the gate configuration v2 and V1P are indistinguishable ((a) warm 12.82 s vs 16.52 s, (c) 24.05 s vs 24.23 s, RSS equal to two decimals), which is expected because neither usage layer runs there.
- Observation (Milestone 4, run 2): with the budget raised until the layers actually run, the plan's central claim is measured and it holds. `RustUsageIndex::build` fires once on the v1 lineage at **83.68 s**, charging `RustAnalyzer::export_index_of_declarations` 35,357 times -- once per workspace file -- and driving a 30.57 GB peak. Its v2 replacement `RustAnalyzer::rust_fact_catch_up` fires once at **0.20 s** (85 ms in a second run), with a 16.37 GB peak. That is the first direct measurement of the structure this plan removes, across both runs of the gate.
- Observation (Milestone 4, run 2): the counter-finding is that v2 does not honour a longer deadline. Paired at every budget on the same workspace and cell: at 30 s, v1p terminates at 33.89 s and v2i at 34.90 s; at 60 s, v1p terminates at 72.15 s and v2i is still running when killed at 540 s; at 120 s, v1p terminates at 126.96 s and v2i is still running when killed at 1800 s. `usages::candidate_discovery` never emits an END on v2 while its inner spans keep firing, so the process is working rather than deadlocked. Two candidate causes, neither proven: a walk region in `usage_walks.rs` that does not poll cancellation, and issue #1809's superlinear blowup on cyclic module graphs reached on the real rustc graph rather than on the inline fixture. This is the first evidence in either run that points at v2's own code, and it has to be diagnosed before the gate is run a third time.
- Observation (Milestone 4, run 2): the run-1 open attribution for `project::collect_workspace_files` is settled, and the answer is that it is time-proportional and shared. The probe binary reports `Project::workspace_file_listing_count` = **11** with **1** actual walk in every gate cell, and **55** requests against **45** walks at a 30 s budget -- on the analyzer snapshot's own `Project`, so the walks are that instance's cache misses and not some other object's. The rate is about two walks per second of scan wall time at every budget (45 in ~20 s, 1044 in 540 s, 3464 in 1800 s) and it is the same on the v1 lineage (v1p: 41 at a 30 s budget, 203 in 127 s). Run 1's 64-137 figure came from its 120 s runs; the rate matches and only the run lengths differ. Nothing here amplifies per candidate.
- Observation (Milestone 4, run 2): `d4a82ef4`'s macro token-tree expansion has no measurable cost at scale, which the plan flagged as unmeasured. Full analyzer build over 35,370 files, run back to back with the page cache pre-warmed: v1 (schema 16) 116.6 s, v1p (schema 17, same extraction as HEAD) 128.7 s, v2 (schema 17) 104.6 s, all at 1.34-1.35 GB peak. V1P is 10% slower than v1 and v2 is 10% faster, with host load varying 20x across the three, so the difference is inside this host's noise. The persisted cost is real and small: the store grew 842.5 MB to 847.2 MB, +0.55%, for four new tables.
- Observation (Milestone 4, run 2): the cache-schema question run 1 did not have has no teeth. `CURRENT_MIGRATION_VERSION` is 16 at `b86e575a` and 17 at `d4a82ef4` and HEAD, and the store file carries the version in its name, so a v16 binary writes `bifrost_cache.v16.db` beside a v17 binary's `bifrost_cache.v17.db` and the two never meet. No compatibility failure is reachable; each lineage was still given its own cache built by its own binary.
- Observation (#1809): the cyclic blow-up is exponential rather than superlinear, and the profile identifies which of the two recursions owns it without ambiguity. Counting entries and computations on the synthetic fixture (N modules, each `pub use`-ing a name from C successors modulo N), the alias recursion is flat -- `compute_alias_routes` runs exactly 2N times at every size, with zero partial hits -- while `compute_bindings_at` runs 70, 223, 576, 1,713 and 4,562 times at N = 4, 5, 6, 7, 8 with C = 2, and 1,764, 7,373 and 25,214 at N = 6, 7, 8 with C = 3. That is a factor of about three per added module at C = 2 and four at C = 3 or 4, which is exponential in the cycle length, not polynomial in it. Wall clock on the same fixture at C = 4: 0.19 s at six modules, 3.05 s at eight, 69.4 s at ten, and no result in 420 s at twelve.
  Evidence: temporary atomic counters on the five entry points of `usage_walks.rs`, run over the fixture now checked in as `cyclic_project` in that file's tests.
- Observation (#1809): the mechanism is not a memo keyed too narrowly, and it is not the fixed-point iteration being quadratic in cycle participants either -- it is that no member of a cycle could be memoized at all. `alias_truncations` / `binding_truncations` were monotone per-walker counters compared at frame entry and frame exit, so ANY re-entry anywhere below a frame disqualified that frame from the analyzer cache. In a strongly connected import graph every frame's subtree reaches a cycle, so every frame was disqualified, every frame ran its own local fixed-point loop, and every iteration of that loop recomputed the whole subtree from scratch. The counters bear this out: at N = 8, C = 3 the walk cached exactly 8 entries -- one per `(lib.rs, module)` key, the only keys with no import edge of their own -- out of 151,237 entries.
- Observation (#1809): v1 did not exhibit this because it never asked the question recursively. `build_origin_routes` seeded every declaration identity in the workspace into one worklist and propagated with a `visited` set, and `build_module_alias_routes` iterated every import up to `import_count` times; both are chaotic iteration over the whole workspace, which is O(workspace x rounds) and cycle-blind by construction. The v2 walk asks one key at a time, so it had to close its own cycles, and the first form of that closure was the exponential one. So this IS a v2-introduced defect in the strict sense, even though #1809 stash-verified the walks as pre-existing: the walk layer existed at `366cb82e` because 2c had already landed. What v1 amortized was the cost of the ANSWER, not of the cycle handling; the cycle handling had no v1 counterpart.
- Observation (#1809): nothing in the walk layer polled cancellation, and the fix for the cost does not remove the need to fix that. `RustUsageWalks::new_while` took a `keep_going` predicate, used it for the Cargo-route build, and dropped it; every walk below the constructor then ran to completion regardless of the request's budget. The measured consequence is the Milestone 4 rerun's kill at 1800 s under a 120 s budget. Nine loops needed a poll, and the one that matters most is `edges_binding_identity`, where one candidate is one full forward-edge computation and a common identifier offers thousands of candidates on a large workspace. Polling alone would have been unsafe without the second half: nine analyzer caches were written unconditionally at the end of the loops that fill them, so a truncated answer would have been memoized for the whole generation. Both halves are pinned by `a_cancelled_walk_stops_promptly_and_memoizes_nothing`, each demonstrated failing on its own.
- Observation (#1817): the 12.5 s of orchestration is not reachability work, it is a product where a sum belongs. Varying the Cargo topology against a FIXED file count separates the two: 832 files in 4 crates with 16 targets build in 0.074 s and the same 832 files in 128 crates with 512 targets build in 0.493 s, on the pre-#1817 code. Reachability itself cannot behave that way -- the number of (file, target) pairs barely moves between those two workspaces -- so the growth is loops that iterate the whole workspace once per crate or once per target. There are four: `cargo_target_roots` searching every analyzed file for one crate's target roots (and rebuilding a `HashSet` of all of them while it does), `cargo_target_memberships` rebuilding that same set per crate, the macro-visibility stage and the passthrough fixed point each sweeping every file once per target, and `build_files_by_reachable_root_while` scanning every route entry in the workspace for each (file, root, target) triple.
  Evidence: the synthetic scaling probe in `cargo_routes.rs`'s tests (checked in as `synthetic_workspace`; the timing driver itself was temporary), measured before and after in one run.
- Observation (#1817): the first of the two whole-workspace membership passes threw away everything except its reachability, and rebuilt the entire manifest topology to get it. `build_from_module_children_while` read and TOML-parsed every manifest, constructed every crate, resolved every dependency route and materialised `files_by_reachable_root` -- and `build_while` used exactly one field of the result, `target_roots_by_file`, before running the whole thing again. The topology does not depend on module edges at all, which is why it can be discovered once and shared by both passes; the second pass differs from the first only in which module edges it walks.
- Observation (#1817): an auto-discovered Cargo target is always two, three or four path components below its manifest directory, and that bound is what turns the per-crate file search inside out. `auto_cargo_target_kind` matches exactly those three shapes and nothing else, so a file needs to be offered only to its ancestors at those depths -- at most three per file -- instead of being tested against every crate directory in the workspace. Explicit targets need no search at all: they name their file, so they are looked up in the analyzed set. The coupling between the grouping bound and the accepted shapes is the kind that breaks silently (a deeper target shape would simply stop being discovered), so `auto_target_paths_stay_within_the_grouped_depth` pins it in both directions -- nothing discovered outside the range, and every depth in the range discovering something.
- Observation (#1817): the same file's module edges were resolved four to six times per build and every resolution paid the file system. `module_child_edges` resolves each `#[path]` scope and then calls `exists()` on up to two candidate files per declaration, and it was called once per (file, target) pair in each membership pass plus once more per (file, target) during macro visibility. Nearly every one of those calls passes an empty passthrough map, so the answer depends only on (file, is_crate_root) -- two possible answers per file, not one per target. The one shape that makes the `is_crate_root` half load-bearing is a file that is both a Cargo target root and a declared module: `tests/fixtures.rs` is an auto-discovered integration test target AND `mod fixtures;` of `tests/it.rs`, and its own `mod shared;` resolves to `tests/shared.rs` under the first reading and `tests/fixtures/shared.rs` under the second. No existing fixture had that shape, so keying the cache on the file alone passed every test until the equivalence fixture was given one.
- Observation (#1817): per-target laziness -- deriving each target's reachability on demand rather than materialising all of it -- was the direction this task carried in, and the consumer surface refuses it. The index's dominant accessor is `target_roots_for_file`, the INVERSE of a walk from a root, and the walk cannot be inverted cheaply: the edge set is itself target-parameterised (a `#[macro_use]` passthrough macro's visibility is per target), so an upward walk would have to know the target before it could compute the edges that tell it the target. Two consumers are unconditionally whole-workspace anyway -- `RustUsageWalks::direct_module_domains_of` iterates every external module declaration in the workspace by design, and `file_is_test_only` is the complement of production reachability from every root -- so a lazy index would be forced within the first usage query regardless. What the profile showed is that laziness was not the lever: the cost was quadratic, not linear, and removing the quadratic terms leaves an eager build whose cost is the workspace once.

- Observation (Milestone 4, run 3): #1817's fixture claim transfers to the real tree, and the control makes it unambiguous. On the same 35,370-file rustc tree, same cells, same process model, `RustAnalyzer::build_cargo_routes` costs **10.14-11.90 s** on V1P (which lacks #1817) and **0.61-0.78 s** on HEAD -- a 15-18x reduction that moves the span from 87-90% of the scan backend to 0.1-21%. The Cargo-route build has stopped being the wall in every cell of this benchmark, three runs after it became one.
  Evidence: run-3 gate table, the six timed cells across v1p and v3; the two binaries differ only by `575c2ffb` and `13bb6263`, and the identity table pins that by the `cargo_target_memberships` and `reachable_root` symbols being present in v1p and gone at HEAD.
- Observation (Milestone 4, run 3): run 2's headline comparison was not like for like, and the corrected one is a wash. `rust_fact_catch_up` (0.07-0.18 s) replaces the *warm*, not the index build's query work. The product-for-product pair is `RustQueryResolver::candidate_files`, which on V1P is entirely `RustUsageIndex::build` at **88.42 s** and on HEAD is entirely `usage_candidate_files_while` at **86.84-87.77 s**. Both complete -- V1P's build charges all 35,357 `export_index_of_declarations` and its sub-stages sum to its total; HEAD's walk returns the same 87 s at both a 120 s and a 600 s budget, so it is not truncated. What v2 buys at the candidate stage is therefore not latency: it is 3,127 export projections instead of 35,357, a 16.58 GB peak instead of 30.27 GB at the same budget, and nothing workspace-sized retained afterwards.
- Observation (Milestone 4, run 3): the cell-(b) catastrophe is shared code and predates v2, and a paired budget test proves it rather than inferring it. HEAD's cell (b) runs **653-749 s** under a 3 s budget, of which **664-698 s is `searchtools::scan_usages_symbol_resolution`** -- `resolve_codeunit_fuzzy` at `scan_usages.rs:2037`, which takes no cancellation predicate (the deadline is checked only after it returns) and charges 20,935 `multi.definitions[main]` lookups, 20,930 store round trips and about 1,500 whole-workspace listings. V1P's 14-15 s in the same cell is not speed: its 11.90 s of Cargo routes expires the budget before the per-symbol loop starts, so the loop's entry check short-circuits the symbol. Give V1P a 30 s budget so it survives its own route cost and it enters the same resolution and pays **721.58 s** with the identical inner profile. #1817 did not create this; it removed the block that was hiding it.
- Observation (Milestone 4, run 3): the deadline is still soft, but the region has moved and the shape is different from run 2's. The scan backend lands at exactly 30.00 s and 60.00 s on those budgets, 129.89 s on a 120 s budget (8% over) and 1145.52 s on a 600 s budget (91% over). The overrun appears only once `usages::graph_find_usages` runs, whose 1034 s is 1,115 `RustAnalyzer::build_reference_context` calls, so that stage polls too rarely. This is not run 2's non-termination -- every run terminates -- and nothing in the evidence makes it v2-specific.
- Observation (Milestone 4, run 3): peak RSS is not proportional to run length, which is what makes run 2's gate-3 caveat resolvable. The longest gate cell in this run is cell (b) warm at 653-749 s, and it peaks at **0.66 GB**; the 120 s supplementary run peaks at 16.58 GB in a fifth of that time. RSS tracks the usage-graph phase specifically, not wall clock: cell (b)'s time goes into store round trips, which retain nothing. The honest summary of gate 3 is that v2 stays under 4 GB whenever it does not answer, and reaches **23.42 GB** in the one run that did answer.
- Observation (Milestone 4, run 3): the shared candidate-discovery storm is materially smaller and is no longer per import, but it is not gone. `sql_definition_candidates.rows` fires **98,553** times on HEAD and 170,460 on V1P at a 120 s budget, against run 1's 397k-662k. The residue is per short name rather than per `use` statement -- `rows[Foo]` alone fires 100-109 times in one query, `rows[foo]` 57-62 -- so a lookup is still being re-taken per candidate. The whole-workspace listing loop is unchanged and remains shared: 271 walks on HEAD against 203 on V1P at the same budget, about 2.2 per second of scan on both, each paired with a whole-tree `git status`, exactly the rate run 2 measured.
- Observation: only three of the seventeen `RustUsageIndex` products are genuinely cross-file (module-file resolution, alias routes, transitive export chains), and each is a bounded walk from a seed, not a closure. Everything else is a per-file fact or a per-file fact plus a SQL index.
  Evidence: classification table in research report section 7.3.
- Observation (#1748): the 397k-662k `sql_definition_candidates.rows` figure is exactly "one store round trip per `use` statement in the workspace", and the arithmetic says so before any profile does. 397,000 / 35,370 files = 11.2 and 662,000 / 35,370 = 18.7, which are import counts per file, not candidate counts. The mechanism is `find_direct_importers_with_cancellation` (`usages/candidates.rs`), which visits EVERY analyzed workspace file and asks `import_provider.could_import_file(candidate, imports, target)`; `RustAnalyzer::could_import_file` answers by resolving each `use` path to an fq name and calling `self.inner.definitions(&fq_name)`, and each of those opens its own pooled reader, transaction and generation check. It is charged twice per file in practice, because when the answer is `false` -- which it is for nearly every file -- the caller immediately resolves the same imports again through `imported_code_units_of`.
  Evidence: `usages/candidates.rs` lines 219-257 (the workspace-wide `par_iter`), `rust/imports.rs` `impl ImportAnalysisProvider for RustAnalyzer` (`could_import_file` and `imported_code_units_of` performing the same resolution), `tree_sitter_analyzer.rs` `sql_definition_candidates_vec` (the `sql_definition_candidates.rows` span, one store transaction per candidate short name).
- Observation (#1748): every other language with this shape had already been fixed, one language at a time, and Rust was simply missed. Python caches `resolve_import_target_files(source_file)` and JS/TS caches `resolved_import_target_files(host, file)`, and the JS/TS cache carries the comment "`could_import_file` re-ran `resolve_js_ts_import_paths` for every (candidate, target) pair the shared usages candidate walker checks -- unbounded per-call cost on a large workspace". That per-file caching is necessary but not sufficient at rustc scale: with a single target file the walk visits each candidate exactly once, so a per-file cache saves nothing within one query. The multiplicity is files x imports, and only a batch across files removes it.
  Evidence: `python/imports.rs:807`, `js_ts/providers.rs:206-236`.
- Observation (#1748, open): the second measured multiplicity -- `project::collect_workspace_files` running 64-137 times "inside" `usages::candidate_discovery` -- was NOT reproduced or attributed, and nothing here fixes it. Static reading finds no per-lookup caller of the project listing on the Rust candidate-discovery path: `analyzed_files()` is request-memoized, `WorkspaceFileResolver` shares the #1334 request cell, `RustPackageFileIndex` is built from the analyzed set rather than the project listing, and the two `analyzer.project().all_files()` calls in `scan_usages.rs` are per tool call, outside the span. Two facts make the count plausible without any per-lookup amplification: `crate::profiling` is a stderr tracer with a THREAD-LOCAL depth, so work on rayon or background threads prints inside the window between `candidate_discovery`'s BEGIN and END without being under it; and under `UpdateStrategy::Manual` -- which batch and benchmark consumers use -- `listing_cache_for` returns `None`, so there is no session listing cache at all and every `all_files()` is a fresh ignore-aware walk plus a `git status` over the whole tree (recorded in `.agents/plans/searchtools-too-broad-scope-guards.md`). Attributing it needs the kill-gate harness to report `Project::workspace_file_listing_count`, which is a per-instance counter that already exists; guessing from the span log cannot separate "inside" from "concurrent with".
- Observation (#1748, out of scope but load-bearing for any future fixture): the Rust usage walks blow up superlinearly on a CYCLIC module import graph, independently of candidate discovery. On an inline fixture where each of N caller modules imports from three neighbours modulo N, one `UsageFinder::query` costs about 1.0 s at N=8 with two neighbours, 5.6 s at N=8 with three, and does not finish in 600 s at N=24 with four. Candidate discovery is not the cost -- with this change the same query charges 1 batched read and 1 point lookup. The counter-pinned fixture is therefore deliberately small (8 callers, 4 imports each); anyone enlarging it will hit this instead of what the test measures.

## Decision Log

- Decision: split the Milestone 4 gate and unblock Milestone 5. The usage-layer comparison is declared answered: v2 is equal-or-better on every axis attributable to the usage layers (per-generation build 88.42 s / 30.27 GB re-paid on every edit vs catch-up 0.07-0.18 s; edit-then-query 6.91 s passing the 10 s gate vs 13.92 s; warm query 2.5x better at 5.51 s, 10 percent over the absolute 5 s bar), and every remaining gate failure is proven shared and pre-existing (#1839, the graph_find_usages phase, the listing loop -- each measured identical or worse on the v1 lineage). Holding v1's deletion hostage to shared scan-pipeline defects would measure the wrong thing indefinitely. The shared walls move to their own tracked stream before the next benchmark campaign.
  Rationale: three runs of evidence; the original end-to-end gate conflated the usage layers with the shared pipeline. Run 2's headline was corrected in run 3: the catch-up replaces the warm, not the query work, so v2's case rests on incrementality and memory -- which were the owner's stated requirements -- not on first-query latency, which is dominated by shared walls on both lineages.
  Date/Author: 2026-08-08 / Jonathan (sign-off), Fable (framing).

- Decision: per-file facts in SQLite plus query-time composition, replacing the materialized index entirely. Persisting the materialized graph was rejected.
  Rationale: a persisted monolith still invalidates as a monolith; the owner's requirements are single-file incremental invalidation, data pulled on demand rather than resident, and no minutes-long rebuild ever. Only decomposing the unit of storage to the file meets all three.
  Date/Author: 2026-08-07 / Jonathan (direction), Fable (design).
- Decision: block-until-ready stays the default query behavior; a caller that does not want to block opts in via the readiness probe. This deliberately inverts IntelliJ's throw-by-default (`IndexNotReadyException`).
  Rationale: owner directive from #1757. IntelliJ throws because its "not ready" can last minutes; under v2 "not ready" means "a small changed-file set has not been re-parsed", so blocking is cheap. Recorded divergence, not an oversight.
  Date/Author: 2026-08-07 / Jonathan.
- Decision: adopt IntelliJ's small-change lazy catch-up: below a threshold of changed files, bring them up to date inline on the querying thread; above it, hand the batch to the background pass and let the readiness probe report false meanwhile.
  Rationale: single-file edits then never surface any readiness state at all (research report section 5.2, `ChangedFilesCollector.ensureUpToDateAsync`, threshold < 20 there).
  Date/Author: 2026-08-07 / Fable.
- Decision: Milestone 4 is a kill-gate, not a formality. v1 is deleted only after the benchmark passes; if it fails, the plan stops and the failure is taken back to the owner with numbers.
  Rationale: the honest risk is query latency moving from a heap probe to indexed SQLite lookups plus per-candidate verification. A high-occurrence identifier is the case that breaks this design if anything does.
  Date/Author: 2026-08-07 / Fable.
- Decision: allocator hygiene (`MALLOC_ARENA_MAX`, `malloc_trim`) from #1758 option 1 is deferred until after Milestone 4 measurement.
  Rationale: v2 removes the 10.8 GB transient that made glibc arena retention matter; re-measure before adding process-global allocator knobs.
  Date/Author: 2026-08-07 / Fable.
- Decision: new tables use STRICT, WITHOUT ROWID where the primary key is the natural access path, and ON DELETE CASCADE from `blobs`, matching the store's existing conventions.
  Rationale: invariants belong in the schema; this is also the store's established style.
  Date/Author: 2026-08-07 / Fable.
- Decision (Milestone 1, DDL reconciliation): `rust_exports` gains a nullable `imported_name` column and makes `exported_name` nullable. The plan's design DDL had `exported_name TEXT NOT NULL` and no `imported_name`, but the projection it must carry is `ExportEntry::ReexportedNamed { module_specifier, imported_name }` plus `ReexportStar { module_specifier }`: a named re-export publishes a name that may differ from the name it publishes FROM (`pub use a::B as C`), and a glob publishes no single name at all.
  Rationale: NULL for a glob is honest and keeps `idx_rust_exports_name` free of meaningless entries, since SQLite indexes skip NULL keys for equality lookups.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 1, DDL reconciliation): `rust_import_targets` gains `imported_name`, `is_glob`, `visibility`, `owner_module`, `owner_start`, `owner_end`, `local_start`, `local_end` beyond the plan's `(module_path, bound_name)`.
  Rationale: the row must reproduce `RustProjectedImport` (`rust/imports.rs`), which is `RustImportInfo` plus a `RustImportOwner` that is either a module extent or a function-local extent. Milestone 2's `origin_routes_by_file` and `module_domains` need the visibility to compute an import's domain, and `usage_local_module_prefix_visible_at` needs `edge.importer_module` and `edge.extent.contains(byte)`. Persisting `(module_path, bound_name)` alone would force a re-parse to recover the rest, which is exactly what this plan exists to remove. `visibility` is TEXT encoded by `encode_rust_visibility` because `RustVisibility::InPath` carries a path and a text column stays inspectable in plain SQL; the codec round-trip is pinned by `rust_visibility_encoding_round_trips`.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 1, DDL reconciliation): `rust_modules` records three kinds of row under the plan's `is_inline` flag -- the file root (ordinal 0, empty `module_name`, spanning the whole source), each `mod name { ... }` body, and each `mod name;` declaration. `is_inline` is 1 for the first two (the body is in this file) and 0 for the third.
  Rationale: `module_at_byte` needs the file-root extent to answer "which module encloses this byte" for a byte outside every inline module, so the root row is load-bearing rather than redundant. Resolving `mod name;` to a file stays a query-time cross-file walk, per the plan's classification, so the row records only the declaration's own extent.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 1): the facts travel to the store on `ParsedFile` / `FileState` like `scala_exports` and `cpp_template_metadata`, and are NOT hydrated back into a `FileState` read from the store.
  Rationale: the tree only exists inside `adapter.parse_file`, and `prepare_parsed_blob` receives a `FileState`, so `FileState` is the only available transport. Hydrating them back would be dead weight on every cache hit, because the query side reads these rows by blob oid straight from SQL -- that is the whole point of the redesign. The field's doc comment states the rule, following the `parse_errors` precedent already in that struct.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 1): Milestone 1's tests are unit tests in `crates/bifrost-analysis/src/analyzer/rust/facts.rs` and `crates/bifrost-analysis/src/analyzer/store/mod.rs`, not `InlineTestProject` integration tests under `tests/`.
  Rationale: the fact types are the store's row shapes, not a product API, so they are `pub(crate)`; an integration test could only reach them by making the whole extraction surface `pub`, including `RustVisibility`. The store test uses `parse_state(&RustAdapter, file)`, which calls the real `RustAdapter::parse_file`, so it covers the same wiring end to end without widening visibility. Removing the extraction call makes three of the four store tests fail (demonstrated), which is the fail-before evidence for the wiring.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 1): the store reader (`AnalyzerStore::rust_usage_facts` and the three inverted lookups) lands in Milestone 1 alongside the writer, behind one scoped `#[allow(dead_code)]` that Milestone 2 removes.
  Rationale: the plan's Milestone 1 scope says nothing reads the rows yet, but a write-only commit cannot be tested against anything except raw SQL, and keeping the reader beside the writer it inverts is what makes the round trip reviewable in one place. The allow is scoped to one `impl` block and two functions and is named in their doc comments.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 1): the Rust analysis-epoch salt gains `per-file-usage-facts-2026-08`.
  Rationale: the cache schema version bump to 16 already re-keys the store file, so no pre-existing row can survive into it; the salt bump is redundant for that file but is the documented mechanism for "Rust extraction semantics changed", and leaving it out would make a future backport to an unversioned store silently serve rows without fact tables.
  Date/Author: 2026-08-07 / Opus (implementation).

- Decision (Milestone 2a): split Milestone 2 into 2a (the query layer plus the per-file products), 2b (the inverted-derivable products), and 2c (the cross-file group and the final consumer switch). 2a landed; 2b and 2c did not.
  Rationale: the milestone as written assumes the seventeen products can be re-pointed independently, and the two observations above show they cannot: `binding_seeds` transitively needs the whole cross-file group, and its inverted key has to change from "module path as written" to "identifier", which is a rewrite rather than a re-pointing. Shipping a half-migrated `binding_seeds` would have meant two sources of truth for the same answer with the existing suites as the only guard, which is exactly the state the Idempotence section says to avoid. Splitting keeps every landed commit revertable and keeps `RustUsageIndex` authoritative until its replacement is complete.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2a): the two products migrated first are `module_at_byte` and the re-export half of `export_index_of_declarations`.
  Rationale: both are purely per-file, both were reading a syntax tree during the workspace-wide index build, and both are covered densely by the existing Rust usage suites -- so they exercise the whole path (extraction, persistence, live-path mapping, package composition, read) with the strongest available regression guard. `module_at_byte` additionally removes a map from the index outright, proving a product can leave the monolith rather than merely be shadowed.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2a): the three `(generation, query)`-keyed walk caches (`module_resolution`, `export_chain`, `resolve`) are NOT added yet; the one cache that exists is the per-file fact cache, keyed `(generation, blob)`.
  Rationale: the walks those three caches memoize are Milestone 2c work, and adding empty caches now would be unused scaffolding that the next contributor has to reverse-engineer. The per-file cache is the one the landed code actually needs, and its content-hash key gives single-file invalidation for free -- an edited file is a different blob, so nothing has to be evicted.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2a): `RustUsageQueries` returns a `RustImportBinding` rather than reconstructing `RustProjectedImport`.
  Rationale: `RustProjectedImport` carries a rendered snippet and a `StructuredImportPath` with lexical scopes, none of which is a usage fact and all of which would need a re-parse to rebuild. `build_importer_reverse` reads only the path, the local name, the wildcard flag, the visibility, and the owner extent, and those are exactly the persisted columns.
  Date/Author: 2026-08-07 / Opus (implementation).

- Decision (Milestone 2b, sequencing): 2b delivers `identities_by_name` only. `module_importers` and `importer_reverse` move with 2c.
  Rationale: the milestone as scoped assumed the three inverted-derivable products share a candidate-then-verify shape that needs nothing new. `identities_by_name` does: its candidates come from the store's short-name index over `code_units` and its verification is a per-file declaration read. The other two do not: for both, "verify this candidate" means "recompute this candidate file's forward import edges and see whether any lands on the target", and forward-edge computation needs alias routes, module-file resolution and physical owners -- the whole 2c group. Shipping either half-verified would have meant either a second source of truth or an unverified superset, both of which the 2a split exists to avoid. The plan text anticipated this and delegated the sequencing call to the implementer.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2b): the per-file declaration-identity derivation is extracted into one function, `rust_declaration_facts`, that BOTH the v1 workspace build and the query layer call, rather than being reimplemented on the query side.
  Rationale: the two must agree exactly or `usage_reference_at` starts answering differently depending on which path reached it, and a test can only sample that agreement. One function makes it structural. The v1 build keeps its `keep_going` cancellation by passing its own callback; the query layer passes `|| true` and memoizes the result. This is also what makes the migration reviewable: the diff shows the derivation moving, not being rewritten.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2b): the declaration-facts cache is keyed by `ProjectFile`, not by `(generation, blob)` like the per-file usage-fact cache.
  Rationale: the derivation is not a function of the file's bytes alone -- it consults `structural_parent_of`, `rust_declaration_visibility` and `is_type_alias`, which are analyzer state. A content-hash key would claim an invariance the value does not have. `RustAnalyzer::update` builds a fresh analyzer with fresh caches, which is the correct invalidation for analyzer-derived state and is what every other per-file cache on this struct already relies on.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2b): `identities_named` filters its candidates to `is_analyzed` files.
  Rationale: the v1 map was built by walking `get_analyzed_files()`, so it could never contain an identity from a file outside the analyzed set. The store's short-name index can offer one (a stale row for a path no longer analyzed), and without the filter the two would disagree. The equivalence pin `identities_named_matches_the_v1_identity_buckets` is what holds this honest.
  Date/Author: 2026-08-07 / Opus (implementation).

- Decision (Milestone 2c): 2c lands as one commit, not as a sequence of per-product migrations, and this session therefore stopped after 2b rather than starting it.
  Rationale: the sequencing observation above. Every partial ordering that was considered puts a memoized lazy walk inside an eager build's hot loop, which is slower than both the state before and the state after, and Milestone 4 (the benchmark that would catch it) is deliberately downstream. Landing 2b alone keeps every commit an improvement, which is what the Idempotence section asks for. The alternative -- landing a partial 2c behind a flag selecting eager or lazy resolution -- was rejected outright: it is exactly the mode parameter the repository conventions prohibit, and it would double the surface the Milestone 4 benchmark has to measure.
  Date/Author: 2026-08-07 / Opus (implementation).

- Decision (Milestone 2c): the walk caches are keyed by the query alone, not by `(store generation, query key)` as the plan's Interfaces section says.
  Rationale: the Milestone 2b lesson applies to all of them. Every derivation here consults analyzer state -- structural parents, declaration visibility, Cargo routes, the analyzed-file set -- and not the files' bytes alone, so a content-hash or store-generation key would claim an invariance the values do not have. The analyzer instance IS the generation: `update` / `update_all` construct a fresh `RustAnalyzer` with a fresh `RustWalkCaches`. The walk-cache test `walk_results_are_memoized_per_generation_and_retire_with_the_analyzer` pins both halves.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2c): nine caches, not the plan's three. The plan names three concerns; a `moka` cache is typed, so each value shape needs its own field. The grouping is recorded on `RustWalkCaches`: `module_resolution` is `module_files` / `owner_roots` / `module_domains`, `resolve` is `alias_routes` plus the `forward_import_edges` they feed, and `export_chain` is `module_bindings` / `origin_routes` plus the macro scope chain, which is the same walk over `mod` items instead of `use` items.
  Rationale: collapsing them behind one enum-keyed cache would need one value enum too, and every read would pay a match plus an unreachable arm. The named concerns are documentation, not a field count.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2c): `RustUsageIndex` and its builders stay in the tree, compiling, behind scoped `#[allow(dead_code)]` attributes that name Milestone 5.
  Rationale: the plan's Milestone 2 scope says exactly this, and Milestone 4's kill-gate benchmark compares the two implementations, which needs both to build. Keeping v1 also kept the equivalence pins from 2a and 2b working, and it is what made the 2c divergences findable: the probe that identified the `definitions(fq_name)` collapse compared `index.module_aliases.resolve_segments` against the lazy walk on the same fixture.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2c): the candidate sources for `importer_reverse` are the union of the files whose code mentions the imported name, the files whose code mentions the target module's last component, the files backing the target module itself, the files that write `super` as an import path, and -- for a crate-root target, which has no last component -- the files that write `crate` plus the Cargo-visible dependents. Verification recomputes each candidate's forward edges.
  Rationale: each source covers one shape the importer must have written. A named import spells the item; a namespace or glob import spells the module; `use self::*` can only come from a file backing the module; `use super::*` and `use crate::*` name no module at all and are answered by the written-path index instead. The known gap is a namespace or glob import written through an alias (`use x::m as am; use am::*;`), which mentions the alias rather than the module: no case in the Rust usage suites exercises it, and closing it would need an inverted alias index this milestone does not add. Recorded rather than papered over.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2c): `bindings_at` recurses rather than walking an explicit stack, against the repository's default preference for iterative traversal.
  Rationale: the depth is the re-export chain length, not the AST depth or the file count, and a re-export chain is a human-written construct. The test `an_export_chain_survives_a_deep_re_export_ladder` pins 250 links, which is the bound the implementation is known to survive; the v1 export-target walk uses an explicit stack because its depth was pinned at 5,000. If a real workspace exceeds this, converting the recursion is a contained change.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2c): the usage-index warm (`warm_usage_index`, `warm_rust_usage_index`, `usage_index_ready`) is left wired exactly as #1757 left it, still building an index nothing reads.
  Rationale: re-pointing readiness is Milestone 3's named scope, and doing it here would mean either changing a tool contract inside a milestone about the consumer switch or leaving the probe permanently false. The consequence is real and must not be forgotten: until Milestone 3 lands, a warm start still pays the v1 build, so the Milestone 4 benchmark has to disable the warm or measure it separately, and the v2 numbers are not comparable with it enabled.
  Date/Author: 2026-08-07 / Opus (implementation).
- Decision (Milestone 2c): `cancelled_cold_candidate_discovery_does_not_publish_partial_index` moves its structural pin from the usage index to Cargo routes, and additionally asserts that discovery does NOT build the usage index.
  Rationale: the test's subject is "a cancelled cold discovery publishes nothing half-finished". Cargo routes is now the only whole-workspace structure that path builds, so it is the only structure that can be published half-finished. Asserting the usage index is never built turns the removed assertion into a guard against the switch being reverted by accident. This is the one existing test whose text changed; every Rust usage suite passes unchanged.
  Date/Author: 2026-08-07 / Opus (implementation).

- Decision (Milestone 3): `update` / `update_all` are left as they are, including the `usage_index: Arc::new(PoolSafeMemo::new())` reset for the v1 memo.
  Rationale: the milestone's rule is "nothing workspace-sized may be dropped and rebuilt", and dropping an EMPTY memo costs nothing -- nothing builds the v1 index any more, so the reset is a no-op that disappears with the struct in Milestone 5. Rewriting those two constructors now would touch every field for no behavior change and would make the Milestone 5 deletion diff harder to read. Every other field they reset is either bounded (the weighted caches, whose re-derivation is per query and on demand) or outside this plan (`cargo_routes`, `hierarchy_index`; see the Surprises entry).
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (Milestone 3): the catch-up hook is `RustUsageWalks::with_cargo_routes`, the single constructor every cross-file walk goes through, and NOT `RustUsageQueries::new`.
  Rationale: the query layer is also constructed by the two per-file consumers (`module_at_byte`, the re-export half of the export index), which today answer without listing the workspace. The catch-up scan needs the analyzed-file listing, so hooking it there would add a workspace listing to paths whose cost is pinned by the #1230 counters -- a latency regression in exchange for a correctness guarantee those paths do not need, since each reads one named file's rows and a missing row there yields an empty answer for that file rather than a wrong workspace-wide one. Walks already list the workspace to build `RustPackageFileIndex`, so the hook is free there.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (Milestone 3): the catch-up set is computed once per analyzer generation over the whole analyzed Rust file set, memoized in a `PoolSafeMemo` on the analyzer, rather than being narrowed to the files an `update` changed.
  Rationale: this is what the plan's Milestone 3 text specifies, and the narrowed alternative is not correct on its own -- a generation whose catch-up never ran (no query arrived) would hand its unrepaired set to the next generation, so the narrowing needs inherited state across generations, which is exactly the kind of cross-generation bookkeeping this design removed everywhere else. The cost is one batched membership query over the live Rust oids, no parsing: `blobs_with_rust_facts` chunks 400 keys per statement and seeks the `rust_modules` primary key, so it tracks the live file set rather than the table's history. `PoolSafeMemo` because a query reaches this from inside its own rayon fan-out (#549); its duplicate-serial-run rule is safe here because the work is idempotent -- at worst the same files are parsed twice and the same rows rewritten.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (Milestone 3): `rust_modules` is the witness table for "this blob has facts".
  Rationale: a Rust blob always has its file-root extent at ordinal 0 (the Milestone 1 DDL decision), so absence there means absence of the whole fact set. It is also exactly the rule the reader already applies -- `rust_usage_facts_of_blob` returns `None` on an empty module list -- so the catch-up's question and the query's question cannot disagree.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (Milestone 3): the above-threshold batch runs on the existing dedicated build pool through a new `spawn_on_dedicated_build_pool`, not on a spawned thread and not on the global rayon pool.
  Rationale: the querying thread returns straight to its own parallel fan-out, so the batch must not consume a global-pool worker; the dedicated pool is the mechanism that already exists for exactly this (#1757) and it stays for the hierarchy warm (#1772). `PoolSafeMemo::get_or_build_on_dedicated_pool` now has no production caller and is kept behind a scoped allow that names #1772, together with its regression test.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (Milestone 3): the readiness probe becomes "no catch-up batch is outstanding" and a second predicate, `rust_usage_facts_warm`, carries "the catch-up has run for this generation". The MCP field name `usage_index_ready` does not change.
  Rationale: the two questions were the same event under a build and are not under a catch-up (see Surprises). Renaming the tool field would break the contract #1757 established for no gain; the field's doc comment and the tool description now say what it means. `query_indexes_warm` and the one-shot-service test ask the warmth question, because "did this session start background work" is what they are actually about.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (Milestone 3): the deferred batch carries a `#[cfg(test)]` barrier gate.
  Rationale: "the probe reports false while a batch drains" is a two-state assertion, and without a hold the false state is a race against a batch that persists twenty-one small files in milliseconds. A sleep-based test would be flaky in exactly the direction that hides a regression. The persistence path already carries injection hooks of this shape (`should_inject_preparation_failure_for_test`), so this follows an established pattern rather than inventing one.
  Date/Author: 2026-08-08 / Opus (implementation).

- Decision (Milestone 4): the benchmark built four binaries, not two. `RustAnalyzer::build_cargo_routes` had no profiling scope of its own -- the only cargo-route span in the tree is `RustUsageIndex::build::cargo_routes`, which is inside a build v2 never performs -- so cell (c) could not be decomposed at all on v2. Two extra binaries (`v1i`, `v2i`) add exactly one `profiling::scope("RustAnalyzer::build_cargo_routes")` to `build_cargo_routes_while` and change nothing else; the gate verdicts are read off the unmodified v1 and v2 binaries and the instrumented pair supplies the attribution. They were built in throwaway detached worktrees so no source file in the working tree was touched, and the worktrees were removed afterwards.
  Rationale: a subtracted number that nobody can source to a span is not evidence. The alternative -- reporting cell (c) end to end only -- would have left the plan unable to distinguish "v2 is slow" from "something outside v2 is slow", which is the single question the cell exists to answer.
  Date/Author: 2026-08-07 / Opus (measurement).
- Decision (Milestone 4, run 2): the gate verdicts are read against **V1P** -- `b86e575a` with `d4a82ef4` and `366cb82e` cherry-picked -- rather than against unmodified `b86e575a`, and both are reported.
  Rationale: the gate compares v1-as-it-was against v2-as-delivered, but run 1 proved v1-as-it-was cannot start on this workspace, so its numbers bound nothing. V1P is the v1 usage implementation carrying exactly the two prerequisites v2 also carries, which is the only comparator that isolates the usage layer. It is honest about its provenance: `d4a82ef4` conflicted in two files, the plan file (documentation, incoming side taken) and `store/mod.rs`, where the HEAD side of the single hunk was EMPTY because the base lacks the Milestone 3 helpers the patch's context carried -- so the resolution was to drop three marker lines and keep the incoming block verbatim, with no line of the patch rewritten. Neither file version contains a literal `=======` line the marker strip could have eaten (verified). `366cb82e` applied clean. V1P compiled without error. A hand-port was not attempted and would have been refused.
  Date/Author: 2026-08-08 / Opus (measurement).
- Decision (Milestone 4, run 2): gate 3 is recorded as PASS-as-measured with the caveat attached, not as a clean pass.
  Rationale: v2's peak RSS across (a)-(c) is 0.45-0.56 GB against a 4 GB bar, which is what the plan asked for. But the figure is where the process got before the 3 s deadline stopped it, not a plateau -- the same binary at a 30 s budget peaks at 16.02 GB -- and V1P measures the same 0.45-0.56 GB, so the reduction is the prerequisites' and not v2's. Recording it as a clean pass would credit v2 with a number it did not produce and would hide that the query performed no usage work. Gates 1 and 2 fail regardless, so nothing turns on the distinction except honesty.
  Date/Author: 2026-08-08 / Opus (measurement).
- Decision (Milestone 4, run 2): each cell was run twice in the same cache state, once with `BIFROST_TIMING` unset and once with it set, and the two are never mixed.
  Rationale: run 1's limitation 4 recorded that timing is not free on v2. Splitting the run gives an unperturbed wall clock and RSS for the verdict and a span decomposition for the attribution, at the cost of doubling the cell count. The alternative -- one timed run per cell -- would have put span I/O inside every gate number.
  Date/Author: 2026-08-08 / Opus (measurement).
- Decision (Milestone 4, run 3): V1P is the **run-2 binary reused byte for byte** (sha256 prefix `1c681b389162f41d`, matching run 2's record), not rebuilt, and it is deliberately NOT given `575c2ffb` or `13bb6263`. V1-unchanged was not run at all.
  Rationale: reusing the binary reproduces run 2's cherry-pick and its one mechanical conflict resolution by identity instead of by repetition, so nothing can drift between the two runs. `575c2ffb` fixes v2-only code and has no v1 counterpart; `13bb6263` is shared, so V1P does pay the old orchestration cost, but the `build_cargo_routes` span separates that cost out in every row -- which is more informative than cherry-picking, because it turns V1P into the control that measures #1817. V1-unchanged has two runs of record and run 2 established that all of its numbers belonged to the shared prerequisites, so a third identical row would add no information.
  Date/Author: 2026-08-08 / Opus (measurement).
- Decision (Milestone 4, run 3): the two gate-deciding cells get four to six repetitions; every other cell keeps one per configuration.
  Rationale: v3 cell (a) warm lands at 5.51 s against a 5 s bar, so a one-repetition FAIL would have been indistinguishable from host noise. Six repetitions (5.21-5.61 s) put every observation above the bar, and four repetitions of cell (c) (6.11-7.61 s) put every observation below its bar. Repeating the other cells would have cost hours for verdicts that are decided by factors of 15 to 130.
  Date/Author: 2026-08-08 / Opus (measurement).
- Decision (Milestone 4, run 3): gate 2 is recorded as a PASS on its stated bar, with the "resolved nothing" caveat attached to every quotation of it -- not as a conditional pass and not as a failure.
  Rationale: the plan's gate 2 is a wall-clock bar and 6.61 s median clears it with no subtraction, which is a real and new result and the first gate this plan has passed. But the cell still returns `resolved=0 total_hits=0` and neither proof span fires in it, so the number says how fast the pipeline gives up, not how fast it answers. Recording it as a failure would hide a genuine improvement; recording it without the caveat would license Milestone 5 on a latency figure for work that did not happen.
  Date/Author: 2026-08-08 / Opus (measurement).
- Decision (Milestone 4, run 3): the cell-(b) attribution is settled by giving V1P a raised budget on the same symbol rather than by reading the code.
  Rationale: at the gate budget V1P looks 45x faster than HEAD on cell (b) (14.22 s against 653 s), and the naive reading is that v2 regressed. The code says otherwise -- `resolve_codeunit_fuzzy` is byte-identical between the two revisions -- but the plan's own standard is a measurement, and the run-1 and run-2 attributions were both settled that way. One V1P run at a 30 s budget produces 721.58 s in the same span with the same 20,930 store round trips, which converts the reading from an inference into a paired observation.
  Date/Author: 2026-08-08 / Opus (measurement).
- Decision (Milestone 4): the cell-(c) figure after subtracting the cargo-routes span (7.70 s, under the 10 s bar) is recorded as a decomposition and NOT as a conditional pass.
  Rationale: the residual is analyzer construction plus 1.33 s of scan work, and the scan had not resolved the symbol when its deadline fired. A subtraction can show where the time went; it cannot show that the remaining code would have met the bar, because that code did not run. Recording it as "passes once cargo_routes is discounted" would license Milestone 5 on the strength of work that was never measured.
  Date/Author: 2026-08-07 / Opus (measurement).

- Decision (#1793): four narrow tables (`rust_module_scopes`, `rust_module_routes`, `rust_module_route_gates`, `rust_item_macros`), not one route table with an encoded route string.
  Rationale: the reader needs an ordered chain -- the enclosing inline modules, each with its own optional `#[path]` -- and the chain has to be walked step by step (see Surprises). Encoding that chain in a TEXT column would have meant inventing an escape for arbitrary `#[path]` values and a parser for it, which is the hand-rolled source-text parser the conventions prohibit. A parent-pointer scope tree is the same information in the store's own vocabulary, and it deduplicates: one scope row serves every declaration written in it. The gate chain is a child table for the same reason.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1793): Cargo manifests are read from disk at build time and not persisted.
  Rationale: the measurement above. The plan direction asked for a measurement rather than a guess, and 4.9 ms against 34-44 s settles it. Manifests are also not analyzed blobs, so persisting them would have needed a second keying scheme in a store whose whole discipline is content-hashed blob rows.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1793): item-position macro invocations are expanded optimistically at analysis time and gated at read time, rather than persisting the fragment text or re-parsing the invoking files during the build.
  Rationale: the passthrough verdict is cross-file, so no per-file row can carry it; the gate is the smallest thing that can. The cost is that analysis now re-parses every item-level macro token tree, which is work `parse_rust_file` largely already does for `#1015`'s macro-interior reparse, and it is paid once per blob instead of once per process generation.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1793): a blob with no module-route rows is repaired by parsing that one file inside the build, NOT by calling the Milestone 3 catch-up first.
  Rationale: the catch-up's above-threshold policy defers to the background pool and returns, which is correct for a usage query (the readiness probe reports the wait) and wrong for the route index: the index would be built and memoized for the whole generation from an incomplete row set, and it answers forward queries too, where nothing reports a wait. A per-file parse is bounded by the shortfall -- normally zero, because analysis writes these rows -- and it degrades to exactly the old behavior in the worst case instead of to a silently empty index. It is also the gate `0b35bb12` used for the scan path: recover per item, count the recoveries, and pin the count.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1793): the equivalence pin is at the module-edge boundary, and the pre-#1793 syntax walk stays in `cargo_routes.rs` behind `#[cfg(test)]` to be the reference it compares against.
  Rationale: the edge function is the whole substituted seam -- `build_while`'s orchestration (the manifest topology, the macro-visibility fixed point, the reachability walks, the test-only complement) is unchanged apart from where its edges come from. Pinning at that boundary compares the two derivations directly, over both values of `is_crate_root` and with and without a visible passthrough macro, where an index-level A/B would have needed a second copy of the whole orchestration to compare against. The index level is covered instead by the existing suites, which all reach `analyzer.cargo_routes()`, plus one new multi-crate behavior test. The frozen walk also still backs `build_from_disk`, whose fixtures have no store.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1793): the route facts travel inside `RustUsageFacts` and are written by the existing `insert_rust_fact_rows`, but the build reads them through a separate batched reader rather than through `rust_usage_facts`.
  Rationale: one transport, one write path and one cascade means the Milestone 1 witness rule still holds -- a blob with `rust_modules` rows has these rows too -- and the two write paths cannot diverge. The read is different in kind: the route index is a whole-workspace product that needs every file's rows at once, where the usage layer reads one candidate at a time. `AnalyzerStore::rust_module_route_facts` is four chunked `IN` seeks per 400 blobs; asking per blob would have been tens of thousands of round trips, and going through `rust_usage_facts` would have dragged every file's identifier-occurrence rows along with it.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1793): the fallback counter lives on `RustAnalyzer`, not as a process-global static.
  Rationale: the two idioms both exist in this tree (`full_declaration_scan_count_for_test` is per-analyzer, `rust_tree_parse_count_for_test` is global). Per-analyzer is the one that does not depend on nextest's process-per-test isolation to stay meaningful, and the question is per-generation anyway.
  Date/Author: 2026-08-08 / Opus (implementation).

- Decision (#1774): the request memo holds the live-path WALK, not the scan's answer, and the `keep` predicate stays outside it.
  Rationale: `try_sql_nonpersisted_workspace_declarations_vec_matching_limited` applies `keep` in the middle of its own body, and everything after it -- `snapshot.validate` (a stat per candidate), the structured-import blob query, and declaration hydration -- is scoped to whatever `keep` admitted. Memoizing the finished answer would have meant memoizing `keep(|_| true)`, which hydrates every declaration in the workspace and is far more expensive on a large tree than the walk it replaces. Memoizing the prefix -- the (live file, oid, path-synthetic module unit) triples -- removes the O(all paths) term that every caller shared while leaving each caller's narrowed tail exactly as it was. The live snapshot travels inside the memo so a hit and its tail read the same live-path state, which is strictly more consistent than the previous code, where each call re-sampled.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1774): a cancelled walk publishes nothing.
  Rationale: the walk is interruptible mid-way and returns the paths it inspected so the caller can report an incomplete result. Publishing a partial entry would let a later caller in the same request read a truncated workspace as the workspace, which is the "empty answer read as proven absence" failure this repository keeps guarding against. `Err(inspected)` therefore reports the budget figure and leaves the memo empty.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1748): `definitions(fq_name)` gets a request-scoped memo of its own, keyed by name, next to `parent_units`.
  Rationale: this is the #1230 item 6 idiom applied to the read one level below it -- `definition_parent_unit` already memoizes `definitions` results by OWNER name for a request, for the same reason and with the same invariant. A plain `HashMap` under one lock rather than per-key single flight, because each entry is one bounded lookup and a racing duplicate is cheaper than the coordination. Failed reads are never memoized: the error propagates and the entry stays missing, so the next caller retries instead of inheriting an empty answer. With no scope open there is no memo and the behaviour is exactly the unmemoized lookup, which keeps direct-analyzer callers honest.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1748): the batch is a provider hook on `ImportAnalysisProvider` with a do-nothing default, not a change to `could_import_file`'s signature.
  Rationale: eleven languages implement this trait and only Rust has the per-candidate store lookup. A new required parameter would have touched all eleven to serve one; a defaulted `prefetch_import_targets(files, import_infos, cancellation)` leaves the other ten byte-identical and lets each opt in when its own measurement says so. Doing nothing is always correct -- the per-candidate path still answers exactly as before, just without the warm memo -- so the hook cannot change results, only cost. The keys are enumerable up front because the walk already holds every candidate's import facts before it inspects any candidate.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1748): the batched store read is one chunked `IN` seek over short names, and the assembly it feeds is the SAME function the point lookup uses.
  Rationale: `sql_definition_candidates_vec` was split into "get the rows" and `assemble_definition_candidates`, and both the point path and the prefetch call the latter. Duplicating the exact/normalized precedence, the definition ordering, the dirty-unit merge and the single-module rule into a second copy is how the batched answer would eventually drift from the unbatched one; sharing the function makes drift impossible, and one test asserts the two paths produce identical `CodeUnit` vectors. The `IN` list follows `declaration_candidate_rows_by_identifiers_for_langs` (#1688) and the 400-key chunk bound matches the other bulk readers in `store/mod.rs`. Rows carry their own `short_name`, so regrouping needs no second read. The path-symbol half reuses the existing `forward_path_module_fqns_batch`, whose per-FQN error already degrades to `None` -- which here means "leave that one name to the point lookup", the honest fallback.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1748): no count-based early trip was added to candidate discovery, and the reason is that computing the count IS the work.
  Rationale: the plan direction asked for the `searchtools-too-broad-scope-guards.md` pattern -- trip before the per-candidate work, with the true total. That pattern applies where a cheap pre-count exists (a glob's match count, a resolved candidate set). Here the "candidate universe" before discovery is every file of the target's language, which on rustc is 35,370 and would trip on every query, and the discovered candidate set is not known until the walk that costs the time has run. The same conclusion was already reached and recorded for the workspace-root `get_summaries` path ("a pre-flight count guard cannot help here: computing the count is the walk"). What DOES bound the fan-out already: `candidates.len() > max_files` (default 1000) truncates before the graph scan and reports `CandidateFilesBudgetExhausted`, `max_source_bytes` admits by size and reports `SourceBytesBudgetExhausted`, and `SCAN_USAGES_MAX_CALLSITES` produces the structured `TooManyCallsites` result. None of those was the defect; the defect was the per-candidate SQL inside the unbounded phase, which is what the batch removes.
  Date/Author: 2026-08-08 / Opus (implementation).

- Decision (#1809): the cycle rule is chaotic iteration over everything the outermost frame reaches, not a strongly-connected-component collapse.
  Rationale: an SCC collapse (Tarjan lowlink carried through the recursion, iterate only the component's entry frame, publish the component when it pops) is the textbook answer and is strictly tighter. It is also materially harder to get right here -- a component member that pops before its entry frame has to stay reachable at its provisional value, and when an entry frame later discovers it is itself a member of an outer component, every key it already published as pending has to be re-parented. Both are easy to write and hard to review, and getting either wrong publishes a non-converged value to a cache that lives for the generation. The looser rule needs one extra fact -- that the outermost frame iterates -- and gives the same asymptotics on the shape that matters: the iteration runs only when a re-entry actually happened, so an acyclic walk pays exactly one round (the 250-link re-export ladder test still recurses once per link and no more), and a cyclic one pays rounds x reachable keys. Measured 6 recursions per module at every size from six to thirty-two modules.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1809): convergence is detected by a per-walk revision counter that any key bumps when its value's LENGTH changes, not by comparing values.
  Rationale: both computations accumulate through `push_unique` / `push_unique_binding`, so a value can only grow, and the previous implementation already relied on exactly this (`next.len() == routes.len()`). Comparing whole values would need `PartialEq` on `RustModuleAliasRoute` and `RustModuleBinding` at every frame of every round for no additional information. The counter is what makes the rule correct across the component rather than only at the entry frame: a round in which any nested member grew is a round that has to be followed by another.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1809): the cancellation predicate lives on `RustUsageWalks` as `Option<&'a dyn Fn() -> bool + Sync>`, not as a `CancellationToken` field and not as a parameter on each walk.
  Rationale: the callers already hold a `keep_going` closure rather than a token -- `rust_usage_candidate_files` builds `&|| !cancellation.is_cancelled()` and `usage_candidate_files_while` threads it -- so taking a token would have meant changing four signatures to convert a closure back into the thing it wraps. Threading a parameter through each walk would have meant changing every walk's signature and every caller of every walk, including the ones that legitimately have no token (`usage_reference_at` and the graph-scan entry points construct with `RustUsageWalks::new`). A field defaults those to "never cancelled", which is exactly their previous behaviour, and confines the change to the two `new_while` call sites.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1809): every cache write in the walk layer is gated on `!self.cancelled()`, including the ones whose producing loop cannot break early.
  Rationale: the gate has to be a rule rather than a case analysis. A loop that does not break today can be given a poll tomorrow, and the failure it would then introduce -- a truncated workspace answer memoized for the generation and read back by every later query as complete -- is silent, workspace-wide and unreproducible. This is the `#1774` "a cancelled walk publishes nothing" decision applied one layer down, and `graph_support.rs`'s `issue_1304_interrupted_inverted_reference_context_is_not_cached` is the same rule already pinned elsewhere in this analyzer.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1809): the graph-scan entry points (`usage_reference_at`, `usage_binding_seeds`, `usage_importers`, `usage_binding_names`) are NOT given the predicate in this change.
  Rationale: they construct through `RustUsageWalks::new`, and their callers poll between candidates through `UsageScanScope`, so the unbounded region there is one candidate's walk rather than the whole scan -- and that region is what the cost fix just made polynomial. Plumbing a token into them means changing `IAnalyzer`-facing signatures used by the extractor, the inverted index and the resolver, which is a wider change than the defect being fixed and would land untested against the measurement that motivated it. Recorded as a known remaining gap: if a future measurement shows a scan overrunning inside the graph phase rather than inside candidate discovery, this is where to look first.
  Date/Author: 2026-08-08 / Opus (implementation).

- Decision (#1817): the orchestration is made linear in the workspace and stays eager, rather than being made lazy per Cargo target as the task direction proposed. Recorded as a deviation with its evidence.
  Rationale: the profile above. The cost was a product of workspace size and topology size, and every one of the four factors is a loop that can be inverted or hoisted without changing a single answer; after that the build costs the workspace once, which is the floor any correct answer has to pay because `target_roots_by_file` is defined for every analyzed file. Per-target laziness would not have reached that floor -- it would have moved the same total work behind a memo that the first usage query forces anyway, through `direct_module_domains_of`'s whole-workspace declaration loop and `is_actual_crate_root`'s per-candidate `target_roots_for_file` -- while adding an inversion problem the current edge model cannot express (the observation above). The smallest change that removes the O(workspace x topology) passes is the one that removes them, not the one that defers them.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1817): the guard is a frozen copy of the pre-#1817 orchestration under `#[cfg(test)]`, compared product by product, and not a set of behaviour assertions about the new one.
  Rationale: this is the `#1793` idiom (`rust_external_module_child_edges`) one layer up, and for the same reason: five algebraic rewrites of one derivation cannot be sampled honestly. A behaviour test can only assert what its author thought to ask, and the failure mode here is a target membership that quietly loses a file in a shape nobody wrote a fixture for. `frozen_orchestration` shares everything the rewrite did not touch -- manifest discovery, crate construction, `module_child_edges`, the declaration merge, the test-only complement -- so the diff between the two is exactly the change under test. Three fail-befores were demonstrated against it: shrinking the auto-target grouping depth, dropping `is_crate_root` from the edge cache key, and dropping a file's membership in its own target root.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1817): the structural pin counts whole-workspace sweeps in a thread-local, and measures the frozen orchestration beside the new one inside the same test.
  Rationale: the defect is "how many times does this build iterate the workspace", so that is what the counter should say; a timing assertion would measure the host. Thread-local rather than a process-global static because the build is one sequential call stack, so the pin does not depend on nextest's process-per-test isolation to stay meaningful -- the `#1793` fallback-counter decision reached the same place from the other direction. Running both implementations on the same two workspaces (2 crates x 24 modules and 16 crates x 3 modules) puts the fail-before inside the pin: the new count must be identical across the two and at most eight, and the frozen count must grow and stay at least eight times larger.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1817): one membership walk seeded from every target root, in place of one walk per crate.
  Rationale: the walk frontier is `(file, target, is_crate_root)` and the owners map is a union, so per-crate walks and one shared walk reach the same pairs and produce the same result -- the per-crate split bought nothing and cost one rebuild of the analyzed-file set per crate. It also removes the only case where two crates claiming the same target root did the same walk twice.
  Date/Author: 2026-08-08 / Opus (implementation).
- Decision (#1817): `files_by_reachable_root` stays materialised, with the per-root expansion hoisted, rather than being replaced by a query-time union.
  Rationale: hoisting the expansion is what removes the quadratic term; storing source roots and unioning inside `files_that_can_reference_target_of` would additionally save memory, but that accessor sits inside importer candidate discovery, where it can be asked repeatedly in one query, and it would have traded a build cost that is now small for a per-query cost that is not measured. The smaller change is the one whose cost is known.
  Date/Author: 2026-08-08 / Opus (implementation).

## Outcomes & Retrospective

Milestone 1 (2026-08-07). The store now carries four per-blob Rust fact tables and analysis populates them. Migration `crates/bifrost-core/migrations/cache/0016-rust-usage-facts.sql` follows the existing numbered-migration mechanism exactly: a new `include_str!` constant, an entry appended to `CACHE_MIGRATION_SQL`, `CURRENT_MIGRATION_VERSION` 15 -> 16 (the compile-time assertion ties the two), and a matching `execute_batch` in the `CURRENT_SCHEMA_OBJECTS` test fixture. The store file is therefore now `bifrost_cache.v16.db` and v15 caches are untouched beside it, which is the point of the version-in-the-name scheme.

The final DDL as landed is in the migration file, with per-table rationale. It differs from the plan's design DDL in three places, each recorded above in the Decision Log: `rust_exports` gained `imported_name` and a nullable `exported_name`; `rust_import_targets` gained the eight columns needed to reproduce `RustProjectedImport` without a re-parse; `rust_modules` carries the file-root extent as ordinal 0.

Extraction lives in `crates/bifrost-analysis/src/analyzer/rust/facts.rs` and is called once from the end of `parse_rust_file` (`rust/declarations.rs`), with the tree that pass already holds. It reuses the existing projections (`rust_import_projection`, `rust_module_extents`) rather than re-deriving them, so the persisted rows and the live ones cannot drift. Identifier occurrences are the one genuinely new extraction: an explicit-stack walk that records the tree's identifier leaf kinds under a code bit (canonicalized with `strip_raw_identifier_prefix`, so a lookup by a declaration's `short_name` matches), and the identifier-shaped words inside comment and string tokens under their own bits.

Rows reach SQLite through both write paths -- `write_prepared_blob_unchecked_tx` (the batched production path) and `write_parsed_blob` (the legacy path) -- via one shared `insert_rust_fact_rows`, so a parity test comparing the two cannot diverge. `RustFactRows::from_facts` does the fallible `usize -> i64` conversions during preparation, off the write transaction, matching how every other row shape here is built.

What remains after Milestone 1: nothing in the product read these rows. The reader existed and was tested, but `RustUsageIndex` still answered every usage query.

Milestone 2a (2026-08-07). `crates/bifrost-analysis/src/analyzer/rust/usage_queries.rs` is the store-backed query layer. It reads one blob's facts through `RustAnalyzer::rust_usage_facts_of_blob`, memoized in a weighted bounded cache keyed by `(analysis generation, blob oid)` -- a content-hash key, so an edited file is a different entry and single-file invalidation costs nothing. It composes the stored file-root-relative module names with the live file's package name on the way out, which is the only place a path enters. On top of that sit the per-file products (`module_extents_of`, `module_at_byte`, `declared_file_modules_of`, `import_bindings_of`, `re_exports_of`), the three inverted lookups (`files_mentioning` with a context-mask filter, `files_importing_module_path`, `files_exporting`), and IntelliJ's two query-cost mitigations: `bucket_by_locality` orders candidates anchor-file-first then same-directory then rest without dropping any, and `any_file_mentioning` stops at the first candidate that verifies.

Two products moved off `RustUsageIndex` completely. `module_extents` is gone from the struct: `module_at_byte` now reads `rust_modules`, and the workspace-wide build no longer opens a syntax tree to produce extents. Two helpers (`unique_seed_identity_for_fqn`, `unique_seed_identity_for_import_targets`) stopped touching the index at all as a result. The re-export half of `export_index_of_declarations` in `rust/graph_support.rs` reads `rust_exports` instead of re-walking the file's root `use` declarations; its local-export half stays declaration-driven, because "is this declaration visible outside its module" is a visibility question over `code_units`, not something a `use` list answers.

The acceptance bar held: the existing Rust usage suites pass unchanged, with only the documented pre-existing failures. Seven new tests cover the layer, two of them equivalence pins that recompute the projection from a live syntax tree and require the store rows to match -- including one file with a non-empty package name, so the composition is genuinely exercised. Breaking the composition fails that pin (demonstrated).

What remains, and why it is not a small step. Milestone 2's remaining products are not independently movable. `binding_seeds` is the entry point every consumer reaches, and it walks `importer_reverse`, which is keyed by target file and produced from `module_aliases` plus `physical_owners` plus `module_files` -- three workspace-wide structures that are built from each other. Worse, the persisted inverted key is the module path as written, and one target module is written five different ways by five different importers, so "which files import target T" is not a `rust_import_targets` lookup at all. It has to become the `IdIndex` shape: candidates are the files whose text mentions the target's name, and each candidate's forward edges are then computed and filtered. That is a rewrite of `binding_seeds` and of the cross-file group as one piece, not a re-pointing, and it is what Milestones 2b and 2c cover.

Milestone 2b (2026-08-07). `identities_by_name` is deleted from `RustUsageIndex`, and with it the workspace-wide pass that bucketed every declaration domain key by name.

The move has two halves. First, the per-file derivation that produces identities and their visibility domains -- roughly a hundred lines that lived inside the index build's per-file closure -- became `rust_declaration_facts` in `rust/usage_queries.rs`, returning a `RustDeclarationFacts` of identities, value-constructor identities, declared module domains, and identity-to-domains. The v1 build calls it with its own cancellation callback and folds the result into the same maps as before; the query layer calls it through a new byte-budgeted per-file cache on `RustAnalyzer`. One function, so the two cannot drift.

Second, the name lookup. `identities_named(name)` asks `lookup_candidates_by_identifier` -- the store's indexed short-name lookup over `code_units` -- for the files that declare that identifier, then verifies each against its own declaration facts. Two of the three former call sites did not need it at all: they already filtered the bucket down to one known file, so they became per-file reads (`identities_in_file_named`). Only the site that knows the resolved module but not the declaring file performs a real name search.

Acceptance held: the existing Rust usage suites pass unchanged, with only the documented pre-existing failures (three in `brokk-bifrost-analysis`, all stash-verified against the pre-milestone tree and all outside Rust). Two new tests: an equivalence pin that requires `identities_named` to reproduce the v1 index's `declaration_domains` buckets name for name and domain for domain, and a candidate-rejection test whose fixture declares the same identifier as a module-scope function in one file and as an associated function in another. The second fails when the module-scope check is removed (demonstrated by probe).

What 2b did not do, and why it is not an omission: `module_importers` and `importer_reverse` stayed. Both are keyed by something the persisted rows are not keyed by, and for both the verification step is "recompute this candidate's forward import edges" -- which needs alias routes, module-file resolution and physical owners. They move with 2c, as one piece, and the Decision Log records the call.

Milestone 2c (2026-08-07). `RustUsageIndex` answers nothing. `rg "usage_index\(\)"` finds no consumer call site: the remaining hits are two comments and the warm entry point. Every one of the fifteen remaining products is now a bounded, memoized walk in `crates/bifrost-analysis/src/analyzer/rust/usage_walks.rs`, and the seed and reference capabilities that consumed them (`binding_seeds`, `importers_of_seeds`, `matching_edges_for_importer`, `declaration_visible_at`, `export_targets_from_files` and the visibility helpers) were re-pointed in place, method by method, with their control flow deliberately unchanged.

Layer 0 turned out not to be walks at all: `physical_roots` is `ModuleKey::new(file, &rust_package_name(file))` gated on analyzed membership, `actual_crate_roots` is a per-file predicate, and `inferred_crates_by_file` is one indexed package lookup. Layer 1, module-file resolution, needed no new index but did need the correction recorded in Surprises. Layer 1b, physical ownership, inverted from a downward breadth-first walk over the whole workspace to an upward walk from one file. Layer 2, alias routes, replaced a fixed point over every import in the workspace with a memoized recursion that preserves the longest-prefix-before-domain-filtering rule. Layer 3 replaced `importer_reverse` and `module_importers` with candidates-then-verify over per-file forward edges, `origin_routes_by_file` with a backward walk over what each module binds, and `macro_visible_ranges` with a per-file scope-edge memo plus a per-macro outward walk -- which also removes the pass that opened every syntax tree in the workspace.

The acceptance bar held. Every Rust usage suite passes unchanged: `tests/suite_usages` and the scan-usages Rust cases, with only the documented pre-existing failures. Getting there found exactly three real divergences, all recorded in Surprises: a `ProjectFile` built from an empty root in the crate-root candidate path, the `definitions(fq_name)` collapse, and the length-one export-chain cycle. Seven new tests cover the v2 seam -- candidate rejection through module resolution, per-generation memoization, export-chain cycle termination, a 250-link chain, the longest-alias-prefix rule, the self-republication visibility upgrade, and the structural pin that a usage query charges no whole-workspace declaration scan. The candidate-rejection guard fails when verification accepts a candidate on the imported name alone (demonstrated), and the cycle handling was demonstrated failing on the macro-visibility suite test before the fixed-point iteration landed.

What remains is Milestone 3's: the warm still builds an index nothing reads, and readiness still reports on it.

Milestone 3 (2026-08-08). Nothing builds `RustUsageIndex` any more, on any path.

The invalidation half turned out to need no change, and proving that was the work. `RustAnalyzer::update` and `update_all` construct a new analyzer with fresh caches rather than mutating in place, so the Milestone 2c keying decision -- the analyzer instance IS the generation -- is true of the real update path, not just of `update_all` in a test. `a_single_file_edit_is_reflected_by_the_next_usage_query` writes a new import into a file after a first query has filled every walk cache with the pre-edit answer, applies it through `analyzer.update(...)`, and requires the next query to bind the new target while charging zero whole-workspace declaration scans. It passes on HEAD and fails as soon as `update` carries `walk_caches` across, which is what makes it a guard. So there was no live staleness bug from 2c.

The gap that was real is different in kind: a live file whose blob carries no fact rows is INVISIBLE to a v2 answer, not slow, because the inverted lookups map blobs to files and a blob with no rows offers no candidate. `crates/bifrost-analysis/src/analyzer/rust/fact_catch_up.rs` closes it with IntelliJ's small-change policy. `rust_files_without_facts` maps the analyzed Rust files to their live oids and asks the store, in 400-key chunks, which of those blobs have a `rust_modules` row; below twenty files the shortfall is re-parsed and persisted on the querying thread, at or above twenty it goes to the dedicated build pool and the readiness probe reports false until it drains. The whole thing runs at most once per analyzer generation behind a `PoolSafeMemo`, and the hook is `RustUsageWalks::with_cargo_routes`, the one constructor every cross-file walk passes through.

Two implementation details are load-bearing and both are recorded in Surprises: a catch-up batch must pick one representative per blob key, because byte-identical files share a blob and the persistence layer rejects a duplicate key in one batch with an assert; and it must skip a file whose disk bytes no longer hash to its live oid, because blob rows are content-addressed and a row that lies is worse than a row that is missing.

The warm is now the same catch-up. `RustAnalyzer::warm_usage_index` is deleted; `warm_usage_facts` calls `ensure_rust_facts_caught_up`, `WorkspaceAnalyzer::warm_rust_usage_index` became `warm_rust_usage_facts`, and the MCP `StartupIndexWarm::AtStartup` thread calls that. The reference-context half and its `BIFROST_WARM_USAGE_ANALYSIS` opt-out are unchanged, because that fan-out is a separate concern that survives v2. `query_indexes_warm` for Rust is now "hierarchy built and catch-up settled". The readiness probe splits in two: `rust_usage_facts_ready` (no batch outstanding) is what `get_active_workspace` reports as the unchanged `usage_index_ready` field, and `rust_usage_facts_warm` (the catch-up has run) is what the warm-ness callers ask.

Four new tests, each demonstrated failing against the state it guards: the single-file edit test above; `a_below_threshold_catch_up_runs_inline_and_never_reports_a_wait`, which deletes a workspace's fact rows and requires the next query to answer anyway with the probe never false (it fails without the walk hook); `an_above_threshold_catch_up_defers_and_reports_false_until_it_drains`, which holds the batch on a barrier so the false state is observed without a timing assumption (it fails if the policy always inlines); and `warming_the_usage_facts_builds_neither_the_hierarchy_nor_the_reference_contexts`, which also asserts the v1 index is never built. Three existing tests changed text: the hierarchy warm test now asserts the catch-up rather than the v1 memo, the workspace probe test asserts the readiness/warmth distinction, and the MCP one-shot-service test asserts warmth rather than readiness, because a v2 session with nothing outstanding is ready before it warms.

What Milestone 4 must account for before it attributes any number to v2: the Rust usage path still drops a workspace-sized structure on every file change, and it is `cargo_routes`, whose build hydrates and parses every analyzed Rust file. Every walk needs it. Cell (c) of the benchmark measures that rebuild, not the fact catch-up. The Surprises entry has the evidence.

Milestone 4, run 1 (2026-08-07). **All three gates fail for v2. All three fail
for v1 by the same margins. The plan stops; Milestone 5 does not start.** Full
report, repro commands and limitations: `usage-v2-killgate-v1.md` in the session
scratchpad; the numbers that decide each gate are reproduced here.

Setup. Two featureless release binaries: v1 = `b86e575a` (the parent of the 2c
consumer switch `8f0d2a75`, where `binding_seeds` and `importers_of_seeds` still
read `self.usage_index()`), v2 = HEAD `41b93227`. Both built through
`scripts/with-isolated-cargo-target.sh` in throwaway detached worktrees, and
identified by distinguishing strings rather than by trusting the build script
(v1 carries `RustUsageIndex::build::module_aliases`; v2 carries
`RustAnalyzer::rust_fact_catch_up` and `usage_walks.rs`). Two further binaries,
v1i and v2i, add one `profiling::scope("RustAnalyzer::build_cargo_routes")` to
`build_cargo_routes_while` and nothing else, because no existing span brackets
the Cargo-route build outside `RustUsageIndex::build` -- which v2 never runs.
Workspace: the rustc tree `rust--01f6ddf7` (35,370 `.rs` files) copied off the
read-only corpus to a writable path. One cache per binary, each built from
scratch by its own binary (~843 MB, ~2 min); both commits are at cache schema
v16, verified in `cache_db.rs` at both revisions. Host: 120 CPUs, 98 GB, busy
throughout (1-min loadavg 20-390, recorded per cell), one repetition per cell.

Cells. (a) `compiler/rustc_target/src/spec/mod.rs#SanitizerSet`, 75 mentioning
files, cross-crate. (b) `main`, selected by the plan's own
`SELECT identifier, COUNT(*) ... ORDER BY COUNT(*) DESC` over
`rust_identifier_occurrences` -- the winner at **22,976 blobs** (next: `a`
15,929, `the` 13,493), anchored to `compiler/rustc/src/main.rs#main` because
`main` is declared 21,942 times. (c) a trailing comment appended to the file
that declares the (a) symbol, then the (a) query, restored after (`git diff
--quiet` clean each time). (d) `/usr/bin/time -v` maximum RSS.

Results, product default configuration, wall seconds / peak RSS GB:

| cell | v1 cold | v1 warm | v2 cold | v2 warm |
| --- | --- | --- | --- | --- |
| (a) | 50.97 / 13.85 | 58.51 / 13.84 | 45.36 / 14.23 | **47.97 / 14.22** |
| (b) | 63.74 / 13.85 | 84.82 / 13.79 | 45.47 / 14.22 | **42.26 / 14.24** |
| (c) | -- | 43.49 / 13.93 (edited) | -- | **74.91 / 14.33** (edited; v2i, quieter host: 41.86 / 14.34) |

Every single cell, both binaries, returns `status=failure`,
`incomplete_reason=time_budget`, `resolved=0`, `total_hits=0`. Nothing was
answered.

Gate verdicts, each with the measurement that decides it. **Gate 1 FAILS** on
its absolute bar: v2 (a) warm = 47.97 s against 5 s, 9.6x over. Its relative
half passes (v2 is 0.82x of v1's 58.51 s, inside 2x) but the plan's text is an
AND, and a query that returns nothing cannot pass on latency. **Gate 1(b)
FAILS**: v2 (b) warm = 42.26 s against 5 s. **Gate 2 FAILS**: v2 (c) = 74.91 s
against 10 s (v1: 43.49 s). **Gate 3 FAILS**: v2 peak RSS 14.22-14.33 GB against
4 GB, 3.6x over, and *worse* than v1's 13.79-13.93 GB rather than the reduction
this plan predicted.

Cell (c) decomposition, v2i, warm cache, one edited file: wall 41.86 s, of which
`searchtools.scan_usages_backend` 35.49 s, of which **`RustAnalyzer::build_cargo_routes`
34.16 s (82% of wall)** and all other scan work **1.33 s**; `WorkspaceAnalyzer::build`
5.46 s; the edited file's `reconcile_file_states` 1.95 s. Subtracting the
cargo-routes span leaves 7.70 s, which is under the 10 s bar -- **this is
recorded as a decomposition, not as a passing verdict.** The residual is
analyzer construction plus 1.33 s of scan work, and the scan had not resolved
the symbol when the deadline fired, so nothing inside that 7.70 s demonstrates
v2 meeting anything.

The finding that governs the whole run: `build_cargo_routes` costs 34-44 s in
*every* v2 cell -- cold and warm, edited and unedited -- and it is charged
inside the scan's own 3 s `SCAN_USAGES_MAX_DURATION`. The deadline is 11-15x
expired before `RustUsageWalks::new` can return. The Milestone 3 Surprises entry
predicted this for cell (c); it is true of all of them, on an untouched warm
workspace, so it is not an invalidation problem but the absence of persistence
for `RustCargoRouteIndex`. Two spans are conspicuously absent and worth
recording: `RustAnalyzer::rust_fact_catch_up` never fires (every live blob
already had fact rows, so the Milestone 3 catch-up costs nothing here), and
`RustUsageIndex::build` never fires on v1 either -- **this benchmark never
compared the v1 index against the v2 walks at all.**

A supplementary sweep raised the budget to 120 s so the scan could get past
cargo_routes. All four binaries still returned `resolved=0` / `time_budget`
after ~127 s of scan, at 25.8-27.3 GB peak RSS (so the 14 GB above is not a
plateau -- it is how far the process got in the default budget). The largest
span in all four is `usages::candidate_discovery` (`usages/finder.rs:173`,
byte-identical in both trees) at 75-92 s, inside which
`project::collect_workspace_files` -- a whole-workspace listing -- runs 64 to
137 times in one query and `sql_definition_candidates.rows` runs 397k to 662k
times. Both patterns are at least as strong in v1 (137 listings, 662k lookups)
as in v2 (64 listings, 397k lookups), so neither is v2's. An earlier reading in
that session provisionally attributed the repeated listing to repeated
`RustUsageWalks` construction; the v1 runs refute it.

What this means for the plan. The kill-gate did its job in the sense that it
stopped Milestone 5, but it did not answer the question it was designed to ask.
Two structures outside this plan's scope -- the unpersisted Cargo-route index
and shared candidate discovery -- consume the entire query budget before any
per-file-fact composition runs, so the run supports no claim that v2 is faster,
slower, or equivalent to v1 for usage analysis. Deleting `RustUsageIndex` now
would remove the only comparison point while that question is still open. Both
structures are product regressions under CLAUDE.md's five-second rule and want
the open-issue search before new issues are filed; #1758 names neither. The
owner's call is whether fixing them becomes a prerequisite of this plan or a
separate track that Milestone 4 waits on.

Milestone 4 prerequisite, issue #1793 (2026-08-08). `RustCargoRouteIndex` no
longer parses anything. It composes from per-blob rows plus the Cargo manifests,
and every Rust usage query stops paying the 34-44 s the kill-gate run above
attributed to it.

What the build actually consumed from each file was small: the lexical scopes
`mod` items are written in, the external `mod name;` declarations, and the
`macro_rules!` item macros. Migration
`crates/bifrost-core/migrations/cache/0017-rust-module-routes.sql` gives each of
those a table (`rust_module_scopes`, `rust_module_routes`,
`rust_module_route_gates`, `rust_item_macros`), cache schema version 16 -> 17,
and the Rust analysis-epoch salt gains `cargo-route-facts-2026-08`. Extraction
is `extract_rust_module_route_facts` in `cargo_routes.rs`, called from
`extract_rust_usage_facts` with the tree `parse_rust_file` already holds; the
rows travel on `RustUsageFacts` and are written by the same
`insert_rust_fact_rows` both write paths share, so they cascade with their blob
and are counted in the same `logical_rows` / `string_bytes` accounting.

Everything path-derived stayed with the reader, which is what makes the rows
content-stable: `module_child_edges` computes the file's base directory from
`is_crate_root` and the file's stem, resolves each scope's `#[path]` against the
previous one, composes `declaring_module` from the live file's package name, and
performs the `exists()` check that turns a declaration into an edge. The two
things that could not be per-file facts are recorded rather than papered over --
the macro-passthrough verdict becomes a gate the reader evaluates, and the
`#[path]` chain stays a chain because `canonicalize` resolves symlinks at every
step. Both are in Surprises.

Cost shape. Before: `O(analyzed files)` hydrations plus `O(total source bytes)`
of tree-sitter parsing, per analyzer generation, every generation, inside the
scan's three-second budget. After: `O(rows)` -- four chunked `IN` seeks per 400
blobs over tables whose row count tracks `mod` declarations, not source bytes --
plus the manifest set (347 files, 207 KB, 4.9 ms warm on the rustc tree) and one
`exists()` per candidate, which the old build also paid. On the inline
multi-crate fixtures the whole `analyzer.cargo_routes()` call is inside the
0.1-0.2 s a test takes end to end, and the structural pin
`composing_the_cargo_route_index_parses_no_workspace_file` asserts the parse
count is exactly zero -- it reports 16 when the row read is disabled
(demonstrated), while still answering correctly, so the pin is about the cost
and not the answer.

Equivalence. The pre-#1793 syntax walk is frozen in the same file under
`#[cfg(test)]`, and `module_child_edges_reproduce_the_frozen_syntax_walk`
requires the new extraction plus reader to reproduce it edge for edge -- byte
offsets, the `#[macro_use]` visibility point, the test gate and the duplicate
merge included -- over a fixture with plain, directory-backed, `#[path]`,
`#[macro_use]`, `#[cfg(test)]`, composed-cfg, nested-inline, relocated-inline,
duplicate and macro-expanded declarations, for both values of `is_crate_root`
and with and without a visible passthrough macro. It fails when the gate filter
is removed and when a declaration's `#[path]` is resolved against the wrong base
(both demonstrated). `the_module_route_fixture_exercises_every_declaration_shape`
is what stops that comparison holding vacuously.

The other new tests: `cargo_routes_compose_from_rows_across_a_multi_crate_workspace`
(target membership, cross-crate path-dependency resolution, target relation, the
external-module-declaration list the usage walks read, and test-only
reachability), and in the store
`rust_module_route_tables_record_scopes_routes_gates_and_item_macros`,
`rust_module_route_rows_cascade_with_their_blob`,
`rust_module_route_rows_are_stable_across_a_re_analysis_of_the_same_content`
(the same bytes at `src/lib.rs` and `src/deep/nested/mod.rs`) and
`batched_module_route_facts_match_the_per_blob_read`. All four store tests fail
when the extraction call is removed from `extract_rust_usage_facts`
(demonstrated).

Every existing Rust usage and Cargo-route suite passes unchanged, including
`passthrough_macro_routes_require_faithful_item_replay_and_lexical_visibility`,
which is the densest coverage of the part of this that is not per-file.

Milestone 4 prerequisite, issues #1748 and #1774 (2026-08-08). The
`sql_definition_candidates` half of the shared candidate-discovery storm is
gone, and it was never a Rust problem: `usages/finder.rs` and
`usages/candidates.rs` are language-neutral, and the fix is too.

What the multiplicity actually was. `find_direct_importers_with_cancellation`
visits every analyzed workspace file and asks the language's import provider
`could_import_file(candidate, imports, target)`. Rust answered by resolving each
`use` path to an fq name and calling `definitions(&fq_name)`, one store round
trip -- pooled reader checkout, transaction, generation check -- per `use`
statement. 397,000 / 35,370 files is 11.2 and 662,000 / 35,370 is 18.7: import
counts per file, not candidate counts. It is charged twice per file in the
common case, because when the answer is `false` the caller immediately resolves
the same imports again through `imported_code_units_of`. Every other language
that hit this had already been fixed with a per-file cache (Python's
`resolve_import_target_files`, JS/TS's `resolved_import_target_files`, whose
comment names this exact walker); Rust was missed. Per-file caching would not
have been enough anyway -- with one target file the walk visits each candidate
once, so the multiplicity is files x imports and only a batch across files
removes it.

Three changes, all shared. (1) `definitions(fq_name)` is memoized for the life
of an `AnalyzerQueryScope`, in the `parent_units` shape and next to it. (2) The
whole-workspace live-path walk behind
`sql_nonpersisted_workspace_declarations_vec_matching` -- #1774's subject -- is
materialized at most once per request as `WorkspaceModuleWalk`, with the
narrowing `keep` predicate deliberately left outside the memo so each caller's
expensive tail stays scoped exactly as before. (3) `ImportAnalysisProvider`
gained `prefetch_import_targets`, a defaulted no-op that lets a provider resolve
the whole candidate set's keys in one batch before the walk starts;
`RustAnalyzer` implements it, and `TreeSitterAnalyzer::prefetch_definitions`
fills the request memo from one chunked `IN` seek
(`declaration_order_candidate_rows_by_short_names_for_langs`, 400 names per
statement) plus the existing `forward_path_module_fqns_batch`. The point path
and the batch share `assemble_definition_candidates`, so the two cannot drift.

Counters, on `tests/suite_usages/issue_1748_candidate_discovery_batching.rs`
(8 caller files that import the target last, 8 bystanders that never import it,
64 `use` statements): before, 0 batched reads and 65 point lookups -- one per
`use` statement; after, 1 batched read and 1 point lookup. Also pinned: one
live-path walk per request across three lookups (3 before), one store read for
a repeated `definitions` name (2 before), zero point lookups after a prefetch
(4 before), and the prefetch offered the whole candidate set exactly once
before the first per-candidate question (0 before). Every one of those was
demonstrated failing with the three mechanisms disabled.

What this does NOT fix, and is not claimed to. The kill-gate run's other
measured multiplicity -- `project::collect_workspace_files` running 64-137
times -- was not reproduced or attributed; the Surprises entry records why the
span log alone cannot separate "inside candidate discovery" from "concurrent
with it", and what would settle it. No count-based early trip was added either;
the Decision Log records why a pre-count cannot bound a phase whose cost IS
computing the count, and what does bound the fan-out today. One confirmed waste
was removed on the way past: `present_reference_only_sibling_extensions_by_language`
deep-cloned the project's entire file listing to read extensions off it, and now
reads the shared `Arc`.

Milestone 4, run 2 (2026-08-08, after both prerequisites). **Gates 1 and 2 still
FAIL. Gate 3 passes as measured, and that pass is not load-bearing. Milestone 5
stays blocked.** Full report, repro commands and limitations:
`usage-v2-killgate-v2.md` in the session scratchpad; the deciding numbers are
reproduced here.

Setup. Same rustc tree as run 1 (`rust--01f6ddf7` @ `525258043d7f9dcc`, 35,370
`.rs` files), same cells, same cell-(b) selection -- the plan's own
`ORDER BY COUNT(*) DESC` re-run on the run-2 cache returns `main` at 22,976 blobs
again, identical to run 1. Three gate binaries instead of two: **v1** =
`b86e575a` unchanged (cache schema **16**), **v1p** = `b86e575a` with `d4a82ef4`
and `366cb82e` cherry-picked (schema **17**), **v2** = HEAD `366cb82e` (schema
17). Two measurement-only binaries: **v2i** adds one `eprintln` of
`Project::workspace_file_listing_count` to `run_tool`, **v2s** adds six
`profiling::scope` calls inside `build_cargo_routes`. All five featureless
release builds through `scripts/with-isolated-cargo-target.sh` in throwaway
detached worktrees, identity verified by distinguishing strings. One cache per
lineage, each built by its own binary; the schema-16/17 split is a non-issue
because the version is in the file name. Each cell run twice in the same cache
state, untimed then timed. Host busy and variable (loadavg 4-399), one
repetition per cell.

Gate results, product default budget, untimed runs (wall s / peak RSS GB):

| cell | v1 warm | v1p warm | v2 warm |
| --- | --- | --- | --- |
| (a) | 79.56 / 14.22 | 16.52 / 0.47 | **12.82 / 0.46** |
| (b) | 33.15 / 14.22 | 18.92 / 0.47 | **18.12 / 0.46** |
| (c) edited | 31.54 / 14.35 | 24.23 / 0.56 | **24.05 / 0.56** |

Every cell on every binary: `resolved=0 total_hits=0 failure=1`,
`reason_kind=time_budget`. Nothing was answered, in either run of this gate.

Verdicts, each with its deciding measurement. **Gate 1(a) FAILS** on the absolute
bar: v2 (a) warm = **12.82 s** against 5 s, 2.6x over; the relative half passes
against v1p (0.78x, inside 2x) but the plan's text is an AND and the query
returns nothing. **Gate 1(b) FAILS**: v2 (b) warm = **18.12 s** against 5 s.
**Gate 2 FAILS**: v2 (c) = **24.05 s** against 10 s. **Gate 3 PASSES as
measured**: v2 peak RSS **0.45-0.56 GB** against 4 GB, a 25x reduction from run
1's 14.2 GB -- but the Decision Log records why that is not a clean pass, and
V1P measures the same 0.45-0.56 GB, so the reduction belongs to the
prerequisites rather than to v2.

The GO/NO-GO check failed again: `RustUsageIndex::build` is absent from every v1
cell and `RustAnalyzer::rust_fact_catch_up` from every v2 cell, so **the gate
cells did not compare the usage layers.** What consumed the budget is recorded in
Surprises: `build_cargo_routes` is down from 34-44 s to 9-19 s but is still
87-91% of the scan, and the surviving cost is Cargo-topology orchestration
(12.5 s) rather than the per-file read #1793 replaced (0.18 s).

Cell (c) decomposition, v2, warm cache, one edited file: wall 19.12 s, of which
`searchtools.scan_usages_backend` 16.22 s, of which **`build_cargo_routes`
15.00 s (78% of wall)** and all other scan work **1.22 s**;
`mcp_cold.analyzer_construction` 2.40 s, containing `WorkspaceAnalyzer::build`
1.98 s and the edited file's `reconcile_file_states` 1.84 s. On v2i the same
cell is 13.81 s with 9.76 s of cargo routes, leaving 4.05 s -- **recorded as a
decomposition, not as a conditional pass**, exactly as in run 1, because the scan
still produced no answer. What cell (c) does now establish is that the
single-file edit itself is cheap: 1.84 s to re-analyze the file, and no
whole-workspace usage structure rebuilt on either implementation.

The supplementary runs are where this run earns its keep. Raising
`max_duration_secs` until the layers actually run gives the first direct
measurement of the thing this plan removes: **`RustUsageIndex::build` fires once
at 83.68 s** on the v1 lineage, charging `export_index_of_declarations` 35,357
times and peaking at 30.57 GB, while **`rust_fact_catch_up` fires once at
0.20 s** on v2. Nothing in either run argues against the redesign's premise.

It also found the first defect that points at v2's own code. Paired at every
budget: at 30 s both lineages terminate (v1p 33.89 s, v2i 34.90 s); at 60 s v1p
terminates at 72.15 s and v2i is still running when killed at 540 s; at 120 s
v1p terminates at 126.96 s and v2i is still running when killed at 1800 s.
`usages::candidate_discovery` never emits an END on v2 while its inner spans keep
firing. Candidate causes -- a walk region that does not poll cancellation, or
#1809 reached on the real module graph -- are recorded in Surprises and neither
is proven. This must be diagnosed before the gate runs a third time.

The run-1 open attribution is closed. `Project::workspace_file_listing_count` is
11 with 1 actual walk in every gate cell and 55 requests against 45 walks at a
30 s budget, on the analyzer snapshot's own project; the walks scale at about two
per second of scan wall time and the v1 lineage charges the same rate. It is
shared, time-proportional, and not v2's.

Two blockers remain in front of this gate and one of them is new to this run:
`RustCargoRouteIndex::build_while`'s Cargo-topology orchestration at 12.5 s
inside a 3 s budget, and shared candidate discovery which still does not converge
(105 s of a 121 s scan on v1p). Both want the open-issue search before anything
is filed. Neither is in this plan's scope; the deadline defect is.

Milestone 4 follow-up, issue #1809 (2026-08-08). The deadline defect is fixed and
had two independent causes, both of which the rerun listed as unproven and both
of which turned out to be real.

The cost cause. `bindings_at`'s cycle handling was exponential in the length of
the cycle, not superlinear. Counters over the synthetic fixture (N modules each
`pub use`-ing a name from C successors modulo N) show `compute_bindings_at`
running 70, 223, 576, 1,713 and 4,562 times at N = 4..8 with C = 2, and 1,764,
7,373 and 25,214 at N = 6..8 with C = 3, while the alias recursion stays flat at
2N with no re-entries at all. The mechanism is the truncation counter: it was
monotone per walker and compared at frame entry against frame exit, so any
re-entry anywhere below a frame disqualified that frame from the analyzer cache.
In a strongly connected graph that is every frame, so every frame ran its own
local fixed-point loop and every iteration of that loop recomputed the whole
subtree. At N = 8, C = 3 the walk cached 8 entries out of 151,237.

The replacement is one chaotic iteration owned by the outermost frame: a
re-entry is answered with the value so far, each key costs one computation per
round, and the outermost frame repeats until a round grows nothing -- at which
point every key that round recomputed is at the fixed point and all of them are
memoized together. The iteration runs only when a re-entry happened, so an
acyclic walk still pays exactly one round. Cost after: 6 recursions per module,
flat from six to thirty-two modules. Wall clock for one `bindings_at` at C = 4,
measured with the analyzer already built. Before: 0.19 s at six modules, 3.05 s
at eight, 69.4 s at ten, no result in 420 s at twelve. After: 0.017 s at eight,
0.046 s at sixteen, 0.081 s at twenty-four, 0.107 s at thirty-two. The answers
are identical at every size where the old implementation terminates.

The cancellation cause. Nothing below `RustUsageWalks::new_while` polled the
predicate that constructor was already given -- it was used for the Cargo-route
build and dropped. The walker now keeps it, nine loops poll it, and all nine
analyzer caches are gated on it. The loops: the cycle round loop,
`compute_alias_routes`, `compute_bindings_at`, `forward_import_edges_of`,
`edges_binding_identity`, `importers_of_module`, `owner_roots_of`,
`direct_module_domains_of`, `macro_scope_edges_of`, `macro_visible_ranges_of`
and `macro_declarations_named`. `edges_binding_identity` is the one that
matters most: one candidate there is one full forward-edge computation, and a
common identifier offers thousands of candidates on a large workspace.

Two tests in `usage_walks.rs`.
`a_cyclic_module_graph_costs_a_bounded_number_of_recursions` builds twenty-four
modules with four neighbours each, asserts the re-exported names still resolve
to their declarations, and bounds the recursion count; it does not complete at
all on the previous implementation, which is its hang-before evidence.
`a_cancelled_walk_stops_promptly_and_memoizes_nothing` cancels a walk on the
same fixture and asserts both that it stops after one computation and that a
later uncancelled walker still gets the complete answer; removing the polls
makes the first assertion fail at 10 computations and removing the cache gate
makes the second fail with the truncated answer served from the cache.

What this does NOT do: it does not run the gate a third time, and it does not
claim the gate would now pass. Two blockers named above are untouched.

Milestone 4 prerequisite, issue #1817 (2026-08-08). `RustCargoRouteIndex::build_while`
is decomposed, and what it costs now is the workspace once rather than the
workspace times its Cargo topology.

The profile came first and it settled the design. Synthetic workspaces make the
two axes separable, and holding the file count fixed at 832 while raising the
topology from 4 crates and 16 targets to 128 crates and 512 targets took the old
build from 0.074 s to 0.493 s -- a 6.7x rise for no additional files, which no
reachability walk can produce. Four loops account for it, and the sub-span
decomposition from the run-2 rerun (`physical_routes` 4.15 s, `macro_visibility`
3.79 s, `final_routes` 4.59 s on the rustc tree) lands on the same three places.

What changed. `CargoManifestTopology` is discovered once: manifests read and
parsed once, crates constructed once, target roots resolved once, dependency
routes built once. Both membership passes share it, where each previously
rebuilt the whole thing and the first then discarded everything except
`target_roots_by_file`. Target-root discovery is inverted: files are grouped
under the two-to-four-component ancestors that could auto-discover them
(`files_by_auto_target_directory`), and explicit targets are looked up in the
analyzed set by the path they name, so no crate searches the file list. One
membership walk is seeded from every target root at once. The macro-visibility
stage and the passthrough fixed point iterate `files_by_target_root`, the
inverse of the membership map, instead of filtering the whole file list per
target. `build_files_by_reachable_root_while` computes each root's visible-root
expansion once and applies it, instead of scanning every route entry per
(file, root, target). `ModuleEdgeCache` resolves a gate-free file's module edges
once per (file, is_crate_root), which also removes the duplicated `#[path]`
resolutions and `exists()` calls that came with each recomputation.

Equivalence. The pre-#1817 orchestration is frozen in the same file under
`#[cfg(test)]` as `frozen_orchestration`, sharing every helper the rewrite did
not touch, and `cargo_route_composition_matches_the_pre_1817_orchestration`
compares all seven products of the index against it over two fixtures: the
existing single-crate module-shape fixture and a new multi-target workspace with
a library, three binaries (one four components deep), an integration test, a
bench, an example, a build script, a module file shared by two targets of one
crate, a file that is both a target root and a declared module, an edition-2015
crate whose explicit `[[bin]]` disables auto discovery, a dev-dependency edge, a
`#[path]` declaration, a `#[cfg(test)]` subtree and a `#[macro_use]` passthrough
macro that expands to a module declaration.
`the_multi_target_fixture_exercises_shared_targets_and_expanded_modules` keeps
that fixture from decaying. Three fail-befores were demonstrated: shrinking
`AUTO_TARGET_MAX_DEPTH` to 3, keying the edge cache on the file alone, and
dropping a file's membership in its own target root each fail the pin.

The structural pin is
`a_cargo_route_build_sweeps_the_workspace_a_bounded_number_of_times`. A
thread-local counter records every loop whose length is the analyzed file set;
the new build reports the same count on a 2-crate workspace and a 16-crate one,
and the frozen orchestration reports a count that grows with both and is more
than eight times larger. The counter's call sites are named in the comment above
it, together with what is deliberately not counted.

Measured on the synthetic fixture, debug build, new against frozen: 832 files
with 16 targets 0.033 s against 0.074 s; 832 files with 512 targets 0.046 s
against 0.493 s; 1,792 files with 512 targets 0.078 s against 1.156 s. The new
build tracks the file count and no longer tracks the topology -- a 32-fold rise
in target count at a fixed file count costs it 1.4x, which is the manifest set
itself. Extrapolating the shape rather than the constant: the rustc tree's 12.5 s
was dominated by terms in crates x files and targets x files, and neither term
survives.

Validation: `cargo fmt`, `cargo check` on the two crates, the whole
`brokk-bifrost-analysis` suite (1,835 tests) and the workspace's
`rust_graph|usage|rust_usage|suite_usages|cargo` selection (2,150 tests), and
`cargo clippy --workspace --all-targets -- -D warnings` clean. The only failures
are the three documented pre-existing ones: the JVM artifact test, the two
`live_oid` rendezvous tests, and the TypeScript static-method symbol scan.

What this does NOT do: it does not run the Milestone 4 gate a third time, and it
does not measure the rustc tree. The other blocker the rerun named -- shared
candidate discovery not converging, 105 s of a 121 s scan on v1p -- is untouched.

Milestone 4, run 3 (2026-08-08, after all four fixes). **Gate 1(a) FAILS
narrowly. Gate 1(b) FAILS by 130x on a cause proven shared. Gate 2 PASSES on its
stated bar. Gate 3 passes at the gate budget and fails at any budget that lets
the query answer. Milestone 5 stays blocked.** Full report, repro commands and
limitations: `usage-v2-killgate-v3.md` in the session scratchpad; the deciding
numbers are reproduced here.

Setup. Same rustc tree as runs 1 and 2 (`rust--01f6ddf7` @ `525258043d7f9dcc`,
35,370 `.rs` files), same cells, same cell-(b) selection -- the plan's own
`ORDER BY COUNT(*) DESC` re-run on the run-3 cache returns `main` at 22,976 blobs
again, identical to both prior runs. Three binaries: **v1p** = the run-2 binary
reused byte for byte (sha256 `1c681b389162f41d`), **v3** = HEAD `5c33701b`, and
**v3i** = HEAD plus one `eprintln` of `Project::workspace_file_listing_count`.
Identity verified by distinguishing symbols against run 2's v2 binary as a
control: `cargo_target_memberships` and `reachable_root` are present in v1p and
the control and gone at HEAD (#1817), and `compute_cycle_frame` is present only
at HEAD (#1809). Each cell ran untimed then timed; the untimed run is the wall
clock and RSS of record.

Gate cells, product default 3 s budget, one fresh process per cell:

| binary | cell | state | wall (s) | peak RSS (GB) | scan backend (s) | `build_cargo_routes` (s) | routes share | listings | result |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| **v3** | a | cold | 7.41 | 0.45 | | | | 11 | failure / time_budget, 0 hits |
| **v3** | a | warm | **5.51** | **1.27** | 4.10 | **0.61** | 15% | 15 | failure / time_budget, 0 hits |
| **v3** | b | cold | 8.31 | 0.45 | | | | 11 | failure / time_budget, 0 hits |
| **v3** | b | warm | **653.78** | 0.66 | 666.69 | **0.66** | 0.1% | 1487 | failure / time_budget, 0 hits |
| **v3** | c | edited | **6.91** | 0.77 | 3.23 | **0.64** | 20% | 15 | failure / time_budget, 0 hits |
| v1p | a | cold | 19.22 | 0.45 | | | | n/i | failure / time_budget, 0 hits |
| v1p | a | warm | 13.82 | 0.45 | 12.64 | **11.39** | **90%** | n/i | failure / time_budget, 0 hits |
| v1p | b | cold | 17.62 | 0.46 | | | | n/i | failure / time_budget, 0 hits |
| v1p | b | warm | 14.22 | 0.45 | 13.25 | **11.90** | **90%** | n/i | failure / time_budget, 0 hits |
| v1p | c | edited | 13.92 | 0.56 | 11.29 | **10.14** | **90%** | n/i | failure / time_budget, 0 hits |
| v3i | a | warm | 5.01 | 0.67 | 3.65 | 0.65 | 18% | **15** | failure / time_budget, 0 hits |
| v3i | b | warm | 749.19 | 0.66 | 700.56 | 0.78 | 0.1% | **1467** | failure / time_budget, 0 hits |
| v3i | c | edited | 7.41 | 0.78 | 3.30 | 0.69 | 21% | **15** | failure / time_budget, 0 hits |

Repetitions of the two gate-deciding cells, untimed: v3 (a) warm 5.51, 5.21,
5.61, 5.31, 5.51, 5.51 (median **5.51**); v3 (c) 6.91, 7.61, 6.31, 6.11 (median
**6.61**); v1p (a) warm 13.82, 19.93, 16.12, 14.12 (median 15.12).

Verdicts, each with its deciding measurement. **Gate 1(a) FAILS** on the
absolute half only: v3 (a) warm = **5.51 s median over six repetitions**
against 5 s, 1.10x over; the relative half passes at **0.36x** of v1p, far
inside 2x. **Gate 1(b) FAILS**: v3 (b) warm = **653.78 s** against 5 s -- see
the attribution below, which proves the cost is shared. **Gate 2 PASSES**: v3
(c) = **6.61 s median over four repetitions** against 10 s, with no subtraction,
against v1p's 13.92 s -- but the cell still returns 0 hits, so the pass is on
latency and not on answering. **Gate 3 PASSES at the gate budget** (0.45-1.58 GB
against 4 GB) **and fails above it**: 0.66 GB at the longest any gate cell
actually ran (cell (b), 653-749 s), 16.58 GB at a 120 s budget, and **23.42 GB
in the one run that answered**.

GO/NO-GO. Both proof spans are **absent from all 24 gate cells** for the third
run running, so the gate table again cannot support a v1-versus-v2 claim. Both
fire in the supplementary runs: `RustUsageIndex::build` on v1p at 30.82 / 88.42 /
369.93 s and `RustAnalyzer::rust_fact_catch_up` on v3 at 0.07-0.18 s.

#1817 at rustc scale, reported prominently because the fixture numbers needed
big-tree confirmation: `build_cargo_routes` **10.14-11.90 s on v1p against
0.61-0.78 s on v3**, a 15-18x reduction that moves the span from 87-90% of the
scan backend to 0.1-21%. It is no longer the wall in any cell, three runs after
it became one.

#1809 at rustc scale: run 2's non-termination is gone. Paired budget ladder on
cell (a) warm, every run terminating: v3 33.49 / 63.82 / 135.35 / 1313.58 s at
30 / 60 / 120 / 600 s, v1p 36.55 / 69.89 / 127.22 / 1480.38 s. Run 2 killed v2
at 540 s and 1800 s in the same configuration.

The corrected layer comparison. Run 2 read `RustUsageIndex::build` 83.68 s
against `rust_fact_catch_up` 0.20 s as a 400x win; that pair is not like for
like. The catch-up replaces the *warm*. The query work is
`RustQueryResolver::candidate_files`, which on v1p is entirely
`RustUsageIndex::build` at **88.42 s** and on v3 is entirely
`usage_candidate_files_while` at **86.84-87.77 s** -- a wash, and both complete
(v1p charges all 35,357 `export_index_of_declarations`; v3 returns the same 87 s
at both a 120 s and a 600 s budget). What v2 buys at the candidate stage is
3,127 export projections instead of 35,357, a 16.58 GB peak against 30.27 GB at
the same budget, and no workspace-sized retention -- not latency.

First resolution in three runs. At a 600 s budget v3 **answered**:
`resolved=1 found=1 total_hits=11`, status `found`, partial. Its decomposition
puts `usages::candidate_discovery` at 108.59 s (completing) and the new wall at
`usages::graph_find_usages` **1034.43 s**, dominated by 1,115
`RustAnalyzer::build_reference_context` calls -- a stage no previous run reached.
The two paired v1p runs at 600 s did not resolve, but both ran under 7-8x the
host load, so that half is suggestive and not a controlled comparison.

Cell (b) attributed, by measurement. HEAD's 653-749 s is
`searchtools::scan_usages_symbol_resolution` (664-698 s), i.e.
`resolve_codeunit_fuzzy` at `scan_usages.rs:2037`, which takes no cancellation
predicate and charges 20,935 `multi.definitions[main]` lookups, 20,930 store
round trips and ~1,500 whole-workspace listings for the identifier `main`.
V1P's 14 s is its Cargo-route cost expiring the budget before the per-symbol
loop starts; given a 30 s budget it enters the same resolution and pays
**721.58 s** with the identical inner profile. Shared, pre-existing, and merely
uncovered by #1817.

Cell (c) decomposition (v3, timed, wall 6.11 s): scan backend 3.23 s, of which
candidate discovery 0.99 s and Cargo routes 0.64 s; analyzer construction 2.23 s,
of which `reconcile_file_states` for the edited file **1.75 s**. The largest
single item is now the work the cell exists to measure.

What run 3 does NOT settle: the query still does not answer inside any product
budget; the remaining discovery cost is the ~87 s candidate walk on both
lineages plus a per-short-name `sql_definition_candidates` residue (98,553 calls
on v3, 170,460 on v1p) and the unchanged ~2.2-per-second workspace listing loop;
and the deadline is still soft above the candidate stage (129.89 s on a 120 s
budget, 1145.52 s on a 600 s one). None of those is v2's code.

## Context and Orientation

The repository is Bifrost, a multi-language code analyzer at `/mnt/optane/bifrost-nlp` (branch `bifrost-nlp-ft`). The per-workspace analysis cache is a SQLite database whose schema lives in numbered migrations under `crates/bifrost-core/migrations/cache/` (baseline `0001-current-baseline.sql`; later migrations add to it). The database file name carries the schema version (`bifrost_cache.v15.db` today); find the constant that produces that number and the migration-registration mechanism before adding a migration, and follow the existing pattern exactly. Adding tables bumps the cache version, which invalidates existing prewarmed caches -- acceptable now, because the next benchmark campaign re-prewarms with per-repository caches anyway (see `.agents/plans/codescalebench-grep-hard-cleanup-eval.md` Decision Log).

Terms. A "blob" is a content-hashed file version; `blobs(blob_oid, lang, generation)` is the root table and every per-file table cascades from it. `Liveness` (`crates/bifrost-analysis/src/analyzer/store/liveness.rs`) maps live workspace files to their current blob oids. "Per-file forward facts" are rows describing one file in isolation. An "inverted index" maps a name to the set of blobs mentioning it -- in SQLite terms, a table with an index on the name column. "Query-time composition" means cross-file answers are computed from per-file rows when asked, with memoization, instead of being precomputed into a global structure.

The current implementation to be replaced: `RustUsageIndex` (`crates/bifrost-analysis/src/analyzer/rust/usage_index.rs`, struct around lines 472-494) with seventeen workspace-wide maps; cached as `usage_index: Arc<PoolSafeMemo<RustUsageIndex>>` on `RustAnalyzer` (`rust/mod.rs` around line 86); dropped wholesale in `update()` and `update_all()` (around lines 634 and 660). Its consumers are the Rust usage paths: `crates/bifrost-analysis/src/analyzer/usages/rust_graph.rs` and `rust/graph_support.rs` (via `seeds_for_target`, `importers_of_seeds`, `matching_edges_for_importer`, and the identity/module lookups). The background-warm machinery from #1757 (`warm_usage_index`, the dedicated build pool in `pool_memo.rs`, the `usage_index_ready` probe on `get_active_workspace`) exists and works; v2 removes the need for the usage warm specifically, while the dedicated pool remains for other long builds (see issue #1772).

Prior decisions that bind this plan: the repo prohibits regex/text fallbacks for structured analysis; backward compatibility is not required; no mode flags to share code; assertions over defensive checks; tests must not download models or start indexer threads (`InlineTestProject`, featureless builds). The research report is the design substrate -- read it in full before implementing (path in Artifacts).

### Milestone 2c work breakdown (design output of the 2b session)

This is the inventory the next implementer needs, in dependency order. Everything below lands in one commit, per the Decision Log. Fifteen maps remain on `RustUsageIndex`; the lazy replacement shape for each:

Layer 0, no walk required (pure per-file or already-indexed):

- `physical_roots` -> `ModuleKey::new(file, &rust_package_name(file))`, gated on analyzed membership. No state.
- `actual_crate_roots` -> a per-file predicate over `rust_package_name` / `rust_crate_root_package` / `cargo_routes.target_roots_for_file`. Memoize per file; `cargo_routes` is already memoized.
- `exports_by_file` -> `RustAnalyzer::export_index_of(file)`, which already exists and is already cached (`graph_support.rs` around line 276).
- `declaration_identities`, `value_constructor_identities`, `declaration_domains` -> `RustDeclarationFacts` (landed in 2b). Point lookups key off `code_unit.source()`. Two consumers iterate these maps wholesale and must be re-expressed: `RustPhysicalOwnerIndex::build` (wants module-namespace external module declarations) and `build_macro_visible_ranges` (wants macro-namespace declarations).

Layer 1, module-file resolution -- the base every other walk stands on:

- `module_files` -> a `RustModuleRoutes` view over `RustPackageFileIndex::files_in_package` plus `definitions(fq_name).filter(is_module)`, reproducing `files_for_module`, `resolve` and `resolve_segments` verbatim. Memoize in the `module_resolution` cache. Do not substitute `graph_support::resolve_module_files` (see Surprises).
- `physical_owners` -> the v1 build is a downward BFS from crate roots along `mod name;` edges; the lazy form is the upward walk from one file: take its physical root module M, find the files declaring `last(M)` among `files_for_module(parent(M))`, recurse. Bounded by module nesting depth. `intersects` / `owned_by` / `has_owners` become queries over two upward walks. `inferred_crates_by_file` is the indexed package lookup from Surprises.

Layer 2, alias routes -- the hardest piece:

- `module_aliases` -> the v1 build is a fixed point over every import in the workspace. The lazy form is memoized recursion: `alias_routes_at(K)` for `K = module + [name]` reads the import bindings of `files_for_module(module)`, finds the binding whose local name is `name`, and recursively resolves that binding's own path. The glob rule (a `use I::*` in module O republishes every alias directly under I as an alias under O) becomes a second recursive case. Needs explicit cycle detection where v1 relied on iterating to a fixed point; pathological cyclic aliases are where parity is most at risk, so build a fixture for them first. This is the `resolve` cache.
- Note the longest-prefix search: v1 takes the longest alias key that prefixes the candidate module, computed WITHOUT domain filtering, and only then filters by domain -- if every route at that length is filtered out it falls through to plain module resolution rather than trying a shorter alias. The lazy form must preserve that, or a private alias will start shadowing a public one.

Layer 3, the products keyed by something the rows are not keyed by:

- `importer_reverse` -> per target file, candidates then verify. Candidate sources to union: `files_mentioning(identity.name)` for named imports (an alias still mentions the imported name), `files_mentioning(last component of the target module)` for namespace and glob imports, and `files_importing_module_path(spelling)` for the crate-root case where the target module has no last component. Verification recomputes the candidate's forward edges (layers 1 and 2) and keeps the ones landing on the target. The crate-root glob (`use crate::*` against a `lib.rs` target) is the case to design a fixture for first: the target module has no name to mention.
- `module_importers` -> the same verification, asking whether any forward edge's target module is M.
- `origin_routes_by_file` -> keyed by importer file, so it is per-file once forward edges exist: for each forward edge of F, the identities declared in the edge's target module, plus the aliases that module itself imports, walked backward to their origin. Bounded by re-export chain length. This is the `export_chain` cache.
- `macro_visible_ranges` -> keyed by macro declaration; the lazy form walks that macro's scope graph outward (parent chain via the physical-owner up-walk, children via the file's own `mod` items) instead of building every macro's ranges up front.

`module_domains` (`effective_module_domains`) spans layers: the effective domain of module M is M's declared domains intersected with the effective domain of `parent(M)`, so it is a memoized walk up the module chain whose per-step input is `RustDeclarationFacts` of the files declaring M, plus the Cargo external module declarations the build folds in today.

Cache keying: the plan specifies `(store generation, query key)`. For these values the analyzer instance is the generation -- `update` / `update_all` construct a fresh `RustAnalyzer` with fresh caches -- so a cache living on the analyzer needs only the query key, the same argument recorded for `declaration_facts` in 2b. Use `build_weighted_cache` with byte budgets, as the per-file fact cache does.

## Plan of Work

### Milestone 1: per-file fact tables, written at analysis time

Scope: after this milestone, analyzing a Rust file persists its usage-relevant facts as rows; nothing reads them yet. This is additive and independently verifiable.

Add a cache migration creating four tables (adapt names/columns to what the extraction actually produces -- the shapes below are the design intent, from research report section 7.5; the implementer owns reconciling them with the real projections in `rust/imports.rs` and `rust/declarations.rs`):

    rust_exports(blob_oid, lang, ordinal, exported_name, source_path, is_glob)
      -- one row per name this file re-exports or declares pub; source_path verbatim, unresolved
      -- INDEX on exported_name
    rust_import_targets(blob_oid, lang, ordinal, module_path, bound_name)
      -- one row per import binding; module_path as written, unresolved; bound_name NULL for glob
      -- INDEX on module_path; INDEX on bound_name
    rust_modules(blob_oid, lang, ordinal, module_name, is_inline, start_byte, end_byte)
      -- inline and file modules declared in this file
    rust_identifier_occurrences(blob_oid, lang, identifier, context_mask)
      -- the IdIndex analogue and the load-bearing new piece: which identifiers occur in this
      -- file, with a context bitmask (code / comment / string / macro) so query-time
      -- verification can filter before parsing
      -- INDEX on (lang, identifier)

All STRICT, WITHOUT ROWID on their natural primary keys, ON DELETE CASCADE from `blobs`, per the Decision Log. Bump the cache schema version through the existing mechanism.

Populate them in the same per-blob persistence pass that writes `code_units` for Rust files. The extraction sources already exist: `rust_import_projection` and the export projection in `rust/imports.rs`, module extents in `rust/graph_support.rs`, and the tree-sitter AST for identifier occurrences. Do not re-parse; extract during the pass that already holds the tree. Occurrences dedupe to one row per (blob, identifier) with an OR-ed context mask.

Tests: analyze a small inline Rust project (`InlineTestProject`), open the store, assert the expected rows for a file with re-exports, imports (named, glob, aliased), an inline module, and identifiers in code vs comments vs strings. Assert cascade: deleting the blob row removes the fact rows. Assert content-key stability: re-analyzing an unchanged file inserts nothing new.

### Milestone 2: query-time composition and consumer migration

Scope: after this milestone, every consumer of `RustUsageIndex` answers from the store; the v1 struct still compiles but nothing calls it (deletion waits for the Milestone 4 gate).

Introduce `RustUsageQueries` (module next to the current `usage_index.rs`): a stateless view over the store plus three bounded caches, replacing the seventeen maps according to the classification in research report section 7.3:

- Per-file products (`exports_by_file`, `origin_routes_by_file`, `module_extents`, `physical_roots`, `declaration_identities`, `value_constructor_identities`, `macro_visible_ranges`): read that file's rows on demand; no cache needed beyond what the store already memoizes per request.
- Inverted-derivable products (`identities_by_name`, `module_importers`, `importer_reverse`): one indexed SELECT each (`rust_identifier_occurrences`, `rust_import_targets`), mapping blob oids to live files through `Liveness`, then per-candidate verification against that file's rows -- candidates may be false positives, verification is the contract, exactly as IntelliJ re-checks `IdIndex` hits.
- Genuinely cross-file products (module-file resolution and `physical_owners`, alias routes, transitive export chains, `actual_crate_roots`): bounded walks from a seed over the per-file rows, memoized in three capacity-bounded caches keyed by `(store generation, query key)` so a generation bump invalidates them for free: `module_resolution`, `export_chain`, `resolve`. Use the existing `build_weighted_cache` mechanism from `rust/mod.rs` for byte budgets. `actual_crate_roots` is one row per crate from Cargo metadata; compute on demand and memoize.

Copy IntelliJ's two query-cost mitigations where the call sites allow: narrow candidate sets by locality before verification (target file's directory, then importers, then rest), and early-out processing (stop verifying once the caller's question is answered -- e.g. "is there at least one importer").

Migrate the consumers (`usages/rust_graph.rs`, `graph_support.rs`, and whatever else `rg "usage_index\(\)" crates/` finds) to `RustUsageQueries`. The three entry capabilities to preserve exactly: `seeds_for_target`, `importers_of_seeds`, `matching_edges_for_importer` -- their observable behavior is pinned by the existing Rust usage test suites (`tests/suite_usages/usages_rust_graph_test.rs` and the scan-usages Rust cases), which must pass unchanged. That suite parity is this milestone's acceptance; add focused unit tests only where a v2 code path (candidate verification, memoized walk, generation invalidation) has no existing coverage.

### Milestone 3: invalidation and readiness

Scope: after this milestone, `update()` / `update_all()` no longer drop anything workspace-sized, and readiness reflects the small catch-up set.

In `RustAnalyzer::update` / `update_all`: stop replacing the usage memo (it no longer exists for v2); instead clear the three bounded caches (the `resolve` cache wholesale, the other two by generation-key rotation which is automatic if keyed as specified). Per-file store rows need no action -- changed files get new blob rows through the normal persistence path; stale rows orphan for the existing GC (`store/gc.rs`).

Implement the catch-up policy: a usage query first asks `Liveness` for files whose current oid lacks persisted rust-fact rows (the store's existing generation machinery answers this; follow `oids_for_files` batching). Below the threshold (adopt 20 to start, one constant), parse and persist them inline on the querying thread -- block-until-ready, invisible for single-file edits. At or above it, schedule the batch on the existing background path and have `usage_index_ready` (the #1757 probe on `get_active_workspace`) report false until the batch drains. Re-point the probe's implementation from "is the v1 index built" to "is the rust-fact catch-up set empty"; its tool contract does not change.

Tests: edit one file in an inline project, assert the next usage query answers correctly without any whole-workspace work (structural pin: the store's scan counters from `2ba5dda4`, and assert no full-table scan is charged); assert the probe stays true through a single-file edit and goes false-then-true across a synthetic above-threshold batch.

### Milestone 4: kill-gate benchmark

Scope: this milestone produces numbers, and the plan does not proceed past it on failure.

Environment: a large Rust workspace from the existing campaign sources (`/mnt/T9/repo-clones/.codescale-sources/` has rust compiler and CockroachDB-adjacent trees; the rust compiler tree used in `ccx-incident-131` is the reference). Build two featureless release binaries: the commit before Milestone 2's consumer switch (v1 answering) and HEAD (v2 answering). Use `scripts/with-isolated-cargo-target.sh`; label every cell with binary, cache state, and load, per the house measurement discipline.

Cells, each cold and warm: (a) `scan_usages_by_reference` on a moderate-fan-in symbol; (b) the same on a high-occurrence identifier -- pick the worst by `SELECT identifier, COUNT(*) ... GROUP BY identifier ORDER BY COUNT(*) DESC` over the new table, this is the design-breaking case; (c) single-file edit followed immediately by the query from (a) -- this is v2's headline case, v1 pays its full rebuild here; (d) peak RSS across (a)-(c).

Gates: (1) v2 query latency within 2x of v1 warm and always inside the 5-second product limit for (a); for (b), v2 must stay inside the 5-second limit -- v1's number is reported but not the bar, since v1 buys its speed with the 10.8 GB heap this plan exists to remove; (2) cell (c) completes in under 10 seconds end to end for v2 (v1's number will be minutes; report it); (3) peak RSS for v2 under 4 GB on the reference workspace. On any gate failure: stop, write the numbers into this plan, take it back to the owner.

### Milestone 5: deletion and close-out

Delete `RustUsageIndex`, its seventeen maps, `warm_usage_index`, and the usage-specific warm wiring from #1757 (`warm_rust_usage_index` / `warm_rust_usage_reference_contexts` on `WorkspaceAnalyzer`; the `StartupIndexWarm` machinery stays only if another index still uses it -- check, and if nothing does, delete it too and say so in the commit). The dedicated build pool in `pool_memo.rs` stays (issue #1772 wants it for the hierarchy build). Keep `BIFROST_WARM_USAGE_ANALYSIS` only if the reference-context sweep survives as a separate concern; otherwise remove the env var and its documentation. Update issue #1758 (structural fix landed) and #1757's closing comment if the probe semantics changed. Update the memory file `embedding-backend-sidecar`-style records only if factual claims there went stale. Run the full local gate from CLAUDE.md before the final push.

## Concrete Steps

All commands from the repository root `/mnt/optane/bifrost-nlp`.

Focused iteration (featureless; nothing here touches NLP):

    cargo check -p brokk-bifrost-analysis -p brokk-bifrost-core
    cargo nextest run -p brokk-bifrost-analysis
    cargo nextest run --workspace -E 'test(/rust_graph|usage|rust_usage|suite_usages/)'

Before each push: `cargo fmt` and `cargo clippy --workspace --all-targets -- -D warnings` (the `--all-features` comprehensive gate runs at the pre-push checkpoints the main session performs, not per-milestone). Known pre-existing failures are listed in `.agents/plans/searchtools-too-broad-scope-guards.md` (Surprises) plus the two recorded during #1757; verify any new failure against a stash before investigating.

Milestone 4 builds use `scripts/with-isolated-cargo-target.sh`; check disk space first; never write to the shared DW10 cache -- copy to scratch and delete after, announcing both.

## Validation and Acceptance

Milestone acceptance is written into each milestone above. Plan-level acceptance: the existing Rust usage suites pass unchanged on v2; the new invalidation tests demonstrate single-file incrementality with a structural no-full-scan pin; the Milestone 4 gates pass with recorded numbers; and after Milestone 5 the words `RustUsageIndex` and `warm_usage_index` no longer appear in the tree. Every regression-shaped test must be demonstrated to fail against the code state it guards against (stash or pre-milestone commit), per house rule.

## Idempotence and Recovery

Milestones 1-2 are additive and individually revertable by commit. The consumer switch in Milestone 2 is the first behavior-visible commit; if it breaks something the suites missed, revert that single commit -- v1 is still present until Milestone 5. The cache version bump invalidates prewarmed caches by design; do not run it against the shared DW10 cache directory. Milestone 4 is measurement-only. Milestone 5 is the point of no return and sits behind the gate.

## Artifacts and Notes

- IntelliJ research report (design substrate, code-cited): `.agents/docs/intellij-indexing-research-2026-08.md`. It was authored in a session-temporary scratch path and copied into the repository by this plan's first implementation commit, so the plan is now self-contained against the working tree alone.
- Measurements motivating the plan: issue #1758 and its root-cause comment (2026-08-07); `.agents/docs/codescale-grep-hard-checkpoint-2026-08-07.md`.
- Key current-code anchors: `rust/usage_index.rs` (the struct, ~472-494), `rust/mod.rs` (memo ~86, drops ~634/660, `build_weighted_cache` ~341), `store/liveness.rs` (`oids_for_files`), `store/gc.rs`, `migrations/cache/0001-current-baseline.sql`.

## Interfaces and Dependencies

No new crates. At the end: four new store tables as specified in Milestone 1 (final DDL recorded here when landed); `RustUsageQueries` in `crates/bifrost-analysis/src/analyzer/rust/` exposing at minimum the three preserved capabilities (`seeds_for_target`, `importers_of_seeds`, `matching_edges_for_importer`) plus the per-file and inverted lookups the migrated consumers need; three weighted bounded caches keyed by `(generation, query)`; the catch-up policy with its threshold constant; `usage_index_ready` re-pointed to the catch-up set. `RustUsageIndex` and the usage warm are gone.

## Revision notes

- 2026-08-08 (Milestone 4 run 3, measurement only): recorded the third run of the kill gate, after `575c2ffb` (#1809) and `13bb6263` (#1817). Added a sub-entry under Milestone 4 in Progress with the run-3 verdict. Added six observations to Surprises & Discoveries -- #1817 verified at rustc scale against the frozen V1P control (10.14-11.90 s to 0.61-0.78 s), the correction of run 2's headline comparison to the like-for-like `RustUsageIndex::build` 88.42 s against `usage_candidate_files_while` 86.84-87.77 s, the paired proof that cell (b)'s 653-749 s is shared unbudgeted symbol resolution that #1817 merely uncovered, the surviving soft deadline above the candidate stage and where it now sits, the finding that peak RSS tracks the usage-graph phase rather than run length (which resolves run 2's gate-3 caveat), and the reduced-but-not-gone `sql_definition_candidates` residue with the unchanged listing loop. Added four decisions covering the reuse of run 2's V1P binary verbatim and why V1-unchanged was dropped, the extra repetitions on the two gate-deciding cells, recording gate 2 as a pass with its caveat rather than as a conditional pass, and settling the cell-(b) attribution by a raised-budget V1P run rather than by reading the code. Wrote the run-3 entry in Outcomes & Retrospective with the full results table. No source file changed; the one instrumented binary was built in a throwaway detached worktree, which was removed. Milestone 5 stays blocked.
- 2026-08-08 (Milestone 4 prerequisite, issue #1817): added a sub-entry under Milestone 4 in Progress recording that the Cargo-topology orchestration the run-2 rerun measured at 9-19 s no longer grows with the workspace's crate and target count. Added five observations to Surprises & Discoveries -- the fixed-file-count measurement proving the cost is a product rather than reachability work and the four loops behind it, the first membership pass rebuilding the whole manifest topology only to discard everything but its reachability, the two-to-four-component depth bound that lets the per-crate file search be inverted and why that coupling is pinned, the four-to-six recomputations of each file's module edges and the target-root-and-module file shape that makes the `is_crate_root` half of the cache key load-bearing, and why per-target laziness is refused by the consumer surface. Added five decisions covering the deviation from the lazy direction and its evidence, the frozen-orchestration equivalence guard, the thread-local sweep counter with its fail-before inside the pin, the single seeded membership walk, and keeping `files_by_reachable_root` materialised. Wrote the prerequisite entry in Outcomes & Retrospective with before/after timings. Milestone 5 stays blocked; the gate rerun is still a separate task.
- 2026-08-08 (Milestone 4 follow-up, issue #1809): added a sub-entry under Milestone 4 in Progress recording that the v2-specific non-termination the rerun found is diagnosed and fixed, and that both of the two causes the rerun recorded as unproven were real. Added four observations to Surprises & Discoveries -- the profile showing the blow-up is exponential and belongs entirely to the binding recursion rather than the alias one, the mechanism being that the monotone truncation counter disqualified every frame of a cycle from the cache so each ran its own local fixed point over the whole subtree, why v1 had no counterpart to this (it never asked the question recursively, so what it amortized was the answer and not the cycle handling), and the cancellation audit finding that no walk polled the predicate the constructor was already given. Added five decisions covering the choice of chaotic iteration over an SCC collapse, length-based convergence detection, the predicate's shape on the walker, the unconditional cache gate, and the deliberate exclusion of the graph-scan entry points. Two new tests in `usage_walks.rs`, one hang-before and one fail-before demonstrated. Milestone 5 stays blocked; the gate rerun is still a separate decision with the owner.
- 2026-08-08 (Milestone 4 run 2, measurement only): recorded the rerun of the kill gate after both prerequisites landed. Updated the Milestone 4 entry in Progress with the run-2 verdict. Added six observations to Surprises & Discoveries -- the sub-span decomposition showing #1793's read is 1.4% of `build_cargo_routes` and the surviving 12.5 s is Cargo-topology orchestration, the V1P finding that the prerequisites rather than v2 moved every run-1 number, the first direct measurement of `RustUsageIndex::build` (83.68 s) against `rust_fact_catch_up` (0.20 s), the new v2-specific non-termination at a 60 s and 120 s budget with paired v1p comparators, the now-settled `collect_workspace_files` attribution, and the absence of a measurable macro-expansion cost in the analyzer build. Added three decisions covering the choice of V1P as the comparator and how its cherry-pick conflicts were resolved, why gate 3 is recorded as pass-as-measured rather than a clean pass, and the untimed/timed split of every cell. Wrote the run-2 entry in Outcomes & Retrospective. No source file changed; the two instrumented binaries were built in throwaway detached worktrees, which were removed. Milestone 5 stays blocked.
- 2026-08-08 (Milestone 4 prerequisite, issues #1748 and #1774): added a second sub-entry under Milestone 4 in Progress recording that the `sql_definition_candidates` half of the shared candidate-discovery storm is fixed and that the listing half is not. Added four observations to Surprises & Discoveries -- the arithmetic identifying the multiplicity as one store round trip per `use` statement and the double charge that comes with it, the per-language precedents (Python, JS/TS) that Rust was missed by and why per-file caching alone would not have sufficed at this scale, the open and explicitly unattributed `collect_workspace_files` count with the two facts that make it plausible without per-lookup amplification and the measurement that would settle it, and the out-of-scope superlinear blowup of the Rust usage walks on a cyclic module import graph that constrains any fixture here. Added six decisions covering what the #1774 memo holds and why `keep` stays outside it, why a cancelled walk publishes nothing, the request-scoped `definitions` memo, the defaulted provider hook instead of a signature change, the shared assembly function behind both the point and batched paths, and why no count-based early trip was added. Wrote the prerequisite entry in Outcomes & Retrospective with before/after counters. Milestone 5 stays blocked; the gate rerun is still a separate task.
- 2026-08-08 (Milestone 4 prerequisite, issue #1793): added a sub-entry under Milestone 4 in Progress recording that the Cargo-route rebuild the kill-gate run blamed is fixed, and that the gate rerun is a separate task. Added five observations to Surprises & Discoveries -- the three-item list of what the route build actually read from a tree, the macro-passthrough verdict being the one thing that is not a per-file fact and the gate that carries it, the symlink reason a `#[path]` chain cannot be collapsed, the manifest measurement that kept manifests on disk, and the shared-blob effect on the batched read. Added seven decisions covering the four-table shape, the manifest call, optimistic macro expansion, the per-file parse recovery instead of the Milestone 3 catch-up, the edge-level equivalence pin with the frozen syntax walk, the batched reader beside the per-blob one, and the per-analyzer fallback counter. Wrote the prerequisite entry in Outcomes & Retrospective. Milestone 5 stays blocked; nothing in this change licenses it.
- 2026-08-07 (Milestone 4 run 1, measurement only): recorded the kill-gate result in Progress and Outcomes & Retrospective, and added three observations to Surprises & Discoveries -- that `build_cargo_routes` is charged inside the scan's own three-second budget and consumes 87-97% of every cell rather than only cell (c), that neither implementation reaches its usage layer at all so the benchmark did not compare them, and that the costs behind cargo_routes belong to shared candidate discovery rather than to v2. Added one decision recording why two extra instrumented binaries were built and why the cell-(c) subtraction is not a passing verdict. No source file changed; the instrumented binaries were built in throwaway detached worktrees, which were removed. Milestone 5 is marked blocked.
- 2026-08-08 (Milestone 3 implementation): checked off Milestone 3 in Progress. Added six observations to Surprises & Discoveries -- that the staleness bug the milestone was told to look for does not exist and why the pinning test is still worth having, that the real gap is invisibility rather than staleness, the duplicate-blob-key trap for a batch of files, the content-drift rule that forbids persisting a file whose bytes moved on, the readiness/warmth split the v1 probe conflated, and the out-of-scope finding that `cargo_routes` is still dropped and rebuilt on every edit and will dominate Milestone 4's cell (c). Added seven decisions covering the untouched `update` constructors, the choice of hook site, the per-generation full scan and why the narrowed alternative is not correct alone, the `rust_modules` witness rule, the dedicated-pool scheduling, the probe split with the unchanged tool field, and the test barrier. Wrote the Milestone 3 entry in Outcomes & Retrospective. The Milestone 3 section in Plan of Work is left as authored; the two places where the as-built differs from it -- the hook site and the two-predicate probe -- are recorded in the Decision Log rather than by editing the milestone text.
- 2026-08-07 (Milestone 2c implementation): checked off 2c in Progress. Added five implementation observations to Surprises & Discoveries -- the `definitions(fq_name)` collapse that makes the recorded `inline_by_name` equivalence wrong, the path half of the physical-owner child computation having no index to invert through, the v1 alias fixed point not being the least fixed point of the recursion, the length-one export-chain cycle, and the analyzer growing past the `AnalyzerDelegate` size lint. Added seven decisions covering cache keying, the cache count, keeping v1 compiling, the importer candidate sources and their known gap, the recursion depth of `bindings_at`, leaving the warm wired to the unread index, and the one existing test whose text changed. Wrote the Milestone 2c entry in Outcomes & Retrospective. The `Milestone 2c work breakdown` section is left as authored, because it was the design this implementation followed; the two places where it was wrong are corrected in Surprises rather than by editing the breakdown.
- 2026-08-07 (Milestone 2c design, same session as 2b): added a `Milestone 2c work breakdown` section above the Plan of Work, recording the dependency-ordered inventory of the fifteen remaining maps and the lazy shape of each. Added three design observations to Surprises & Discoveries: the sequencing constraint that forbids landing 2c in pieces, the finding that module-file resolution needs no new index because `RustPackageFileIndex` and `definitions(fq_name)` already are the two maps it is built from (with the `resolve_module_files` look-alike trap), and the finding that three of the cross-file products are per-file predicates rather than walks. Added the decision that 2c lands atomically, and that a flag selecting eager or lazy resolution was rejected. No code changed for 2c.
- 2026-08-07 (Milestone 2b implementation): checked off 2b in Progress and restated 2c's scope to include `module_importers` and `importer_reverse`. Added three Milestone 2b observations to Surprises & Discoveries -- that two of the three `identities_by_name` call sites were per-file questions, that the false positive worth testing is an associated function rather than a prose mention, and that `module_importers` is coupled to the forward-edge computation exactly as `importer_reverse` is -- and four decisions covering the sequencing call, the single shared derivation, the file-keyed cache, and the `is_analyzed` candidate filter. Extended Outcomes & Retrospective with the Milestone 2b entry. The narrative Milestone 2 section is unchanged; 2c is what remains of it.
- 2026-08-07 (Milestone 2a implementation): split the Milestone 2 progress entry into 2a (landed), 2b (inverted-derivable products) and 2c (cross-file group plus the final consumer switch), and recorded why in the Decision Log. The narrative Milestone 2 section below is unchanged and still describes the whole of Milestone 2; 2b and 2c are the parts of it that remain. Added three Milestone 2a observations to Surprises & Discoveries -- the coupling between the three cross-file structures, the mismatch between `importer_reverse`'s target-file key and the persisted written-path key, and the finding that the store-backed path works without a git repository -- and four decisions covering the split, the choice of first products, the deliberate absence of the three walk caches, and the `RustImportBinding` shape. Extended Outcomes & Retrospective with the Milestone 2a entry.
- 2026-08-07 (Milestone 1 implementation): re-pointed the Artifacts entry for the IntelliJ research report from its session-temporary scratch path to the checked-in `.agents/docs/intellij-indexing-research-2026-08.md`, as Milestone 1 required. Added the Milestone 1 DDL reconciliation decisions (three column-set changes against the plan's design DDL), the transport and hydration decision for `ParsedFile`/`FileState`, the test-placement decision, the scoped `allow(dead_code)` for the reader, and the epoch-salt decision to the Decision Log. Added three Milestone 1 observations to Surprises & Discoveries: the two-natured export projection, the deliberate overlap between `rust_exports` and `rust_import_targets`, and the content-key/path-derivation trap in `base_module`. Wrote the Milestone 1 entry in Outcomes & Retrospective. The narrative Milestone 1 section is left as authored, because the work matched it; the reconciliations it explicitly delegated to the implementer are recorded in the Decision Log rather than by editing the milestone text.
