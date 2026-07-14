# Avoid repeated Python import resolution in definition batches

This ExecPlan is a living document. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Python reference-differential batches currently resolve a typed receiver such as
`service.run()` by first collecting the cached local type facts and then calling the
general Python graph receiver resolver for `Service`. That general resolver asks the
import-analysis provider for all imported code units of the source file. On the
`googleapis__google-cloud-python` corpus, a live sample showed that path repeatedly
performing import binding and module-name filesystem work. After this change, direct
named imports use the definition batch's existing import binder before that fallback.
Repeated references keep their current definitions while avoiding that broad import
resolution work.

## Progress

- [x] (2026-07-14) Captured the post-PR #735 hotspot: batch scope facts are cached,
  but `python_receiver_type_unit -> resolve_receiver_type -> resolve_import_bindings`
  still dominates the Python corpus run.
- [x] (2026-07-14) Add a bounded per-file receiver-type cache and direct named-import lookup.
- [x] (2026-07-14) Add lifecycle, isolation, and cache-cap regression coverage.
- [x] (2026-07-14) Run `cargo fmt` and the focused default- and feature-enabled
  Python batch tests.
- [x] (2026-07-14) Rebase the checkpoint onto merged PR #750 and rerun the focused
  Python batch and integration tests.
- [ ] Run clippy and the complete `nlp,python` suite.
- [x] (2026-07-14) Complete the warmed Python differential smoke after addressing
  the remaining candidate-lookup hotspot; retain the JSONL evidence.
- [x] (2026-07-14) Reject a resolver-local content-qualifier cache after profiling:
  candidate rows span distinct Python files, so it did not reduce
  `python_module_name` work.
- [x] (2026-07-14) Reject a longest-module-prefix path-symbol selector after a
  warmed smoke: its non-indexable prefix query dominated the sampled work, so
  the implementation was reverted.
- [x] (2026-07-14) Reject an exact-FQN path-symbol projection: it preserved
  correctness but the corpus still reached re-export traversal, so the added
  SQLite lookup did not replace the generic receiver resolver and was reverted.
- [x] (2026-07-14) Follow explicit named re-export chains through existing import
  binders before the generic export resolver, with regression coverage that keeps
  the generic receiver fallback at zero.
- [x] (2026-07-14) Short-circuit scope-fact import resolution after direct
  definitions or explicit reexports, so it does not eagerly construct Python export
  indexes for every named import.
- [x] (2026-07-14) Replace imported-class method discovery through the workspace
  global index with `direct_children` on the already-resolved class. The focused
  batch regression now proves zero global-index builds and zero full declaration
  scans while factory-return coverage remains green.
- [x] (2026-07-14) Read return types from the concrete callable's persisted ranges
  and indexed file source. This avoids generic `get_source` re-resolving every
  same-FQN function merely to inspect one already-selected declaration.
- [x] (2026-07-14) Route exact Python path-symbol lookups through the existing
  `(lang, exact_fqn)` index, with a query-plan regression that prevents SQLite
  from reverting to a primary-key scan.
- [x] (2026-07-14) Resolve Python module-existence checks directly from path-backed
  module units instead of hydrating broad same-short-name definition candidates.
- [x] (2026-07-14) Short-circuit the empty-module boundary check exposed by the
  first full-scale sample, preserving its false result without hydrating every
  path-derived Python declaration.
- [x] (2026-07-14) Resolve Python base classes from the specific binder entry
  instead of resolving every import in the declaring file during inverse receiver
  hierarchy checks.
- [x] (2026-07-14) Index the already-collected per-file scope-fact ranges for
  inverse scanning instead of rediscovering the enclosing code unit for every AST
  candidate.
- [x] (2026-07-14) Build scan-local scope inputs from the parsed file source and
  persisted declaration ranges instead of generic overload-aware `get_source`.
- [ ] Bulk-hydrate the one-time Python usage index and parse source only for
  files whose local declarations collide with named reexports.
- [ ] Run the full 1,000-file / 10,000-site / 1,000-target acceptance record when
  disk preflight permits, then record the result and close #675 only if it completes.

## Surprises & Discoveries

- Observation: The prior full corpus run was stopped after 49 minutes without a JSONL
  record because free disk dropped from 140 GiB to 72 GiB.
  Evidence: `/private/tmp/bifrost-675-postfix.sample.txt` puts the sampled work under
  `resolve_import_bindings` and `python_module_name`, not `scope_facts`.

- Observation: Passing explicit Homebrew Python 3.14 framework flags and
  `MACOSX_DEPLOYMENT_TARGET=26.5` fixed the local PyO3 link mismatch; the focused
  feature-enabled tests passed. That fresh feature build reduced free disk to 24 GiB,
  so the subsequent unrelated filtered test-binary sweep was interrupted.
  Evidence: `MACOSX_DEPLOYMENT_TARGET=26.5 PYO3_PYTHON=/opt/homebrew/bin/python3.14`
  with `-lpython3.14` completed the three batch tests before the interrupt.

- Observation: After PR #750 added an ephemeral differential-cache mode, an
  ephemeral smoke spent its time rebuilding the whole corpus and produced no JSONL,
  so it is not suitable for the plan's required warmed measurement. The subsequent
  persisted smoke was stopped after a runtime sample found no
  `resolve_import_bindings`, but found `python_module_name` called from
  `QueryResolver::resolve_rows` / SQL definition-candidate lookup, with filesystem
  `stat` work still prominent.
  Evidence: `/private/tmp/bifrost-675-warmed-smoke.sample.txt`.

- Observation: `QueryResolver::resolve_rows` already batches liveness validation by
  unique file. A local `(content_qualifier, file)` hydration cache passed its focused
  unit test but did not move the 20-file smoke: `python_module_name` remained the
  dominant child of `resolve_rows` because short-name candidate queries returned
  mostly distinct Python files. The experiment was reverted.
  Evidence: `/private/tmp/bifrost-675-warmed-smoke-postfix.sample.txt`.

- Observation: A path-symbol experiment correctly restricted same-blob candidate
  hydration to the selected Python path, but SQL had to find module names that were
  prefixes of the requested FQN. The resulting `substr` predicate could not use the
  FQN index; its 10-second warm sample placed
  `path_symbol_rows_with_fqn_prefix_for_langs` above the remaining
  `python_module_name` work. The experiment was reverted before completing the
  smoke.
  Evidence: `/private/tmp/bifrost-675-path-narrowing.sample.txt`.

- Observation: Even after an exact-FQN query was made indexable, the corpus sample
  still spent its receiver resolution in `resolve_import_bindings` and
  `PythonAnalyzer::export_index_of`. Direct named imports commonly target facade
  modules that explicitly re-export the class, so resolving only the first
  `module.Type` FQN does not reach the leaf declaration. The path projection was
  reverted. A bounded walk over binder-derived `ImportKind::Named` edges reaches
  direct reexports without reading or parsing intermediate source; star exports and
  ambiguous shapes continue to use the established resolver.
  Evidence: `/private/tmp/bifrost-675-exact-indexed.sample.txt`.

- Observation: Scope-fact construction had an eager iterator chain that invoked
  `resolve_exported_fqn` even after `analyzer.definitions` had found the imported
  class. After short-circuiting through direct definitions and named reexports,
  `export_index_of` is no longer the dominant sampled receiver work. A 20-file,
  100-site, 20-target warmed smoke was still stopped after nearly five minutes with
  no JSONL record; its remaining cost was one-time `MultiAnalyzer` global declaration
  hydration and `python_module_name`, not generic import binding.
  Evidence: `/private/tmp/bifrost-675-direct-reexport.sample.txt`,
  `/private/tmp/bifrost-675-short-circuit.sample.txt`, and
  `/private/tmp/bifrost-675-short-circuit-later.sample.txt`.

- Observation: The remaining global declaration hydration came from
  `collect_imported_class_method_return_types`, even though that function already
  receives the concrete imported class `CodeUnit`. `IAnalyzer::direct_children`
  delegates to the class's owning analyzer and file, providing the same direct
  methods without materializing unrelated declarations.
  Evidence: `python_batch_context_builds_file_and_scope_state_once` asserts both
  `global_usage_definition_index_build_count_for_test() == 0` and
  `full_declaration_scan_count_for_test() == 0`.

- Observation: Once the global scan was removed, the warmed sample exposed
  `IAnalyzer::get_source` as another broad operation: function source rendering
  calls `definitions(fqn)` to combine overloads, which is unnecessary for return
  inference on a concrete imported callable. Persisted declaration ranges plus the
  indexed source provide the exact structured slice without a workspace lookup.
  Evidence: `/private/tmp/bifrost-675-bounded-direct-children.sample.txt`.

- Observation: After callable source lookup became local, both early and late
  samples no longer contained global declaration hydration or generic `get_source`.
  The remaining repeated work was exact module resolution through
  `path_symbol_rows_by_fqn_for_langs`; its combined exact/normalized predicate and
  SQL ordering selected the `path_symbol_units` primary key by language rather than
  the exact-FQN index.
  Evidence: `/private/tmp/bifrost-675-bounded-callable-source.sample.txt` and
  `/private/tmp/bifrost-675-bounded-callable-source-later.sample.txt`.

- Observation: The indexed path-symbol smoke reduced
  `path_symbol_rows_by_fqn_for_langs` to a negligible fraction of the sample, but
  `PythonAnalyzer::export_index_of` still spent most of its time in
  `record_reexport_event`. Its module-existence check called full FQN definition
  lookup, hydrating every declaration with the same short name and recomputing
  `python_module_name` before eventually consulting path-backed module units.
  Evidence: `/private/tmp/bifrost-675-indexed-path-module.sample.txt`.

- Observation: After direct path-module resolution, the identical warmed
  20-file / 100-site / 20-target smoke completed in 88.1 seconds and queried all
  seven distinct sampled targets. Its runtime sample contains none of the earlier
  generic import-binding or global declaration hydration stacks; broad
  short-name definition lookup is also gone from module checks. The remaining
  one-time startup cost is `PythonUsageIndex::build` parsing workspace files to
  preserve local-definition versus re-export ordering.
  Evidence:
  `.agents/docs/reference-differential/675-python-path-module-fast-smoke.jsonl`
  and `/private/tmp/bifrost-675-path-module-fast.sample.txt`.

- Observation: The first full-limit sample was dominated by one boundary check for
  an unqualified FQN. `python_crosses_unindexed_boundary` asked whether the empty
  module existed; because Python declaration qualifiers are path-derived and stored
  empty, `persisted_package_exists("")` selected and path-hydrated every Python
  declaration before returning false. The full campaign was stopped before writing
  a record so this result could be returned directly.
  Evidence: `/private/tmp/bifrost-675-full-acceptance.sample.txt`.

- Observation: After removing the empty-package scan, the next full-limit sample
  reached inverse usage scanning. `receiver_binds_target` repeatedly traversed class
  ancestry, and `resolve_base_class` resolved every import in each declaring file
  even though it needed only the base expression's binder entry. This made generic
  `resolve_import_bindings` the dominant scaled receiver work again, outside the
  already-fixed definition-batch context.
  Evidence: `/private/tmp/bifrost-675-full-acceptance-post-empty.sample.txt`.

- Observation: The targeted hierarchy binder removed generic import resolution
  from the scaled sample and reduced `resolve_base_class` to negligible work. The
  next dominant stack was `binds_target -> enclosing_scope_facts ->
  enclosing_code_unit`, even though `scan_files_for_seeds` had already built a map
  of the relevant per-function facts for that file.
  Evidence: `/private/tmp/bifrost-675-full-acceptance-binder.sample.txt`.

- Observation: Once per-node enclosing lookup was indexed, scope-fact construction
  became dominant. It called public `get_source` for each concrete class/function;
  function rendering re-resolved the same FQN to combine overloads, returning to
  broad short-name candidate hydration and `python_module_name` filesystem work.
  Evidence: `/private/tmp/bifrost-675-full-acceptance-scope-index.sample.txt`.

- Observation: The first completed full record took 174.1 seconds and spent its
  sampled warm-up almost entirely building `PythonUsageIndex`: `export_index_of`
  reparsed every file and fetched each persisted file state independently.
  Evidence: `/private/tmp/bifrost-675-full-acceptance-scope-source.sample.txt` and
  `.agents/docs/reference-differential/675-python-full-acceptance.jsonl`.

- Observation: Source-omitting bulk hydration does not synthesize path-derived
  module `CodeUnit`s. The first batched run therefore changed 175 module targets
  from `missing` to inconclusive `export graph produced no seeds`, despite
  identical forward results.
  Evidence: `.agents/docs/reference-differential/675-python-full-acceptance-batched.jsonl`.

## Decision Log

- Decision: Cache receiver type results only in `PythonDefinitionContext`, keyed by
  source-file context, trimmed type text, and the indexed-self-file flag.
  Rationale: The analyzer generation is immutable during a definition batch, while
  per-file context removal after the final lookup prevents workspace-lifetime state.
  Date/Author: 2026-07-14 / Codex

- Decision: Prefer binder-derived named imports and same-file classes before the
  shared graph resolver; preserve the shared resolver as the fallback.
  Rationale: The binder carries exact structured import facts. It resolves ordinary
  `from module import Type as Alias` without widening import scope or replacing
  structured resolution with text matching.
  Date/Author: 2026-07-14 / Codex

- Decision: Limit each receiver-type cache to 512 entries and bypass inserts after
  the limit while continuing exact uncached resolution.
  Rationale: The bound is deterministic and keeps only compact type strings plus
  `CodeUnit` results. It stores neither source nor tree state and cannot alter lookup
  outcomes when a large request exceeds the bound.
  Date/Author: 2026-07-14 / Codex

- Decision: Do not retain a QueryResolver hydration cache.
  Rationale: Its key had low reuse in the target corpus and preserved the costly
  one-per-candidate Python module-path stat. The root cause is broad short-name
  candidate retrieval, which needs path-aware filtering before hydration.
  Date/Author: 2026-07-14 / Codex

- Decision: Do not use reverse module-prefix scans over `path_symbol_units` for
  candidate narrowing.
  Rationale: Even though the path-specific resolver preserved correctness for
  duplicate blobs, the lookup had to scan path-symbol rows on every target and
  displaced the original filesystem cost with a larger SQLite cost. Any further
  path-aware candidate filter must be directly indexable or be supplied by an
  already-structured lookup key.
  Date/Author: 2026-07-14 / Codex

- Decision: Resolve only explicit named Python reexports before requesting the
  generic export resolver.
  Rationale: Import binders already encode the path and imported local name for
  this unambiguous shape. Following those structured edges resolves facade modules
  without constructing export indexes; wildcard, namespace, and missing bindings
  retain the existing comprehensive behavior.
  Date/Author: 2026-07-14 / Codex

- Decision: Make scope-fact imported-factory lookup short-circuit in priority order:
  direct definition, explicit named reexport, then the existing generic export walk.
  Rationale: The old iterator chain evaluated every source even when the direct
  result was enough. The ordering preserves the generic fallback while avoiding its
  parse and index construction cost for ordinary named imports.
  Date/Author: 2026-07-14 / Codex

- Decision: Discover imported class factory methods through
  `analyzer.direct_children(class_unit)`.
  Rationale: Import resolution has already selected a concrete declaration, so its
  source-specific children are both more precise and bounded than an FQN lookup in a
  workspace-wide index. This preserves factory-return inference while removing the
  only global declaration scan in the definition-batch scope path.
  Date/Author: 2026-07-14 / Codex

- Decision: Infer a concrete callable's Python return from its own persisted ranges
  over `indexed_source`, trying ranges in source order.
  Rationale: This preserves overload-aware behavior elsewhere in `get_source` while
  keeping factory-return inference scoped to the declaration import resolution
  already selected. It reuses analyzer structure and does not retain source or trees.
  Date/Author: 2026-07-14 / Codex

- Decision: Specialize only Python path-symbol queries whose exact and normalized
  names are identical, and explicitly select
  `idx_path_symbol_units_lang_exact_fqn` for that query.
  Rationale: Python module names normalize to themselves, so the exact predicate
  preserves the lookup result while avoiding a language-wide scan. Keeping the
  generic query for JavaScript, TypeScript, and differing normalized names avoids
  changing their import-details and normalization semantics. The explicit index is
  necessary because SQLite chose the primary key even for the simplified predicate
  in an empty in-memory store.
  Date/Author: 2026-07-14 / Codex

- Decision: Make Python's internal `resolve_module_code_unit` use the path-module
  projection as the complete result whenever that store query succeeds, falling
  back to full definition resolution only on store-query failure.
  Rationale: Python module declarations are synthetic path-backed units, including
  dirty files. Both a hit and a miss are therefore answered by the structured
  module projection; broad short-name candidate hydration cannot add a valid module
  result and made export-index construction scale with unrelated declarations.
  Date/Author: 2026-07-14 / Codex

- Decision: Treat the empty Python module name as nonexistent before consulting
  bounded package or FQN lookup.
  Rationale: `module_code_unit` cannot construct an empty module and the existing
  hydrated query always returned false. The guard preserves the diagnostic outcome
  while removing a one-time scan of every persisted Python declaration.
  Date/Author: 2026-07-14 / Codex

- Decision: Resolve Python hierarchy bases through `import_binder_of` and only the
  binding named by the structured base expression.
  Rationale: The binder already distinguishes namespace and named imports. A
  namespace base keeps exact `module.tail` lookup; a named base keeps export-aware
  resolution followed by the existing direct-definition fallback. Local and
  unresolved bases retain their prior fallbacks, while unrelated imports are never
  materialized.
  Date/Author: 2026-07-14 / Codex

- Decision: Build a scan-local interval index from the persisted ranges of the
  `CodeUnit`s already present in `scope_facts`.
  Rationale: Candidate nodes only need to select one of those facts, not ask the
  analyzer to search every declaration and reload its ranges. Sorting once by start
  byte plus a prefix maximum end supports nested scopes and fast rejection outside
  any function. The index stores only ranges and `CodeUnit`s for one file scan; it
  retains no source or tree state.
  Date/Author: 2026-07-14 / Codex

- Decision: Slice every concrete scope declaration from the scan's existing file
  source using that declaration's persisted ranges, joining multiple ranges in
  source order before local inference.
  Rationale: This preserves overload grouping for a single selected `CodeUnit`
  without asking public source rendering to rediscover same-FQN definitions. The
  source is already owned by the per-file graph and no additional source or tree is
  retained after the scan.
  Date/Author: 2026-07-14 / Codex

- Decision: Build the workspace usage index from fixed-size batches of persisted
  file states, reducing each batch immediately to compact module/export/binder
  entries. Reparse only when a named reexport and a local declaration expose the
  same name.
  Rationale: Source order can change the winner only for that collision. Import
  ordinals already preserve ordering between reexports, while unrelated local
  names commute with them. Batching removes the global parse and repeated
  single-file queries without retaining all 36,100 hydrated corpus states or
  weakening the existing later-local/later-reexport semantics.
  Date/Author: 2026-07-14 / Codex

- Decision: When a source-omitting batch state has no synthetic module unit,
  explicitly add its already-computed module identifier as a local export event.
  Rationale: The ordinary hydrated path exposes the module itself as a seed.
  Restoring that compact event keeps batch hydration behaviorally equivalent
  without loading source merely to synthesize a path-derived unit.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

The implementation is complete and the new focused behavior is covered. A
`PythonDefinitionContext` now owns a 512-entry mutex-protected cache of `Option<CodeUnit>`
values keyed by trimmed type text and the existing self-file mode. It consults the
binder's exact named import map, then same-file classes, and only then takes the
unchanged shared graph-resolver fallback. The context remains removed after its last
request, so no cache survives the batch-file lifecycle.

The full validation and acceptance benchmark remains pending. The receiver path is
covered for direct imports, explicit facade reexports, and imported class factory
methods. Focused counters prove it no longer builds `MultiAnalyzer`'s global index or
scans every declaration. The completed warmed corpus smoke confirms the bounded path
finishes without generic import binding or broad definition hydration dominating typed
receiver resolution, so the full limits may now be started after the required disk
preflight.

## Context and Orientation

`src/analyzer/usages/get_definition/mod.rs` owns `DefinitionBatchContext`, which
groups multiple public definition lookup requests and removes a Python context after
the final request for its file. `src/analyzer/usages/get_definition/python.rs` owns
the Python-specific forward lookup. Its `PythonDefinitionContext` already stores
named-import facts from `PythonAnalyzer::import_binder_of` and same-file declarations.

The shared `python_graph::resolver::resolve_receiver_type` is used by usage analysis
as well as definition lookup. It may call the import-analysis provider, so it must
not gain a definition-batch-specific cache. The new cache belongs exclusively in the
definition context and must leave the shared resolver and public capability traits
unchanged.

## Plan of Work

Add a private receiver-type resolver to `PythonDefinitionContext`. Its key is the
trimmed requested type name and `target_self_file`. On a cache miss, first look up the
name in the context's named imports and resolve that fully qualified name through the
existing `python_class_for_fqn` helper. Then look in same-file declarations. Only if
both exact structured paths fail may it call the existing
`resolve_python_receiver_type` fallback. Store both `Some(CodeUnit)` and `None` while
the 512-entry limit has capacity; after the limit, compute without inserting.

Thread this context method through inferred typed receivers, class-name receivers,
callable resolution, and callable-return resolution. Add test-only counters for cache
misses and generic fallback calls. Preserve current per-file context removal.

## Concrete Steps

From the repository root:

1. Update `PythonDefinitionContext` and its callers, then add focused tests in
   `src/analyzer/usages/get_definition/mod.rs` and `tests/get_definition_test.rs`.
2. Run `cargo fmt`.
3. Run focused library and integration tests with a single matching Python toolchain.
   On this host, set `PYO3_PYTHON` to the Homebrew Python that supplies the linker
   flags rather than mixing `/usr/bin/python3` with Homebrew libraries.
4. Run `cargo clippy --all-targets --all-features -- -D warnings` and
   `cargo test --features nlp,python`.
5. Build `bifrost_reference_differential` in release mode and run a warmed smoke on
   `/Users/dave/Workspace/test-repos/googleapis__google-cloud-python` with smaller
   file, site, and target limits. Preserve the JSONL report in
   `.agents/docs/reference-differential/`.

## Validation and Acceptance

The focused batch test must resolve two references on the same typed imported receiver,
build scope facts once, miss the receiver-type cache once, avoid the generic fallback,
and leave `python_contexts` empty. A multi-file batch using the same local type name
for two different imported classes must resolve each member to its own module. A small
test-only cache limit must retain no more entries than its limit and return the same
outcomes after bypassing insertion.

The warmed smoke must write a completed JSONL record. Before the full corpus command,
require at least 120 GiB free disk and monitor it; stop at 60 GiB free. The full record
uses `--max-files 1000 --max-sites 10000 --max-targets 1000`. It is the evidence
required to close #675 only if a fresh sample no longer shows import binding and module
path work dominating typed receiver resolution.

## Idempotence and Recovery

The source changes and tests are repeatable. The cache is rebuilt from immutable
analyzer facts and is discarded after a batch file's final request. Differential runs
must write a new JSONL path for each attempt and must not alter corpus source files.
If disk falls below the threshold, interrupt the run and retain the sample/report for
follow-up rather than deleting user data or corpus files.

## Interfaces and Dependencies

No public API changes are permitted. The private context resolver receives
`&PythonAnalyzer`, `&DefinitionLookupIndex`, `&dyn IAnalyzer`, `&ProjectFile`, a raw
type string, and the existing `target_self_file` boolean, returning `Option<CodeUnit>`.
It uses only existing binder facts, same-file declarations, `python_class_for_fqn`, and
the existing structured shared-resolver fallback.

Revision note (2026-07-14): Created from the post-#735 corpus sample to target the
remaining import-resolution hotspot without introducing workspace-lifetime caching.
