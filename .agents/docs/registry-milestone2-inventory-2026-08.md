# Milestone 2 inventory: the `IAnalyzer` split

Working document for milestone 2 of `.agents/plans/analysis-language-registry-spi.md`
(decision 4). Taken against `74bf60a3` (milestone 1f complete). It records what the
mechanical sweep found before any code moved, the membership adjudication for
`CodeUnitIndex`, the search-method decision, and the `*_for_test` hook census. The
decision-log section at the end is appended to during implementation, per decision 4's
instruction to record every per-method resolution.

## 1. Implementors

Sixteen `impl IAnalyzer for ...` blocks exist in the tree. Every one of them splits.

Counts below are the landed split (post-`cargo fmt`), so `stays on IAnalyzer` includes the
one added `test_hooks()` accessor per hook-owning implementor.

| Implementor | File | Methods | -> `CodeUnitIndex` | -> `AnalyzerTestHooks` | stays on `IAnalyzer` |
| --- | --- | --- | --- | --- | --- |
| `CppAnalyzer` | `crates/bifrost-analysis/src/analyzer/cpp/mod.rs` | 64 | 27 | 6 | 31 |
| `CSharpAnalyzer` | `crates/bifrost-analysis/src/analyzer/csharp/mod.rs` | 68 | 28 | 10 | 30 |
| `GoAnalyzer` | `crates/bifrost-analysis/src/analyzer/go/mod.rs` | 66 | 28 | 6 | 32 |
| `JavaAnalyzer` | `crates/bifrost-analysis/src/analyzer/java/mod.rs` | 70 | 30 | 8 | 32 |
| `JavascriptAnalyzer` | `crates/bifrost-analysis/src/analyzer/javascript/mod.rs` | 64 | 26 | 8 | 30 |
| `KotlinAnalyzer` | `crates/bifrost-analysis/src/analyzer/kotlin/mod.rs` | 68 | 28 | 8 | 32 |
| `PhpAnalyzer` | `crates/bifrost-analysis/src/analyzer/php/mod.rs` | 63 | 27 | 6 | 30 |
| `PythonAnalyzer` | `crates/bifrost-analysis/src/analyzer/python/mod.rs` | 65 | 27 | 8 | 30 |
| `RubyAnalyzer` | `crates/bifrost-analysis/src/analyzer/ruby/mod.rs` | 60 | 23 | 6 | 31 |
| `RustAnalyzer` | `crates/bifrost-analysis/src/analyzer/rust/mod.rs` | 72 | 28 | 10 | 34 |
| `ScalaAnalyzer` | `crates/bifrost-analysis/src/analyzer/scala/mod.rs` | 73 | 28 | 13 | 32 |
| `TypescriptAnalyzer` | `crates/bifrost-analysis/src/analyzer/typescript/mod.rs` | 65 | 26 | 8 | 31 |
| `TreeSitterAnalyzer<A>` | `crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs` | 68 | 26 | 16 | 26 |
| `MultiAnalyzer` | `crates/bifrost-analysis/src/analyzer/multi_analyzer.rs` | 90 | 29 | 17 | 44 |
| `EmptyAnalyzer` | `crates/bifrost-analysis/src/analyzer/workspace.rs` | 21 | 13 | 0 | 8 |
| `CountingAnalyzer` (test fake) | `crates/bifrost-analysis/src/searchtools/tests.rs` | 23 | 14 | 0 | 9 |
| `NoProviderAnalyzer` (test fake) | `tests/suite_cross_language/structural_search_planner.rs` | 18 | 10 | 0 | 8 |

Totals: 17 implementors, 1018 method bodies, of which 418 are `CodeUnitIndex`, 130 are
`AnalyzerTestHooks`, and 470 stay on `IAnalyzer`.

Census correction found during implementation: there are **seventeen** implementors, not
sixteen. `TreeSitterAnalyzer<A>` implements the trait as
`impl<A> crate::analyzer::IAnalyzer for TreeSitterAnalyzer<A> where A: LanguageAdapter`, a
path-qualified generic form that a `^impl IAnalyzer for` sweep does not match. It is the
one that matters most: every language analyzer's split half forwards to it, so it holds
the real implementations the twelve wrappers delegate to.

The two production non-language implementors the plan called out are both present
(`MultiAnalyzer`, `EmptyAnalyzer`). The test-fake sweep found exactly two
(`CountingAnalyzer`, `NoProviderAnalyzer`); neither overrides a `*_for_test` hook, so both
inherit the no-op `test_hooks()` default. There is no fake in `bifrost-lsp`,
`bifrost-mcp`, `bifrost-runtime`, `bifrost-policy` or `bifrost-nlp`: those crates consume
analyzers built by `WorkspaceAnalyzer`, never hand-rolled ones.

## 2. `CodeUnitIndex` membership

Decision 4's semantic definition: the read-only index over a project's declarations --
enumerating them, resolving names to them, rendering their sources, skeletons and
signatures, and navigating parent/child structure. Signature closure over core types is
the mechanical check, not the definition.

Forty-one methods qualify. Every one of them has a signature closed over
`brokk-bifrost-core` types already (`CodeUnit`, `ProjectFile`, `Language`, `Range`,
`SignatureMetadata`, `SummaryFileProjection`, `Project`, `CancellationToken`, plain
strings and std collections), so the check is satisfied with **zero type moves and zero
new core dependencies**.

Enumerating (14): `project`, `languages`, `analyzed_files`, `get_analyzed_files`,
`is_analyzed`, `is_empty`, `top_level_declarations`, `get_top_level_declarations`,
`declarations`, `get_declarations`, `all_declarations`, `get_all_declarations`,
`all_declarations_with_primary_ranges`, `summary_file_projection`.

Resolving names (7): `definitions`, `get_definitions`, `lookup_candidates_by_short_name`,
`lookup_candidates_by_identifier`, `search_definitions`, `search_definitions_with_literal`,
`search_definitions_persisted`.

Rendering (15): `ranges`, `ranges_of`, `ranges_with_limit`, `get_skeleton`,
`get_skeleton_header`, `get_skeletons`, `get_source`, `get_sources`, `signatures`,
`signatures_of`, `signature_metadata`, `signature_metadata_of`, `indexed_source`,
`indexed_source_matches`, `render_source_fragment`.

Navigating (5): `direct_children`, `get_direct_children`, `direct_children_in_file`,
`get_members_in_class`, `parent_of`.

One free function moves with them: `default_parent_fq_name` (`parent_of`'s default body).
It reads `CodeUnit::fq`, `fq_name::segment_interner` and `common::language_for_file`, all
three already in core.

## 3. Candidates rejected, and why

These were examined under the same definition and left on `IAnalyzer`. The first group
fails the mechanical check; the second passes it but fails the definition; the third is
the search adjudication (section 4).

### 3.1 Signature or default body drags a non-core type

| Method | Non-core type | What moving it would add to core |
| --- | --- | --- |
| `begin_query`, `end_query` | `AnalyzerQueryContext` | owns `store::StoreError`: the whole persisted-store error model |
| `workspace_file_index_cell` | `WorkspaceFileIndexCell`, `WorkspaceFileIndex` | request-scope machinery, not index reads; also lifecycle, see 3.2 |
| `global_usage_definition_index` | `DefinitionIndexHandle<'_>`, `GlobalUsageDefinitionIndex` | the usages resolution model (`analyzer/global_usage_definition_index.rs`) |
| `usage_facts_index` | `UsageFactsIndex` | the usages framework |
| `snapshot_caches` | `AnalyzerSnapshotCaches` | structural derived layers + workspace usage-graph cache + semantic model runtime cache, i.e. `moka` and the semantic engine |
| `semantic_model_overlay` | `SemanticModelOverlay` | the semantic model layer |
| `structural_search_providers` | `structural::StructuralSearchProvider` | the structural search engine |
| `import_analysis_provider`, `import_analysis_provider_for_file`, `type_hierarchy_provider`, `type_alias_provider`, `test_detection_provider` | `ImportAnalysisProvider`, `TypeHierarchyProvider`, `TypeAliasProvider`, `TestDetectionProvider` | nothing after commit 3 (`capabilities.rs` moves to core), but these are capability accessors, not index reads -- decision 4 keeps every provider accessor on `IAnalyzer` |
| `comment_density`, `comment_density_by_fq_name`, `comment_density_by_top_level` | default bodies call `analyzer::comment_density` | the tree-sitter comment scanner |
| `find_exception_handling_smells` | default body calls `analyzer::exception_handling` | the per-language exception model |
| `find_test_assertion_smells*`, `find_structural_clone_smells*`, `compute_cognitive_complexities` | `TestAssertionAnalysis` etc. are core, but the implementations are grammar-backed smells | -- (definition failure, see 3.2) |
| `find_usages`, `query_usages` | `FuzzyResult`, `QueryResult`, `UsageFinder` | the usages framework |
| `update`, `update_all`, `as_capability` | `Self: Sized` | not object-safe; assembly-layer construction |
| `list_symbols`, `list_top_level_symbols`, `list_symbols_with_types` | signature is core-typed (`BTreeSet<CodeUnitType>`), but the shared renderer calls `common::display_identifier_for_target` -> `display_symbol_name` -> `analyzer::languages::language_support` | the entire milestone-1 language SPI. This is the sharpest instance of decision 4's "resolve per-method": rendering a symbol *listing* is arguably index rendering, but its display names are a per-language capability, so the method stays. |

### 3.2 Core-typed but outside the definition

* Syntax/parse-tree queries, not declaration-index reads: `parse_errors`,
  `semantic_diagnostics`, `declaration_syntax_kind`, `enclosing_code_unit`,
  `enclosing_code_unit_for_lines`, `is_access_expression`, `find_nearest_declaration`,
  `extract_call_receiver`. These are the closest calls in the whole inventory --
  `enclosing_code_unit` in particular looks like index navigation -- but decision 4
  enumerates four operations and location-to-declaration lookup is none of them; every
  one of these needs a parse tree the index does not hold.
* Import facts, not declarations: `import_statements`, `import_statements_of`.
* Test classification: `contains_tests`, `in_test_region`, `file_is_test_only`,
  `get_test_modules`, `test_files_to_code_units`.
* Aggregate reports and projections over the index rather than access to it: `metrics`
  (`metrics_from_declarations` is already in core, so this one is a pure definition call),
  `get_symbols`.
* Lifecycle, not reads: `begin_streaming_file_read`, `end_streaming_file_read`,
  `release_streaming_readers`, `warm_query_indexes`, `query_indexes_warm`,
  `snapshot_source_generations`, `snapshot_generations_match`.

## 4. Search-method adjudication

The plan offers three options: move `SearchSymbolPatternBatch` / `QueryBatch` /
`SearchSymbolCandidates` plus `regex` into core; redesign the signatures around
core-owned request data; or leave the methods on `IAnalyzer`.

Findings from the sweep:

* `SearchSymbolPatternBatch` (`i_analyzer.rs:68`) owns `CompiledSymbolPatterns`, which is
  a `RegexSet` or a `Vec<Regex>`. `brokk-bifrost-core` has no `regex` dependency.
* Exactly **one** trait method mentions any of the batch types:
  `search_symbol_candidates(&self, patterns: &SearchSymbolPatternBatch, cancellation:
  Option<&CancellationToken>) -> SearchSymbolCandidates`. `QueryBatch` and
  `SearchSymbolCandidates` appear nowhere else in the trait.
* The other five search/lookup entry points -- `search_definitions(&str, bool)`,
  `search_definitions_with_literal(&str, &str, Language)`,
  `search_definitions_persisted(&str)`, `lookup_candidates_by_short_name(&str)`,
  `lookup_candidates_by_identifier(&str)` -- take plain strings and return
  `BTreeSet<CodeUnit>`. Their *implementations* compile regexes; their *signatures* do not
  name a regex type.
* `autocomplete_definitions(&str) -> Vec<CodeUnit>` also has a core-typed signature, but
  its default body calls `regex::escape` to build the fuzzy camelCase pattern.

**Decision: split at the compiled-request boundary.** The five plain-string lookups move
to `CodeUnitIndex`; `search_symbol_candidates` and `autocomplete_definitions` stay on
`IAnalyzer`.

Reasons:

1. The batch types are cleanly separable -- one method mentions them -- so keeping the
   plain-string lookups on `IAnalyzer` would be keeping them there for a dependency they
   do not have.
2. Name resolution is explicitly half of decision 4's definition, and
   `lookup_candidates_by_identifier` is nothing but name resolution. Excluding it would
   make `CodeUnitIndex` a trait that can enumerate and render declarations but not look
   one up by name, which is the arbitrary-feeling outcome the plan tells us to stop for.
3. The stated criterion is legible: a method belongs to the index if its *request* is
   core-owned data. A pattern string is; a pre-compiled `RegexSet` is not. That criterion
   also decides `autocomplete_definitions` without a special case -- its default body
   compiles a pattern, so it is a compiled-request method wearing a string signature.
4. Moving `regex` into core was rejected. It would be a real dependency addition to the
   crate whose whole purpose (#1549) is to sit at the bottom of the graph and rebuild
   fast, bought for one method. Redesigning `SearchSymbolPatternBatch` around core-owned
   request data was rejected too: pre-compiling once per request and sharing the compiled
   set across every delegate is exactly the point of the type (#1199 bounded symbol
   search), and un-compiling it would regress that.

Consequence for consumers: a holder of `&dyn CodeUnitIndex` can resolve names and
substring-search declarations, but cannot run a batched multi-pattern symbol search. That
is the intended tier boundary, not an oversight.

## 5. `*_for_test` hooks

Twenty-one hook methods are declared on `IAnalyzer` today, none of them `cfg`-gated --
they are plain `#[doc(hidden)]` methods with no-op / `0` defaults:

`reset_global_usage_definition_index_build_count_for_test`,
`global_usage_definition_index_build_count_for_test`,
`reset_definition_candidates_query_count_for_test`,
`definition_candidates_query_count_for_test`,
`reset_full_declaration_scan_count_for_test`, `full_declaration_scan_count_for_test`,
`reset_search_candidate_hydration_count_for_test`,
`search_candidate_hydration_count_for_test`,
`reset_package_declaration_scan_count_for_test`,
`package_declaration_scan_count_for_test`, `reset_candidate_hydration_count_for_test`,
`candidate_hydration_count_for_test`, `full_candidate_hydration_count_for_test`,
`bulk_candidate_hydration_count_for_test`, `reset_workspace_path_scan_count_for_test`,
`workspace_path_scan_count_for_test`,
`reset_scala_project_types_build_count_for_test`,
`scala_project_types_build_count_for_test`, `reset_scala_query_scan_counts_for_test`,
`scala_query_parse_count_for_test`, `scala_query_walk_count_for_test`.

The last five are the Scala-specific group (the plan's "two Scala-specific ones" is a
count of the two counter *families*: the project-types build counter and the query
scan-count pair with its shared reset).

114 overrides across 13 implementors. `MultiAnalyzer` overrides 17 of the 21 and is the
only aggregating implementor: its bodies fan out over `self.delegates()` and `sum()` /
fold, so its hooks object has to be `self` rather than a delegate's.

### Call sites outside the analyzers

Trait hooks only. Several of these files also call `*_for_test` names that are inherent
methods on a concrete analyzer or free functions (`full_hydration_count_for_test`,
`definition_query_count_for_test`, `scala_active_path_node_visits_for_test`,
`rust_tree_parse_count_for_test`, ...); those are untouched by the quarantine.

| File | Hooks used |
| --- | --- |
| `tests/analyzer_persistence.rs` | the full set (75 references) |
| `tests/issue_1194_csharp_scan_complexity.rs` | `package_declaration_scan_count` |
| `tests/issue_1199_search_symbols_latency.rs` | `search_candidate_hydration_count` |
| `tests/suite_usages/usages_csharp_graph_test.rs` | candidate hydration, full-declaration scan |
| `tests/suite_usages/usages_scala_graph_test.rs`, `tests/suite_usages/usages_java_graph_test.rs` | scala query scan counts, full-declaration scan |
| `tests/suite_symbols/get_definition_test.rs`, `tests/suite_symbols/searchtools_fuzzy_symbol_lookup.rs` | definition-candidates query, candidate hydration |
| `tests/suite_cross_language/code_query_pipelines.rs` | full-declaration scan |
| `tests/suite_analyzers/scala_type_hierarchy_test.rs`, `tests/suite_analyzers/cpp_type_hierarchy_test.rs` | scala project-types build, full-declaration scan |
| `tests/suite_smells/scala_dead_code_smells.rs` | scala query scan counts |
| `tests/suite_issues/issue_1230_rust_scan_complexity.rs`, `tests/suite_issues/issue_1332_search_notes_honesty.rs` | full-declaration scan, search-candidate hydration |
| `crates/bifrost-analysis/src/code_quality/git_hotspots.rs` (cfg(test)) | definition-candidates query |
| `crates/bifrost-analysis/src/searchtools/summaries.rs` (cfg(test)) | package-declaration scan |
| `crates/bifrost-analysis/src/analyzer/usages/get_definition/{mod,ruby,scala}.rs` (cfg(test)) | definition-candidates query |
| `crates/bifrost-nlp/src/chunker.rs` (cfg(test)) | package-declaration scan, candidate hydration |
| `crates/bifrost-mcp/src/searchtools_service.rs` (cfg(test)) | global usage definition index build |

Correction to the plan's acceptance wording: of the three suites it names as examples,
only `issue_1194` calls an `IAnalyzer` trait hook. `issue_1175_scan_usages_reparse.rs`
uses `prepared_syntax_parse_count_for_test`, an inherent method on the concrete analyzer,
and `issue_1219_location_scan_target.rs` uses the free functions
`rust_tree_parse_count_for_test` and friends. Neither is affected by the quarantine;
both still have to keep compiling and passing, which is what the acceptance is really
asking for.

`brokk-bifrost-nlp` and `brokk-bifrost-mcp` already carry
`brokk-bifrost-analysis = { ..., features = ["test-support"] }` in their
`[dev-dependencies]`, as does the root manifest, so the feature gate reaches every call
site listed above without a manifest change.

### Quarantine shape

```rust
#[cfg(any(test, feature = "test-support"))]
fn test_hooks(&self) -> &dyn AnalyzerTestHooks { &NoOpAnalyzerTestHooks }
```

`AnalyzerTestHooks` carries the 21 methods with today's no-op / `0` defaults and lives in
`analyzer/i_analyzer.rs`, so nothing test-shaped reaches `brokk-bifrost-core`. Every
implementor that overrides a hook gets
`impl AnalyzerTestHooks for X` plus `fn test_hooks(&self) -> &dyn AnalyzerTestHooks { self }`.

The accessor keeps a default body (returning a `&'static` ZST whose methods are the
existing defaults) rather than being a required method. That is exactly today's
behavior for the three implementors that override no hook, and it keeps `EmptyAnalyzer`
and both test fakes untouched. The quarantine is the `cfg` gate, not the absence of a
default; decision 4's rejection of an "unconditional default-no-op supertrait" is about a
*supertrait*, which this is not.

## 6. `capabilities.rs` / `pool_memo.rs` move (commit 3)

Bounds to rewrite: `TypeHierarchyProvider::get_polymorphic_matches<T: IAnalyzer>` (calls
`analyzer.parent_of`) and `build_direct_descendant_index<A: IAnalyzer, P>` (calls
`analyzer.all_declarations`). Both close over `CodeUnitIndex` methods only.

Dependencies the move adds to `brokk-bifrost-core`:

* `rayon` -- `pool_memo.rs` calls `rayon::current_thread_index()` and
  `capabilities.rs::build_reverse_file_index` uses `par_iter`. Already a workspace
  dependency at 1.10.0 and already in the published graph via the facade and analysis, so
  it adds no new third-party crate to the license inventory.

Everything else `capabilities.rs` names is already in core: `CodeUnit`, `ProjectFile`,
`ImportInfo` (`core/analyzer/model.rs:2604`), `compact_graph::{CompactRows,
CompactRowsBuilder}`, `hash::{HashMap, HashSet}`.

`PoolSafeMemo::get` keeps its `#[cfg(test)]` gate verbatim.

## 7. Decision log

* 2026-08-04: `CodeUnitIndex` gets `Send + Sync` as supertraits, mirroring what
  `IAnalyzer` already guaranteed, so no existing generic bound weakens.
* 2026-08-04: search adjudication as recorded in section 4 -- the five plain-string
  lookups move, `search_symbol_candidates` and `autocomplete_definitions` stay, `regex`
  does not enter core.
* 2026-08-04: `list_symbols` / `list_top_level_symbols` / `list_symbols_with_types` stay
  on `IAnalyzer` despite core-typed signatures. Their renderer resolves display names
  through `analyzer::languages::language_support`; per decision 4 the resolution is "the
  method does not belong on the index", not "move the type", because what it depends on
  is the milestone-1 language SPI, not a misplaced model type.
* 2026-08-04: `metrics` stays despite `metrics_from_declarations` already being in core:
  an aggregate report over the index is not access to it.
* 2026-08-04: the location-to-declaration group (`enclosing_code_unit`,
  `enclosing_code_unit_for_lines`, `is_access_expression`, `find_nearest_declaration`,
  `declaration_syntax_kind`) stays. Core-typed signatures, but they answer from a parse
  tree, and decision 4's definition names four operations that do not include location
  lookup.
* 2026-08-04: no analysis-side type had to move into core to satisfy the membership set.
  The one dependency the milestone adds to core is `rayon`, and it arrives with
  `pool_memo.rs`/`capabilities.rs` in commit 3, not with the trait split.
* 2026-08-04 (during the split): seventeenth implementor found -- `TreeSitterAnalyzer<A>`,
  see section 1. Nothing about the membership decision changed; the census sweep pattern
  was too narrow.
* 2026-08-04 (during the split): ten inherent `pub fn <hook>_for_test` wrappers on
  `CSharpAnalyzer`, `GoAnalyzer` and `RustAnalyzer` were deleted rather than kept. Each was
  a byte-identical forward to the same-named trait hook, and inherent methods win name
  resolution, so leaving them would have meant a concrete-typed caller silently bypassing
  `test_hooks()` while a `dyn`-typed caller went through it -- the two-copies hazard the
  quarantine exists to end. Their callers now go through `test_hooks()` like everyone else.
* 2026-08-04 (during the split): `TreeSitterAnalyzer`'s `AnalyzerTestHooks` impl gained
  `reset_search_candidate_hydration_count_for_test` and
  `search_candidate_hydration_count_for_test`, which its `IAnalyzer` impl had never
  overridden. They existed only as inherent methods, so `RustAnalyzer`'s forward reached
  them by inherent resolution while any `dyn IAnalyzer` view of a `TreeSitterAnalyzer`
  silently returned `0`. Routing the forward through `test_hooks()` surfaced that gap as a
  failure in `issue_1199_symbol_search_hydration_tracks_matches_not_workspace_size`; the
  fix closes the divergence at its source rather than special-casing the two names.
* 2026-08-04 (during the split): every call site of a trait hook is now
  `<receiver>.test_hooks().<hook>()`. Calling a method on the returned
  `&dyn AnalyzerTestHooks` does not require the trait in scope, so no call site imports
  `AnalyzerTestHooks`; only `IAnalyzer` has to be in scope, for `test_hooks()` itself.
* 2026-08-04 (during the split): the supertrait split costs an import, not a call-site
  rewrite. 121 files across the workspace gained `use ...::CodeUnitIndex;` because Rust
  requires the defining trait in scope even for a supertrait method on `dyn IAnalyzer`, and
  ten analysis files had the import placed inside their `#[cfg(test)]` module because only
  their tests need it. `IAnalyzer::<m>` / `<Self as IAnalyzer>::<m>` qualified calls in 17
  files became `CodeUnitIndex::<m>`. No call expression changed shape.
