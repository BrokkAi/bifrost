# Coordinator dispositions (read first)

Recorded 2026-08-06 against the census below, before dispatching the js_ts extraction — the
final fleet language. Dispositions follow the landed playbook; deviations are called out.

- **Crate**: single `crates/bifrost-js-ts` (package `brokk-bifrost-js-ts`) holding both
  dialects — the census confirms they are inseparable (one module, one `EdgePassId`, one
  strategy, one spec, one memo-cache type, one config). Deps are the seven-line block in §5;
  no `build.rs`, **no moka** (JsTsMemoCaches is GoMemoCaches-class shim state and stays in
  analysis, holding the crate's `JsTsUsageIndex` in the normal analysis->crate direction).
- **§3.1 (graph<->route cycle)**: APPROVED as proposed — move the five pure syntax/candidate
  functions (`parse_js_ts_tree`, `resolve_js_ts_direct_import_candidates`,
  `resolve_js_ts_module_binding_candidates`, `ts_resolve_type_text_to_property_owners`,
  `ts_type_annotation_text`) out of `get_definition/js_ts.rs` into the crate; the parked route
  imports them back, the mirror of what `js_ts/syntax.rs` already is. Same treatment for
  `browser_global_property_shape`/`unbound_browser_global_property` (they move with
  `js_ts_graph/resolver.rs` anyway) and `ts_is_global_internal_module` (moves with the
  typescript declaration walk; the parked route imports it from the crate).
- **§3.3 (receiver-facts vocabulary)**: APPROVED as a core lowering, not a new abstraction —
  the six `Receiver*` SPI types plus `BoundedNamedTreeWalk`/`walk_named_tree_preorder_bounded`
  (~205 LOC) go to `bifrost-core`; `ReceiverFactContext.analyzer` becomes
  `&dyn CodeUnitIndex`, and its `AnalyzerDefinitionLookup` field takes the landed
  `BoundedDefinitionLookup` spelling. Everything they carry is already core.
- **§3.5 (scoped edges)**: APPROVED — lower `JsTsScopedUsageEdges` + `JsTsScopedNodeStatus`
  to core (`BoundedJavaResolution` precedent). `LanguageEdgeWeights::Scoped` /
  `DeadCodeBulkEdges::Scoped` / `prove_scoped_candidates` then reference core types only.
- **`JsTsAnalyzerHost` re-cut**: becomes the crate's source trait (`JsTsSource` naming is
  fine, or keep the Host name) on core capability traits, naming the six former
  `TreeSitterAnalyzer` methods as trait members — `JavaSource` shape, two implementors.
  Single-tier unless a build re-enters a memo cell (census found no such cell).
- **`js_ts_tree_sitter_language_for_file`**: crate-side ~15-LOC replacement over core
  `LanguageDialect::for_path`; delete the framework copy in `usages/parsed_tree.rs` if no
  framework caller remains after the move (census says all eight call sites move).
- **`TypeScriptDeclarationPackProducer`**: do nothing — parks with `external.rs`; no
  downstream crate imports it, so the publication DAG is unaffected.
- **Parks** (unchanged from fleet policy): `js_ts/semantic/` + the two 7-LOC registration
  stubs (analyzer/semantic), `js_ts/external.rs` (semantic_model), `get_definition/js_ts.rs` +
  `get_type/js_ts.rs` + `JsTsDefinitionContext` (batch-context inversion; NOT W7-blocked).
- **Epoch salts**: both JS and TS salts bump with the standard token
  (`;js-ts-query-assets-in-brokk-bifrost-js-ts-2026-08`); no prior-salt cfg(test) literals
  exist for either, so no pinned-literal preservation is needed. After the move,
  `EMBEDDED_QUERIES` is empty and `resources/treesitter/` leaves `bifrost-analysis`; keep the
  table and the loader in place (the fleet's stub comments document the relocations).
- **Wiring mirror**: the standard eight-point set — workspace member, dependency-check
  allowed sets ([core] for the crate; analysis gains it), package script + `.scm`
  `require_archive_file` entries for all six assets, `release.yml` publish-crate-js-ts
  needs [release-context, promotion-evidence, publish-crate-core] + analysis-needs roster,
  CONTRIBUTING inventory table + bootstrap paragraph, rust-library.md list, doc stamp,
  test-support feature chain.
- **Sequencing** (churn-aware, §"Schedule risk"): Js-1 = prerequisite pass inside analysis
  (the three lowerings above + host re-cut + R1 ~60 LOC + §3.1 function relocation into
  `js_ts/` modules); Js-2 = crate move + wiring, hottest files (the two declaration walks)
  lifted in one pass, not held across days. Graph band moves in Js-2 with the rest — its
  blockers are exactly the Js-1 lowerings.

---

# JS/TS seam census for the stage-3 fleet (2026-08-06)

Taken at working tip `4bcc9043` (working tree is mid-merge: `crates/bifrost-analysis/src/analyzer/rust/graph_support.rs` is `UU`; nothing in the JS/TS seam is conflicted). `origin/master` tip `9c56ea2a`. Scope: `analyzer/{js_ts,javascript,typescript}/`, `usages/js_ts_graph{.rs,/}`, `usages/get_definition/js_ts.rs`, `usages/get_type/js_ts.rs`, the shared semantic lowerer, the shared structural spec, both SPI blocks, and the framework-resident JS/TS implementation sets. Same shape as the Go/Rust/Python/C#/PHP/Ruby/C++/JVM predecessors.

**Verdict summary: js_ts is 29,299 LOC of seam — third-largest in the fleet behind the JVM realm (84,364) and C++ (49,219), 1.21× C#. Three of the four seams the 2026-08 matrix called ENTANGLED are already closed by landed campaign work (M0's `weighted_cache` extraction, W2's generic `NodeKey` edge engine, #1451's `ReceiverFactsFactory`), and the fourth (the semantic engine's TypeScript special-case) is now `cfg(test)`-only. What remains is structurally unlike every predecessor: `js_ts/providers.rs` already *is* a source trait (`JsTsAnalyzerHost`, 325 LOC of free functions), so the R1 mass is ~60 LOC — the fleet's smallest — while the shim floor is ~1,970 because two `Language` variants mean two analyzers, two `IAnalyzer` impls, two `CodeUnitIndex` impls and two SPI blocks. Projection: ~15.2k moves (55 % of production, 89 % of production outside the parks — the highest rate in the fleet), ~1,970 production shim, frontend ≈ −7.1 s; with the definition routes, ~19.9k / ≈ −9.4 s. `JsTsMemoCaches` is GoMemoCaches-class shim state, not RUST_TREES-class: there is no global parse memo, no `static`/`LazyLock` cache and no `thread_local!` anywhere in the seam, so moka does not enter the crate. Churn: 27 seam-touching `origin/master` commits in seven days — the fleet's low band alongside Python (27) and Go (24), against C++ 81, Rust 55, JVM 53.**

---

## 1. The seam, exact paths and `wc -l`

### `crates/bifrost-analysis/src/analyzer/js_ts/` — 7,801 (6,860 prod / 941 in-file test)

| File | LOC (total / prod) | Purpose |
|---|---|---|
| `external.rs` | 1,996 / 1,815 | `resolve_js_ts_semantic_pack_dependencies` `:45`, `TypeScriptDeclarationPackProducer` `:177`, `JsTsDependencyPackAdapter` `:180`, `DeclarationCollector` `:405`, npm lockfile/`package.json` walk. Imports **49 names from `semantic_model`** `:12–24`, plus `semver::Version`, `serde_json::Value` |
| `syntax.rs` | 929 / 777 | `JsTsImportBinder` `:24`, `JsTsLexicalBindingIndex` `:130`, `JsTsDirectPropertyDefinition` `:135`, `JsTsStaticMemberReceiver` `:141`, `compute_import_binder` `:638`, 15 node predicates. The most-imported file in the seam |
| `structural.rs` | 830 / 658 | **The fleet's densest structural spec** (vs Rust 654, Kotlin 582, Java 561, Scala 533, PHP 512, Python 510, C# 434, C++ 415, Ruby 353, Go 310). One `JsTsStructuralSpec { language }` struct `:33` with two statics `:37,:41`, a `js_ts_kind_table!` macro `:64` instantiated as `JS_KIND_TABLE` `:94` / `TS_KIND_TABLE` `:96`, `JS_TS_OCCURRENCE_ROLE_SUPPORT` `:195`, `js_ts_binding_activation` `:361`, `impl StructuralSpec` `:425`. `materialization_support()` `:485` answers core's `JS_TS_MATERIALIZATION_SUPPORT` |
| `diagnostics.rs` | 749 / 526 | `JsTsSemanticDiagnostic` `:23`, `impl From<…> for SemanticDiagnostic` `:30`, `collect_javascript_semantic_diagnostics` `:41` / `collect_typescript_semantic_diagnostics` `:60` (each guarded by one `resolve_analyzer::<{Javascript,Typescript}Analyzer>`), `JsTsDiagnosticCollector` `:142`, scope/binding walk |
| `tsconfig.rs` | 687 / 521 | `AliasResolver` `:41` (`root`, `canonical_root`, two `Mutex<HashMap>` config caches), `extends` resolution, JSONC stripping, `MAX_CONFIG_READS`/`MAX_EXTENDS_DEPTH`/`MAX_CONFIG_BYTES` budgets |
| `imports.rs` | 542 / 503 | ES + CommonJS import parsing, `resolve_js_ts_import_paths` `:352`, `resolve_js_ts_module_specifier` `:370`, `import_info_tokens` `:483`, `extract_js_ts_call_receiver` `:491` |
| `tests.rs` | 471 / 471 | **Production** — JS/TS test detection + assertion-smell classification; **7 `LazyLock<Regex>`** (`expect`/`assert` families), the seam's only `regex` use |
| `model.rs` | 402 / 402 | `module_code_unit` `:37`, `js_ts_segment` `:18`, export/declarator recording, `file_scoped_field_fq` `:247`, `MaterializationRecord` emission |
| `mod.rs` | 344 / 344 | `JS_TS_COGNITIVE_CONFIG` `:51`; `contains_tests`/`path_contains_tests`/`source_contains_tests` `:83–94`; `synthesize_hydrated_module(&mut FileState)` `:96`; `JS_TS_USAGE_STRATEGY` `:111`; **`JavascriptSupport`/`LanguageSupport` `:113–175` (12 methods)**; **`TypescriptSupport`/`LanguageSupport` `:177–254` (14 methods)**; `JsTsEdgePass` `:261–276` (`EdgePassId::JsTs`); `JsTsTypeLookup` `:280–295`; `JsTsDeadCodeBulk` `:299–344` |
| `providers.rs` | 325 / 325 | **`JsTsAnalyzerHost` trait `:30`** (4 accessors: `ts_inner`, `memo_caches`, `alias_resolver`, `js_ts_language`) + 12 free functions generic over it: the whole `ImportAnalysisProvider`/`TypeHierarchyProvider`/usage-index policy for both dialects |
| `hierarchy.rs` | 314 / 314 | `extract_js_supertypes` `:11`, `extract_ts_supertypes` `:38`, `resolve_direct_ancestors` `:67`, `build_direct_descendant_index_by_unit<A: IAnalyzer, P: TypeHierarchyProvider>` `:99` |
| `clones.rs` | 112 / 112 | Token normalizers + `build_js_ts_clone_ast_signature` `:63`, `parse_js_ts_tree` `:106` |
| `cache.rs` | 65 / 65 | **`JsTsMemoCaches`** `:20` — 5 moka `Cache`, 1 `OnceLock<DirectDescendantIndex>`, 2 `PoolSafeMemo` (`reverse_import_index`, `jsts_usage_index`) + `weight_string_set` `:58`. Imports `build_weighted_cache`/`weight_*` from **`analyzer::weighted_cache`** (M0), not the other way round |
| `identifiers.rs` | 35 / 35 | `collect_js_ts_identifiers` |

### `crates/bifrost-analysis/src/analyzer/js_ts/semantic/` — 4,322 (4,067 prod / 255 in-file test)

`control.rs` 2,640 (CFG/ICFG lowering) · `syntax.rs` 680 · `mod.rs` 346/253 (`JsTsSemanticFlavor` `:25`, `JsTsSemanticLowerer::{javascript,typescript}()` `:66,:72`, `impl ProgramSemanticsLowerer` `:78`) · `values.rs` 336 · `tests.rs` 162 (`#[cfg(test)] mod tests;` at `mod.rs:255`) · `inventory.rs` 158.

### `crates/bifrost-analysis/src/analyzer/javascript/` — 2,850 (2,850 prod / 0 in-file test)

| Block | Lines | LOC |
|---|---|---:|
| imports + `mod semantic;` | `:1–52` | 52 |
| `JavascriptAdapter` + `impl LanguageAdapter` | `:53–207` | 155 (incl. `parse_file` `:126–199`) |
| `struct JavascriptAnalyzer` — **4 fields** (`inner`, `memo_budget`, `memo_caches: Arc<JsTsMemoCaches>`, `alias_resolver: Arc<AliasResolver>`) | `:208–216` | 9 |
| `impl JsTsAnalyzerHost` | `:217–238` | 22 |
| `impl_forward_query_provider!` + `impl JavascriptAnalyzer` (ctors) | `:237–332` | 94 |
| `ImportAnalysisProvider` / `TypeHierarchyProvider` / `TestDetectionProvider` | `:333–395` | 63 (all one-line delegations into `providers::*`) |
| `CodeUnitIndex` | `:396–563` | 168 |
| `IAnalyzer` | `:564–770` | 207 |
| `AnalyzerTestHooks` (`cfg(any(test, feature = "test-support"))`) | `:771–814` | 44 |
| `impl JavascriptAnalyzer` (skeleton) | `:815–841` | 27 |
| **free functions** — the JS declaration walk, CommonJS/ESM export analysis, signature rendering, assignment-declaration state machine | `:842–2843` | **2,002** |

`javascript/semantic.rs` — 7 LOC, `impl_program_semantics_provider!(JavascriptAnalyzer, JsTsSemanticLowerer::javascript())`.

### `crates/bifrost-analysis/src/analyzer/typescript/` — 2,449 (2,449 prod / 0 in-file test)

Same shape: imports `:1–51`; `TypescriptAdapter` + `LanguageAdapter` `:52–237` (186); struct `:238–246` (**4 fields**, identical to JS); `JsTsAnalyzerHost` `:247–268`; `impl TypescriptAnalyzer` `:269–389` (121); `ImportAnalysisProvider` `:390–439`, `TypeAliasProvider` `:440–445`, `TestDetectionProvider` `:446`, `TypeHierarchyProvider` `:448–459`; `CodeUnitIndex` `:460–631` (172); `IAnalyzer` `:632–842` (211); `AnalyzerTestHooks` `:843–887` (45); `impl TypescriptAnalyzer` `:888–917` (30, `build_clone_candidate_data`); **free functions `:918–2442` (1,525)** — the TS declaration walk incl. ambient/global-module handling (`ts_is_global_internal_module` `:971`, `pub(crate)`, imported by `get_definition/js_ts.rs:8`).
`typescript/semantic.rs` — 7 LOC.

### `crates/bifrost-analysis/src/analyzer/usages/js_ts_graph{.rs,/}` — 7,132 (6,821 prod / 311 in-file test)

| File | LOC (total / prod) | Purpose |
|---|---|---|
| `js_ts_graph/extractor.rs` | 2,197 / 2,135 | `scan_files_for_seeds` `:39`, `compute_export_index`, the per-file reference scan. `rayon::prelude`. **Imports `ts_resolve_type_text_to_property_owners` and `ts_type_annotation_text` from `get_definition::js_ts` `:8–10`** |
| `js_ts_graph/receiver_analysis.rs` | 2,059 / 1,844 | `JsTsReceiverFacts` `:46` + `impl ReceiverFactsFactory` `:56`; `JsTsReceiverSyntaxIndex`, `JsTsReceiverFactProvider`, `build_js_ts_receiver_syntax_index`. Imports six `languages.rs` SPI types `:10–13`, `BoundedNamedTreeWalk`/`walk_named_tree_preorder_bounded` `:14–16`, and **four names from `get_definition::js_ts` `:18–22`**. 4 `profiling::scope` sites |
| `js_ts_graph/inverted.rs` | 1,508 / 1,474 | **Fully on the W2 core contract** — `FileEdgeScanInput`, `PerFileEdges`, `build_edge_output` `:66`, `build_edge_weights` `:162`, `collect_file_edges`, `classify_reference_node`, parse-on-demand (`parse_tree_sitter_file`). **No `FileState` reach-in.** Defines `JsTsScopedNodeStatus` `:130` and `JsTsScopedUsageEdges` `:137` |
| `js_ts_graph/resolver.rs` | 767 / 767 | `JsTsUsageIndex`, `build_jsts_usage_index{,_with_cancellation}`, `combine_jsts_usage_indices`, `tree_sitter_language_for` `:681`, `browser_global_property_shape`, `unbound_browser_global_property`. `rayon::prelude` |
| `js_ts_graph.rs` | 533 / 533 | Module entry. `pub(crate) use receiver_analysis::JsTsReceiverFacts` `:42`; three `pub(in crate::analyzer::usages)` re-export groups `:45–53`; `cached_jsts_index` `:108` and `prewarm_cached_jsts_index` `:132` (the two `resolve_analyzer::<{Typescript,Javascript}Analyzer>` downcasts); `JsTsQueryResolver`/`UsageQueryResolver` `:150`; `JsTsEdgeResolver` `:277` (**a plain struct — no `UsageEdgeResolver` impl**); `build_jsts_usage_edges` `:88`; `build_jsts_scoped_usage_edges` `:340`; `JsTsExportUsageGraphStrategy` `:411` (`pub`) |
| `js_ts_graph/hits.rs` | 68 / 68 | `record_hit`/`record_import_hit`/`record_reexport_hit`/… |

`usages/mod.rs:27` declares `pub(crate) mod js_ts_graph` (like the JVM's three, unlike C++'s `pub mod cpp_graph`). One item crosses: `pub use js_ts_graph::JsTsExportUsageGraphStrategy` (`mod.rs:72`).

### Definition / type routes — 4,745

`get_definition/js_ts.rs` 3,984 (`resolve_js_ts` `:103`, `jsts_site_for_focus` `:1702`, 5 `pub(crate)` functions the graph and get_type import, `use super::*` glob, 60 `&dyn IAnalyzer`, **zero `ResolutionSession` references**) · `get_type/js_ts.rs` 761 (`resolve_js_ts_type` `:23`, on core's `BoundedDefinitionLookup`; imports **six** names from `get_definition::js_ts`).

### `.scm` assets

`resources/treesitter/javascript/{definitions.scm 181, imports.scm 8, identifiers.scm 5}` = **194**; `resources/treesitter/typescript/{definitions.scm 228, imports.scm 12, identifiers.scm 6}` = **246**. **These six files are the *only* remaining entries in `EMBEDDED_QUERIES` (`store/epoch.rs:172–203`)** — every other language's assets already moved to its crate, leaving comment stubs (`// C++`, `// C#`, `// Java`, `// PHP`, `// Scala`). `resources/treesitter/` contains exactly two directories. `bifrost-analysis/Cargo.toml` has **no `exclude` list** (the vendored-grammar entries left with `brokk-bifrost-jvm`).

### Root test suites — 10,932 LOC in JS/TS-named files

`tests/suite_usages/`: `usages_js_ts_graph_test.rs` (3,490), `usage_graph_ts_test.rs` (649), `usages_js_ts_path_alias_test.rs` (256).
`tests/suite_analyzers/`: `typescript_analyzer_test.rs` (1,170), `javascript_analyzer_test.rs` (1,084), `javascript_import_test.rs` (579), `typescript_import_test.rs` (492), `javascript_arrow_function_test.rs` (292), `typescript_analyzer_update_test.rs` (59), `typescript_alias_test.rs` (39).
`tests/suite_smells/`: `python_js_ts_dead_code_smells.rs` (1,419, shared with Python), `js_ts_structural_clone_smells.rs` (299), `js_ts_test_assertion_smells.rs` (227).
`tests/suite_semantic/`: `js_ts_dependency_semantic_pack.rs` (542), `measure_jsts_scan_usages_baseline.rs` (149), `measure_jsts_usage_graph_memory.rs` (66).
`tests/`: `jsts_usage_graph_deadlock.rs` (120).
Fixtures: `tests/fixtures/{testcode-js, testcode-ts, usage-graph-ts, usage-graph-ts-modres, usage-graph-ts-samename}`.
**68 root test files touch JS/TS; 53 of them carry no JS/TS name** (`suite_symbols/get_definition_test.rs` 32,306, `suite_semantic/semantic_language_conformance.rs` 19,570, `suite_symbols/searchtools_service.rs` 10,024, `tests/common/value_flow_scenarios.rs`, the whole `suite_cross_language/` tree, …).

**Seam total: 29,299 LOC (27,800 prod / 1,499 in-file test) + 440 `.scm`.**

### Framework-resident JS/TS implementation sets (outside the seam count)

- `usages/get_definition/mod.rs`: `use crate::analyzer::js_ts::syntax::JsTsImportBinder` `:2`; five names from `js_ts_graph` `:35–38`; `pub(super) struct JsTsDefinitionContext` `:781–785` (three crate-side types); `DefinitionBatchContext.js_ts_contexts` `:806`; `fn js_ts_context` `:892–913`; `jsts_site_for_focus` call `:1164`; dispatch arm `:1250`; in-file test `:1919–1938`. **≈ 60 LOC.**
- `usages/get_definition/trace.rs:625–632`: the `Language::JavaScript | Language::TypeScript` arm of `boundary_evidence`, calling `js_ts_graph::cached_jsts_index`. Allowlisted.
- `usages/get_definition/call_sites.rs`: `jsts_call_reference_candidate` `:898` plus arms `:341, :403, :778`. Allowlisted.
- `usages/parsed_tree.rs:9–19`: **`js_ts_tree_sitter_language_for_file`** — a JS/TS-named free function in a framework file, called at 8 sites across 6 seam files. **Not allowlisted and invisible to the reach-in gate** (the gate matches module segments and `<Lang><Suffix>` type idents, not free-function names — the same class of blindness the C++ census recorded).
- `usages/candidates.rs:418–430` and `:566–569`: the JS↔TS unified candidate-file set and the `should_union_text_candidates` JS/TS clause. **≈ 20 LOC**, production, not allowlisted.
- `code_quality/dead_code_smells.rs:14, 852–915`: `prove_scoped_candidates`, the only proof shape that destructures a language product. **≈ 90 LOC.** Allowlisted.
- `analyzer/languages.rs:20, 329, 461`: `LanguageEdgeWeights::Scoped(JsTsScopedUsageEdges)` and `DeadCodeBulkEdges::Scoped(JsTsScopedUsageEdges)`. Assembly file.
- `analyzer/lexical_definitions.rs`: **16 `Language::JavaScript | TypeScript` arms** plus `js_ts_scope_declaration_matches` `:695`. Not allowlisted (arms, not modules/types).
- `analyzer/exception_handling.rs:78, 129–166, 795`: `analyze_js_ts` + `js_ts_statement_count`.
- `analyzer/reference_candidates.rs:133, 138`: `is_js_ts_export_alias`. Allowlisted.
- `analyzer/workspace.rs:12–15, 309–317`: the `DependencyPackEcosystem::Npm` arm. Allowlisted as "Python-specific workspace surface" — the entry does not mention the npm arm.

---

## 2. Per-file classification

**(a) core-resident already.** Everything the JVM census verified, plus (checked in `bifrost-core`): `Language::{JavaScript,TypeScript}` with extension tables `model.rs:113–114` (`js,mjs,cjs,jsx` / `ts,tsx`) and secondary extensions `:128` (`vue`, `svelte`); **`LanguageDialect::TypeScriptTsx` and `LanguageDialect::for_path` (`model.rs:179–236`)** — the TSX decision itself is already core; `has_js_ts_test_filename` (`test_paths.rs:50`); **`JsTsAnalyzerConfig` / `JsTsDependencyDiscoveryConfig` (`config.rs:46,51`)** — one shared config for two languages, the `JvmAnalyzerConfig` shape; `JS_TS_MATERIALIZATION_SUPPORT` (`structural/materialization.rs:462`); `DirectDescendantIndex`, `memoized_reverse_import_index`, `build_reverse_file_index`, `build_direct_descendant_index` (`capabilities.rs:118,157,239,306`); `PoolSafeMemo` (`pool_memo.rs`); `profiling`; `tree_walk::{WalkControl, walk_named_tree_preorder, walk_tree_iterative, subtree_contains, collect_parse_errors}`; `semantic_diagnostics::{ScopeStack, node_range}`; `test_assertions`; `cognitive_complexity::Config`; `fq_name::{FqName, SegmentId, SegmentKind, segment_interner}`; and the entire lowered `usages` band — `model`, `outcome`, `graph_core`, `local_inference`, `parsed_tree`, `receiver_analysis`, `reference_site`, `reexport_seeds`, `same_owner`, `scan_scope`, `resolution_session`, **`inverted_edges` including `NodeKey`, `UsageNodeKey`, `UsageEdgeWeights<K>`, `FileEdgeScanInput<K>`, `PerFileEdges<K>`, `ClassRangeIndex`**.

The W2 lowering's doc comment names JS/TS as the reason the engine is generic: *"Module-scoped ecosystems (JS/TS), where the same bare export name in two files is two distinct symbols, instantiate the same engine with `K = UsageNodeKey`"* (`core/analyzer/usages/inverted_edges.rs:13–18`). That is the fourth matrix seam already paid for.

Clean today, zero analysis machinery: **`js_ts/{clones.rs 112, identifiers.rs 35, model.rs 402, hierarchy.rs 314, imports.rs prod 503, syntax.rs prod 777, structural.rs prod 658, tests.rs 471, tsconfig.rs prod 521}`, `js_ts/mod.rs`'s cognitive-config + test-predicate band ~43, `javascript/mod.rs` free-fn band 2,002, `typescript/mod.rs` free-fn band 1,525, the two `LanguageAdapter` bodies ~250, `js_ts/diagnostics.rs` prod minus its two downcast guards ~505, `js_ts/providers.rs` 325** (see (c)). ≈ **8,443.**

**(b) retarget-only after the landed workstreams** — `js_ts_graph/{hits, extractor, inverted, resolver}.rs` and the query/edge-resolver half of `js_ts_graph.rs`, on the `<Lang>Source` graph-support trait idiom (`bifrost-jvm/src/java/graph_support.rs` is the newest template; `bifrost-ruby/src/graph_support.rs` the original). The `IAnalyzer` surface these four files actually use is **eight methods**: `all_declarations`, `declarations`, `parent_of`, `ranges`, `enclosing_code_unit`, `project`, `analyzed_files`, `global_usage_definition_index` — of which only the last is not already on core's `CodeUnitIndex`, and it has the landed `BoundedDefinitionLookup` spelling (`JavaSource::usage_definitions`).

**(c) analysis machinery, per file**

| File | Machinery | Covered by an established pattern? |
|---|---|---|
| `js_ts/providers.rs` | `JsTsAnalyzerHost: IAnalyzer + TypeHierarchyProvider` with `type Adapter: LanguageAdapter` and `fn ts_inner(&self) -> &TreeSitterAnalyzer<Self::Adapter>`; 7 distinct `TreeSitterAnalyzer` calls (`all_files`, `bulk_import_infos`, `import_info_of`, `raw_supertypes_of`, `top_level_declarations`, `get_source`) | **Yes, and half-done** — this is the `<Lang>Source` shape one refactor early. The work is re-cutting the trait on core capability traits and naming the six `TreeSitterAnalyzer` methods as trait members |
| `js_ts/cache.rs` | 5 moka `Cache`, `OnceLock<DirectDescendantIndex>`, 2 `PoolSafeMemo`, `build_weighted_cache` | **Yes** — GoMemoCaches shape; **stays in analysis**, importing `JsTsUsageIndex` from the crate |
| `js_ts/mod.rs` SPI ×2 | `LanguageSupport`, `LanguageEdgePass`, `DeadCodeBulkProof`, `TypeLookupResolver`, `ReceiverFactsFactory`, `LimitedQueryRows`, `resolve_analyzer` ×5, `ParserFlavor` | **Yes** — the `<Lang>Support` shim, doubled |
| `js_ts/diagnostics.rs` | 2 `resolve_analyzer` guards (~21 LOC), `js_ts_tree_sitter_language_for_file` | **Yes** — split the guards shim-side |
| `js_ts/hierarchy.rs` | `A: IAnalyzer` bound on `build_direct_descendant_index_by_unit` | **Yes** — `CodeUnitIndex` substitution |
| `js_ts_graph/{inverted,resolver,extractor,hits}.rs` | W2 contract (core), `rayon`, `analyzed_files_for_language` (core), 8 `IAnalyzer` methods | **Yes** — cleanest graph band in the fleet; **no `FileState` reach-in, no production-path counters, no `test-support` chain needed** |
| `js_ts_graph.rs` | `resolve_analyzer::<{Typescript,Javascript}Analyzer>` ×2 (`cached_jsts_index`, `prewarm_cached_jsts_index`), `GraphUsageAnalyzer`, `UsageAnalyzer` | **Yes** — the `php_graph.rs` shape, splitting at the two downcasts |
| `js_ts_graph/receiver_analysis.rs` | Six `pub(crate)` SPI types from `analyzer/languages.rs`; `BoundedNamedTreeWalk`/`walk_named_tree_preorder_bounded` from `tree_sitter_analyzer.rs`; four names from the parked definition route | **NO — §3.3** |
| `js_ts_graph/extractor.rs` | Two names from the parked definition route | **NO — §3.1** |
| `js_ts/external.rs` | 49 `semantic_model` names | **Parked** — C#/Ruby precedent (§3.4) |
| `js_ts/semantic/*`, `{javascript,typescript}/semantic.rs` | `analyzer::semantic::*`, registration macro naming the analyzer type ×2 | **Parked** — fleet-wide |
| `get_definition/js_ts.rs`, `get_type/js_ts.rs` | `use super::*` glob, `DefinitionBatchContext`, `analyzer::typescript::ts_is_global_internal_module` | **Parked**; **not W7-blocked** (zero `ResolutionSession` uses) — blocked by the batch context (§3.2) |

**R1-class inherent language logic — sized.** Four inherent `impl` blocks totalling 272 LOC / 27 methods, of which **≈ 60 LOC / 5 methods** is language logic:

| Site | LOC / methods | Disposition |
|---|---:|---|
| `javascript/mod.rs:239–332` | 94 / 12 | ctors, `from_project`, `inner`, `ranges_limited`, three `jsts_usage_index*` delegations → **shim**; `module_import_skeleton` ~9 moves |
| `javascript/mod.rs:815–841` | 27 / 1 | `build_clone_candidate_data` → **shim** (calls moved helpers) |
| `typescript/mod.rs:269–389` | 121 / 14 | same → **shim**; `module_import_skeleton` ~9, `type_alias_skeleton` ~8, `is_type_alias` ~4 move |
| `typescript/mod.rs:888–917` | 30 / 1 | `build_clone_candidate_data` ~29 moves |
| **Total needing free-function rewrite** | **≈ 60 / 5** | vs Rust 2,896/73, JVM 2,133/138, C# 1,210/52, Python 916/37, C++ 448/20, Ruby 383/29, PHP 131/15 |

**This is the smallest R1 mass in the fleet by a factor of two, and the reason is `providers.rs`:** the two-analyzer reconciliation that produced `JsTsAnalyzerHost` already converted the shared method surface into free functions over a trait. The 12 provider impl methods on each analyzer are one-line delegations.

**`PreparedSyntaxTree` outside the lowerer: none.** All 5 sites are in `js_ts/semantic/{mod.rs:16,98,328, inventory.rs:49, control.rs:6}` (parked). No graph, definition or declaration file touches it — the JVM shape, unlike C++ (27 sites) and Rust.

**moka / global caches / rayon / regex.** **Zero `static`/`LazyLock` caches, zero `thread_local!`.** The 8 `LazyLock`s are 7 `Regex` in `js_ts/tests.rs` and 1 `cognitive_complexity::Config` in `js_ts/mod.rs`. `rayon` appears in exactly two files (`js_ts_graph/{extractor,resolver}.rs`). Instance-resident caching is one `Arc<JsTsMemoCaches>` per analyzer (5 moka + 1 `OnceLock` + 2 `PoolSafeMemo`), shared by both dialects' analyzers, invalidated wholesale by replacing the bucket on `update`/`update_all`. **Verdict: `JsTsMemoCaches` is GoMemoCaches-class shim state, not RUST_TREES-class — moka stays in `bifrost-analysis` and the JS/TS crate needs no moka dependency.** The one wrinkle: `JsTsMemoCaches.jsts_usage_index: PoolSafeMemo<JsTsUsageIndex>` will hold a crate type from the shim (analysis → crate, the normal direction).

**Dead-code bulk-proof shape.** One `JsTsDeadCodeBulk` for both dialects, `bulk: Some(...)` on both supports, `preflight` summing `analyzable_file_count` over `[JavaScript, TypeScript]` with label `"JS/TS"`, `needs_precise_scan → false`, and the only `build` in the repo returning `DeadCodeBulkEdges::Scoped`. **One `EdgePassId::JsTs` for two `Language`s** — the inverse of the JVM's one ecosystem / three passes, and the only 2:1 mapping in the repo.

**Receiver architecture.** JS/TS is the **only** implementer of `ReceiverFactsFactory` (`languages.rs:602`, doc: *"JS/TS is the only implementer today"*). Nine languages implement `StructuralReceiverResolver`; Java runs a resolution session; JS/TS builds its own syntax index. `receiver_query/mod.rs` contains **zero** `js_ts` references — everything crosses through the SPI at `:518, 541, 611`.

---

## 3. JS/TS-specific hard spots, examined

### 3.0 What became of the four matrix seams

| Matrix seam (2026-08) | Status at `4bcc9043` |
|---|---|
| **1.** `js_ts::cache::{build_weighted_cache, weight_code_unit_vec_by_unit, weight_code_unit_set, weight_project_file_set}` imported by **nine** other language modules | **CLOSED (M0).** `analyzer/weighted_cache.rs` (60 LOC) owns all four; `js_ts/cache.rs:8–11` is now a consumer alongside `{cpp,csharp,go,kotlin,php,python,ruby,rust,scala}`. `grep 'js_ts::cache'` outside `js_ts/`, `javascript/`, `typescript/` returns nothing |
| **2.** `SEM.semantic -> LANG.js_ts` (`semantic/service.rs:707` `TypescriptAdapter`, `:1235` `JsTsSemanticLowerer::typescript`) | **CLOSED for production.** `#[cfg(test)] mod tests` starts at `service.rs:696`; both references are inside it, along with 6 more `TypescriptAdapter` uses. The production semantic engine is language-blind |
| **3.** `USAGES.fw -> UGRAPH.js_ts::receiver_analysis` (six `pub(in crate::analyzer::usages)` items + `JsTsReceiverFactProvider` pulled by `receiver_query.rs:31,36`) | **CLOSED (#1451 / 1f-2).** `receiver_query/mod.rs` has zero JS/TS references; the crossing is `LanguageSupport::receiver_facts() -> &'static dyn ReceiverFactsFactory` with `prepare_file`/`make_receiver_facts`. **Relocated, not eliminated:** `get_definition/mod.rs:35–38` now imports `JsTsReceiverFactProvider`, `JsTsReceiverSyntaxIndex`, `build_js_ts_receiver_syntax_index`, `cached_jsts_index`, `compute_jsts_import_binder` (§3.2) |
| **4.** `JsTsScopedUsageEdges` cannot satisfy `UsageEdgeResolver` | **CLOSED as stated, reshaped as a type leak.** `js_ts_graph.rs` no longer implements `UsageEdgeResolver` at all — `JsTsEdgeResolver` `:277` is a plain struct with inherent methods, and the W2 engine is generic over `K`. What survives is `JsTsScopedUsageEdges`/`JsTsScopedNodeStatus` inside two framework enum variants (§3.5) |

### 3.1 The parked-route ↔ movable-graph cycle

`usages/get_definition/js_ts.rs` (3,984, parked) and the movable graph band import each other:

*Graph → route (six names, two files):*
- `js_ts_graph/receiver_analysis.rs:18–22` → `parse_js_ts_tree`, `resolve_js_ts_direct_import_candidates`, `resolve_js_ts_module_binding_candidates`, `ts_resolve_type_text_to_property_owners`, `ts_type_annotation_text`
- `js_ts_graph/extractor.rs:8–10` → `ts_resolve_type_text_to_property_owners`, `ts_type_annotation_text`

*Route → graph (two names):*
- `get_definition/js_ts.rs:9–11` → `browser_global_property_shape`, `unbound_browser_global_property` (defined `js_ts_graph/resolver.rs`)

*Type route → route (six more):*
- `get_type/js_ts.rs:6–11` → `jsts_type_space_candidates`, `resolve_js_ts_direct_import_candidates`, `resolve_js_ts_module_binding_candidates`, `ts_function_return_property_owners`, `ts_receiver_owner_candidates_at_byte`, `ts_resolve_type_text_to_property_owners`, `ts_type_annotation_text`

Definition sites: `get_definition/js_ts.rs:876, 925, 3313, 3767, 3974`. No other language's usage graph reaches into its own definition route; every predecessor's dependency runs route → graph only. **4,203 LOC of movable graph (extractor + receiver_analysis) cannot compile in a crate until those five functions have a home the crate can name.** The five are pure syntax/candidate resolution (`parse_js_ts_tree` is 11 LOC calling `js_ts_tree_sitter_language_for_file`), so the smallest resolution is moving them into the crate and having the parked route import them back — the mirror of what `js_ts/syntax.rs` already is.

`get_definition/js_ts.rs` also imports `crate::analyzer::typescript::ts_is_global_internal_module` `:8` — an analyzer-module reach-in from the definition route.

### 3.2 `DefinitionBatchContext`'s JS/TS field

```rust
// usages/get_definition/mod.rs:781
pub(super) struct JsTsDefinitionContext {
    pub(super) imports: JsTsImportBinder,                  // analyzer/js_ts/syntax.rs:24
    pub(super) aliases: Arc<AliasResolver>,                // analyzer/js_ts/tsconfig.rs:41
    pub(super) syntax_index: Arc<JsTsReceiverSyntaxIndex>, // usages/js_ts_graph/receiver_analysis.rs
}
```
Held as `js_ts_contexts: HashMap<(ProjectFile, Language), JsTsDefinitionContext>` `:806`, built by `js_ts_context` `:892–913` (which calls `build_js_ts_receiver_syntax_index` and `compute_jsts_import_binder` and constructs an `AliasResolver` from the project root), pinned by the in-file test `js_ts_batch_context_reuses_import_alias_and_receiver_syntax_state` `:1919–1938`.

This is the `CppVisibilityIndex` / `ScalaDefinitionContext` inversion at **three crate-side types in one framework struct** — more than C++'s one, fewer than Scala's three-plus-cache. Favorably it is **one-way**: `js_ts_graph/*` names `DefinitionBatchContext` zero times. Unfavorably the key is `(ProjectFile, Language)` rather than `ProjectFile`, because one batch can hold both dialects for the same path.

### 3.3 The receiver-facts factory crossing and its providers' homes

The SPI is clean, but its **types are analysis-`pub(crate)`**:

| Item | Home | Visibility | Implementers |
|---|---|---|---|
| `ReceiverFactsFactory` | `analyzer/languages.rs:602` | `pub(crate)` | `JsTsReceiverFacts` only |
| `ReceiverFacts<'tree>` | `analyzer/languages.rs:617` | `pub(crate)` | JS/TS only |
| `ReceiverFileSetup` | `analyzer/languages.rs:565` | `pub(crate)` | — |
| `ReceiverFileCtx<'a>` | `analyzer/languages.rs:580` | `pub(crate)` | — |
| `ReceiverFactContext<'a,'tree>` | `analyzer/languages.rs:589` | `pub(crate)` | — |
| `ReceiverFileFacts` | `analyzer/languages.rs` | `pub(crate)` | — |
| `BoundedNamedTreeWalk`, `walk_named_tree_preorder_bounded` | `analyzer/tree_sitter_analyzer.rs:172,240` | `pub(crate)` | **three use sites repo-wide**: the definition, `receiver_query/mod.rs`, `js_ts_graph/receiver_analysis.rs` |

Everything these *carry* is already core: `ReceiverAnalysisBudget`, `ReceiverAnalysisReport`, `ReceiverValue`, `ReceiverMemberTargetReport`, `ReceiverFactProvider`, `ReceiverAnalysisCacheKey`, `ReceiverContext`, `ReceiverSummaryQuery`, `NoopReceiverFactProvider` (`core/analyzer/usages/receiver_analysis.rs`). So `receiver_analysis.rs` (2,059 LOC, the second-largest movable file in the seam) is blocked purely on lowering ~110 LOC of trait/enum/struct vocabulary plus the ~95-LOC bounded walk. No landed crate needed either, because no landed language implements `ReceiverFactsFactory`.

`ReceiverFactContext` additionally carries `analyzer: &'a dyn IAnalyzer` and `definitions: &'a AnalyzerDefinitionLookup<'a>` — the first must become `&dyn CodeUnitIndex` or a source trait, the second already has the core `BoundedDefinitionLookup` spelling.

### 3.4 The TS declaration pack band

`js_ts/external.rs` (1,996) imports **49 names** from `analyzer::semantic_model` (14,455 LOC, not lowered in stage 3), plus `serde_json` and `semver`. Three items are `pub` at `analyzer/mod.rs:140–143`:

- `resolve_js_ts_semantic_pack_dependencies` — consumed by `analyzer/workspace.rs:310` (the `DependencyPackEcosystem::Npm` arm) and by `tests/suite_semantic/js_ts_dependency_semantic_pack.rs` (7 sites).
- `JsTsDependencyPackAdapter` — same two consumers.
- **`TypeScriptDeclarationPackProducer` — zero consumers outside `js_ts/external.rs` itself.** Grep across `crates/` and `tests/` finds it only at its definition `:177`, its `ExternalArtifactPackProducer` impl `:182`, its inherent `produce` `:201`, one internal call from the adapter `:384`, and two in-file tests `:1869,1949`. It is not re-exported by `bifrost-analysis/src/lib.rs`, not named by `bifrost-semantic-packs`, and not exercised by any root suite. **Live public API with no external caller — the `summary.rs` class from the JVM census.**

**Unlike the JVM park, nothing downstream imports this band.** `bifrost-semantic-packs/src/release_bundle.rs` names four JVM producers; it names no JS/TS type. So the park is clean: the module stays, the publication DAG is unaffected, and `serde_json`/`semver` stay in `bifrost-analysis` for it. But `js_ts/tsconfig.rs` (movable) also uses `serde_json`, so the crate needs `serde_json` regardless — the PHP `composer.rs` precedent.

### 3.5 `JsTsScopedUsageEdges` in two framework enums

```rust
// analyzer/usages/js_ts_graph/inverted.rs:130,137
pub(crate) enum JsTsScopedNodeStatus { Resolved, Ambiguous, Unseedable }
pub(crate) struct JsTsScopedUsageEdges {
    pub(crate) edges: UsageEdgeWeights<UsageNodeKey>,          // core
    pub(crate) node_status: BTreeMap<UsageNodeKey, JsTsScopedNodeStatus>,
}
```
Named in `analyzer/languages.rs:20` and used as `LanguageEdgeWeights::Scoped(...)` `:329` and `DeadCodeBulkEdges::Scoped(...)` `:461`; destructured in `code_quality/dead_code_smells.rs:867–905` (`prove_scoped_candidates`, ~90 LOC, three arms on `JsTsScopedNodeStatus`). W2 lowered the struct's only field type. What is left to lower is a three-variant enum and a two-field struct.

The reach-in gate does not see it: `languages.rs` is in `ASSEMBLY_FILES`, `dead_code_smells.rs` is allowlisted ("per-language dead-code scoring; follow-up"), and `JsTsScopedUsageEdges` does not end in any of the gate's four `LANGUAGE_TYPE_SUFFIXES` (`Adapter`, `Analyzer`, `Support`, `UsageGraphStrategy`). This is the same class of leak the gate's own note now records as *closed* for `BoundedJavaResolution` — *"a character-for-character duplicate of core's `BoundedResolution`, so `JavaResolutionSession::finish` now returns core's"* — so the precedent for lowering it is proven and one campaign old.

### 3.6 The parser-flavor plumbing

TypeScript is the only language whose grammar depends on the file path:

```rust
// analyzer/js_ts/mod.rs:240
fn parser_language(&self, flavor: ParserFlavor) -> tree_sitter::Language {
    match flavor {
        ParserFlavor::TypeScriptTsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        ParserFlavor::Default => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    }
}
```
The chain is `LanguageDialect::for_path` (**core**, `model.rs:184–216`) → `ParserFlavor::for_dialect` (**analysis `pub(crate)`**, `mod.rs:218–230`) → `LanguageSupport::parser_language(flavor)` (**analysis SPI**, `languages.rs:222`) → the grammar crate. Ten of the eleven `parser_language` impls ignore the argument. Because the SPI block stays shim-side, the flavor enum costs nothing directly — the cost is `usages/parsed_tree.rs:9`'s `js_ts_tree_sitter_language_for_file`, which routes through the registry and is called at 8 sites in 6 files that all move. `js_ts_graph/resolver.rs:681` already carries a crate-local `tree_sitter_language_for(language)` that reads the grammar constants directly, so the crate-side replacement is ~15 LOC over core's `LanguageDialect::for_path`.

Grammar constants are read at 22 sites, of which two are framework-side and both are `cfg(test)`: `usages/inverted_edges.rs:493,682` (`tree_sitter_typescript::LANGUAGE_TYPESCRIPT`, test block starts `:480`-ish) and `tree_sitter_analyzer.rs:9207,9245` (`cfg(test)` from `:160`). Following all eight landed precedents, **`bifrost-analysis` keeps its `tree-sitter-javascript` and `tree-sitter-typescript` dependencies after the move.**

### 3.7 Epoch salts ×2 and the last `.scm` in analysis

| Language | `lang_epoch!` site | Salt tokens | Query content in the salt |
|---|---|---:|---|
| JavaScript | `epoch.rs:381–387` | **4** (`synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07`) | 194 LOC from `resources/treesitter/javascript/` |
| TypeScript | `epoch.rs:394–400` | **4** (identical token list) | 246 LOC from `resources/treesitter/typescript/` |

Neither has a prior-salt helper. Both salts must bump on relocation, exactly as Go's, Python's, Rust's, C#'s, PHP's, Ruby's, C++'s and Java's did (`"…-query-assets-in-brokk-bifrost-<lang>-2026-08"`). **Once they move, `EMBEDDED_QUERIES` is empty, `resources/treesitter/` is gone from `bifrost-analysis`, and every language's query assets live in its own crate's `queries.rs`** (`CPP_QUERY_ASSETS` is the template).

---

## 4. Reverse edges

**Framework files inside `bifrost-analysis` naming a JS/TS concrete type (production):**
- `analyzer/mod.rs:21,22,44,138,139,140–143,209` — `mod {javascript, js_ts, typescript}`; `pub use {javascript::JavascriptAnalyzer, typescript::TypescriptAnalyzer}`; `pub(crate) use js_ts::{AliasResolver, resolve_js_ts_module_specifier}`; the three pack re-exports. Allowlisted ("re-export hub").
- `lib.rs:52,62` — `JavascriptAnalyzer`, `TypescriptAnalyzer` in the crate-root re-export surface. Allowlisted.
- `analyzer/languages.rs:20,29,724,725` — `Language::{JavaScript,TypeScript} => Some(&js_ts::{Javascript,Typescript}Support)`, plus the `JsTsScopedUsageEdges` import. Assembly file.
- `analyzer/multi_analyzer.rs:8,13,42,45,259,260` — `AnalyzerDelegate::{JavaScript(JavascriptAnalyzer), TypeScript(TypescriptAnalyzer)}` and the two `build_delegate!` arms. Assembly file.
- `analyzer/workspace.rs:12,15,310,316` — the npm pack arm. Allowlisted.
- `analyzer/usages/mod.rs:72` — `pub use js_ts_graph::JsTsExportUsageGraphStrategy`. Allowlisted.
- `analyzer/usages/get_definition/{mod.rs, trace.rs, call_sites.rs}` — §3.2 and §1. Allowlisted.
- `analyzer/usages/get_type/mod.rs:18,30` — `mod js_ts` + `pub(crate) use js_ts::resolve_js_ts_type`. Allowlisted.
- `code_quality/dead_code_smells.rs:14,862–915` — §3.5. Allowlisted.
- `analyzer/usages/parsed_tree.rs:9` — **not allowlisted, gate-invisible** (§1).
- `analyzer/usages/candidates.rs:418,566` — **not allowlisted**, `Language::*` arms only.
- `analyzer/lexical_definitions.rs` (16 arms + `js_ts_scope_declaration_matches:695`), `analyzer/exception_handling.rs` (`analyze_js_ts:129`, `js_ts_statement_count:795`), `analyzer/reference_candidates.rs:133,138`, `analyzer/structural/lexical_environment.rs:815`, `searchtools/{scan_usages.rs:1114,2977, selectors.rs:1602}`, `analyzer/value_flow/mod.rs:16,17`, `analyzer/semantic/{icfg.rs, ids.rs}` — `Language::*` arms, no module or type reach-in.

**`cfg(test)`-only, inside `bifrost-analysis`** (production-compile-clean, break on a move):
`analyzer/store/mod.rs:8132, 10333, 11449, 11527, 12208, 12253, 12289, 12327` (8 `Typescript`/`JavascriptAdapter` uses inside `mod tests`); `analyzer/tree_sitter_analyzer.rs:7968, 7972, 9207, 9245`; `analyzer/semantic/service.rs:707, 742, 851, 896, 904, 914, 1081, 1235, 1470, 1534` (**10 — the whole of matrix seam 2**); `analyzer/structural/provider.rs:574, 640, 676, 730, 757, 791`; `analyzer/structural/search/tests/{index_access.rs, execution.rs, contracts.rs, details.rs, mod.rs}` (51 combined); `analyzer/usages/call_relations.rs:1402, 2212, 2216, 2257, 2391`; `analyzer/usages/receiver_query/tests.rs` (6); `analyzer/usages/js_ts_graph/receiver_analysis.rs:1849–1859`; `analyzer/languages.rs:747, 749, 1017, 1021`; `searchtools/tests.rs:963` (`mod tests` gated at `searchtools/mod.rs:62`).

**Cross-crate:**
- **`bifrost-policy`** — `src/evaluator/tests.rs` (7 `TypescriptAnalyzer::from_project` sites) and `src/render/mod.rs:357,380`. **Both `cfg(test)`** (`evaluator.rs:3958–3959`, `render/mod.rs:343`); the crate already carries `brokk-bifrost-analysis` with `features = ["test-support"]` as a dev-dependency.
- **`bifrost-nlp`** — `src/chunker.rs:304,320` builds a `TypescriptAnalyzer` fixture for `function_chunk_excludes_file_license_header`. **`cfg(test)`** (`chunker.rs:148`). The census brief's "bifrost-nlp's chunker builds TS fixtures" is confirmed and is the crate's only JS/TS contact — no production reference, and no `Language::TypeScript` arm anywhere else in `bifrost-nlp`.
- **`bifrost-lsp`** — twelve `Language::{JavaScript,TypeScript}` arms in `handlers/{formatting.rs:292, semantic_tokens.rs:429,434,522,528, hover.rs:116,117}` (the rest `cfg(test)`). **No type reach-in** — unlike `import_ambiguity.rs`, which names `JavaAnalyzer`/`ScalaAnalyzer`/`CSharpAnalyzer` but no JS/TS type.
- **`bifrost-mcp`** — one arm, `searchtools_service.rs:350` (`Language::JavaScript | Language::TypeScript => "npm"`).
- **`bifrost-semantic-packs`, `bifrost-runtime`** — none.
- **`bifrost-core`** — `Language::{JavaScript,TypeScript}` (`model.rs:25,26,69,70,86,87,113,114,128`), `LanguageDialect::TypeScriptTsx` (`model.rs:181–236`), `has_js_ts_test_filename` (`test_paths.rs:50`), `JsTsAnalyzerConfig`/`JsTsDependencyDiscoveryConfig` (`config.rs:46,51`), `JS_TS_MATERIALIZATION_SUPPORT` (`structural/materialization.rs:462`), and the `UsageNodeKey` doc that names JS/TS as its reason (`usages/inverted_edges.rs:13`).

---

## 5. crates.io deps a `brokk-bifrost-js-ts` crate needs

| crate | version in `bifrost-analysis/Cargo.toml` | needed by |
|---|---|---|
| `brokk-bifrost-core` | path, `=` pin | everything |
| `tree-sitter` | 0.25.10 | everything |
| `tree-sitter-javascript` | **0.25.0** | `js_ts/{structural,mod,syntax,imports}.rs`, `javascript/mod.rs`, `js_ts_graph/{resolver,inverted,extractor,receiver_analysis}.rs` |
| `tree-sitter-typescript` | **0.23.2** | same set + `typescript/mod.rs` (three constants: `LANGUAGE_TYPESCRIPT`, `LANGUAGE_TSX`, `HIGHLIGHTS_QUERY`) |
| `regex` | 1.12.2 | `js_ts/tests.rs` (×7) |
| `rayon` | 1.10.0 | `js_ts_graph/{extractor,resolver}.rs` |
| `serde_json` | 1.0.145 | `js_ts/tsconfig.rs` (`AliasResolver`) |

**A seven-line dependency block, no `build.rs`, no `build-dependencies`.** Explicitly **not**: `moka` (all instance caches stay on the shim analyzers — §2), `semver` (only `js_ts/external.rs`, which parks), `serde`, `walkdir`, `flate2`, `zip`. This is the fleet's first crate needing both `rayon` and `serde_json` (Go/Python/Rust have `rayon`; PHP/Ruby/C++/JVM have `serde_json`).

**Grammar notes.**
1. `tree-sitter-javascript 0.25.0` is on the fleet's current line (Go 0.25.0, Python 0.25.0 class); `tree-sitter-typescript 0.23.2` is a generation behind (the C# 0.23.1 / C++ 0.23.4 / Java 0.23.5 / PHP 0.23.11 / Ruby 0.23.1 class). The two are versioned independently even though one module drives both.
2. `JavascriptSupport::highlight_query` answers `tree_sitter_javascript::HIGHLIGHT_QUERY` (**singular**); `TypescriptSupport::highlight_query` answers `tree_sitter_typescript::HIGHLIGHTS_QUERY` (**plural**). Both come from the grammar crate, so neither is a `.scm` asset.
3. `bifrost-analysis` keeps both grammar dependencies (six `cfg(test)` sites plus `store/epoch.rs` fingerprinting) — the landed precedent at eight crates.
4. Publication: the crate lands at order **2** alongside the eight existing language crates; `CONTRIBUTING.md:238–255` (the inventory table), `:222–232` (the DAG prose), `:275–282` (the bootstrap note) and `.github/workflows/release.yml:498–536` all need the entry in the same change, plus the token-based bootstrap publication before the next tag.

---

## 6. LOC accounting

Calibration: Go 8,544 moved / 1,598 prod shim; Rust 16,375 / ~1,900; Python 10,129 / ~1,590; C# 8,180 / ~1,660; PHP 5,935 / ~1,120; Ruby 5,805 / ~1,105; C++ 30,321 / ~1,822; JVM 36,549 / ~4,650.

| Band | LOC | Content |
|---|---:|---|
| **Movable now** (retarget only) | **~8,443** | `js_ts/` 4,623 (`syntax` 777, `structural` 658, `imports` 503, `diagnostics` 505, `tsconfig` 521, `tests` 471, `model` 402, `providers` 325, `hierarchy` 314, `clones` 112, `identifiers` 35); `javascript/mod.rs` free-fn band 2,002 + adapter bodies ~110; `typescript/mod.rs` free-fn band 1,525 + adapter bodies ~140; `js_ts/mod.rs` cognitive-config + test-predicate band ~43 |
| **Movable after the graph-source + R1 pass** | **~6,743** | `js_ts_graph/extractor.rs` 2,135, `receiver_analysis.rs` 1,844, `inverted.rs` 1,474, `resolver.rs` 767, `hits.rs` 68; `js_ts_graph.rs` moving half ~395; R1 free-function rewrite ~60 (5 methods). **Three residues, all lowerings rather than new abstractions:** `ReceiverFactsFactory`'s six-type family + `BoundedNamedTreeWalk` (§3.3), the five `get_definition/js_ts.rs` functions (§3.1), and `JsTsScopedNodeStatus` (§3.5) |
| **Parked on `analyzer/semantic`** | **4,336** | `js_ts/semantic/` 4,322 + `{javascript,typescript}/semantic.rs` 14 (the macro textually requires the analyzer type, ×2) |
| **Parked on `semantic_model`** | **1,996** | `js_ts/external.rs`. **The fleet's second-smallest pack park** (PHP 0, C++ 0, Ruby 4,777, JVM 11,929) |
| **Parked on the definition route** | **~4,800** | `get_definition/js_ts.rs` 3,984 + `get_type/js_ts.rs` 761 + ~55 LOC of `get_definition/mod.rs` wiring. **Not W7-blocked** — zero `ResolutionSession` uses; blocked by `DefinitionBatchContext` and the `use super::*` glob |
| **Shim floor (production)** | **~1,970** | `javascript/mod.rs` ~719 (imports 52 + adapter shell 43 + struct 9 + host 22 + ctors 111 + provider delegations 63 + `CodeUnitIndex` 168 + `IAnalyzer` 207 + hooks 44); `typescript/mod.rs` ~725 (51 + 44 + 9 + 22 + 101 + 70 + 172 + 211 + 45); `js_ts/mod.rs` ~301 (imports 49 + SPI ×2 141 + `JsTsEdgePass`/`JsTsTypeLookup`/`JsTsDeadCodeBulk` 85 + `synthesize_hydrated_module` 14 + statics 2); `js_ts/cache.rs` 65; `js_ts_graph.rs` ~138 (the two downcasts + strategy struct); `js_ts/diagnostics.rs` guards ~21 |
| **Retained analyzer-bound tests** | **~440** | Of 1,499 in-file test LOC, 1,063 sit in moving files and travel (`diagnostics` 223, `receiver_analysis` 215, `structural` 172, `tsconfig` 166, `syntax` 152, `extractor` 62, `imports` 39, `inverted` 34); 255 park with `semantic/`; 181 park with `external.rs`. `receiver_analysis.rs`'s 215 use `TypescriptAnalyzer` and become the retained residue |

**Total 29,299** (27,800 prod / 1,499 in-file test) **+ 440 `.scm`.**

- Moves ≈ **15,186 production (55 % of prod)** + ~1,063 traveling tests. **Fourth-largest absolute move in the fleet** (JVM 36,549 · C++ 30,321 · Rust 16,375 · **js_ts 15,186** · Python 10,129).
- Parked ≈ **11,132 (40 %)** — semantic 4,336 + `semantic_model` 1,996 + definition/type 4,800.
- **Move rate outside the parks: 15,186 / 17,156 = 89 % — the highest in the fleet** (JVM 82 %, Ruby 76 %, C++ 71 %, Rust 68 %). Cause: `providers.rs` already free-functionized the analyzer surface, the graph band is fully on the core W2 contract with no `FileState` reach-in, and the shared `.scm` walk is the only analyzer-coupled declaration path.
- Analysis residue ≈ **14,113**, of which **~1,970 is production shim** — **1.23× the Go 1,598 floor, 1.08× C++'s 1,822, 42 % of the JVM's 4,650**. The single structural reason is two `Language` variants: two `IAnalyzer` impls (418 LOC), two `CodeUnitIndex` impls (340), two `AnalyzerTestHooks` (89), two `LanguageAdapter` shells (~87), two ctor sets (~212) and two `LanguageSupport` registrations (141). One crate carrying two registrations is the same cost shape as the JVM's three, at two-thirds the count.
- Predicted analysis-frontend effect at Go's measured 0.47 s/kLOC: **≈ −7.1 s**. With the definition routes following, moves rise to 19,931 → **≈ −9.4 s**.

**Per-band separability.** The `js_ts/` flat band (4,623) and the two declaration walks (3,527) are independent of everything and of each other. The graph band (6,743) is a single body — `extractor`, `inverted`, `resolver`, `receiver_analysis` and `hits` import each other's `pub(super)` items freely. The two dialects are **not** separable at any point: one module, one `EdgePassId`, one strategy, one structural spec, one lowerer, one memo-cache type, one config.

---

## The five hardest couplings

**1. The graph band imports the parked definition route, and the route imports the graph back.** `js_ts_graph/receiver_analysis.rs:18–22` takes `parse_js_ts_tree`, `resolve_js_ts_direct_import_candidates`, `resolve_js_ts_module_binding_candidates`, `ts_resolve_type_text_to_property_owners` and `ts_type_annotation_text` from `get_definition/js_ts.rs` (`:3974, 925, 876, 3313, 3767`); `js_ts_graph/extractor.rs:8–10` takes two of the same; `get_type/js_ts.rs:6–11` takes seven. In the other direction `get_definition/js_ts.rs:9–11` imports `browser_global_property_shape` and `unbound_browser_global_property` from `js_ts_graph::resolver`, and `:8` imports `analyzer::typescript::ts_is_global_internal_module`. **4,203 LOC of otherwise-movable graph (receiver_analysis 2,059 + extractor 2,197) is held hostage by a 3,984-LOC parked file.** No landed language has this direction of dependency — every predecessor's route reads the graph, never the reverse. The mitigating fact is that `get_definition/js_ts.rs` carries **zero** `ResolutionSession` references, so unlike Scala's `get_definition/scala.rs` it is not waiting on W7; what parks it is `use super::*` and `DefinitionBatchContext`. The five functions are pure syntax/candidate resolution and could move into the crate with the parked route importing them back, which is exactly what `js_ts/syntax.rs` already is for this file.

**2. Two `Language` variants share one module, so the shim floor is doubled while the R1 mass is the fleet's smallest.** `JavascriptAnalyzer` and `TypescriptAnalyzer` are byte-for-byte the same four fields (`inner`, `memo_budget`, `Arc<JsTsMemoCaches>`, `Arc<AliasResolver>`), implement the same `JsTsAnalyzerHost` (`javascript/mod.rs:217`, `typescript/mod.rs:247`), and delegate every provider method into `js_ts/providers.rs` — 325 LOC of free functions over a source trait that no other language had before its extraction. That makes R1 ≈ 60 LOC / 5 methods (Rust's was 2,896/73). It also means the crate must re-cut `JsTsAnalyzerHost` from `IAnalyzer + TypeHierarchyProvider` with `fn ts_inner(&self) -> &TreeSitterAnalyzer<Self::Adapter>` onto core capability traits, naming the six `TreeSitterAnalyzer` methods (`all_files`, `bulk_import_infos`, `import_info_of`, `raw_supertypes_of`, `top_level_declarations`, `get_source`) as trait members — the `JavaSource` shape at two implementors. And the analyzer↔graph dual runs in both directions at two types: `JsTsMemoCaches.jsts_usage_index: PoolSafeMemo<JsTsUsageIndex>` holds a graph type from the shim (`cache.rs:40`), while `js_ts_graph.rs:108,132` downcasts through `resolve_analyzer::<TypescriptAnalyzer>` and `::<JavascriptAnalyzer>` to fetch it — four downcast arms in two functions, both reached from `get_definition/trace.rs:626`, `dead_code_smells`, and the edge builders. Everything that is one block for a single-language crate is two blocks here: two `IAnalyzer` impls, two `CodeUnitIndex` impls, two `AnalyzerTestHooks`, two `LanguageAdapter` shells, two `LanguageSupport` registrations, and one `JsTsAnalyzerConfig` covering both.

**3. `JsTsScopedUsageEdges` is a JS/TS product type inside two framework enum variants, and the gate cannot see it.** `analyzer/languages.rs:20` imports it; `:329` makes it `LanguageEdgeWeights::Scoped` and `:461` makes it `DeadCodeBulkEdges::Scoped`; `code_quality/dead_code_smells.rs:867–905` destructures it and branches on all three `JsTsScopedNodeStatus` variants across ~90 LOC. W2 already lowered the hard half — `UsageNodeKey`, `NodeKey`, `UsageEdgeWeights<K>`, `PerFileEdges<K>`, `FileEdgeScanInput<K>` are core, and core's own doc names JS/TS as the reason (`inverted_edges.rs:13–18`). What is left is a three-variant enum and a two-field struct, i.e. the `BoundedJavaResolution` lowering one campaign later — and the gate's own allowlist now records that one as *closed*, so the precedent is proven. The gate is blind here on two counts: `languages.rs` is an `ASSEMBLY_FILE`, and `JsTsScopedUsageEdges` matches none of the four `LANGUAGE_TYPE_SUFFIXES`, so even an un-allowlisted framework file could name it without tripping.

**4. `ReceiverFactsFactory` and its five companion types are analysis-`pub(crate)` and JS/TS is their only implementer.** `analyzer/languages.rs:560–638` defines `ReceiverFileSetup`, `ReceiverFileCtx`, `ReceiverFactContext`, `ReceiverFactsFactory`, `ReceiverFacts<'tree>` and `ReceiverFileFacts`; `analyzer/tree_sitter_analyzer.rs:172,240` defines `BoundedNamedTreeWalk` and `walk_named_tree_preorder_bounded` with **three use sites in the whole repo**. `js_ts_graph/receiver_analysis.rs` (2,059 LOC — the second-largest movable file) needs all eight. Everything the SPI *carries* is already core (`ReceiverValue`, `ReceiverAnalysisReport`, `ReceiverMemberTargetReport`, `ReceiverFactProvider`, `ReceiverAnalysisBudget`, `ReceiverAnalysisCacheKey`), so this is ~205 LOC of vocabulary lowering, not a redesign — but it is the only lowering the fleet has needed that benefits exactly one language, and `ReceiverFactContext` still carries `&dyn IAnalyzer` and `&AnalyzerDefinitionLookup`. The #1451 / 1f-2 work that produced this SPI is what closed matrix seam 3; it moved the crossing from `receiver_query.rs` (now JS/TS-free) into a trait that itself has to cross.

**5. `DefinitionBatchContext` holds a JS/TS context of three crate-side types, keyed by `(ProjectFile, Language)`.** `get_definition/mod.rs:781–785` defines `JsTsDefinitionContext { imports: JsTsImportBinder, aliases: Arc<AliasResolver>, syntax_index: Arc<JsTsReceiverSyntaxIndex> }` — one type from `js_ts/syntax.rs:24`, one from `js_ts/tsconfig.rs:41`, one from `js_ts_graph/receiver_analysis.rs`. It is a field on the framework batch struct `:806`, built by `js_ts_context` `:892–913` (which calls `build_js_ts_receiver_syntax_index`, `compute_jsts_import_binder` and `AliasResolver::new(project.root())`), and pinned by an in-file test at `:1919`. This is the `CppVisibilityIndex` inversion at three types instead of one, and the key is a pair rather than a `ProjectFile` because one batch can hold both dialects for one path. Favorably it is one-way — `js_ts_graph/*` names `DefinitionBatchContext` zero times, so nothing has to invert; the framework file simply imports three types from the crate, as `get_definition/mod.rs` already does for C++.

**Three smaller items for completeness.** (i) `usages/parsed_tree.rs:9–19`'s `js_ts_tree_sitter_language_for_file` is a JS/TS-named free function in a framework file, called at eight sites in six moving files, **not allowlisted and structurally invisible to the reach-in gate** (which matches module segments and `<Lang><Suffix>` type idents, never free-function names) — the same class of blindness the C++ census recorded for the searchtools identity block; the crate-side replacement is ~15 LOC over core's `LanguageDialect::for_path`, and `js_ts_graph/resolver.rs:681` already has half of it. (ii) `TypeScriptDeclarationPackProducer` is `pub` at `analyzer/mod.rs:141` with **zero consumers outside its own file** — not `bifrost-semantic-packs`, not `lib.rs`, not `tests/`, not even `js_ts_dependency_semantic_pack.rs`; it is the `summary.rs` class, and "do nothing" is defensible because unlike the JVM producers no downstream crate imports it, so the park changes nothing in the publication DAG. (iii) JS/TS holds the last two `.scm` directories in `bifrost-analysis/resources/` and the last six entries in `EMBEDDED_QUERIES` (`store/epoch.rs:172–203`, whose other eight languages are now comment stubs), so this extraction is the one that deletes `resources/treesitter/` and empties that table.

---

## Schedule risk: upstream churn

`origin/master` commits touching each language's seam in the last seven days:

| cpp | rust | jvm | js_ts | python | csharp | go | ruby | php |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 81 | 55 | 53 | **27** | 27 | 26 | 24 | 21 | 17 |

js_ts sits in the fleet's low band — a third of C++'s and half the JVM's. Four-week churn concentrates in the two declaration walks, not the graph: `typescript/mod.rs` 13 commits (last 2026-08-06), `javascript/mod.rs` 13 (2026-08-06), `js_ts/structural.rs` 7 (2026-08-05), `js_ts/syntax.rs` 5 (2026-08-04), `js_ts/external.rs` 5 (2026-08-04, **parked**), `get_definition/js_ts.rs` 5 (2026-08-01, **parked**), `js_ts_graph/extractor.rs` 4 (2026-08-02), `js_ts/model.rs` 3 (2026-08-05), `js_ts_graph/{receiver_analysis,inverted}.rs` 3 each (2026-08-02).

Two facts shape the schedule. First, **the hottest files are the two declaration walks, which are also the cleanest (a)-class movers** — 3,527 LOC of free functions with no analyzer coupling, so they can be lifted in a single low-risk pass but must not be held across days. The brief's note that upstream nlp-ft work touches js_ts semantic actively is consistent with `js_ts/semantic/control.rs` (2 commits, 2026-08-01) sitting in the parked band, where it never has to be held at all. Second, the graph band (6,743 LOC, 10 commits in four weeks across five files) is a single body that must move together and is gated on three independent lowerings (§3.1, §3.3, §3.5); those are cheap in LOC but sequential.

Lowest-churn seam files, safe to move first: `js_ts_graph.rs` (1 commit, 2026-07-29), `js_ts/providers.rs` (1, 2026-07-29), `js_ts/cache.rs` (1, 2026-07-29), `js_ts/{clones,identifiers}.rs` (0 in four weeks), `js_ts_graph/hits.rs`, `js_ts/hierarchy.rs` (2), `js_ts/tsconfig.rs` (2), `js_ts/imports.rs` (2).