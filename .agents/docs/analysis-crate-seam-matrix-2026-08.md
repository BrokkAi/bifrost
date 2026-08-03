# brokk-bifrost-analysis vertical split: seam matrix (stage 1)

Directional reference inventory of `crates/bifrost-analysis/src`, measured at commit `abf5b803`. Reports what the code does today; no design recommendations. The closing VERDICT classifies each language unit and stops there.

## 1. Method

### 1.1 Extraction

A Python extractor walks all 510 `.rs` files under `crates/bifrost-analysis/src` and produces one record per cross-unit reference.

1. Comments, string literals and raw strings are blanked (newline-preserving) so `crate::` paths inside doc comments and test fixture source strings are not counted.
2. A module tree is built from the filesystem (`analyzer/rust/mod.rs` -> `analyzer::rust`, `analyzer/usages/rust_graph.rs` -> `analyzer::usages::rust_graph`).
3. Every `use` statement is parsed, including `pub` / `pub(crate)` / `pub(in ...)` forms, nested brace groups and `as` aliases; each leaf is expanded to a full path. Prefixes `crate::`, `self::` and `super::`(xN) are resolved to absolute module paths. Bare prefixes (external crates) are dropped.
4. `use` statements are then blanked out of the file and the remainder scanned for path *expressions* (`crate::a::b::c`, `super::...`) in code bodies. Both kinds counted; each record carries `how = use | path`.
5. **Re-export chasing.** `analyzer/mod.rs` re-exports a large amount of language-owned code (`pub use rust::{...}` at `analyzer/mod.rs:183`, `pub use kotlin::KotlinAnalyzer` at `analyzer/mod.rs:136`). A naive extractor attributes `crate::analyzer::RustAnalyzer` to the analyzer root. The extractor builds a re-export table from every `pub use` / `pub(crate) use` in the crate and follows it transitively, so `crate::analyzer::RustAnalyzer` resolves to `analyzer::rust::RustAnalyzer` (LANG.rust). Load-bearing: without it, roughly 150 language references disappear into CORE.
6. Each resolved path is split into longest known module prefix plus item name, and classified against a definition index built from `pub? (struct|enum|trait|type|fn|const|static|mod)` and `macro_rules!` declarations, giving kind, visibility and definition file:line.

Totals: **7829 cross-unit references**, 7654 from production files and 175 from files named `tests.rs` / `*benchmark.rs`.

### 1.2 Hand-verification

**Check A: `analyzer/usages/rust_graph.rs` lines 1-22.** Reading the header by eye gives 19 cross-unit imports: 1 from `usages::common`, 2 from `usages::inverted_edges`, 3 from `usages::model`, 2 from `usages::outcome`, 4 from `usages::traits`, 5 from `crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, resolve_analyzer}`, 1 re-exported language item (`RustAnalyzer`), 1 from `crate::hash`. The imports from `rust_graph::extractor` and `rust_graph::resolver` are intra-unit and must not appear. The extractor emitted exactly those 19 records with exactly that bucketing, resolving `analyzer::RustAnalyzer` to `analyzer::rust::RustAnalyzer` (LANG.rust, def `analyzer/rust/mod.rs:67`) and `CodeUnit` to `analyzer::model` (def `analyzer/model.rs:1868`). No spurious intra-unit records.

**Check B: `code_quality/dead_code_smells.rs`.** Hand-reading lines 7-20 gives 32 imports; `grep -n 'crate::'` gives a further 30 body-path lines. The extractor emitted 32 `use` records for lines 7-20 and matched every hand-identified body path, including ones a use-only extractor would miss: `crate::analyzer::usages::scala_graph::ScalaDeadCodeBulkContext` at line 148, `crate::analyzer::usages::rust_graph::build_rust_usage_edges` at 906, `crate::analyzer::usages::inverted_edges::MAX_CALLSITES` at 927, `crate::analyzer::usages::cpp_graph::is_cpp_global_main` at 2241. It correctly resolved the re-export chain `crate::analyzer::usages::JsTsScopedNodeStatus` (line 10) to `analyzer::usages::js_ts_graph::inverted` (def `analyzer/usages/js_ts_graph/inverted.rs:138`), and `use crate::analyzer::ProjectFile` at line 588 inside a nested test module.

Two apparent glob-import hits found by grep, `analyzer/rust/diagnostics.rs:965` and `searchtools/tests.rs:1069`, were checked and are inside `r#"..."#` test fixtures; the stripper blanks both correctly. Not real references.

### 1.3 Known extraction limits

- **`use super::*` prelude globs (62 files).** Named items reached through a glob are not counted. The important case: `analyzer/usages/get_definition/<lang>.rs`, all eleven of which begin with `use super::*;` (e.g. `analyzer/usages/get_definition/cpp.rs:1`). Their per-language graph imports are attributed to the block in `analyzer/usages/get_definition/mod.rs` that writes them, not the child that consumes them. §5.2 handles this; it changes the interpretation of 89 references, not their existence.
- **`use crate::analyzer::semantic::*` (11 language lowerers)**: `analyzer/rust/semantic.rs:16`, `analyzer/java/semantic/mod.rs:15`, `analyzer/kotlin/semantic/mod.rs:46`, `analyzer/js_ts/semantic/mod.rs:14`, `analyzer/scala/semantic.rs:11`, `analyzer/python/semantic.rs:19`, `analyzer/go/semantic.rs:15`, `analyzer/cpp/semantic.rs:14`, `analyzer/csharp/semantic.rs:15`, `analyzer/ruby/semantic.rs:18`, `analyzer/php/semantic.rs:15`. `analyzer/semantic/mod.rs:67-77` re-exports nine whole modules through that glob (`capabilities::*`, `icfg::*`, `ids::*`, `ir::*`, `oracle::*`, `provider::*`, `render::*`, `workspace_oracle::*`, plus `pub(crate) inventory::*` and `pub(crate) lowering::*`). LANG -> SEM.semantic counts are a floor, not a ceiling.
- **Module-alias imports.** `use crate::analyzer::usages;` then `usages::foo()` counts once. Rare here; dominant style is fully-qualified leaf imports.
- Test code inside `#[cfg(test)] mod tests` in production files counts as production. Only whole `tests.rs` / `*benchmark.rs` files are classified as test.

## 2. Unit definitions

49 prospective units. Language-adjacent:

| unit | contents |
| --- | --- |
| `LANG.<x>` | `analyzer/<x>/` for rust, java, kotlin, scala, jvm, python, go, cpp, csharp, ruby, php; `LANG.js_ts` merges `analyzer/js_ts/`, `analyzer/javascript/`, `analyzer/typescript/`. Includes each language's `semantic*` lowerer, which lives inside the language directory. |
| `UGRAPH.<x>` | `analyzer/usages/<x>_graph{.rs,/}`, `analyzer/usages/get_definition/<x>.rs`, `analyzer/usages/get_type/<x>.rs`; `analyzer/usages/cpp_call_match.rs` counts as UGRAPH.cpp |
| `USAGES.fw` | everything else under `analyzer/usages/`: finder, candidates, traits, model, outcome, common, inverted_edges, receiver_query, receiver_analysis, receiver_sites, reference_site, local_inference, call_relations, graph_core, parsed_tree, same_owner, reexport_seeds, target_kind, workspace_graph, workspace_graph_cache, get_definition/mod.rs, get_definition/call_sites.rs, get_definition/resolution_session.rs, get_type/mod.rs |

Core/other: `CORE.analyzer_root` (analyzer/*.rs), `CORE.store`, `CORE.util` (cancellation, path_*, text_utils, hash, compact_graph, profiling, schema_version, util), `CORE.cachedb` (cache_db, cache_gc, gitblob, git_file), `CORE.metrics` (clone_detection, cognitive_complexity, comment_density, exception_handling, test_assertions), `STRUCT.spec` (structural/spec.rs + kinds.rs), `STRUCT.query` (structural/query/), `STRUCT.engine` (rest), `SEM.semantic`, `SEM.semantic_model`, `SEM.dataflow`, `SEM.typestate`, `SEM.taint`, `SEM.value_flow`, `SEM.semantic_diagnostics`, and query-surface units `QS.searchtools`, `QS.code_quality`, `QS.diff_analysis`, `QS.relevance`, `QS.symbol_rename`, `QS.summary`, `QS.workspace_document`, `QS.sexp`, `QS.misc`.

`analyzer/value_flow/` is not in the brief's SEMANTIC list; reported separately as `SEM.value_flow` for you to place.

## 3. Rollup tables

### 3.1 Per-unit totals (all 7829 references)

| unit | out | in |
| --- | ---: | ---: |
| CORE.analyzer_root | 273 | 2760 |
| CORE.cachedb | 1 | 54 |
| CORE.metrics | 47 | 88 |
| CORE.store | 90 | 93 |
| CORE.util | 20 | 745 |
| CRATE_ROOT | 0 | 252 |
| LANG.cpp | 149 | 51 |
| LANG.csharp | 205 | 60 |
| LANG.go | 248 | 34 |
| LANG.java | 147 | 40 |
| LANG.js_ts | 359 | 99 |
| LANG.jvm | 327 | 14 |
| LANG.kotlin | 186 | 81 |
| LANG.php | 132 | 43 |
| LANG.python | 229 | 30 |
| LANG.ruby | 271 | 40 |
| LANG.rust | 391 | 66 |
| LANG.scala | 204 | 88 |
| QS.code_quality | 132 | 0 |
| QS.diff_analysis | 18 | 0 |
| QS.misc | 18 | 9 |
| QS.relevance | 110 | 11 |
| QS.searchtools | 257 | 6 |
| QS.sexp | 0 | 8 |
| QS.summary | 5 | 0 |
| QS.symbol_rename | 23 | 6 |
| QS.workspace_document | 0 | 1 |
| SEM.dataflow | 159 | 215 |
| SEM.semantic | 222 | 586 |
| SEM.semantic_diagnostics | 4 | 25 |
| SEM.semantic_model | 108 | 708 |
| SEM.taint | 120 | 5 |
| SEM.typestate | 172 | 41 |
| SEM.value_flow | 93 | 44 |
| STRUCT.engine | 511 | 131 |
| STRUCT.query | 72 | 54 |
| STRUCT.spec | 5 | 97 |
| UGRAPH.cpp | 311 | 35 |
| UGRAPH.csharp | 217 | 23 |
| UGRAPH.go | 133 | 16 |
| UGRAPH.java | 170 | 15 |
| UGRAPH.js_ts | 230 | 26 |
| UGRAPH.kotlin | 184 | 9 |
| UGRAPH.php | 165 | 10 |
| UGRAPH.python | 124 | 14 |
| UGRAPH.ruby | 131 | 28 |
| UGRAPH.rust | 181 | 9 |
| UGRAPH.scala | 251 | 48 |
| USAGES.fw | 424 | 1011 |

Shape: language and language-graph units are strongly *outbound*. Largest inbound sits on CORE.analyzer_root (2760), USAGES.fw (1011), CORE.util (745), SEM.semantic_model (708), SEM.semantic (586) — all shared infrastructure. No language unit receives more than 99 references from the whole rest of the crate.

### 3.2 Secondary rollup: merged JVM realm and merged JS/TS, production files only

`JVM-realm` = LANG.java + LANG.kotlin + LANG.scala + LANG.jvm + UGRAPH.{java,kotlin,scala}. `LANG.<x>` folds `UGRAPH.<x>` into `LANG.<x>`. Intra-unit references vanish.

| merged unit | in | inbound breakdown |
| --- | ---: | --- |
| JVM-realm | 85 | USAGES.fw=38, CORE.analyzer_root=19, QS.code_quality=12, CORE.store=9, QS.searchtools=5, STRUCT.engine=1, QS.relevance=1 |
| LANG.cpp | 57 | USAGES.fw=37, QS.searchtools=11, CORE.analyzer_root=4, QS.code_quality=4, CORE.store=1 |
| LANG.js_ts | 57 | USAGES.fw=23, CORE.analyzer_root=8, JVM-realm=8, QS.code_quality=4, LANG.cpp=2, LANG.php=2, SEM.semantic=2, LANG.csharp=1, LANG.go=1, LANG.python=1, LANG.ruby=1, LANG.rust=1, CORE.store=1, STRUCT.engine=1, QS.searchtools=1 |
| LANG.ruby | 36 | USAGES.fw=26, CORE.analyzer_root=5, QS.code_quality=2, CORE.store=1, STRUCT.engine=1, QS.searchtools=1 |
| LANG.csharp | 34 | USAGES.fw=24, CORE.analyzer_root=7, QS.code_quality=2, QS.searchtools=1 |
| LANG.python | 30 | USAGES.fw=17, CORE.analyzer_root=6, CORE.store=2, STRUCT.engine=2, QS.code_quality=1, QS.relevance=1, QS.searchtools=1 |
| LANG.go | 25 | USAGES.fw=13, CORE.analyzer_root=5, QS.searchtools=4, QS.code_quality=2, CORE.store=1 |
| LANG.rust | 24 | USAGES.fw=9, CORE.analyzer_root=7, QS.code_quality=5, QS.searchtools=2, QS.relevance=1 |
| LANG.php | 22 | USAGES.fw=12, QS.code_quality=4, CORE.analyzer_root=3, CORE.store=1, STRUCT.engine=1, QS.searchtools=1 |

`LANG.js_ts` is the only merged unit receiving references from other *language* units (11 of 57). Every one is to `analyzer::js_ts::cache` — see §5.3.

### 3.3 Largest cross-unit pairs

| n | pair |
| ---: | --- |
| 222 | LANG.js_ts -> CORE.analyzer_root |
| 213 | LANG.jvm -> SEM.semantic_model |
| 178 | LANG.rust -> CORE.analyzer_root |
| 160 | SEM.semantic -> CORE.analyzer_root |
| 148 | UGRAPH.cpp -> CORE.analyzer_root |
| 138 | SEM.dataflow -> SEM.semantic |
| 135 | LANG.go -> CORE.analyzer_root |
| 134 | USAGES.fw -> CORE.analyzer_root |
| 129 | LANG.kotlin -> CORE.analyzer_root |
| 124 | LANG.scala -> CORE.analyzer_root |
| 120 | UGRAPH.cpp -> USAGES.fw |
| 117 | STRUCT.engine -> CORE.analyzer_root |
| 107 | LANG.ruby -> CORE.analyzer_root |
| 105 | LANG.ruby -> SEM.semantic_model |
| 104 | UGRAPH.csharp -> USAGES.fw |
| 102 | UGRAPH.js_ts -> USAGES.fw |

## 4. Design-critical pairs

### 4.1 Each language -> usages framework; usages framework -> each language

`UGRAPH.<x> -> USAGES.fw` is the dominant language-side dependency: cpp=120, csharp=104, js_ts=102, scala=77, php=74, java=72, python=60, go=58, kotlin=54, rust=50. All downward references into framework types and strategy traits. Representative, from `analyzer/usages/rust_graph.rs:6-18`:

- **traits**: `analyzer::usages::traits::UsageAnalyzer` [pub, `analyzer/usages/traits.rs:64`], `UsageEdgeResolver` [pub(crate), `analyzer/usages/traits.rs:107`], `UsageQueryResolver` [pub(crate), `analyzer/usages/traits.rs:92`]
- **types**: `UsageScanScope` [pub(crate), `analyzer/usages/traits.rs:14`], `UsageEdges` [pub(crate), `analyzer/usages/inverted_edges.rs:388`], `UsageEdgeWeights` [pub(crate), `analyzer/usages/inverted_edges.rs:425`], `UsageHitSurface` [pub, `analyzer/usages/model.rs:46`], `ReferenceGraphResult` [pub, `analyzer/usages/model.rs:273`], `FuzzyResult` [pub, `analyzer/usages/model.rs:291`], `GraphUsageOutcome` [pub, `analyzer/usages/outcome.rs:3`], `GraphFailureReason` [pub(crate), `analyzer/usages/outcome.rs:55`]
- **functions**: `analyzer::usages::common::language_for_target` [pub(crate), `analyzer/usages/common.rs:21`]

The reverse direction is the interesting one. **`USAGES.fw -> LANG.<x>` is only 3-9 references per language (53 total); `USAGES.fw -> UGRAPH.<x>` is 146.**

Analyzer handles only (concrete-type downcast lists, one line each): `analyzer/usages/receiver_query.rs:47` names all twelve analyzer structs; `analyzer/usages/get_definition/mod.rs:78` names nine; `analyzer/usages/workspace_graph.rs:546` names Java/Kotlin/ScalaAnalyzer; `analyzer/usages/finder.rs:17` names PhpAnalyzer; `analyzer/usages/finder.rs:638` calls `RustAnalyzer::from_project`; `analyzer/usages/call_relations.rs:1400` names TypescriptAnalyzer and PythonAnalyzer.

Genuine per-language *helper* reach-ins by the framework (the non-handle residue):

| target | kind/vis | def | consumed at |
| --- | --- | --- | --- |
| `analyzer::cpp::identity::cpp_callable_definitions_share_identity_evidence` | fn pub(crate) | `analyzer/cpp/identity.rs:91` | `analyzer/usages/candidates.rs:6` |
| `analyzer::cpp::imports::include_paths` | fn pub(crate) | `analyzer/cpp/imports.rs:352` | `analyzer/usages/get_definition/mod.rs:78` |
| `analyzer::cpp::imports::resolve_include_targets` | fn pub(crate) | `analyzer/cpp/imports.rs:269` | `analyzer/usages/get_definition/mod.rs:78` |
| `analyzer::cpp::declarations::node_text` | fn | `analyzer/cpp/declarations.rs` | `analyzer/usages/get_definition/mod.rs:78` |
| `analyzer::csharp::csharp_callable_arity` | fn pub(crate) | `analyzer/csharp/mod.rs:1742` | `analyzer/usages/get_definition/mod.rs:78` |
| `analyzer::csharp::structural::CSHARP_STRUCTURAL_SPEC` | static pub(crate) | `analyzer/csharp/structural.rs:14` | `analyzer/usages/receiver_sites.rs:362` |
| `analyzer::js_ts::syntax::JsTsImportBinder` | struct pub(crate) | `analyzer/js_ts/syntax.rs:23` | `analyzer/usages/get_definition/mod.rs:2`, `analyzer/usages/receiver_query.rs:128` |
| `analyzer::js_ts::syntax::compute_import_binder` | fn pub(crate) | `analyzer/js_ts/syntax.rs:630` | `analyzer/usages/get_definition/mod.rs:34`, `analyzer/usages/receiver_query.rs:36` |
| `analyzer::js_ts::tsconfig::AliasResolver` | struct pub(crate) | `analyzer/js_ts/tsconfig.rs:41` | `analyzer/usages/get_definition/mod.rs:78` |
| `analyzer::kotlin::syntax::kotlin_callee` | fn pub(crate) | `analyzer/kotlin/syntax.rs:53` | `analyzer/usages/get_definition/call_sites.rs:419`, `analyzer/usages/receiver_query.rs:3013` |
| `analyzer::kotlin::syntax::kotlin_value_arguments` | fn pub(crate) | `analyzer/kotlin/syntax.rs:71` | `analyzer/usages/get_definition/call_sites.rs:438` |
| `analyzer::kotlin::syntax::kotlin_navigation_member` | fn pub(crate) | `analyzer/kotlin/syntax.rs:136` | `analyzer/usages/receiver_query.rs:3016` |
| `analyzer::php::aliases::PhpFileContext` | struct pub | `analyzer/php/aliases.rs:28` | `analyzer/usages/get_definition/mod.rs:42` |
| `analyzer::php::aliases::resolve_php_type` | fn pub | `analyzer/php/aliases.rs:559` | `analyzer/usages/get_definition/mod.rs:42` |
| `analyzer::php::aliases::resolve_php_function` | fn pub(crate) | `analyzer/php/aliases.rs:589` | `analyzer/usages/get_definition/mod.rs:42` |
| `analyzer::php::aliases::resolve_php_constant` | fn pub(crate) | `analyzer/php/aliases.rs:600` | `analyzer/usages/get_definition/mod.rs:42` |
| `analyzer::python::usage_index::ModuleBindingTimeline` | type pub(crate) | `analyzer/python/usage_index.rs:41` | `analyzer/usages/get_definition/mod.rs:78` |
| `analyzer::python::usage_index::ModuleBindingEventKind` | enum pub(crate) | `analyzer/python/usage_index.rs:51` | `analyzer/usages/get_definition/mod.rs:78` |
| `analyzer::ruby::declarations::parse_ruby_tree` | fn pub(crate) | `analyzer/ruby/declarations.rs:40` | `analyzer/usages/get_definition/mod.rs:1400` |
| `analyzer::ruby::structural::RUBY_STRUCTURAL_SPEC` | static pub(crate) | `analyzer/ruby/structural.rs:15` | `analyzer/usages/get_definition/call_sites.rs:1060` |

Go, Java, Rust and Scala have **zero** framework reach-ins beyond the analyzer handle.

Two further framework-to-language-graph calls sit outside the dispatch tables, running from the shared candidate layer into per-language modules: `analyzer/usages/candidates.rs:652` calls `python_graph::python_usage_candidate_files`, `analyzer/usages/candidates.rs:657` calls `rust_graph::rust_usage_candidate_files`. PHP has an analogous case in the finder at `analyzer/usages/finder.rs:367,384,402` (`add_php_composer_candidates`, `add_php_import_alias_candidates`), reaching into `PhpAnalyzer` directly.

### 4.2 Each language's graph module -> that language

Uniformly same-language and modest. No graph module references a language other than its own, with one exception.

| pair | refs | distinct items |
| --- | ---: | ---: |
| UGRAPH.scala -> LANG.scala | 62 | 29 |
| UGRAPH.js_ts -> LANG.js_ts | 58 | 23 |
| UGRAPH.kotlin -> LANG.kotlin | 58 | 24 |
| UGRAPH.csharp -> LANG.csharp | 48 | 24 |
| UGRAPH.rust -> LANG.rust | 47 | 17 |
| UGRAPH.php -> LANG.php | 30 | 10 |
| UGRAPH.cpp -> LANG.cpp | 28 | 17 |
| UGRAPH.ruby -> LANG.ruby | 28 | 12 |
| UGRAPH.go -> LANG.go | 22 | 10 |
| UGRAPH.python -> LANG.python | 12 | 8 |
| UGRAPH.java -> LANG.java | 7 | 2 |

Representative, UGRAPH.rust -> LANG.rust: `analyzer::rust::RustAnalyzer` [struct pub, `analyzer/rust/mod.rs:67`], `analyzer::rust::graph_support::RustReferenceContext` [struct pub, `analyzer/rust/graph_support.rs:35`], `analyzer::rust::usage_index::RustReferenceNamespace` [enum pub(crate), `analyzer/rust/usage_index.rs:77`], `analyzer::rust::declarations::rust_package_name` [fn pub(crate), `analyzer/rust/declarations.rs:225`], `analyzer::rust::imports::rust_focused_use_path` [fn pub(crate), `analyzer/rust/imports.rs:172`], `analyzer::rust::imports::resolve_rust_import_package_scoped` [fn pub(crate), `analyzer/rust/imports.rs:642`], `analyzer::rust::imports::resolve_rust_module_segments_with_crate` [fn pub(crate), `analyzer/rust/imports.rs:662`].

Exception: `UGRAPH.java -> LANG.scala` (2 refs), from `analyzer/usages/java_graph/jvm_scala.rs`. See §5.4.

### 4.3 The framework's hardcoded per-language dispatch tables

**`analyzer/usages/finder.rs:726-811`** — `graph_find_usages(language: Language, ...)`, a 12-arm `match language` (11 languages + `Language::None`). Each arm constructs `&<Lang>UsageGraphStrategy::new()` and hands it to `graph_strategy_find_usages(strategy: &dyn GraphUsageAnalyzer, ...)` at `analyzer/usages/finder.rs:709-717`. Strategy structs imported at `analyzer/usages/finder.rs:3-15`: `CppUsageGraphStrategy` (`analyzer/usages/cpp_graph.rs:118`), `CSharpUsageGraphStrategy` (`csharp_graph.rs:68`), `GoUsageGraphStrategy` (`go_graph.rs:146`), `JavaUsageGraphStrategy` (`java_graph.rs:141`), `JsTsExportUsageGraphStrategy` (`js_ts_graph.rs:442`), `KotlinUsageGraphStrategy` (`kotlin_graph.rs:98`), `PhpUsageGraphStrategy` (`php_graph.rs:78`), `PythonExportUsageGraphStrategy` (`python_graph.rs:226`), `RubyUsageGraphStrategy` (`ruby_graph.rs:62`), `RustExportUsageGraphStrategy` (`rust_graph.rs:241`), `ScalaUsageGraphStrategy` (`scala_graph.rs:150`). All `pub`.

**`analyzer/usages/workspace_graph.rs:352-491`** — the edge path. Does *not* use the strategy traits; a `macro_rules! record_package_edges` (`analyzer/usages/workspace_graph.rs:352-373`) is instantiated ten times against free `pub(crate) fn`s at lines 378 (go), 383 (python), 388 (rust), 400 (java), 405 (scala), 410 (kotlin), 415 (csharp), 420 (cpp), 425 (php), 430 (ruby). JS/TS is hand-written at `analyzer/usages/workspace_graph.rs:434-491`, calling `js_ts_graph::build_jsts_scoped_usage_edges` (`analyzer/usages/js_ts_graph.rs:371`).

**`analyzer/usages/receiver_query.rs:16`** — eleven `resolve_<lang>_bounded` functions plus `get_definition::java::{JavaResolutionSession, BoundedJavaResolution}` and `get_definition::js_ts::parse_js_ts_tree`, all `pub(crate)`. Dispatched at `analyzer/usages/receiver_query.rs:2061`.

**`analyzer/usages/receiver_query.rs:25`** — eleven `resolve_<lang>_type_bounded` functions from `analyzer::usages::get_type::<lang>`, all `pub(crate)`. Dispatched at `analyzer/usages/receiver_query.rs:2018`.

Additionally `analyzer/usages/receiver_query.rs:31,36` reach into `analyzer::usages::js_ts_graph::receiver_analysis` for six items declared `pub(in crate::analyzer::usages)` — `JsTsReceiverSyntaxIndex`, `JsTsReceiverSyntaxIndexBuild`, `build_js_ts_receiver_syntax_index_bounded`, `member_expression_at_site`, `node_range`, `smallest_named_node_covering` — plus `JsTsReceiverFactProvider` [pub(crate)]. JS/TS is the only language whose receiver analysis is reached this way.

Further hardcoded `match language` sites: `analyzer/usages/parsed_tree.rs:16`, `analyzer/usages/receiver_query.rs:2097` (unsupported-reason), `:2143` (`signature_metadata_limited` per-analyzer downcast), `:2883` (`ranges_limited`), `:2953` (`structural_factory_name_node`), `analyzer/usages/workspace_graph.rs:38` (`UsageEcosystem::of`), `:57` (`as_str`), `:124` (`language_label`). Non-`match` language special-casing: `analyzer/usages/candidates.rs:124` (Python), `:128` (Ruby), `:167,177` (C++), `:336-348` (`add_cross_language_jvm_candidates`), `:418-425` (JS/TS), `:493-504`, `:563-580` (Python/JS/TS/Scala), `:589` (Scala companion), and `analyzer/usages/call_relations.rs:1244,1268` (Python).

### 4.4 Language -> semantic engine, and semantic engine -> language

| unit | SEM.semantic_model | SEM.semantic | SEM.semantic_diagnostics |
| --- | ---: | ---: | ---: |
| LANG.jvm | 213 | 0 | 0 |
| LANG.ruby | 105 | 10 | 2 |
| LANG.rust | 92 | 10 | 4 |
| LANG.csharp | 67 | 9 | 0 |
| LANG.go | 57 | 8 | 5 |
| LANG.python | 53 | 9 | 5 |
| LANG.js_ts | 49 | 11 | 2 |
| LANG.java | 0 | 9 | 0 |
| LANG.kotlin | 0 | 9 | 1 |
| LANG.scala | 0 | 9 | 2 |
| LANG.cpp | 0 | 7 | 2 |
| LANG.php | 0 | 9 | 2 |

The `LANG.* -> SEM.semantic` column is remarkably uniform — every language imports the same small named set on top of the glob, which is the lowering SPI:

- **traits**: `analyzer::semantic::service::ProgramSemanticsLowerer` (11), `analyzer::semantic::service::SemanticAdapterIdentity` (11)
- **types**: `analyzer::semantic::cfg::ProcedureCfgBuilder` (11), `cfg::CompletionKind` (11), `cfg::CompletionRequest` (11), `cfg::ScopeBinding` (11), `cfg::ScopeFrameId` (11), `cfg::CompletionRoute` (10), `cfg::CleanupRegionId` (9)
- **functions**: `analyzer::semantic::lowering::formal_multiplicity` (2)
- **macros**: `analyzer::semantic::impl_program_semantics_provider` — `macro_rules!` defined at `analyzer/semantic/mod.rs:14`, re-exported `pub(crate) use impl_program_semantics_provider;` at `analyzer/semantic/mod.rs:51`. Invoked from `analyzer/rust/semantic.rs:25`, `analyzer/java/semantic/mod.rs:24`, `analyzer/kotlin/semantic/mod.rs:58`, `analyzer/scala/semantic.rs:22`, `analyzer/go/semantic.rs:24`, `analyzer/ruby/semantic.rs:26`, `analyzer/php/semantic.rs:24`, `analyzer/typescript/semantic.rs:7`. **The only macro crossing a prospective boundary.**

The `SEM.semantic_model` column splits languages cleanly: seven that produce dependency/semantic packs pull heavily (79 distinct items, headed by `semantic_model::producer::ArtifactProducerLimits`, `semantic_model::catalog::MemberFact`, `producer::ProducerDiagnostic`, `catalog::DependencyPackLimits`, `producer::ExternalArtifactKind`); five (java, kotlin, scala, cpp, php) pull nothing — for the JVM three because `LANG.jvm` owns all of it.

**Semantic engine -> language is 2 references total**, both in one file: `analyzer/semantic/service.rs:707` -> `analyzer::typescript::TypescriptAdapter` [struct pub, `analyzer/typescript/mod.rs:50`], and `analyzer/semantic/service.rs:1235` -> `analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript` [`analyzer/js_ts/semantic/mod.rs:60`]. The engine is otherwise language-blind.

### 4.5 Usages framework <-> semantic

Small, `pub` in both directions.

`USAGES.fw -> SEM.*` (20 refs, all from `analyzer/usages/receiver_query.rs`, mostly the import block at line 4): `analyzer::semantic::capabilities::{WorkspaceSemanticOracle` (`analyzer/semantic/workspace_oracle.rs:27`), `SemanticRequest` (`analyzer/semantic/provider.rs:577`), `SemanticOutcome` (`:454`), `SemanticProviderError` (`:635`), `SemanticBudget` (`:72`), `SemanticBudgetDimension` (`:16`), `SemanticBudgetExceeded` (`:100`), `SemanticWork` (`:20`), `SemanticCapability` (`analyzer/semantic/capabilities.rs:10`), `OracleLimits` (`analyzer/semantic/oracle/limits.rs:71`), `OracleLimitValues` (`:4`), `AbstractObjectIdentity` (`analyzer/semantic/oracle/model.rs:765`), `CallResultHandle` (`:290`), `CandidateCoverage` (`analyzer/semantic/oracle/relation.rs:475`), `SourcePointsToResult` (`analyzer/semantic/workspace_oracle/source.rs:145`)`}` plus `ProcedurePortKind::{Receiver, Parameter}` at `analyzer/usages/receiver_query.rs:2313,2317,2666,3308`. All `pub`.

`SEM.* -> USAGES.fw` (8 refs, all from `analyzer/semantic/workspace_oracle/dispatch.rs:24-25`): `analyzer::usages::call_relations::{CallRelationService` (pub, `analyzer/usages/call_relations.rs:221`), `CallRelationLimits` (pub(crate), `:110`), `CallDispatchTarget` (pub(crate), `:59`), `CallDispatchBoundaryKind` (pub(crate), `:78`), `ExactCallLocation` (pub(crate), `:52`), `call_dispatch_equivalence_source` (pub(crate), `:70`)`}`, `analyzer::usages::model::UsageProof` (pub, `analyzer/usages/model.rs:39`), `analyzer::usages::get_definition::DefinitionLookupStatus` (pub, `analyzer/usages/get_definition/mod.rs:422`).

`UGRAPH.* -> SEM.*` is 9 refs, dominated by `analyzer/usages/get_definition/go.rs:63,70,84` using `analyzer::semantic_model::catalog::SemanticModelOverlay` (pub, `analyzer/semantic_model/overlay.rs:248`).

### 4.6 Structural: spec vs engine vs query

The spec/engine distinction is real and sharp.

`STRUCT.spec` receives 97 references. **Every one of the eleven language units imports exactly the same four items and nothing else:**

- `analyzer::structural::spec::StructuralSpec` [trait pub, `analyzer/structural/spec.rs:18`]
- `analyzer::structural::spec::RoleSink` [struct pub, `analyzer/structural/spec.rs:89`]
- `analyzer::structural::kinds::NormalizedKind` [enum pub, `analyzer/structural/kinds.rs:18`]
- `analyzer::structural::kinds::Role` [enum pub, `analyzer/structural/kinds.rs:124`]

(Kotlin shows 5 because it takes one item twice.) The remaining 44 come from STRUCT.engine (25), STRUCT.query (20), USAGES.fw (4), SEM.semantic_model (2), CORE.analyzer_root (1).

`STRUCT.engine` receives 131. The language share is 5-10 each, confined to two things: `analyzer::structural::adapter_helpers::{first_named_child` (`analyzer/structural/adapter_helpers.rs:13`), `attach_role_with_derived_name` (`:17`), `attach_positional_argument_roles` (`:54`), `attach_terminal_callee` (`:72`), `assert_kind_table_matches_grammar` (`:87`)`}` — all `pub(crate) fn` — and `analyzer::structural::provider::StructuralSearchProvider` [trait pub, `analyzer/structural/provider.rs:44`].

`STRUCT.query` receives 54 references and **all 54 come from STRUCT.engine**. No language, usages or semantic unit references the RQL query layer directly.

Structural engine -> language is 17 references, 11 of them in `analyzer/structural/search/tests.rs:4`. The four production ones: `analyzer/structural/execution/derived.rs:1155` (JavaAnalyzer, PhpAnalyzer, RubyAnalyzer), `analyzer/structural/extract.rs:218` -> `analyzer::python::structural::PYTHON_STRUCTURAL_SPEC` [static pub(crate), `analyzer/python/structural.rs:19`], `analyzer/structural/index.rs:1841` -> `PythonAnalyzer::from_project`, `analyzer/structural/provider.rs:511` -> `TypescriptAnalyzer`.

### 4.7 Every reference INTO a language unit from outside it

Sections 4.1-4.6 cover USAGES.fw, UGRAPH, SEM and STRUCT. The remainder:

**CORE.analyzer_root -> LANG.\*** (72 refs). Almost entirely the analyzer registry: each `*Analyzer` named in `analyzer/multi_analyzer.rs:3`, `analyzer/global_usage_definition_index.rs:2`, the `analyzer/mod.rs` re-export block, and each `*Adapter` at `analyzer/tree_sitter_analyzer.rs:8341-8347`. Non-registry residue:

| target | kind/vis | consumed at |
| --- | --- | --- |
| `analyzer::rust::field_roles::RustFieldNameRole` | enum pub(crate), `analyzer/rust/field_roles.rs:9` | `analyzer/lexical_definitions.rs:10` |
| `analyzer::rust::field_roles::classify_rust_field_name` | fn pub(crate), `analyzer/rust/field_roles.rs:22` | `analyzer/lexical_definitions.rs:10` |
| `analyzer::rust::adapter::RustAdapter` | struct pub(crate), `analyzer/rust/adapter.rs:24` | `analyzer/tree_sitter_analyzer.rs:8345` |
| `analyzer::cpp::declarations::is_direct_recovered_exported_class_field_declaration` | fn pub(crate), `analyzer/cpp/declarations.rs:900` | `analyzer/lexical_definitions.rs:624` |
| `analyzer::csharp::strip_csharp_generic_arity` | fn pub, `analyzer/csharp/mod.rs:1183` | `analyzer/common.rs:194`, `analyzer/symbol_lookup.rs:2` |
| `analyzer::csharp::csharp_normalize_full_name` | fn pub(crate), `analyzer/csharp/mod.rs:1151` | `analyzer/common.rs:139` |
| `analyzer::csharp::dependency_discovery::is_csharp_dependency_input` | fn pub(crate), `analyzer/csharp/dependency_discovery.rs:45` | `analyzer/multi_analyzer.rs:198` |
| `analyzer::kotlin::language::LANGUAGE` | const pub(crate), `analyzer/kotlin/language.rs:11` | `analyzer/lexical_definitions.rs:1252`, `analyzer/mod.rs:326` |
| `analyzer::scala::language::LANGUAGE` | const pub(crate), `analyzer/scala/language.rs:8` | `analyzer/mod.rs:323` |
| `analyzer::kotlin::diagnostics::collect_kotlin_semantic_diagnostics` | fn pub(crate), `analyzer/kotlin/diagnostics.rs:62` | `analyzer/multi_analyzer.rs:956` |
| `analyzer::ruby::ruby_semantic_identifier_range` | fn pub(crate), `analyzer/ruby/mod.rs:106` | `analyzer/declaration_range.rs:127` |
| `analyzer::ruby::imports::ruby_symbol_name` | fn | `analyzer/declaration_range.rs:231` |
| `analyzer::go::GO_MODULE_SCOPE_SEGMENT` | const pub(crate), `analyzer/go/mod.rs:41` | `analyzer/symbol_lookup.rs:4` |
| `analyzer::python::external::{PythonDependencyPackAdapter, resolve_python_semantic_pack_dependencies}` | pub, `analyzer/python/external.rs:29,976` | `analyzer/workspace.rs:8` |

**CORE.store -> LANG.\*** (16 refs): per-language `*Adapter` structs at `analyzer/store/mod.rs:7767-7775`; `analyzer::scala::imports::ScalaExportInfo` [struct pub(crate), `analyzer/scala/imports.rs:29`] at `analyzer/store/mod.rs:4603,5794,6459` (+2); `analyzer::scala::language::LANGUAGE` at `analyzer/store/epoch.rs:350` and `analyzer/store/mod.rs:8662` (+2); `analyzer::python::declarations::python_package_prefix_fq` [fn pub(crate), `analyzer/python/declarations.rs:38`] at `analyzer/store/mod.rs:27`.

**QS.searchtools -> LANG.\*** (26 refs). Largest block is C++ identity: `analyzer::cpp::identity::{CppOccurrenceClassifier` (struct pub(crate), `analyzer/cpp/identity.rs:34`), `CppOccurrenceRole::Definition` (`:16`), `CppCallableUnitRole` (`:8`), `cpp_callable_unit_role` (`:52`), `cpp_indexed_callable_linkage` (`:76`), `cpp_callable_definitions_share_identity_evidence` (`:91`)`}` at `searchtools/mod.rs:315,322,332` and `searchtools/selectors.rs:3,261,294,300`. Also `analyzer::go::{GO_MODULE_SCOPE_SEGMENT, packages::GoModuleRoot` (`analyzer/go/packages.rs:15`), `packages::go_module_roots` (`analyzer/go/packages.rs:138`)`}` at `searchtools/mod.rs:26`. Separately, `searchtools/scan_usages.rs:2476,2490,2504,2518,2537,2548,2559,2573,2587,2601,2615` is an eleven-way hardcoded sequence of direct `build_*_usage_edges` calls — a second copy of the `workspace_graph.rs` dispatch table.

**QS.code_quality -> LANG.rust** (5 refs): `RustAnalyzer` and `crate::analyzer::resolve_analyzer::<crate::analyzer::RustAnalyzer>` at `code_quality/dead_code_smells.rs:18,854,872`.

**QS.relevance -> LANG.\*** (3 refs): JavaAnalyzer, PythonAnalyzer, RustAnalyzer.

## 5. Specific questions

### 5.1 The #1239-era trait seams

Definitions in `analyzer/usages/traits.rs` (135 lines):

| line | item | visibility |
| ---: | --- | --- |
| 14 | `struct UsageScanScope<'a>` | `pub(crate)` |
| 64 | `trait UsageAnalyzer: Send + Sync` | `pub` |
| 75 | `trait GraphUsageAnalyzer: UsageAnalyzer` | `pub(crate)` |
| 92 | `trait UsageQueryResolver<'a>: Sized` | `pub(crate)` |
| 107 | `trait UsageEdgeResolver<'a>: Sized` | `pub(crate)` |
| 133 | `trait CandidateFileProvider: Send + Sync` | `pub` |

The module is private (`mod traits;` at `analyzer/usages/mod.rs:46`); only `CandidateFileProvider` and `UsageAnalyzer` are re-exported (`analyzer/usages/mod.rs:86`).

**`KotlinResolutionCtx`** — `analyzer/usages/kotlin_graph/resolver.rs:316`, visibility `pub(super)` (visible only inside `analyzer::usages::kotlin_graph`). Seven methods (`resolver.rs:317-339`): `analyzer`, `source`, `bindings`, `resolve_type_fqn`, `resolve_callable_fqn`, `enclosing_owner_fq_names`, `declared_type_cache`. Two impls, both Kotlin: `analyzer/usages/kotlin_graph/extractor.rs:116` (`for ScanCtx<'_>`, query path) and `analyzer/usages/kotlin_graph/inverted.rs:149` (`for KotlinEdgeScan<'_, '_>`, edge path). **The only genuinely polymorphic trait in the inventory**: free functions in `resolver.rs` take `ctx: &mut impl KotlinResolutionCtx` at lines 466, 491, 552, 574, 602, 645, 667, 755, 774, 793. Static generic dispatch, never `dyn`. Being `pub(super)`, it is invisible outside `kotlin_graph` — Kotlin-internal, not a cross-language seam.

**`UsageEdgeResolver<'a>`** (`analyzer/usages/traits.rs:107`, `pub(crate)`) — `try_new`, `build_edges`, `build_edge_weights`. Eleven impls: `analyzer/usages/python_graph.rs:190`, `rust_graph.rs:208`, `go_graph.rs:107`, `js_ts_graph.rs:277`, `java_graph/shared.rs:139`, `kotlin_graph/shared.rs:213`, `scala_graph/shared.rs:1067`, `csharp_graph/shared.rs:107`, `cpp_graph/shared.rs:257`, `php_graph/shared.rs:95`, `ruby_graph/shared.rs:13`. **Zero polymorphic use** — no generic function anywhere is bounded on it; every call is monomorphic inside the language's own module, immediately wrapped in a free `build_*` fn (`rust_graph.rs:50,62`, `python_graph.rs:40,63,78`, `go_graph.rs:44,56`, `js_ts_graph.rs:94`, `java_graph.rs:31,43`, `kotlin_graph.rs:80,93`, `scala_graph.rs:39,49,64`, `csharp_graph.rs:51,63`, `cpp_graph.rs:55,67`, `php_graph.rs:35,47`, `ruby_graph.rs:48,57`). A uniformity contract, not a dispatch mechanism.

**`UsageQueryResolver<'a>`** (`analyzer/usages/traits.rs:92`, `pub(crate)`) — `try_new`, `find_usages`. Its own doc comment states it is "used only as a static bound, never as `dyn`". **Ten impls; Ruby is missing.** `python_graph.rs:101`, `rust_graph.rs:90`, `go_graph.rs:64`, `js_ts_graph.rs:150`, `java_graph/shared.rs:24`, `kotlin_graph/shared.rs:37`, `scala_graph/shared.rs:917`, `csharp_graph/shared.rs:19`, `cpp_graph/shared.rs:121`, `php_graph/shared.rs:18`. `analyzer/usages/ruby_graph.rs:31` imports only `{UsageAnalyzer, UsageEdgeResolver, UsageScanScope}`, and `RubyUsageGraphStrategy::find_graph_usages` (`ruby_graph.rs:73-173`) inlines the whole query scan. Zero polymorphic use.

**`UsageAnalyzer`** (`analyzer/usages/traits.rs:64`, `pub`) — one method, `find_usages`. Eleven impls, all on the `*UsageGraphStrategy` structs: `js_ts_graph.rs:550`, `python_graph.rs:271`, `php_graph.rs:125`, `rust_graph.rs:315`, `java_graph.rs:188`, `kotlin_graph.rs:145`, `csharp_graph.rs:115`, `cpp_graph.rs:165`, `go_graph.rs:254`, `scala_graph.rs:197`, `ruby_graph.rs:176`. Every body is the same three lines. **Used as `dyn` in exactly one place, outside the usages subsystem**: `code_quality/dead_code_smells.rs:2387`, `fn graph_strategy_for(candidate: &CodeUnit) -> Option<Box<dyn UsageAnalyzer>>`, consumed at `dead_code_smells.rs:2375`. The main find-usages path in `finder.rs` does not go through it.

**`GraphUsageAnalyzer`** (`analyzer/usages/traits.rs:75`, `pub(crate)`) — implemented for all eleven strategies by `macro_rules! impl_graph_usage_analyzer` at `analyzer/usages/finder.rs:681-695`, applied at `finder.rs:697-707`; the macro just forwards to the inherent `find_graph_usages`. It *is* used as `dyn` at `analyzer/usages/finder.rs:710`, but only immediately after the hardcoded 12-arm `match language` at `finder.rs:726`, so the dynamic dispatch buys nothing structurally — it exists to collapse eleven arm bodies to one shape.

**`CandidateFileProvider`** (`analyzer/usages/traits.rs:133`, `pub`) — four production impls, all language-agnostic: `analyzer/usages/candidates.rs:38` (`ImportGraphCandidateProvider`), `:391` (`TextSearchCandidateProvider`), `:484` (`ExplicitCandidateProvider`), `:524` (`FallbackCandidateProvider<G, T>`; `default_provider` at `:632`). Genuinely used as `dyn` at `analyzer/usages/finder.rs:132,150,177` and externally at `searchtools/scan_usages.rs:2035`. The healthiest seam in the subsystem, but not per-language, so it does not help a per-language split.

Which languages flow through traits: on the **query path**, all eleven go through `match language` -> `*UsageGraphStrategy` -> `dyn GraphUsageAnalyzer` -> inherent `find_graph_usages`; ten then reach a `UsageQueryResolver` impl, Ruby does not. On the **edge path**, none go through a trait at all — ten via the `record_package_edges` macro, JS/TS hand-written, because `build_jsts_scoped_usage_edges` returns `JsTsScopedUsageEdges` keyed by `UsageNodeKey{file, fqn}` rather than by fqn string (see `analyzer/usages/workspace_graph.rs:52-54`) and structurally cannot satisfy `UsageEdgeResolver`.

**Four independently hand-maintained language lists exist today**: `analyzer/usages/finder.rs:726-811` (query, 11), `analyzer/usages/workspace_graph.rs:375-491` (edges, 10 + JS/TS special case), `searchtools/scan_usages.rs:2476-2615` (11), and `code_quality/dead_code_smells.rs:2387-2416` (**only 9** — C++ and Python are absent, handled separately at `dead_code_smells.rs:1136` and `:1004`).

### 5.2 `get_definition/mod.rs` is a shared per-language prelude, not a consumer

The biggest interpretation caveat in the report, and it cuts *in favour* of the split.

`analyzer/usages/get_definition/mod.rs` (2353 lines) opens with plain `use` blocks importing 89 items from the eleven per-language graph modules — 26 C++ at line 7, 16 C# at 18, 7 Go at 27, 4 JS/TS at 34, 5 PHP at 42, 7 Python at 46, 18 Ruby at 58, 9 Scala, 1 Java at 33. Nearly all declared `pub(in crate::analyzer::usages)`.

The real consumers are the per-language children. All eleven of `analyzer/usages/get_definition/{cpp,csharp,go,java,js_ts,kotlin,php,python,ruby,rust,scala}.rs` begin with `use super::*;` (e.g. `get_definition/cpp.rs:1`) and call the items unqualified. Confirmed by tracing one: `cpp_name_for` is imported at `get_definition/mod.rs:13` and used only in `get_definition/cpp.rs:2474,2966,3023,3747,4550,5901,5922,5925` (and inside `analyzer/cpp/hierarchy.rs:145`, its own language).

So 89 of the 146 `USAGES.fw -> UGRAPH.*` references are a prelude serving same-language children, not framework logic reaching into languages. The three genuinely cross-cutting framework files are `receiver_query.rs` (30), `finder.rs` (11) and `workspace_graph.rs` (11), per §4.3. Corollary: the `use super::*` glob also hides the true `get_definition/<lang>.rs -> <lang>_graph` volume, which is intra-language and does not cross a prospective boundary.

The `pub(in crate::analyzer::usages)` visibility class is worth flagging on its own: used extensively across the per-language graph modules, it cannot span a crate boundary. Every such item consumed from another prospective crate has to be re-declared wider.

### 5.3 Helpers shared informally across language units

The complete list of LANG -> LANG references outside the JVM realm is **17 references to four functions, all in one module**:

| function | kind/vis | def | importers |
| --- | --- | --- | --- |
| `analyzer::js_ts::cache::build_weighted_cache` | fn pub(crate) | `analyzer/js_ts/cache.rs:53` | 9: `analyzer/cpp/mod.rs:20`, `analyzer/csharp/cache.rs:7`, `analyzer/go/cache.rs:11`, `analyzer/kotlin/mod.rs:69`, `analyzer/php/mod.rs:15`, `analyzer/python/cache.rs`, `analyzer/ruby/cache.rs`, `analyzer/rust/cache.rs`, `analyzer/scala/mod.rs:18` |
| `analyzer::js_ts::cache::weight_code_unit_vec_by_unit` | fn pub(crate) | `analyzer/js_ts/cache.rs:97` | 4: `analyzer/cpp/mod.rs:20`, `analyzer/kotlin/mod.rs:69`, `analyzer/php/mod.rs:15`, +1 |
| `analyzer::js_ts::cache::weight_code_unit_set` | fn pub(crate) | `analyzer/js_ts/cache.rs:88` | 2: `analyzer/kotlin/mod.rs:69`, `analyzer/scala/mod.rs:18` |
| `analyzer::js_ts::cache::weight_project_file_set` | fn pub(crate) | `analyzer/js_ts/cache.rs:76` | 2: `analyzer/kotlin/mod.rs:69`, `analyzer/scala/mod.rs:18` |

`analyzer/js_ts/cache.rs` is a generic weighted-cache utility that happens to live in the JS/TS directory. Nothing else in the crate has a language importing another language's code outside the JVM realm. **The deliberateness tax for informally shared helpers is one module, four functions.**

Shared non-core modules that two or more languages import from are otherwise all genuinely shared infrastructure with a single obvious owner: `STRUCT.spec` (4 items, all 11), `structural::adapter_helpers` (5 fns, all 11), the `SEM.semantic` lowering SPI (~9 items plus one macro, all 11), `SEM.semantic_model` (7 languages), `analyzer::jvm` (JVM three only).

### 5.4 JVM realm coupling: confirmed, they must ship together

Bidirectional at the module-internal level; not severable by promoting a small set of items.

`LANG.jvm -> LANG.java` (19): `analyzer::java::imports::JavaTypeResolution::{External, Source}` [enum pub(crate), `analyzer/java/imports.rs:6`] at `analyzer/jvm/external.rs:3098,3627,3633,3637` (+2); `analyzer::java::declarations::{node_text` (`analyzer/java/declarations.rs:728`), `parse_tree` (`:736`), `determine_package_name` (`:29`), `normalize_java_full_name` (`:70`), `is_class_like_declaration_kind` (`:765`), `class_like_body_children_rev` (`:776`)`}` — all `pub(crate) fn` — at `analyzer/jvm/external.rs:1`, `analyzer/jvm/java_artifact.rs:2`, `analyzer/jvm/jdk_artifact.rs:6`; `JavaAnalyzer` at `analyzer/jvm/realm.rs:30`.

`LANG.jvm -> LANG.kotlin` (11): `analyzer::kotlin::declarations::{KotlinClassLikeKind` (`analyzer/kotlin/declarations.rs:597`), `KotlinDeclaredVisibility` (`:633`), `kotlin_class_like_kind` (`:608`), `kotlin_declared_visibility` (`:641`), `parse_kotlin_file` (`:81`)`}` at `analyzer/jvm/kotlin_artifact.rs:7`; `analyzer::kotlin::imports::KOTLIN_DEFAULT_IMPORT_PACKAGES` [const pub(crate), `analyzer/kotlin/imports.rs:47`] at `kotlin_artifact.rs:11`; `analyzer::kotlin::language` module at `kotlin_artifact.rs:12`; `analyzer::kotlin::syntax::{kotlin_user_type_segments` (`analyzer/kotlin/syntax.rs:232`), `kotlin_type_spelling` (`:325`)`}` at `kotlin_artifact.rs:13`; `KotlinAnalyzer::new_with_config` at `analyzer/jvm/external.rs:3477`; `KotlinAnalyzer` at `analyzer/jvm/realm.rs:30`.

`LANG.jvm -> LANG.scala` (6): `analyzer::scala::declarations::{parse_scala_file` (`analyzer/scala/declarations.rs:62`), `ScalaDeclarationVisibility` (`:1596`), `scala_declaration_visibility` (`:1603`)`}` at `analyzer/jvm/scala_artifact.rs:6`; `analyzer::scala::scala_normalize_full_name` [fn pub(crate), `analyzer/scala/mod.rs:59`] and `analyzer::scala::language` at `analyzer/jvm/scala_artifact.rs:9`; `ScalaAnalyzer` at `analyzer/jvm/realm.rs:30`.

Return direction: `LANG.kotlin -> LANG.jvm` (7) — `analyzer::jvm::realm::JvmSourceRealm` [struct pub(crate), `analyzer/jvm/realm.rs:36`] at `analyzer/kotlin/diagnostics.rs:22`, `analyzer/kotlin/hierarchy.rs:10`, `analyzer/kotlin/imports.rs:27` (+1); `analyzer::jvm::dependency_discovery::is_jvm_dependency_input` [fn pub(crate), `analyzer/jvm/dependency_discovery.rs:228`] at `analyzer/kotlin/mod.rs:73`; `analyzer::jvm::external::JvmExternalDeclarationIndex` [struct pub(crate), `analyzer/jvm/external.rs:53`] at `analyzer/kotlin/mod.rs:74`; `analyzer::jvm::external::JvmExternalType` [struct pub(crate), `analyzer/jvm/external.rs:59`] at `analyzer/kotlin/types.rs:33`. `LANG.java -> LANG.jvm` (3) — `is_jvm_dependency_input` at `analyzer/java/mod.rs:29`, `JvmExternalDeclarationIndex` at `analyzer/java/mod.rs:30`, `JvmExternalType` at `analyzer/java/imports.rs:2`. `LANG.scala -> LANG.jvm` (2) — `JvmSourceRealm` and `JvmExternalDeclarationIndex` at `analyzer/scala/mod.rs:23`.

`analyzer/jvm/realm.rs:30` imports all three analyzer types in a single statement, so `JvmSourceRealm` — which java, kotlin and scala all consume — is defined in terms of all three languages simultaneously. That is a cycle at module granularity (kotlin -> jvm::realm -> kotlin) and it is not removable by promoting visibility.

One direct java<->scala edge outside `jvm/`: `analyzer/usages/java_graph/jvm_scala.rs` (UGRAPH.java) references LANG.scala twice. The workspace edge path also treats the trio as one ecosystem: `analyzer/usages/workspace_graph.rs:390-411` runs java, scala and kotlin over the shared `UsageEcosystem::Jvm` candidate set, deduplicated at `workspace_graph.rs:502`.

**Refutation complete: java, kotlin, scala and jvm cannot be separate crates without introducing a new abstraction between them. They form one unit.**

### 5.5 Orphan-rule exposure

629 `impl <Trait> for <Type>` blocks extracted, both trait name and self type resolved against the definition index. Result: **no orphan-rule breakage.**

- **Impls sited in a LANG/UGRAPH unit where both the trait and the self type are foreign to that unit: 0.**
- Impls sited outside a language unit over a language-owned type: 0 real. The single mechanical hit, `profiling.rs:36 impl Drop for Scope`, was checked — `Scope` there is `profiling.rs`'s own type, merely sharing a name with a Python-side `Scope`. False positive.
- Impls in a language unit of an *external* (std) trait for a foreign type: 8, all `impl From<<Lang>SemanticDiagnostic> for SemanticDiagnostic` — `analyzer/go/diagnostics.rs:28`, `analyzer/js_ts/diagnostics.rs:30`, `analyzer/kotlin/diagnostics.rs:45`, `analyzer/php/diagnostics.rs:25`, `analyzer/python/diagnostics.rs:25`, `analyzer/ruby/diagnostics.rs:27`, `analyzer/rust/diagnostics.rs:25`, `analyzer/scala/diagnostics.rs:24`. `SemanticDiagnostic` is core-owned (`analyzer/model.rs`, re-exported at `analyzer/mod.rs:137`). These remain **legal** under RFC 2451: the impl is `impl ForeignTrait<LocalType> for ForeignType` with the local type as a covering type argument and no generic parameters preceding it. Verified against the actual signature at `analyzer/rust/diagnostics.rs:25`: `impl From<RustSemanticDiagnostic> for SemanticDiagnostic`.

The healthy pattern dominates. Language units implement traits owned by core (js_ts=11, cpp=6, go=6, kotlin=6, rust=6, java=5, python=5, php=4, ruby=4, csharp=3 impls of `CORE.analyzer_root` traits — `IAnalyzer` and the adapter traits), and each `UGRAPH.<x>` implements 3-4 traits owned by `USAGES.fw`. Both directions are "foreign trait, local type", always permitted. `LANG.jvm` implements 4 traits owned by `SEM.semantic_model`.

The real constraint is not coherence but **visibility**: the large body of `pub(crate)` and `pub(in crate::analyzer::usages)` items in §4.1, §4.3, §5.1, §5.2 and §5.4, plus the `pub(crate)` macro `impl_program_semantics_provider` (§4.4), all become compile errors the moment a boundary is drawn through them.

### 5.6 `code_quality` -> usages internals: the SPI input

`QS.code_quality` makes 132 cross-unit references, of which **50 reach the usages subsystem, and all 50 originate in the single file `code_quality/dead_code_smells.rs`.** 33 target per-language graph modules, 17 the framework; 30 of the 50 pull `pub(crate)` items. Grouped by the usage evidence each site needs:

**(a) Strategy handles — needs a per-language `UsageGraphStrategy` value.** All imported at `code_quality/dead_code_smells.rs:11`, all `struct pub`, dispatched through the if-chain at `dead_code_smells.rs:2387-2416`: `CSharpUsageGraphStrategy`, `GoUsageGraphStrategy`, `JavaUsageGraphStrategy`, `JsTsExportUsageGraphStrategy`, `KotlinUsageGraphStrategy`, `PhpUsageGraphStrategy`, `RubyUsageGraphStrategy`, `RustExportUsageGraphStrategy`, `ScalaUsageGraphStrategy`. **C++ and Python are deliberately absent** and served by group (b).

**(b) Whole-workspace edge construction — needs `UsageEdges`/`UsageEdgeWeights` over a node set, per language.** All `pub(crate) fn` except where noted:

| site | callee |
| --- | --- |
| `code_quality/dead_code_smells.rs:906` | `analyzer::usages::rust_graph::build_rust_usage_edges` |
| `code_quality/dead_code_smells.rs:1004` | `analyzer::usages::python_graph::build_cached_python_usage_edges_for_targets` |
| `code_quality/dead_code_smells.rs:1038` | `analyzer::usages::java_graph::build_java_usage_edges` |
| `code_quality/dead_code_smells.rs:1062` | `analyzer::usages::scala_graph::build_full_scala_usage_edges` |
| `code_quality/dead_code_smells.rs:1086` | `analyzer::usages::go_graph::build_go_usage_edges` |
| `code_quality/dead_code_smells.rs:1110` | `analyzer::usages::csharp_graph::build_csharp_usage_edges` |
| `code_quality/dead_code_smells.rs:1136` | `analyzer::usages::cpp_graph::build_cpp_usage_edges` |
| `code_quality/dead_code_smells.rs:1160` | `analyzer::usages::php_graph::build_php_usage_edges` |
| `code_quality/dead_code_smells.rs:1184` | `analyzer::usages::ruby_graph::build_ruby_usage_edges` (pub) |
| `code_quality/dead_code_smells.rs:1342` | `analyzer::usages::js_ts_graph::build_jsts_scoped_usage_edges` |

**(c) Bulk dead-code eligibility pre-pass — needs a per-language "bulk vs precise scan" verdict.** Only four languages expose it:

| site | item | kind/vis |
| --- | --- | --- |
| `dead_code_smells.rs:1997` | `analyzer::usages::java_graph::dead_code_bulk_eligibility` | fn pub(crate), `analyzer/usages/java_graph.rs:114` |
| `dead_code_smells.rs:2004` | `java_graph::JavaDeadCodeBulkEligibility::NeedsPrecise` | enum pub(crate) |
| `dead_code_smells.rs:2032` | `scala_graph::dead_code_bulk_eligibility` | fn pub(crate) |
| `dead_code_smells.rs:2035` | `scala_graph::ScalaDeadCodeBulkEligibility::NeedsPrecise` | enum pub(crate) |
| `dead_code_smells.rs:148,2013,2024` | `scala_graph::ScalaDeadCodeBulkContext` and `::from_analyzer` | struct pub(crate), `analyzer/usages/scala_graph.rs:74` |
| `dead_code_smells.rs:2075` | `cpp_graph::dead_code_bulk_eligibility` | fn pub(crate) |
| `dead_code_smells.rs:2078` | `cpp_graph::CppDeadCodeBulkEligibility::NeedsPrecise` | enum pub(crate) |
| `dead_code_smells.rs:2084` | `php_graph::dead_code_bulk_eligibility` | fn pub(crate) |
| `dead_code_smells.rs:2085` | `php_graph::PhpDeadCodeBulkEligibility::NeedsPrecise` | enum pub(crate) |

**(d) Language-specific special cases — one bespoke predicate/type each.**

| site | item | kind/vis |
| --- | --- | --- |
| `dead_code_smells.rs:2241` | `analyzer::usages::cpp_graph::is_cpp_global_main` | fn pub(crate), `analyzer/usages/cpp_graph.rs:102` |
| `dead_code_smells.rs:10` | `js_ts_graph::inverted::JsTsScopedNodeStatus` | enum pub(crate), `analyzer/usages/js_ts_graph/inverted.rs:138` |
| `dead_code_smells.rs:1355` | `js_ts_graph::inverted::JsTsScopedUsageEdges` | struct pub(crate) |

**(e) Framework-owned, no language content — the edge/hit data model.** `analyzer::usages::inverted_edges::{UsageEdges` (lines 9, 969), `UsageNodeKey` (9), `UsageEdgeWeights` (1356), `MAX_CALLSITES` (927, 1275, 1402)`}` — all `pub(crate)`; `analyzer::usages::traits::{UsageAnalyzer, CandidateFileProvider}` (11, pub); `analyzer::usages::candidates::{ImportGraphCandidateProvider` (8), `FallbackCandidateProvider` (11), `TextSearchCandidateProvider` (11), `default_provider` (2366)`}` (pub); `analyzer::usages::model::{FuzzyResult, UsageHit, UsageHitKind, UsageHitSurface}` (11, pub).

Shape: groups (a), (b) and (e) are uniform across languages and already trait-shaped or nearly so. Groups (c) and (d) are the irregular part — four languages have a bulk-eligibility path and seven do not, two have a bespoke escape hatch, and two (C++, Python) are missing from the strategy if-chain entirely — and they are what prevents `dead_code_smells.rs` from talking to a single uniform interface today.

## 6. VERDICT

Rule: **CLEAN** = inbound references only to trait implementations or core-owned abstractions; **MODERATE** = a bounded, enumerable list of items must be promoted (visibility widened, or moved) but no reference runs the wrong way; **ENTANGLED** = bidirectional references between the unit and something that would live in another crate, requiring a new seam.

**No language unit classifies as CLEAN.** The reason is uniform and structural rather than language-specific: the usages framework carries four hand-maintained hardcoded language lists (§5.1), and the traits that look like seams (`UsageQueryResolver`, `UsageEdgeResolver`) carry no dispatch at all, so every language is reached by name from at least three places.

Every language shares these unavoidable, uniform promotions, not repeated in the per-language lists: (i) registration in `analyzer/usages/finder.rs:726-811`, `analyzer/usages/workspace_graph.rs:375-491`, `searchtools/scan_usages.rs:2476-2615`, `code_quality/dead_code_smells.rs:2387-2416`; (ii) `pub(crate)` -> `pub` widening of every `build_*_usage_edge*`, `resolve_*_bounded` and `resolve_*_type_bounded` function, plus the `pub(crate)` traits `UsageQueryResolver`, `UsageEdgeResolver`, `GraphUsageAnalyzer` and `UsageScanScope`; (iii) the `pub(crate)` macro `analyzer::semantic::impl_program_semantics_provider` (`analyzer/semantic/mod.rs:14,51`); (iv) the analyzer-handle downcast lists at `analyzer/multi_analyzer.rs:3`, `analyzer/tree_sitter_analyzer.rs:8341-8347`, `analyzer/store/mod.rs:7767-7775`, `analyzer/usages/receiver_query.rs:47`.

**LANG.rust + UGRAPH.rust — MODERATE.** 24 production inbound refs. Zero framework helper reach-ins beyond the analyzer handle. Promotions: `analyzer::rust::field_roles::{RustFieldNameRole, classify_rust_field_name}` (`analyzer/lexical_definitions.rs:10`), `analyzer::rust::adapter::RustAdapter`, `RustAnalyzer::from_project` at `analyzer/usages/finder.rs:638`, `rust_graph::rust_usage_candidate_files` called from the shared candidate layer at `analyzer/usages/candidates.rs:657`, and `rust_graph::build_rust_usage_edges` for code_quality.

**LANG.go + UGRAPH.go — MODERATE.** 25 production inbound refs. Zero framework helper reach-ins. Promotions: `analyzer::go::GO_MODULE_SCOPE_SEGMENT` (`analyzer/symbol_lookup.rs:4`, `searchtools/mod.rs:26`), `analyzer::go::packages::{GoModuleRoot, go_module_roots}` (`searchtools/mod.rs:26`), `analyzer::go::adapter::GoAdapter`. Note `analyzer/usages/get_definition/go.rs:63,70,84` depends on `SEM.semantic_model::catalog::SemanticModelOverlay`, so a Go crate gains a semantic-model dependency.

**LANG.php + UGRAPH.php — MODERATE.** 22 production inbound refs, the fewest. Promotions: `analyzer::php::aliases::{PhpFileContext, resolve_php_type, resolve_php_function, resolve_php_constant}` (`analyzer/usages/get_definition/mod.rs:42`), `php_graph::{dead_code_bulk_eligibility, PhpDeadCodeBulkEligibility}` (code_quality), `analyzer::php::adapter::PhpAdapter`, and `PhpAnalyzer` named directly at `analyzer/usages/finder.rs:17` for the composer/import-alias candidate expansion at `analyzer/usages/finder.rs:367,384,402`.

**LANG.python + UGRAPH.python — MODERATE.** 30 production inbound refs. Promotions: `analyzer::python::usage_index::{ModuleBindingTimeline, ModuleBindingEventKind}` (`analyzer/usages/get_definition/mod.rs:78`), `analyzer::python::declarations::python_package_prefix_fq` (`analyzer/store/mod.rs:27`), `analyzer::python::structural::PYTHON_STRUCTURAL_SPEC` (`analyzer/structural/extract.rs:218`), `PythonAnalyzer::from_project` (`analyzer/structural/index.rs:1841`), `analyzer::python::adapter::PythonAdapter`, and `python_graph::python_usage_candidate_files` called from `analyzer/usages/candidates.rs:652`.

**LANG.csharp + UGRAPH.csharp — MODERATE.** 34 production inbound refs. Promotions: `analyzer::csharp::strip_csharp_generic_arity` and `csharp_normalize_full_name` — consumed by core's own name normalisation at `analyzer/common.rs:139,194` and `analyzer/symbol_lookup.rs:2`, so the item must move into core or core must call through a hook; `analyzer::csharp::csharp_callable_arity` (`analyzer/usages/get_definition/mod.rs:78`), `analyzer::csharp::structural::CSHARP_STRUCTURAL_SPEC` (`analyzer/usages/receiver_sites.rs:362`), `analyzer::csharp::dependency_discovery::is_csharp_dependency_input` (`analyzer/multi_analyzer.rs:198`).

**LANG.ruby + UGRAPH.ruby — MODERATE.** 36 production inbound refs. Promotions: `analyzer::ruby::declarations::parse_ruby_tree` (`analyzer/usages/get_definition/mod.rs:1400`), `analyzer::ruby::structural::RUBY_STRUCTURAL_SPEC` (`analyzer/usages/get_definition/call_sites.rs:1060`), `analyzer::ruby::ruby_semantic_identifier_range` and `analyzer::ruby::imports::ruby_symbol_name` (`analyzer/declaration_range.rs:127,231`), `analyzer::ruby::adapter::RubyAdapter`, `RubyAnalyzer` at `analyzer/structural/execution/derived.rs:1155`. Ruby additionally carries the one structural asymmetry in the query path: no `UsageQueryResolver` impl (`analyzer/usages/ruby_graph.rs:73-173` inlines the scan), so it cannot be extracted behind the same shape as the other ten.

**LANG.cpp + UGRAPH.cpp — MODERATE, largest promotion list.** 57 production inbound refs, 11 from `QS.searchtools`. Promotions: the whole `analyzer::cpp::identity` surface (`CppOccurrenceClassifier`, `CppOccurrenceRole`, `CppCallableUnitRole`, `cpp_callable_unit_role`, `cpp_indexed_callable_linkage`, `cpp_callable_definitions_share_identity_evidence`) consumed by `searchtools/mod.rs:315,322,332`, `searchtools/selectors.rs:3,261,294,300` and `analyzer/usages/candidates.rs:6`; `analyzer::cpp::imports::{include_paths, resolve_include_targets}` and `analyzer::cpp::declarations::node_text` (`analyzer/usages/get_definition/mod.rs:78`); `analyzer::cpp::declarations::is_direct_recovered_exported_class_field_declaration` (`analyzer/lexical_definitions.rs:624`); `cpp_graph::{dead_code_bulk_eligibility, CppDeadCodeBulkEligibility, is_cpp_global_main}` (code_quality). Nothing runs the wrong way; the list is simply long.

**LANG.js_ts (js_ts + javascript + typescript) + UGRAPH.js_ts — ENTANGLED.** 57 production inbound refs, and the only language unit referenced by other language units. Four distinct seams need creating:

1. `analyzer::js_ts::cache::{build_weighted_cache, weight_code_unit_vec_by_unit, weight_code_unit_set, weight_project_file_set}` (`analyzer/js_ts/cache.rs:53,76,88,97`) are imported by nine other language modules (§5.3). A JS/TS crate cannot be a dependency of every other language crate; this module has to be relocated.
2. `SEM.semantic -> LANG.js_ts`: `analyzer/semantic/service.rs:707` uses `analyzer::typescript::TypescriptAdapter`, `analyzer/semantic/service.rs:1235` uses `analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript`. The *only* two references from the semantic engine into any language; every other language reaches semantic through `ProgramSemanticsLowerer`. JS/TS is special-cased in the engine.
3. `USAGES.fw -> UGRAPH.js_ts::receiver_analysis`: `analyzer/usages/receiver_query.rs:31,36` pulls six `pub(in crate::analyzer::usages)` items plus `JsTsReceiverFactProvider`. No other language's receiver analysis is reached this way.
4. The workspace edge path cannot use the shared shape: `analyzer/usages/workspace_graph.rs:434-491` is hand-written because `build_jsts_scoped_usage_edges` returns `JsTsScopedUsageEdges` keyed by `UsageNodeKey{file, fqn}`, which structurally cannot satisfy `UsageEdgeResolver` (`analyzer/usages/workspace_graph.rs:52-54`).

   Plus ordinary promotions: `analyzer::js_ts::syntax::{JsTsImportBinder, compute_import_binder}` and `analyzer::js_ts::tsconfig::AliasResolver` (`analyzer/usages/get_definition/mod.rs:2,34,78`, `analyzer/usages/receiver_query.rs:36,128`), `TypescriptAnalyzer` at `analyzer/structural/provider.rs:511`, and the `JsTsScoped*` types for code_quality.

**JVM realm (LANG.java + LANG.kotlin + LANG.scala + LANG.jvm + UGRAPH.{java,kotlin,scala}) — ENTANGLED as four units, MODERATE as one.**

As four separate crates: ENTANGLED, definitively. `analyzer/jvm/realm.rs:30` constructs `JvmSourceRealm` over all three analyzers, and it is consumed back by kotlin (`analyzer/kotlin/diagnostics.rs:22`, `analyzer/kotlin/hierarchy.rs:10`, `analyzer/kotlin/imports.rs:27`) and scala (`analyzer/scala/mod.rs:23`) — a module-level cycle. `analyzer/jvm/external.rs` additionally reaches into `analyzer::java::declarations` and `analyzer::java::imports::JavaTypeResolution` internals (19 refs) while java reaches back for `JvmExternalDeclarationIndex`/`JvmExternalType` (3 refs). Same pattern for kotlin (11 out / 7 back) and scala (6 out / 2 back). §5.4 gives every site.

As one merged crate: MODERATE. 85 production inbound refs. Promotions: `analyzer::scala::imports::ScalaExportInfo` and `analyzer::scala::language::LANGUAGE` (`analyzer/store/mod.rs:4603,5794,6459,8662`, `analyzer/store/epoch.rs:350`), `analyzer::kotlin::language::LANGUAGE` (`analyzer/lexical_definitions.rs:1252`, `analyzer/mod.rs:326`), `analyzer::kotlin::diagnostics::collect_kotlin_semantic_diagnostics` (`analyzer/multi_analyzer.rs:956`), `analyzer::kotlin::syntax::{kotlin_callee, kotlin_value_arguments, kotlin_navigation_member}` (`analyzer/usages/get_definition/call_sites.rs:419,438`, `analyzer/usages/receiver_query.rs:3013,3016`), the java/scala/kotlin adapters at `analyzer/store/mod.rs:7769,7773` and `analyzer/tree_sitter_analyzer.rs:8342`, and the java/scala bulk-eligibility surface for code_quality. `LANG.jvm`'s 213 references into `SEM.semantic_model` make that crate a hard dependency of the JVM crate.

result: Seam matrix complete — no language unit is CLEAN; rust/go/php/python/csharp/ruby/cpp are MODERATE with enumerated promotion lists, js_ts is ENTANGLED (js_ts::cache shared by 9 languages, semantic engine special-cases TypeScript, framework reaches js_ts_graph::receiver_analysis, and JsTsScopedUsageEdges can't satisfy UsageEdgeResolver), and the JVM realm is ENTANGLED as four units but MODERATE merged as one (JvmSourceRealm cycle at analyzer/jvm/realm.rs:30); zero orphan-rule breakage, the real cost is visibility promotion plus four hand-maintained language dispatch lists. Report could NOT be committed — harness blocks agent .md report writes, so the full document is in this message and needs filing at .agents/docs/analysis-crate-seam-matrix-2026-08.md by you.
