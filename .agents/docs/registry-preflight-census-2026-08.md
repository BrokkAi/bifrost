# Registry pre-flight census: deltas and dispositions (2026-08-04)

Pre-flight sweep for `.agents/plans/analysis-language-registry-spi.md`, taken at commit
`ec74ddac`. Method: `git log 999a0d5c..HEAD -- crates/bifrost-analysis/src` plus a full
framework-file sweep for language-module/concrete-type references and `match Language`
sites, compared against the plan's inventory. Companion:
`.agents/docs/registry-preflight-absent-capability-inventory-2026-08.md` (behavior pins).

Headline: no commit since `999a0d5c` added or moved a per-language dispatch site — every
delta below is a census omission, not upstream churn. The plan's six lists all verify
intact at their cited locations. Coordination risk from "upstream actively mints new
sites" did not materialize in this window; the one open PR (#1558, policy scoping) does
not touch dispatch files.

## 1. New dispatch lists (plan scope additions)

These are full dispatch tables the plan's census missed. Both convert in milestone 1b
(they are downcast/resolver tables, the same shape as receiver_query's).

- Seventh list: `analyzer/global_usage_definition_index.rs:185-208` —
  `analyzer_for_language` is a 13-arm `match language` doing
  `resolve_analyzer::<XAnalyzer>(analyzer).map(|v| v as &dyn ForwardQueryProvider)` for
  all twelve analyzers (`Language::None => None`). Imports at `:3-5` name eleven
  analyzers; `KotlinAnalyzer` is inline-pathed at `:206`. Disposition: new
  `LanguageSupport` method `forward_query_provider(&self, analyzer: &dyn IAnalyzer) ->
  Option<&dyn ForwardQueryProvider>` — each support owns its downcast, mirroring
  `warm_usage_analysis`.
- Same file `:822-827`: `package_parent_name` separator match (`Go => "/"`,
  `Cpp => "::"`, `_ => "."`). A silent-default fallback of exactly the class decision 2
  targets. Disposition: default trait method (default `"."`; Go/C++ override), rides
  along with 1b.
- `analyzer/usages/get_type/mod.rs:189` — an 11-arm `resolve_<lang>_type` dispatch into
  `get_type/<lang>` submodules: the get_type analogue of receiver_query's two
  bounded-resolver tables. Disposition: absorbed into milestone 1b alongside them.

## 2. Registry-natural tables (milestone 1f scope additions)

Each reaches into language modules (trips the gate) or is the plan's flagged
`source_ingestion` case; each becomes a `LanguageSupport` method:

- `analyzer/mod.rs:362-379` `structural_spec_for` — names all twelve
  `<lang>::structural::<LANG>_STRUCTURAL_SPEC` statics. Becomes
  `structural_spec(&self)`.
- `analyzer/mod.rs:313-336` `parser_language_for_flavor` — 13-arm grammar table; Scala
  and Kotlin arms reach `<lang>::language::LANGUAGE`. Becomes a grammar/parser-language
  method (flavor parameter preserved).
- `analyzer/source_ingestion.rs:245-265` `highlight_query_for` — 13 arms, Scala/Kotlin
  via `include_str!`. Becomes `highlight_query(&self) -> Option<&'static str>`; the two
  `include_str!` arms move onto `ScalaSupport`/`KotlinSupport`.

## 3. Small reach-ins missed by the plan (milestone 1b/1f, implementer-adjudicated)

Convert onto capability methods or restructure; each choice recorded in the plan's
decision log at conversion time:

- C# name handling: `analyzer/symbol_lookup.rs:2` + `analyzer/common.rs:185`
  (`strip_csharp_generic_arity`), `analyzer/common.rs:124-133` (`display_symbol_name`
  4-arm match calling `csharp_normalize_full_name`).
- Ruby: `analyzer/declaration_range.rs:127` (`ruby_semantic_identifier_range`), `:231`
  (`ruby_symbol_name`).
- Kotlin syntax helpers reached from framework files: `receiver_query.rs:3013,3016` and
  `get_definition/call_sites.rs:419,438` (`kotlin_callee`, `kotlin_value_arguments`,
  `kotlin_navigation_member`).
- `receiver_query.rs:128` types a field as `js_ts::syntax::JsTsImportBinder` — part of
  milestone 1b's receiver conversion context.
- The searchtools cpp identity block spans two files, not one: `selectors.rs` (imports
  at `:3-6`, uses through `:1018`) and `sources.rs:47-593`.
- PHP candidate expansion correction: the plan cites the definitions
  (`finder.rs:362+`); the calls whose position relative to the `protected_candidates`
  clone matters for decision 2 are at `finder.rs:193,197`.

## 4. Named gate-allowlist entries (with reasons)

- `analyzer/mod.rs` — after its two tables convert (section 2), the remaining language
  references are the `pub use` re-export hub feeding the facade's curated surface.
  Assembly-adjacent public API.
- `analyzer/usages/mod.rs` — eleven `<Lang>UsageGraphStrategy` re-exports. After
  milestone 1c, retarget or delete any that no framework file still needs; allowlist
  whatever remains as public-surface re-exports.
- `analyzer/multi_analyzer.rs` — already the plan's assembly layer; note it legitimately
  reaches four language modules today (`jvm::realm`, `jvm::dependency_discovery`,
  `csharp::is_csharp_dependency_input`, `kotlin::diagnostics`).
- `summary.rs` — eight production signatures typed `&JavaAnalyzer`; `pub` at the crate
  root and re-exported (`lib.rs:65`). Intentionally Java-specific public API, same class
  as `activate_python_environment_packs`.
- `analyzer/tree_sitter_analyzer.rs:553,1336` and `analyzer/store/mod.rs:4603,5794,6450`
  — production signatures embed `crate::analyzer::scala::ScalaExportInfo`. A type-level
  leak with no `LanguageSupport` method shape; converting it is an unplanned refactor.
  Allowlisted with a named follow-up: the extraction ExecPlan must lower or generalize
  `ScalaExportInfo` before a Scala crate can exist.
- `analyzer/structural/execution/benchmark.rs:1413-1417` — benchmark fixture-name
  selection (production module but benchmark support only).

## 5. Gate design corrections

- The `syn` gate must be module-tree-aware for `cfg(test)`: sixteen `tests.rs` files
  carry no in-file `#[cfg(test)]` — they are gated by `#[cfg(test)] mod tests;` in the
  parent. A file-independent walker misreads them as production. Two would false-fire:
  `analyzer/structural/search/tests.rs` (11-arm analyzer-constructing match) and
  `searchtools/tests.rs`. The gate walks the module tree from `lib.rs`, tracking
  `cfg(test)` on `mod` items, rather than globbing files.
- The gate's subject is module/type reach-ins. Bare `match Language` sites with no
  module coupling are out of its scope by design; section 6 records where they live so
  nobody mistakes gate-green for dispatch-free.
- `workspace.rs:443` maps `Language::None` to
  `unreachable!("Language::None is filtered before delegate build")` — unlike finder's
  terminal failure. When milestone 1f moves construction to the assembly layer, that
  panic contract is preserved (assembly filters None before building); the commit
  message states so explicitly.

## 6. Out-of-scope inventory (documented, not converted)

Per-language knowledge in framework files with no module/type reach-in. The registry
plan does not touch these; the extraction ExecPlan must revisit them because a
per-language crate cannot leave its logic behind in analysis:

- `analyzer/exception_handling.rs:71-91` — 11-arm dispatch to ten file-local
  `analyze_<lang>` implementations: a full per-language implementation set living in a
  framework file. The largest single item extraction will have to resolve.
- `analyzer/lexical_definitions.rs` — eleven `match language` node-kind tables
  (`:468,887,959,978,1029,1052,1073,1090,1148,1171,1186`).
- `analyzer/reference_candidates.rs:127,200,214` — node-kind classification.
- `analyzer/store/epoch.rs:36-50` — per-language epoch marker cells.
- `analyzer/usages/get_definition/mod.rs:1160` (main per-language resolution dispatch
  into `get_definition/<lang>.rs` submodules — those submodules count as per-language
  directories for the gate) and `:1388-1404` (per-language parse table; Ruby arm
  reaches `ruby::parse_ruby_tree`, which milestone 1f folds or allowlists).
- `analyzer/usages/get_definition/call_sites.rs:334,399,773` — call-node dispatch.
- Display-name tables, already divergent ("C/C++" vs "C++"):
  `searchtools/selectors.rs:1562`, `searchtools/scan_usages.rs:1066`,
  `code_quality/dead_code_smells.rs:2423`. Three copies of the same knowledge — a
  candidate for a single `Language` display method in core as a small follow-up, kept
  out of milestone 1 because the divergence may be deliberate per-surface wording.
- `analyzer/semantic_model/overlay.rs:525-529` — string-keyed universal-root dispatch
  (`"java" => "java.lang.Object"`), invisible to any `Language`-typed rule.
- `analyzer/usages/get_type/mod.rs:277-284` — Go-special parse fallback.
- Out-of-crate (outside the gate's walk entirely): `bifrost-lsp` has its own 3-arm
  downcast table (`handlers/import_ambiguity.rs:16-20`, plus
  `handlers/type_definition.rs:97` for Rust) through the public `resolve_analyzer` API.
  No action this plan; it inherits whatever contract `resolve_analyzer` keeps.

## 7. workspace.rs current line anchors (for milestone 1f)

Imports `:8-13` (twelve analyzers + `PythonDependencyPackAdapter` +
`resolve_python_semantic_pack_dependencies` — the second Python-specific import the plan
missed); `build_language_delegate` fn `:406`, match `:430-443`; sole call site `:369`;
`warm_rust_usage_analysis` `:460-470` (carry its #1416 doc comment onto
`RustSupport::warm_usage_analysis` verbatim); `activate_python_environment_packs` `:203`
(adapter use at `:229`); `EmptyAnalyzer` struct `:19`, `impl IAnalyzer` `:29`,
constructed at `:254,397,685`.
