//! The JS/TS shim.
//!
//! The language knowledge moved to `brokk-bifrost-js-ts`. What stays is what
//! needs an analyzer: the moka memo bucket ([`cache`]), the memoizing provider
//! wrappers and the one downcast ([`providers`]), the two analyzer-guarded
//! diagnostic entry points ([`diagnostics`]), the `ReceiverFactsFactory`
//! boundary adapter ([`receiver_facts`]), the clone-candidate entry point
//! ([`clones`]), the two `LanguageSupport` registrations below, and the bands
//! parked on `analyzer::semantic` ([`semantic`]) and `semantic_model`
//! ([`external`]).

pub(crate) mod cache;
pub(crate) mod clones;
pub(crate) mod diagnostics;
pub(crate) mod external;
pub(crate) mod providers;
#[cfg(test)]
mod receiver_analysis_tests;
pub(crate) mod receiver_facts;
pub(crate) mod semantic;
mod structural;
use crate::analyzer::store::LimitedQueryRows;

pub(crate) use brokk_bifrost_js_ts::imports::resolve_js_ts_module_specifier;
pub(crate) use brokk_bifrost_js_ts::tsconfig::AliasResolver;
pub use external::{
    JsTsDependencyPackAdapter, TypeScriptDeclarationPackProducer,
    resolve_js_ts_semantic_pack_dependencies,
};

use crate::analyzer::cognitive_complexity;
use crate::analyzer::common::language_for_target;
use crate::analyzer::languages::{
    DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport,
    EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx, LanguageEdgePass, LanguageEdgeSites,
    LanguageEdgeWeights, LanguageSupport, ReceiverFactsFactory, TypeLookupQuery,
    TypeLookupResolver, analyzable_file_count,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_js_ts_type};
use crate::analyzer::usages::inverted_edges::{NodeKey, UsageNodeKey};
use crate::analyzer::usages::js_ts_graph::{
    JsTsExportUsageGraphStrategy, JsTsReceiverFacts, build_jsts_scoped_usage_edges,
    build_jsts_usage_edges,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{CodeUnit, Language};
use crate::analyzer::{
    ForwardQueryProvider, IAnalyzer, JavascriptAnalyzer, ParserFlavor, ProjectFile, Range,
    TypescriptAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use brokk_bifrost_js_ts::model::module_code_unit;
use std::sync::LazyLock;

static JS_TS_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &[
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["ternary_expression"],
        case_types: &["switch_case"],
        default_case_types: &["switch_default"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||", "??"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &[
            "function_declaration",
            "function_expression",
            "generator_function",
            "generator_function_declaration",
            "method_definition",
            "arrow_function",
        ],
        else_clause_types: &["else_clause"],
        ..cognitive_complexity::Config::empty()
    });

pub(crate) fn cognitive_complexity_config() -> &'static cognitive_complexity::Config {
    &JS_TS_COGNITIVE_CONFIG
}

pub(crate) fn source_contains_tests(source: &str) -> bool {
    source.contains("describe(") || source.contains("test(") || source.contains("it(")
}

pub(crate) fn path_contains_tests(file: &ProjectFile) -> bool {
    let rel = file.rel_path().to_string_lossy().to_ascii_lowercase();
    rel.contains(".test.") || rel.contains(".spec.")
}

pub(crate) fn contains_tests(file: &ProjectFile, source: &str) -> bool {
    path_contains_tests(file) || source_contains_tests(source)
}

pub(crate) fn synthesize_hydrated_module(file: &ProjectFile, source: &str, state: &mut FileState) {
    if state.imports.is_empty() {
        return;
    }
    let module = module_code_unit(file);
    state.top_level_declarations.push(module.clone());
    state.declarations.insert(module.clone());
    state.ranges.entry(module).or_default().push(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 1,
        end_line: compute_line_starts(source).len(),
    });
}

static JS_TS_USAGE_STRATEGY: JsTsExportUsageGraphStrategy = JsTsExportUsageGraphStrategy::new();

pub(crate) struct JavascriptSupport;

impl LanguageSupport for JavascriptSupport {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<JavascriptAnalyzer>(analyzer)
            .map(|javascript| javascript.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<JavascriptAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::JavaScriptTypeScript
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &JS_TS_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&JsTsEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&JS_TS_USAGE_STRATEGY),
            bulk: Some(&JsTsDeadCodeBulk),
        }
    }

    fn receiver_facts(&self) -> Option<&'static dyn ReceiverFactsFactory> {
        Some(&JsTsReceiverFacts)
    }

    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        Some(&JsTsTypeLookup)
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_javascript::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_js_ts::structural::JAVASCRIPT_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_javascript::HIGHLIGHT_QUERY)
    }
}

pub(crate) struct TypescriptSupport;

impl LanguageSupport for TypescriptSupport {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    /// `$static` is an internal marker keeping static and instance members distinct in
    /// the index; it is not written in source and not shown to a reader.
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol.strip_suffix("$static").unwrap_or(symbol).to_string()
    }

    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        identifier.strip_suffix("$static").unwrap_or(identifier)
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<TypescriptAnalyzer>(analyzer)
            .map(|typescript| typescript.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<TypescriptAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::JavaScriptTypeScript
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &JS_TS_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&JsTsEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&JS_TS_USAGE_STRATEGY),
            bulk: Some(&JsTsDeadCodeBulk),
        }
    }

    fn receiver_facts(&self) -> Option<&'static dyn ReceiverFactsFactory> {
        Some(&JsTsReceiverFacts)
    }

    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        Some(&JsTsTypeLookup)
    }

    /// The one language whose grammar depends on the flavor: `.tsx` files parse under
    /// the TSX grammar while sharing the TypeScript adapter and structural spec.
    fn parser_language(&self, flavor: ParserFlavor) -> tree_sitter::Language {
        match flavor {
            ParserFlavor::TypeScriptTsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            ParserFlavor::Default => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        }
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_js_ts::structural::TYPESCRIPT_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_typescript::HIGHLIGHTS_QUERY)
    }
}

/// One pass for both dialects: JavaScript and TypeScript are resolved together, so
/// `JavascriptSupport` and `TypescriptSupport` return this same object and the collector
/// runs it once. The two finalizations differ in node identity as well as product -- the
/// sites path is fqn-keyed like every other language, while the weights path is keyed by
/// `{file, fqn}` so same-named exports in different modules stay distinct.
struct JsTsEdgePass;

impl LanguageEdgePass for JsTsEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::JsTs
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_jsts_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_jsts_scoped_usage_edges(ctx.analyzer, ctx.scoped_nodes, ctx.keep_file)
            .map(LanguageEdgeWeights::Scoped)
    }
}

/// One resolver for both dialects, as with `JS_TS_USAGE_STRATEGY`: the JS/TS type
/// resolver takes the dialect as an argument rather than being specialized on it.
struct JsTsTypeLookup;

impl TypeLookupResolver for JsTsTypeLookup {
    fn resolve_type(&self, query: TypeLookupQuery<'_>) -> TypeLookupOutcome {
        query.support.set_language(query.language);
        resolve_js_ts_type(
            query.analyzer,
            query.support,
            query.file,
            query.language,
            query.source,
            query.tree,
            query.site,
        )
    }
}

/// One proof for both dialects, as with [`JsTsEdgePass`]: JavaScript and TypeScript
/// candidates share a bucket and one scoped build.
struct JsTsDeadCodeBulk;

impl DeadCodeBulkProof for JsTsDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::JsTs
    }

    fn needs_precise_scan(&self, _routing: DeadCodeRouting<'_>) -> bool {
        false
    }

    /// The cap is measured against JavaScript *and* TypeScript file counts summed,
    /// because one scoped build covers both, and its diagnostics say "JS/TS" rather than
    /// naming either dialect.
    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "JS/TS",
            files: [Language::JavaScript, Language::TypeScript]
                .into_iter()
                .map(|language| analyzable_file_count(analyzer, language))
                .sum(),
        }
    }

    /// Keyed by `{file, fqn}`, and its product carries the per-node seed statuses the
    /// caller needs to tell a resolved export from an ambiguous or unseedable one.
    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let mut nodes: HashSet<UsageNodeKey> = analyzer
            .all_declarations()
            .filter(|unit| {
                matches!(
                    language_for_target(unit),
                    Language::JavaScript | Language::TypeScript
                ) && !unit.is_synthetic()
                    && (unit.is_function() || unit.is_class() || unit.is_field())
            })
            .map(|unit| UsageNodeKey::from_unit(&unit))
            .collect();
        nodes.extend(candidates.iter().map(UsageNodeKey::from_unit));
        build_jsts_scoped_usage_edges(analyzer, &nodes, |_| true).map(DeadCodeBulkEdges::Scoped)
    }
}
