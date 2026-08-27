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
    JsTsDependencyPackAdapter, TYPESCRIPT_STDLIB_PACKAGE, TYPESCRIPT_STDLIB_VERSION,
    TypeScriptDeclarationPackProducer, TypeScriptLibraryActivationOutcome,
    resolve_js_ts_semantic_pack_dependencies, typescript_library_activation_evidence,
};

use crate::analyzer::cognitive_complexity;
use crate::analyzer::common::language_for_target;
use crate::analyzer::languages::{
    DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport,
    EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx, ExternalCalleeSite, LanguageEdgePass,
    LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport, LocalDeclarationBindingScope,
    LocalDeclarationVisibility, ReceiverFactsFactory, analyzable_file_count,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::inverted_edges::{NodeKey, UsageNodeKey};
use crate::analyzer::usages::js_ts_graph::{
    JsTsExportUsageGraphStrategy, JsTsReceiverFacts, build_jsts_scoped_usage_edges,
    build_rooted_jsts_scoped_usage_edges,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerQueryScope, ForwardQueryProvider, IAnalyzer, JavascriptAnalyzer, ParserFlavor,
    ProjectFile, QueryScope, Range, TypescriptAnalyzer, resolve_analyzer,
};
use crate::analyzer::{CodeUnit, Language, SummaryFileProjection};
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_js_ts::imports::npm_package_of_module_specifier;
use brokk_bifrost_js_ts::model::module_code_unit;
use brokk_bifrost_js_ts::syntax::{
    JsTsLexicalBindingIndex, compute_import_binder as compute_js_ts_import_binder,
    js_ts_variable_declarator_binding_scope,
};
use std::sync::LazyLock;

fn js_ts_local_declaration_binding_scope<'tree>(
    node: tree_sitter::Node<'tree>,
) -> Option<LocalDeclarationBindingScope<'tree>> {
    let scope = js_ts_variable_declarator_binding_scope(node)?;
    let visibility = if node
        .parent()
        .is_some_and(|parent| parent.kind() == "variable_declaration")
    {
        LocalDeclarationVisibility::Hoisted
    } else {
        LocalDeclarationVisibility::Lexical
    };
    Some(LocalDeclarationBindingScope { scope, visibility })
}

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

pub(crate) fn synthesize_summary_module(
    file: &ProjectFile,
    source: &str,
    has_structured_imports: bool,
    projection: &mut SummaryFileProjection,
) {
    if !has_structured_imports {
        return;
    }
    let module = module_code_unit(file);
    projection.top_level_declarations.push(module.clone());
    projection.ranges.entry(module).or_default().push(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 1,
        end_line: compute_line_starts(source).len(),
    });
}

static JS_TS_USAGE_STRATEGY: JsTsExportUsageGraphStrategy = JsTsExportUsageGraphStrategy::new();

/// The canonical owner a single-segment JS/TS external callee publishes, or
/// `None` when the owner names no external identity at all (#2598).
///
/// One rule for both dialects, because the binding structure it reads is the
/// same one. The callee has already failed to resolve by the time this runs, so
/// the only question left is what the file itself says about the owner name:
///
///   * bound by an import or `require` that names a package or runtime builtin
///     -- the owner is that module's identity. A default, namespace or
///     CommonJS module-object binding *is* the module, so the specifier is the
///     owner and `import p from 'path'` keys identically to
///     `import path from 'path'`. A named import binds a member *of* the
///     module, and that member is itself the owner: `import { Buffer } from
///     'buffer'` makes `Buffer.from` owner `Buffer`, never `buffer`;
///   * bound by an import whose specifier is relative or absolute -- refused.
///     That specifier addresses a workspace file, so a call through it that did
///     not resolve is a resolution gap to fix, not an external surface to
///     model;
///   * bound by anything else in scope at the call -- a parameter, a local, a
///     class, a function, a catch binder -- refused. `opts.parse(x)` where
///     `opts` is a parameter names the parameter's runtime value, and no
///     authored summary can claim it;
///   * bound by nothing -- admitted as itself. `JSON`, `Buffer` and `crypto`
///     reach a call site with no binding anywhere in the file precisely because
///     they are the runtime's own globals.
///
/// The last arm is a definition check, not a reviewed table of global names. A
/// table would have to be kept current with several runtimes and would still
/// answer wrongly for a file that shadows one of its entries; the binding
/// question answers both cases from the file in hand.
fn js_ts_single_segment_external_owner(
    owner: &str,
    site: &ExternalCalleeSite<'_>,
) -> Option<String> {
    let binder = compute_js_ts_import_binder(site.source, site.tree);
    let Some(binding) = binder.binding(owner) else {
        // Nothing in the file binds the name at this point, so it is the
        // runtime's own global and is its own owner.
        let lexical = JsTsLexicalBindingIndex::build(site.tree.root_node(), site.source);
        return (!lexical.is_bound_at(owner, site.callee_start_byte)).then(|| owner.to_owned());
    };
    // A relative or absolute specifier addresses a workspace file rather than a
    // package, which is what `npm_package_of_module_specifier` answers `None`
    // for.
    npm_package_of_module_specifier(&binding.module_specifier)?;
    match binding.kind {
        ImportKind::Default | ImportKind::Namespace | ImportKind::CommonJsRequire => {
            Some(binding.module_specifier.clone())
        }
        ImportKind::Named => Some(owner.to_owned()),
        // A glob binds no single name, so it cannot be what bound this owner.
        ImportKind::Glob => None,
    }
}

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

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<JavascriptAnalyzer>(analyzer)
            .map(|javascript| javascript.signatures_limited(unit, limit))
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

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::new(
            &JS_TS_USAGE_STRATEGY,
            &JsTsEdgePass,
        )
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

    fn local_declaration_binding_scope<'tree>(
        &self,
        node: tree_sitter::Node<'tree>,
    ) -> Option<LocalDeclarationBindingScope<'tree>> {
        js_ts_local_declaration_binding_scope(node)
    }

    fn scans_local_declarations_after_focus(&self) -> bool {
        true
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_javascript::LANGUAGE.into()
    }

    fn publishes_single_segment_external_owners(&self) -> bool {
        true
    }

    fn single_segment_external_owner(
        &self,
        owner: &str,
        site: &ExternalCalleeSite<'_>,
    ) -> Option<String> {
        js_ts_single_segment_external_owner(owner, site)
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

    fn local_declaration_binding_scope<'tree>(
        &self,
        node: tree_sitter::Node<'tree>,
    ) -> Option<LocalDeclarationBindingScope<'tree>> {
        js_ts_local_declaration_binding_scope(node)
    }

    fn scans_local_declarations_after_focus(&self) -> bool {
        true
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

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<TypescriptAnalyzer>(analyzer)
            .map(|typescript| typescript.signatures_limited(unit, limit))
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

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::new(
            &JS_TS_USAGE_STRATEGY,
            &JsTsEdgePass,
        )
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

    /// The one language whose grammar depends on the flavor: `.tsx` files parse under
    /// the TSX grammar while sharing the TypeScript adapter and structural spec.
    fn parser_language(&self, flavor: ParserFlavor) -> tree_sitter::Language {
        match flavor {
            ParserFlavor::TypeScriptTsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            ParserFlavor::Default => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        }
    }

    fn publishes_single_segment_external_owners(&self) -> bool {
        true
    }

    fn single_segment_external_owner(
        &self,
        owner: &str,
        site: &ExternalCalleeSite<'_>,
    ) -> Option<String> {
        js_ts_single_segment_external_owner(owner, site)
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
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        build_rooted_jsts_scoped_usage_edges(
            ctx.analyzer,
            scope.token(),
            ctx.scoped_callers,
            ctx.keep_file,
        )
        .map(LanguageEdgeSites::Scoped)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        build_jsts_scoped_usage_edges(ctx.analyzer, scope.token(), ctx.scoped_nodes, ctx.keep_file)
            .map(LanguageEdgeWeights::Scoped)
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
        let scope = AnalyzerQueryScope::new(analyzer);
        build_jsts_scoped_usage_edges(analyzer, scope.token(), &nodes, |_| true)
            .map(DeadCodeBulkEdges::Scoped)
    }
}
