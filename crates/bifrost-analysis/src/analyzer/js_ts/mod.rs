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
    js_ts_declaration_name, js_ts_variable_declarator_binding_scope,
};
use std::path::{Component, Path};
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

/// Whether the parsed tree contains a conventional JavaScript test DSL call.
///
/// This deliberately examines call-expression structure instead of searching
/// source text. A production call such as `emit(...)`, `init(...)`, or
/// `split(...)` can contain the bytes `it(` in its spelling, but it is not a
/// test declaration. Requiring a function-shaped final argument also avoids
/// treating an ordinary helper invocation named `test` as a test declaration.
fn tree_contains_test_dsl_calls(tree: &tree_sitter::Tree, source: &str) -> bool {
    fn identifier_text<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<&'a str> {
        (node.kind() == "identifier")
            .then(|| node.utf8_text(source.as_bytes()).ok())
            .flatten()
    }

    fn identifier_or_property_text<'a>(
        node: tree_sitter::Node<'a>,
        source: &'a str,
    ) -> Option<&'a str> {
        matches!(node.kind(), "identifier" | "property_identifier")
            .then(|| node.utf8_text(source.as_bytes()).ok())
            .flatten()
    }

    fn is_test_dsl_name(name: &str) -> bool {
        matches!(
            name,
            "context" | "describe" | "it" | "specify" | "suite" | "test"
        )
    }

    fn is_test_dsl_modifier(name: &str) -> bool {
        matches!(
            name,
            "concurrent" | "each" | "fails" | "only" | "serial" | "skip" | "todo"
        )
    }

    fn is_test_dsl_callee(node: tree_sitter::Node<'_>, source: &str) -> bool {
        match node.kind() {
            "identifier" => identifier_text(node, source).is_some_and(is_test_dsl_name),
            "member_expression" => {
                let Some(object) = node.child_by_field_name("object") else {
                    return false;
                };
                let Some(property) = node.child_by_field_name("property") else {
                    return false;
                };
                identifier_text(object, source).is_some_and(is_test_dsl_name)
                    && identifier_or_property_text(property, source)
                        .is_some_and(is_test_dsl_modifier)
            }
            // `test.each(cases)(name, callback)` has a call expression as its
            // outer callee. Retain the structured proof by following that
            // expression back to the known DSL member, without accepting an
            // arbitrary production call merely because it has a callback.
            "call_expression" => node
                .child_by_field_name("function")
                .is_some_and(|function| is_test_dsl_callee(function, source)),
            _ => false,
        }
    }

    fn has_callback_argument(node: tree_sitter::Node<'_>) -> bool {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return false;
        };
        arguments
            .named_children(&mut arguments.walk())
            .last()
            .is_some_and(|last| matches!(last.kind(), "arrow_function" | "function_expression"))
    }

    fn is_test_dsl_call(node: tree_sitter::Node<'_>, source: &str) -> bool {
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        is_test_dsl_callee(function, source) && has_callback_argument(node)
    }

    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" && is_test_dsl_call(node, source) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

/// Whether the parsed tree contains an ESLint-style RuleTester suite.
///
/// RuleTester files commonly live at `tests/lib/rules/foo.js`, which is not a
/// filename convention recognized by [`path_contains_tests`]. Their test
/// invocation is also a method call (`ruleTester.run`) rather than one of the
/// framework-global calls covered by [`tree_contains_test_dsl_calls`]. Keep this
/// recognition structural: establish a RuleTester import, find a local
/// constructed tester, and then require its `.run()` call.
fn rule_tester_suite_contains_tests(tree: &tree_sitter::Tree, source: &str) -> bool {
    fn identifier_text<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<&'a str> {
        (node.kind() == "identifier")
            .then(|| node.utf8_text(source.as_bytes()).ok())
            .flatten()
    }

    fn property_text<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<&'a str> {
        (node.kind() == "property_identifier")
            .then(|| node.utf8_text(source.as_bytes()).ok())
            .flatten()
    }

    fn is_require_call(node: tree_sitter::Node<'_>, source: &str) -> bool {
        node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .and_then(|function| identifier_text(function, source))
                == Some("require")
    }

    fn string_fragment<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<&'a str> {
        (node.kind() == "string")
            .then(|| node.named_child(0))
            .flatten()
            .filter(|child| child.kind() == "string_fragment")
            .and_then(|child| child.utf8_text(source.as_bytes()).ok())
    }

    fn require_module<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<&'a str> {
        if !is_require_call(node, source) {
            return None;
        }
        let argument = node.child_by_field_name("arguments")?.named_child(0)?;
        string_fragment(argument, source)
    }

    fn is_rule_tester_module(module: &str) -> bool {
        module == "eslint"
            || module.ends_with("/rule-tester")
            || module.ends_with("/rule-tester/rule-tester")
    }

    fn add_destructured_rule_tester_bindings(
        pattern: tree_sitter::Node<'_>,
        source: &str,
        bindings: &mut HashSet<String>,
    ) {
        if pattern.kind() != "object_pattern" {
            return;
        }
        let mut cursor = pattern.walk();
        for child in pattern.named_children(&mut cursor) {
            if child.kind() == "shorthand_property_identifier_pattern"
                && child.utf8_text(source.as_bytes()).ok() == Some("RuleTester")
            {
                bindings.insert("RuleTester".to_string());
            } else if child.kind() == "pair_pattern"
                && child
                    .child_by_field_name("key")
                    .and_then(|key| key.utf8_text(source.as_bytes()).ok())
                    == Some("RuleTester")
                && let Some(value) = child
                    .child_by_field_name("value")
                    .and_then(|value| identifier_text(value, source))
            {
                bindings.insert(value.to_string());
            }
        }
    }

    let mut nodes = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
        nodes.push(node);
    }

    let mut rule_tester_bindings = HashSet::default();
    for node in &nodes {
        if node.kind() == "variable_declarator" {
            let Some(name) = node.child_by_field_name("name") else {
                continue;
            };
            let Some(value) = node.child_by_field_name("value") else {
                continue;
            };
            let is_rule_tester_value = require_module(value, source)
                .is_some_and(is_rule_tester_module)
                || (value.kind() == "member_expression"
                    && value
                        .child_by_field_name("property")
                        .and_then(|property| property.utf8_text(source.as_bytes()).ok())
                        == Some("RuleTester")
                    && value
                        .child_by_field_name("object")
                        .and_then(|object| require_module(object, source))
                        .is_some_and(is_rule_tester_module));
            if is_rule_tester_value {
                if identifier_text(name, source) == Some("RuleTester") {
                    rule_tester_bindings.insert("RuleTester".to_string());
                }
                add_destructured_rule_tester_bindings(name, source, &mut rule_tester_bindings);
            }
        }

        if node.kind() != "import_statement" {
            continue;
        }
        let Some(module) = node
            .child_by_field_name("source")
            .and_then(|source_node| string_fragment(source_node, source))
        else {
            continue;
        };
        if !is_rule_tester_module(module) {
            continue;
        }
        let import_clause = node
            .named_children(&mut node.walk())
            .find(|child| child.kind() == "import_clause");
        if let Some(import_clause) = import_clause {
            let mut clause_cursor = import_clause.walk();
            for child in import_clause.named_children(&mut clause_cursor) {
                if child.kind() == "identifier"
                    && child.utf8_text(source.as_bytes()).ok() == Some("RuleTester")
                {
                    rule_tester_bindings.insert("RuleTester".to_string());
                }
            }
        }
        let mut import_stack = vec![*node];
        while let Some(import_node) = import_stack.pop() {
            let mut cursor = import_node.walk();
            import_stack.extend(import_node.named_children(&mut cursor));
            if import_node.kind() != "import_specifier" {
                continue;
            }
            let Some(imported) = import_node
                .child_by_field_name("name")
                .and_then(|name| identifier_text(name, source))
            else {
                continue;
            };
            if imported != "RuleTester" {
                continue;
            }
            let local = import_node
                .child_by_field_name("alias")
                .and_then(|alias| identifier_text(alias, source))
                .unwrap_or(imported);
            rule_tester_bindings.insert(local.to_string());
        }
    }

    if rule_tester_bindings.is_empty() {
        return false;
    }

    let tester_bindings: HashSet<String> = nodes
        .iter()
        .filter_map(|node| {
            if node.kind() != "variable_declarator" {
                return None;
            }
            let name = node.child_by_field_name("name")?;
            let value = node.child_by_field_name("value")?;
            let constructor = value
                .kind()
                .eq("new_expression")
                .then(|| value.child_by_field_name("constructor"))
                .flatten()?;
            let constructor_name = identifier_text(constructor, source)?;
            let binding_name = identifier_text(name, source)?;
            rule_tester_bindings
                .contains(constructor_name)
                .then(|| binding_name.to_string())
        })
        .collect();

    if tester_bindings.is_empty() {
        return false;
    }

    nodes.iter().any(|node| {
        if node.kind() != "call_expression" {
            return false;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        if function.kind() != "member_expression" {
            return false;
        }
        let Some(object) = function.child_by_field_name("object") else {
            return false;
        };
        let Some(property) = function.child_by_field_name("property") else {
            return false;
        };
        property_text(property, source) == Some("run")
            && tester_bindings.contains(identifier_text(object, source).unwrap_or_default())
    })
}

fn has_strong_test_root(file: &ProjectFile) -> bool {
    let rel = crate::path_utils::rel_path_string(file);
    Path::new(&rel).components().any(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        let name = name.to_string_lossy();
        name.eq_ignore_ascii_case("test")
            || name.eq_ignore_ascii_case("tests")
            || name.eq_ignore_ascii_case("__tests__")
            || name.eq_ignore_ascii_case("spec")
            || name.eq_ignore_ascii_case("specs")
    })
}

fn has_node_test_filename(file: &ProjectFile) -> bool {
    let Some(file_name) = file.rel_path().file_name() else {
        return false;
    };
    let Some(extension) = file.rel_path().extension() else {
        return false;
    };
    let file_name = file_name.to_string_lossy();
    let extension = extension.to_string_lossy();
    let node_extension = extension.eq_ignore_ascii_case("js")
        || extension.eq_ignore_ascii_case("mjs")
        || extension.eq_ignore_ascii_case("cjs");
    node_extension
        && (file_name
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("test-"))
            || file_name
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("test_")))
}

pub(crate) fn path_contains_tests(file: &ProjectFile) -> bool {
    let Some(file_name) = file.rel_path().file_name() else {
        return false;
    };
    let file_name = file_name.to_string_lossy().to_ascii_lowercase();
    // Keep the existing suffix conventions for all JS/TS layouts. Node's
    // `test-*.js`/`test_*.js` convention is intentionally narrower: those
    // names are accepted only below a strong test root. In particular,
    // `testData/`, `fixtures/`, and arbitrary production directories do not
    // become test roots merely because a file starts with `test-`.
    file_name.contains(".test.")
        || file_name.contains(".spec.")
        || (has_strong_test_root(file) && has_node_test_filename(file))
}

pub(crate) fn contains_tests(file: &ProjectFile, source: &str, tree: &tree_sitter::Tree) -> bool {
    path_contains_tests(file)
        || tree_contains_test_dsl_calls(tree, source)
        || rule_tester_suite_contains_tests(tree, source)
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
    if binder.has_competing_static_imports(owner) || binder.was_truncated(owner) {
        return None;
    }
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

    /// An `export default ...` statement names its declaration with the `default`
    /// keyword, which both grammars spell as an anonymous token the named-children
    /// search cannot see (#2733).
    fn declaration_name_node<'t>(
        &self,
        declaration: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        js_ts_declaration_name(declaration)
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

    /// Same anonymous `default` keyword as JavaScript: the TS and TSX grammars
    /// share the `export_statement` shape with tree-sitter-javascript (#2733).
    fn declaration_name_node<'t>(
        &self,
        declaration: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        js_ts_declaration_name(declaration)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("javascript grammar");
        parser.parse(source, None).expect("javascript tree")
    }

    fn parse_typescript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("typescript grammar");
        parser.parse(source, None).expect("typescript tree")
    }

    #[test]
    fn rule_tester_commonjs_suite_is_structurally_a_test() {
        let source = r#"
const RuleTester = require("../../../lib/rule-tester/rule-tester");
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, { valid: [], invalid: [] });
"#;
        let tree = parse_javascript(source);
        assert!(contains_tests(
            &ProjectFile::new("/tmp/project", "tests/lib/rules/rule.js"),
            source,
            &tree
        ));
    }

    #[test]
    fn rule_tester_suite_detection_is_shared_with_typescript() {
        let source = r#"
const RuleTester = require("eslint");
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, { valid: [], invalid: [] });
"#;
        let tree = parse_typescript(source);
        assert!(contains_tests(
            &ProjectFile::new("/tmp/project", "tests/lib/rules/rule.ts"),
            source,
            &tree
        ));

        let import_source = r#"import { RuleTester } from "eslint";
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, {});
"#;
        let import_tree = parse_typescript(import_source);
        assert!(rule_tester_suite_contains_tests(
            &import_tree,
            import_source
        ));
        let destructured_source = r#"const { RuleTester } = require("eslint");
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, {});
"#;
        let destructured_tree = parse_javascript(destructured_source);
        assert!(rule_tester_suite_contains_tests(
            &destructured_tree,
            destructured_source
        ));

        let member_source = r#"const RuleTester = require("eslint").RuleTester;
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, {});
"#;
        let member_tree = parse_javascript(member_source);
        assert!(rule_tester_suite_contains_tests(
            &member_tree,
            member_source
        ));

        let aliased_source = r#"const { RuleTester: RT } = require("eslint");
const tester = new RT({});
tester.run("rule", rule, {});
"#;
        let aliased_tree = parse_javascript(aliased_source);
        assert!(rule_tester_suite_contains_tests(
            &aliased_tree,
            aliased_source
        ));

        let default_source = r#"import RuleTester from "eslint";
const tester = new RuleTester({});
tester.run("rule", rule, {});
"#;
        let default_tree = parse_typescript(default_source);
        assert!(rule_tester_suite_contains_tests(
            &default_tree,
            default_source
        ));
    }

    #[test]
    fn rule_tester_detection_rejects_unrelated_bindings_and_text() {
        let cases = [
            r#"
const RuleTester = require("rule-tester");
const worker = new OtherTester({});
worker.run("rule", rule, {});
"#,
            r#"
const RuleTester = require("unrelated");
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, {});
"#,
            r#"
const RuleTester = require("rule-tester");
const ruleTester = new RuleTester({});
worker.run("rule", rule, {});
"#,
            r#"
// const RuleTester = require("rule-tester"); ruleTester.run("not a suite");
const text = "new RuleTester({}); ruleTester.run()";
"#,
            r#"
const RuleTester = require("rule-tester");
const ruleTester = new RuleTester({});
ruleTester["run"]("rule", rule, {});
"#,
            r#"
const RuleTester = require("not-eslint").RuleTester;
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, {});
"#,
            r#"
const { OtherTester: RuleTester } = require("eslint");
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, {});
"#,
            r#"
import RuleTester from "not-eslint";
const ruleTester = new RuleTester({});
ruleTester.run("rule", rule, {});
"#,
        ];

        for source in cases {
            let tree = parse_javascript(source);
            assert!(!rule_tester_suite_contains_tests(&tree, source), "{source}");
        }
    }

    #[test]
    fn test_dsl_detection_uses_call_structure_and_callback_shape() {
        let positive_sources = [
            r#"describe("suite", () => {});"#,
            r#"test("case", function () {});"#,
            r#"it.only("case", async () => {});"#,
            r#"test.each(cases)("case", () => {});"#,
            r#"suite("suite", () => {});"#,
        ];
        for source in positive_sources {
            let tree = parse_javascript(source);
            assert!(tree_contains_test_dsl_calls(&tree, source), "{source}");
        }

        let near_miss_sources = [
            // These ordinary production callees themselves contain the old
            // `it(` source-search needle at the end of their identifiers.
            r#"emit("event", () => {});"#,
            r#"init("runtime", () => {});"#,
            r#"split("value", () => {});"#,
            r#"const text = "describe(";"#,
            // A same-named helper without a test callback is not a DSL
            // declaration.
            r#"test("ordinary helper");"#,
        ];
        for source in near_miss_sources {
            let tree = parse_javascript(source);
            assert!(!tree_contains_test_dsl_calls(&tree, source), "{source}");
        }
    }

    #[test]
    fn node_test_filename_requires_a_strong_test_root() {
        let production = "module.exports = function init(value) { return value; };";
        let cases = [
            ("test/parallel/test-http.js", true),
            ("test/parallel/test_http.js", true),
            ("test/embedding/test-api.mjs", true),
            ("testData/parallel/test-http.js", false),
            ("fixtures/test-http.js", false),
            ("lib/test-http.js", false),
            ("src/test-http.js", false),
            ("test/parallel/helper.js", false),
            ("test/parallel/test-http.ts", false),
        ];
        for (path, expected) in cases {
            let file = ProjectFile::new("/tmp/project", path);
            let tree = parse_javascript(production);
            assert_eq!(contains_tests(&file, production, &tree), expected, "{path}");
        }
    }

    #[test]
    fn conventional_test_suffixes_remain_supported_without_source_text() {
        for path in ["src/parser.test.js", "src/parser.spec.ts"] {
            let file = ProjectFile::new("/tmp/project", path);
            let tree = parse_javascript("");
            assert!(contains_tests(&file, "", &tree), "{path}");
        }
    }
}
