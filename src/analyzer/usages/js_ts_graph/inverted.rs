//! Whole-workspace inverted edge builder for JavaScript / TypeScript.
//!
//! The per-symbol path scans every importer of a symbol once per symbol; this
//! walks each file once and resolves every reference to the callee it names, via
//! the shared [`build_edges`] driver. JS/TS node fqns are bare names (`Anchor`,
//! `AxisDomain.constructor`), so resolving a reference means finding the exported
//! name it binds to:
//!
//! - a bare identifier bound by a named import resolves to the import's *exported*
//!   name; bound by a same-file declaration, to that name;
//! - `ns.member` where `ns` is a namespace import resolves to `member`;
//! - `Class.member` where `Class` is an imported/same-file class resolves to
//!   `Class.member`.
//!
//! Local variables and parameters shadow imports/declarations and are skipped.
//! Default-import and instance-typed-receiver resolution are not handled yet (they
//! need module/default-export and type inference); those references are simply not
//! emitted, mirroring a recall gap rather than a wrong edge.

use super::extractor::{
    compute_import_binder, is_declaration_identifier, is_object_in_member_expression,
    is_property_key_in_member, rightmost_jsx_identifier, slice,
};
use super::resolver::JsTsProjectGraph;
use crate::analyzer::usages::inverted_edges::{EdgeCollector, UsageEdges, build_edges};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::ImportKind;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// Build every JS/TS `caller -> callee` edge in one pass over the project graph,
/// using the shared [`build_edges`] driver for all the language-agnostic accounting.
pub(super) fn build_jsts_edges<F>(
    analyzer: &dyn IAnalyzer,
    graph: &JsTsProjectGraph,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = graph.parsed.keys().cloned().collect();
    build_edges(
        analyzer,
        &files,
        nodes,
        keep_file,
        |file| {
            graph
                .parsed
                .get(file)
                .map(|parsed| parsed.line_starts.as_slice())
        },
        |file, collector| {
            let Some(parsed) = graph.parsed.get(file) else {
                return;
            };
            let source = parsed.source.as_str();

            // Per-file resolution context: which bare names resolve to which
            // exported name, and which locals are namespace imports.
            let binder = compute_import_binder(source, &parsed.tree);
            let mut named_imports: HashMap<String, String> = HashMap::default();
            let mut namespace_locals: HashSet<String> = HashSet::default();
            for (local, binding) in &binder.bindings {
                match binding.kind {
                    ImportKind::Named => {
                        named_imports.insert(
                            local.clone(),
                            binding
                                .imported_name
                                .clone()
                                .unwrap_or_else(|| local.clone()),
                        );
                    }
                    ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => {
                        namespace_locals.insert(local.clone());
                    }
                    // Default imports need the target module's default-export name.
                    ImportKind::Default => {}
                }
            }
            let same_file: HashSet<String> = analyzer
                .declarations(file)
                .map(|unit| unit.identifier().to_string())
                .collect();

            let mut ctx = TsScan {
                source,
                named_imports,
                namespace_locals,
                same_file,
                collector,
            };
            let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
            scan_node(parsed.tree.root_node(), &mut ctx, &mut locals);
        },
    )
}

struct TsScan<'a, 'b> {
    source: &'a str,
    named_imports: HashMap<String, String>,
    namespace_locals: HashSet<String>,
    same_file: HashSet<String>,
    collector: &'a mut EdgeCollector<'b>,
}

impl TsScan<'_, '_> {
    /// The callee fqn a bare name refers to: a named import's exported name, or a
    /// same-file declaration's own name. `None` when the name is neither.
    fn bare_callee(&self, text: &str) -> Option<String> {
        if let Some(exported) = self.named_imports.get(text) {
            return Some(exported.clone());
        }
        if self.same_file.contains(text) {
            return Some(text.to_string());
        }
        None
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

fn scan_node(node: Node<'_>, ctx: &mut TsScan<'_, '_>, locals: &mut LocalInferenceEngine<String>) {
    let kind = node.kind();
    let introduces_scope = matches!(
        kind,
        "statement_block"
            | "arrow_function"
            | "function_expression"
            | "generator_function"
            | "function_declaration"
            | "method_definition"
    );
    if introduces_scope {
        locals.enter_scope();
        if let Some(parameters) = node.child_by_field_name("parameters") {
            declare_pattern_shadows(parameters, ctx.source, locals);
        }
    }

    // Bindings declared in import/export clauses are not usages.
    if matches!(
        kind,
        "import_statement"
            | "import_clause"
            | "import_specifier"
            | "namespace_import"
            | "export_clause"
            | "export_specifier"
    ) {
        if introduces_scope {
            locals.exit_scope();
        }
        return;
    }

    if kind == "variable_declarator"
        && let Some(name) = node.child_by_field_name("name")
    {
        declare_pattern_shadows(name, ctx.source, locals);
    }

    match kind {
        "identifier" | "type_identifier" | "shorthand_property_identifier" => {
            handle_identifier(node, ctx, locals)
        }
        "member_expression" => handle_member(node, ctx, locals),
        "jsx_opening_element" | "jsx_self_closing_element" => handle_jsx(node, ctx, locals),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx, locals);
    }

    if introduces_scope {
        locals.exit_scope();
    }
}

/// Declare every identifier bound by a parameter / declaration pattern as a local
/// shadow, so later references to those names are not mistaken for imports.
fn declare_pattern_shadows(
    node: Node<'_>,
    source: &str,
    locals: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            let text = slice(node, source);
            if !text.is_empty() {
                locals.declare_shadow(text.to_string());
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                declare_pattern_shadows(child, source, locals);
            }
        }
    }
}

fn handle_identifier(
    node: Node<'_>,
    ctx: &mut TsScan<'_, '_>,
    locals: &LocalInferenceEngine<String>,
) {
    let text = slice(node, ctx.source);
    if text.is_empty() || locals.is_shadowed(text) {
        return;
    }
    if is_declaration_identifier(node)
        || is_property_key_in_member(node)
        || is_object_in_member_expression(node)
    {
        return;
    }
    if let Some(callee) = ctx.bare_callee(text) {
        ctx.record(callee, node);
    }
}

fn handle_member(node: Node<'_>, ctx: &mut TsScan<'_, '_>, locals: &LocalInferenceEngine<String>) {
    let (Some(object), Some(property)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("property"),
    ) else {
        return;
    };
    if object.kind() != "identifier" {
        return;
    }
    let object_text = slice(object, ctx.source);
    let property_text = slice(property, ctx.source);
    if object_text.is_empty() || property_text.is_empty() || locals.is_shadowed(object_text) {
        return;
    }

    // `ns.member` — namespace import access resolves to the exported member.
    if ctx.namespace_locals.contains(object_text) {
        ctx.record(property_text.to_string(), property);
        return;
    }
    // `Class.member` — static access on an imported / same-file class resolves to
    // the member's `Owner.member` fqn.
    if let Some(class) = ctx.bare_callee(object_text) {
        ctx.record(format!("{class}.{property_text}"), property);
    }
}

fn handle_jsx(node: Node<'_>, ctx: &mut TsScan<'_, '_>, locals: &LocalInferenceEngine<String>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some((rightmost, leaf_text)) = rightmost_jsx_identifier(name_node, ctx.source) else {
        return;
    };
    if leaf_text.is_empty() || locals.is_shadowed(leaf_text) {
        return;
    }
    if let Some(callee) = ctx.bare_callee(leaf_text) {
        ctx.record(callee, rightmost);
    }
}
