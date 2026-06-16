//! Whole-workspace inverted edge builder for Python.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Python node fqns are dotted module
//! paths (`pkg.util.format_value`, `app.helper`), so a reference resolves through
//! the file's import binder:
//!
//! - a `from pkg.util import f` binding resolves a bare `f` to `pkg.util.f`;
//! - an `import pkg.util as u` binding resolves `u.f` to `pkg.util.f`;
//! - a same-file/same-module name resolves to that declaration's fqn.
//!
//! Parameters and local assignments shadow same-named imports and module-level
//! declarations (Python scopes are function-wide), matching the forward scan's
//! shadow handling so a local named like an import does not produce a false edge.
//! Instance-attribute (`self.method`) resolution is not handled — a recall gap
//! rather than a wrong edge.

use super::extractor::{
    PythonProjectGraph, collect_assigned_identifiers, is_declaration_identifier, slice,
};
use crate::analyzer::PythonAnalyzer;
use crate::analyzer::usages::inverted_edges::{EdgeCollector, UsageEdges, build_edges};
use crate::analyzer::usages::model::ImportKind;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// Build the whole Python `caller -> callee` edge set in a single inverted pass.
pub(super) fn build_python_edges<F>(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    graph: &PythonProjectGraph,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = graph.parsed_files().cloned().collect();
    build_edges(
        analyzer,
        &files,
        nodes,
        keep_file,
        |file| {
            graph
                .parsed_file(file)
                .map(|parsed| parsed.line_starts.as_slice())
        },
        |file, collector| {
            let Some(parsed) = graph.parsed_file(file) else {
                return;
            };
            let source = parsed.source.as_str();

            // Per-file resolution context from the import binder. A namespace
            // binding's module_specifier is either the full fqn (for
            // `from m import f`) or the module prefix (for `import m as u`); the
            // node-membership check downstream disambiguates which applies.
            let binder = py.import_binder_of(file);
            let mut named: HashMap<String, String> = HashMap::default();
            let mut namespace: HashMap<String, String> = HashMap::default();
            for (local, binding) in &binder.bindings {
                match binding.kind {
                    ImportKind::Named => {
                        if let Some(imported) = &binding.imported_name {
                            named.insert(
                                local.clone(),
                                format!("{}.{}", binding.module_specifier, imported),
                            );
                        }
                    }
                    ImportKind::Namespace => {
                        namespace.insert(local.clone(), binding.module_specifier.clone());
                    }
                    ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {}
                }
            }
            let same_file: HashMap<String, String> = analyzer
                .declarations(file)
                .map(|unit| (unit.identifier().to_string(), unit.fq_name()))
                .collect();

            let mut ctx = PyScan {
                source,
                named,
                namespace,
                same_file,
                collector,
            };
            scan_tree(parsed.tree.root_node(), &mut ctx);
        },
    )
}

struct PyScan<'a, 'b> {
    source: &'a str,
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, String>,
    collector: &'a mut EdgeCollector<'b>,
}

impl PyScan<'_, '_> {
    /// The callee fqn a bare name refers to: a named import, a namespace import of
    /// a symbol (module_specifier is the full fqn), or a same-file declaration.
    fn bare_callee(&self, text: &str) -> Option<String> {
        if let Some(fqn) = self.named.get(text) {
            return Some(fqn.clone());
        }
        if let Some(fqn) = self.namespace.get(text) {
            return Some(fqn.clone());
        }
        if let Some(fqn) = self.same_file.get(text) {
            return Some(fqn.clone());
        }
        None
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

fn scan_tree(root: Node<'_>, ctx: &mut PyScan<'_, '_>) {
    // A stack of in-scope local names, one frame per enclosing function. A name
    // bound in any frame shadows a same-named import/declaration.
    let mut shadows: Vec<HashSet<String>> = Vec::new();
    walk(root, ctx, &mut shadows);
}

fn walk(node: Node<'_>, ctx: &mut PyScan<'_, '_>, shadows: &mut Vec<HashSet<String>>) {
    match node.kind() {
        "import_statement" | "import_from_statement" => return,
        // A function (or lambda) opens a scope; its parameters and the names it
        // assigns are local throughout it, so collect them up front.
        "function_definition" | "lambda" => {
            shadows.push(collect_function_locals(node, ctx.source));
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk(child, ctx, shadows);
            }
            shadows.pop();
            return;
        }
        "identifier" => handle_identifier(node, ctx, shadows),
        "attribute" => handle_attribute(node, ctx, shadows),
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, ctx, shadows);
    }
}

fn is_shadowed(shadows: &[HashSet<String>], name: &str) -> bool {
    shadows.iter().any(|scope| scope.contains(name))
}

fn handle_identifier(node: Node<'_>, ctx: &mut PyScan<'_, '_>, shadows: &[HashSet<String>]) {
    // The object of an `attribute` is handled by handle_attribute.
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "attribute")
    {
        return;
    }
    if is_declaration_identifier(node) {
        return;
    }
    let text = slice(node, ctx.source);
    if text.is_empty() || is_shadowed(shadows, text) {
        return;
    }
    if let Some(callee) = ctx.bare_callee(text) {
        ctx.record(callee, node);
    }
}

fn handle_attribute(node: Node<'_>, ctx: &mut PyScan<'_, '_>, shadows: &[HashSet<String>]) {
    let (Some(object), Some(attribute)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("attribute"),
    ) else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let attribute_text = slice(attribute, ctx.source);
    if object_text.is_empty() || attribute_text.is_empty() {
        return;
    }
    // `module.symbol` where the object is a namespace import: the callee is the
    // module prefix plus the accessed attribute. A local of the same name as the
    // module shadows the import.
    if is_shadowed(shadows, object_text) {
        return;
    }
    if let Some(module) = ctx.namespace.get(object_text) {
        ctx.record(format!("{module}.{attribute_text}"), attribute);
    }
}

/// The local names a function binds: its parameters plus every name it assigns.
/// Python scoping is function-wide, so a name assigned anywhere in the body is
/// local throughout; nested function/class scopes are skipped (they get their
/// own frame), but the names they bind in *this* scope are kept.
fn collect_function_locals(func: Node<'_>, source: &str) -> HashSet<String> {
    let mut locals = HashSet::default();
    if let Some(params) = func.child_by_field_name("parameters") {
        collect_parameter_names(params, source, &mut locals);
    }
    if let Some(body) = func.child_by_field_name("body") {
        collect_bound_targets(body, source, &mut locals);
    }
    locals
}

fn collect_parameter_names(params: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        let name = match child.kind() {
            "identifier" => Some(child),
            // typed / default / splat parameters carry the binding either in a
            // `name` field or as their first identifier child.
            _ => child
                .child_by_field_name("name")
                .or_else(|| child.named_child(0).filter(|n| n.kind() == "identifier")),
        };
        if let Some(name) = name {
            let text = slice(name, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
        }
    }
}

/// Collect names bound by assignment within a scope, without descending into
/// nested function/class scopes (only the nested definition's own name is bound
/// here).
fn collect_bound_targets(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let text = slice(name, source).trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
                continue;
            }
            "lambda" => continue,
            "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                if let Some(left) = node.child_by_field_name("left") {
                    collect_assigned_identifiers(left, source, out);
                }
            }
            "named_expression" => {
                if let Some(name) = node.child_by_field_name("name") {
                    collect_assigned_identifiers(name, source, out);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}
