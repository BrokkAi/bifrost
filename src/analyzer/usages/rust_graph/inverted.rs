//! Whole-workspace inverted edge builder for Rust.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Rust node fqns are dotted module paths
//! (`util.format_value`, `service.Service`, `service.Service.new`), so a
//! reference resolves through the file's import binder plus the path arithmetic
//! in [`RustAnalyzer::resolve_module_package`]:
//!
//! - a `use crate::util::format_value;` binding resolves a bare `format_value`
//!   to `util.format_value`;
//! - a `use crate::util;` namespace binding resolves `util::format_value` to
//!   `util.format_value`;
//! - a `Type::assoc` path resolves through the type's import / same-file fqn to
//!   `module.Type.assoc`;
//! - a same-file item resolves to that declaration's fqn.
//!
//! Parameters and `let` bindings shadow same-named imports/items within the
//! function that introduces them, so a local named like an import does not
//! produce a false edge (more precise than the forward scan, which shadows
//! `let`/item names but never parameters). Instance-method dispatch
//! (`recv.method()`) needs receiver type inference and is not resolved here — a
//! recall gap, not a wrong edge.

use crate::analyzer::usages::inverted_edges::{EdgeCollector, UsageEdges, build_edges};
use crate::analyzer::{IAnalyzer, ProjectFile, RustAnalyzer, RustReferenceContext};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use std::sync::Arc;
use tree_sitter::{Node, Parser, Tree};

/// A Rust file parsed once for the inverted scan: source, tree, and line starts.
struct ParsedFile {
    source: String,
    tree: Tree,
    line_starts: Vec<usize>,
}

/// Build the whole Rust `caller -> callee` edge set in a single inverted pass.
pub(super) fn build_rust_edges<F>(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = rust.get_analyzed_files().into_iter().collect();
    let parsed: HashMap<ProjectFile, ParsedFile> = files
        .par_iter()
        .filter(|file| keep_file(file))
        .filter_map(|file| {
            let source = file.read_to_string().ok()?;
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .ok()?;
            let tree = parser.parse(source.as_str(), None)?;
            let line_starts = compute_line_starts(&source);
            Some((
                file.clone(),
                ParsedFile {
                    source,
                    tree,
                    line_starts,
                },
            ))
        })
        .collect();

    build_edges(
        analyzer,
        &files,
        nodes,
        keep_file,
        |file| parsed.get(file).map(|parsed| parsed.line_starts.as_slice()),
        |file, collector| {
            let Some(parsed) = parsed.get(file) else {
                return;
            };
            let source = parsed.source.as_str();

            // One shared, cached per-file resolution context. Both this inverted
            // builder and (from Phase 1b) the forward scan resolve references
            // through it, so the two paths can't drift.
            let refs = rust.reference_context_of(file);
            let mut ctx = RustScan {
                source,
                refs,
                collector,
            };
            let mut shadows: Vec<HashSet<String>> = Vec::new();
            walk(parsed.tree.root_node(), &mut ctx, &mut shadows);
        },
    )
}

struct RustScan<'a, 'b> {
    source: &'a str,
    refs: Arc<RustReferenceContext>,
    collector: &'a mut EdgeCollector<'b>,
}

impl RustScan<'_, '_> {
    /// The callee fqn a bare name refers to: a named import, a same-file item,
    /// or a free function imported via `use path::func;` — which the binder's
    /// snake_case heuristic classifies as a namespace whose resolved value is the
    /// function's own fqn (it only forms an edge when that value is a real node).
    fn bare_callee(&self, text: &str) -> Option<String> {
        self.refs.resolve_bare(text).map(str::to_string)
    }

    /// The callee fqn a `path::name` refers to: a module function via a namespace
    /// import, or an associated function on an imported / same-file type.
    fn scoped_callee(&self, path: &str, name: &str) -> Option<String> {
        self.refs.resolve_scoped(path, name)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

fn walk(node: Node<'_>, ctx: &mut RustScan<'_, '_>, shadows: &mut Vec<HashSet<String>>) {
    match node.kind() {
        "use_declaration" => return,
        // A function or closure opens a scope; its parameters and `let` bindings
        // are local to it and shadow same-named imports/items.
        "function_item" | "closure_expression" => {
            shadows.push(collect_scope_locals(node, ctx.source));
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk(child, ctx, shadows);
            }
            shadows.pop();
            return;
        }
        "identifier" | "type_identifier" => handle_identifier(node, ctx, shadows),
        "scoped_identifier" | "scoped_type_identifier" => handle_scoped(node, ctx, shadows),
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

fn handle_identifier(node: Node<'_>, ctx: &mut RustScan<'_, '_>, shadows: &[HashSet<String>]) {
    // The path/name parts of a scoped path are resolved by handle_scoped.
    if node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        )
    }) {
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

fn handle_scoped(node: Node<'_>, ctx: &mut RustScan<'_, '_>, shadows: &[HashSet<String>]) {
    let (Some(path), Some(name)) = (
        node.child_by_field_name("path"),
        node.child_by_field_name("name"),
    ) else {
        return;
    };
    let path_text = slice(path, ctx.source);
    let name_text = slice(name, ctx.source);
    if path_text.is_empty() || name_text.is_empty() || is_shadowed(shadows, path_text) {
        return;
    }
    if let Some(callee) = ctx.scoped_callee(path_text, name_text) {
        ctx.record(callee, name);
    }
}

/// The local names a function/closure binds: its parameters plus every `let`
/// binding in its body. Nested function/closure scopes are skipped — they get
/// their own frame.
fn collect_scope_locals(scope: Node<'_>, source: &str) -> HashSet<String> {
    let mut locals = HashSet::default();
    if let Some(params) = scope.child_by_field_name("parameters") {
        collect_param_patterns(params, source, &mut locals);
    }
    if let Some(body) = scope.child_by_field_name("body") {
        collect_let_bindings(body, source, &mut locals);
    }
    locals
}

/// Collect the binding names of a `parameters`/`closure_parameters` list, taking
/// only each parameter's pattern (not its type annotation, which would otherwise
/// shadow an imported type).
fn collect_param_patterns(params: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        match child.kind() {
            "self_parameter" => {}
            "parameter" => {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    collect_pattern_bindings(pattern, source, out);
                }
            }
            // Unannotated closure parameters are bare patterns.
            _ => collect_pattern_bindings(child, source, out),
        }
    }
}

/// Collect `let`-bound names in a scope, without descending into nested
/// function/closure scopes.
fn collect_let_bindings(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_item" | "closure_expression" => continue,
            "let_declaration" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    collect_pattern_bindings(pattern, source, out);
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

fn collect_pattern_bindings(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            let text = slice(node, source);
            if !text.is_empty() {
                out.insert(text.to_string());
            }
            continue;
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
