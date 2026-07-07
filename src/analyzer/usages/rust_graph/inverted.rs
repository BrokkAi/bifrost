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
//! (`recv.method()`) resolves only when a local receiver fact proves the receiver
//! type, such as `let recv = Service::new()` or `let recv = make_service()`.

use super::extractor::{first_generic_type_argument, type_node_last_segment};
use crate::analyzer::usages::inverted_edges::{
    EdgeCollector, UsageEdges, build_edges, parse_and_collect,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use crate::analyzer::{
    DefinitionLookupIndex, IAnalyzer, ProjectFile, RustAnalyzer, RustReferenceContext,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

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
    let support = analyzer.definition_lookup_index();
    let language = tree_sitter_rust::LANGUAGE.into();
    build_edges(&files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            // One shared, cached per-file resolution context. Both this inverted
            // builder and (from Phase 1b) the forward scan resolve references
            // through it, so the two paths can't drift.
            let refs = rust.reference_context_of(file);
            let factory_returns = collect_factory_return_types(
                parsed.tree.root_node(),
                parsed.source.as_str(),
                &refs,
            );
            let mut ctx = RustScan {
                rust,
                support,
                file,
                source: parsed.source.as_str(),
                refs,
                factory_returns,
                collector,
            };
            let mut scopes: Vec<ScopeFacts> = Vec::new();
            walk(parsed.tree.root_node(), &mut ctx, &mut scopes);
        })
    })
}

struct RustScan<'a, 'b> {
    rust: &'a RustAnalyzer,
    support: &'a DefinitionLookupIndex,
    file: &'a ProjectFile,
    source: &'a str,
    refs: Arc<RustReferenceContext>,
    factory_returns: HashMap<String, String>,
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
        match super::resolve_scoped_associated_item(
            self.rust,
            self.support,
            &self.refs,
            self.file,
            path,
            name,
        ) {
            ReceiverAnalysisOutcome::Precise(mut candidates) if candidates.len() == 1 => {
                candidates.pop().map(|candidate| candidate.fq_name())
            }
            ReceiverAnalysisOutcome::Precise(_)
            | ReceiverAnalysisOutcome::Ambiguous(_)
            | ReceiverAnalysisOutcome::Unknown
            | ReceiverAnalysisOutcome::Unsupported { .. }
            | ReceiverAnalysisOutcome::ExceededBudget { .. } => None,
        }
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.collector
            .record_unproven_name(name, node.start_byte(), node.end_byte());
    }
}

#[derive(Default)]
struct ScopeFacts {
    shadows: HashSet<String>,
    receiver_types: HashMap<String, String>,
}

fn walk(node: Node<'_>, ctx: &mut RustScan<'_, '_>, scopes: &mut Vec<ScopeFacts>) {
    let mut stack = vec![WalkFrame::Enter(node)];
    while let Some(frame) = stack.pop() {
        match frame {
            WalkFrame::Enter(node) => match node.kind() {
                "use_declaration" => {}
                // A function or closure opens a parameter scope. `let` bindings
                // are seeded incrementally when traversal reaches them so later
                // shadowing cannot type earlier receiver calls.
                "function_item" | "closure_expression" => {
                    scopes.push(collect_parameter_scope_facts(node, ctx));
                    stack.push(WalkFrame::ExitScope);
                    push_children(node, &mut stack);
                }
                "block" => {
                    scopes.push(ScopeFacts::default());
                    stack.push(WalkFrame::ExitScope);
                    push_children(node, &mut stack);
                }
                "let_declaration" => {
                    handle_let_declaration(node, ctx, scopes);
                    push_children(node, &mut stack);
                }
                "call_expression" => {
                    handle_method_call(node, ctx, scopes);
                    push_children(node, &mut stack);
                }
                "identifier" | "type_identifier" => {
                    handle_identifier(node, ctx, scopes);
                    push_children(node, &mut stack);
                }
                "scoped_identifier" | "scoped_type_identifier" => {
                    handle_scoped(node, ctx, scopes);
                    push_children(node, &mut stack);
                }
                _ => push_children(node, &mut stack),
            },
            WalkFrame::ExitScope => {
                scopes.pop();
            }
        }
    }
}

enum WalkFrame<'tree> {
    Enter(Node<'tree>),
    ExitScope,
}

fn push_children<'tree>(node: Node<'tree>, stack: &mut Vec<WalkFrame<'tree>>) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(WalkFrame::Enter(child));
        }
    }
}

fn is_shadowed(scopes: &[ScopeFacts], name: &str) -> bool {
    scopes.iter().any(|scope| scope.shadows.contains(name))
}

fn receiver_type(scopes: &[ScopeFacts], name: &str) -> Option<String> {
    scopes
        .iter()
        .rev()
        .find_map(|scope| scope.receiver_types.get(name).cloned())
}

fn handle_identifier(node: Node<'_>, ctx: &mut RustScan<'_, '_>, scopes: &[ScopeFacts]) {
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
    if text.is_empty() || is_shadowed(scopes, text) {
        return;
    }
    if let Some(callee) = ctx.bare_callee(text) {
        ctx.record(callee, node);
    }
}

fn handle_scoped(node: Node<'_>, ctx: &mut RustScan<'_, '_>, scopes: &[ScopeFacts]) {
    let (Some(path), Some(name)) = (
        node.child_by_field_name("path"),
        node.child_by_field_name("name"),
    ) else {
        return;
    };
    let path_text = slice(path, ctx.source);
    let name_text = slice(name, ctx.source);
    if path_text.is_empty() || name_text.is_empty() || is_shadowed(scopes, path_text) {
        return;
    }
    if let Some(callee) = ctx.scoped_callee(path_text, name_text) {
        ctx.record(callee, name);
    }
}

fn handle_method_call(node: Node<'_>, ctx: &mut RustScan<'_, '_>, scopes: &[ScopeFacts]) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    if function.kind() != "field_expression" {
        return;
    }
    let (Some(receiver), Some(field)) = (
        function.child_by_field_name("value"),
        function.child_by_field_name("field"),
    ) else {
        return;
    };
    let receiver_name = slice(receiver, ctx.source);
    let method_name = slice(field, ctx.source);
    if receiver_name.is_empty() || method_name.is_empty() {
        return;
    }
    if let Some(owner) = receiver_type(scopes, receiver_name) {
        ctx.record(format!("{owner}.{method_name}"), field);
    } else {
        ctx.record_unproven(method_name, field);
    }
}

/// The local names a function/closure binds through its parameters. `let`
/// bindings are handled incrementally by `handle_let_declaration`.
fn collect_parameter_scope_facts(scope: Node<'_>, ctx: &RustScan<'_, '_>) -> ScopeFacts {
    let mut facts = ScopeFacts::default();
    if let Some(params) = scope.child_by_field_name("parameters") {
        collect_param_patterns(params, ctx.source, &mut facts.shadows);
        collect_typed_params(params, ctx, &mut facts.receiver_types);
    }
    facts
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

fn handle_let_declaration(node: Node<'_>, ctx: &RustScan<'_, '_>, scopes: &mut [ScopeFacts]) {
    let Some(scope) = scopes.last_mut() else {
        return;
    };
    if let Some(pattern) = node.child_by_field_name("pattern") {
        collect_pattern_bindings(pattern, ctx.source, &mut scope.shadows);
        collect_let_receiver_type(node, ctx, &mut scope.receiver_types);
    }
}

fn collect_typed_params(
    params: Node<'_>,
    ctx: &RustScan<'_, '_>,
    receiver_types: &mut HashMap<String, String>,
) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let Some(pattern) = child.child_by_field_name("pattern") else {
            continue;
        };
        let Some(name) = simple_pattern_name(pattern, ctx.source) else {
            continue;
        };
        let Some(type_node) = child.child_by_field_name("type") else {
            continue;
        };
        if let Some(fqn) = type_node_fqn(type_node, ctx) {
            receiver_types.insert(name, fqn);
        }
    }
}

fn collect_let_receiver_type(
    node: Node<'_>,
    ctx: &RustScan<'_, '_>,
    receiver_types: &mut HashMap<String, String>,
) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(name) = simple_pattern_name(pattern, ctx.source) else {
        return;
    };
    if let Some(type_node) = node.child_by_field_name("type")
        && let Some(fqn) = type_node_fqn(type_node, ctx)
    {
        receiver_types.insert(name, fqn);
        return;
    }
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    if let Some(fqn) = expression_receiver_type(value, ctx) {
        receiver_types.insert(name, fqn);
    }
}

fn expression_receiver_type(node: Node<'_>, ctx: &RustScan<'_, '_>) -> Option<String> {
    match node.kind() {
        "struct_expression" => node
            .child_by_field_name("name")
            .and_then(|name| type_node_fqn(name, ctx)),
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            callable_return_type(function, ctx)
        }
        _ => None,
    }
}

fn callable_return_type(function: Node<'_>, ctx: &RustScan<'_, '_>) -> Option<String> {
    match function.kind() {
        "identifier" => {
            let name = slice(function, ctx.source);
            ctx.refs
                .resolve_bare(name)
                .and_then(|fqn| ctx.factory_returns.get(fqn).cloned())
        }
        "scoped_identifier" | "scoped_type_identifier" => {
            let path = function.child_by_field_name("path")?;
            let name = function.child_by_field_name("name")?;
            let path_text = slice(path, ctx.source);
            let name_text = slice(name, ctx.source);
            let callee = ctx.refs.resolve_scoped(path_text, name_text)?;
            ctx.factory_returns.get(&callee).cloned()
        }
        _ => None,
    }
}

fn collect_factory_return_types(
    root: Node<'_>,
    source: &str,
    refs: &RustReferenceContext,
) -> HashMap<String, String> {
    let mut returns = HashMap::default();
    let mut stack = vec![(root, None::<String>)];
    while let Some((node, impl_owner_fqn)) = stack.pop() {
        match node.kind() {
            "impl_item" => {
                let owner_fqn = node
                    .child_by_field_name("type")
                    .and_then(|type_node| type_node_fqn_with_impl(type_node, source, refs, None));
                push_children_with_impl(node, owner_fqn, &mut stack);
            }
            "function_item" => {
                let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| simple_node_text(name, source))
                else {
                    continue;
                };
                let Some(return_type) = function_return_type_node(node) else {
                    continue;
                };
                let Some(return_fqn) =
                    type_node_fqn_with_impl(return_type, source, refs, impl_owner_fqn.as_deref())
                else {
                    continue;
                };
                if let Some(owner_fqn) = impl_owner_fqn.as_ref() {
                    returns.insert(format!("{owner_fqn}.{name}"), return_fqn);
                } else if let Some(fqn) = refs.resolve_bare(&name) {
                    returns.insert(fqn.to_string(), return_fqn);
                }
            }
            _ => push_children_with_impl(node, impl_owner_fqn, &mut stack),
        }
    }
    returns
}

fn push_children_with_impl<'tree>(
    node: Node<'tree>,
    impl_owner_fqn: Option<String>,
    stack: &mut Vec<(Node<'tree>, Option<String>)>,
) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push((child, impl_owner_fqn.clone()));
        }
    }
}

fn function_return_type_node(function: Node<'_>) -> Option<Node<'_>> {
    if let Some(return_type) = function.child_by_field_name("return_type") {
        return Some(return_type);
    }

    let parameters = function.child_by_field_name("parameters")?;
    let body = function.child_by_field_name("body");
    let mut cursor = function.walk();
    function
        .named_children(&mut cursor)
        .filter(|child| child.start_byte() >= parameters.end_byte())
        .filter(|child| body.is_none_or(|body| !same_node(*child, body)))
        .find(|child| is_rust_type_node(*child))
}

fn type_node_fqn(type_node: Node<'_>, ctx: &RustScan<'_, '_>) -> Option<String> {
    type_node_fqn_with_impl(type_node, ctx.source, &ctx.refs, None)
}

fn type_node_fqn_with_impl(
    type_node: Node<'_>,
    source: &str,
    refs: &RustReferenceContext,
    impl_owner_fqn: Option<&str>,
) -> Option<String> {
    match type_node.kind() {
        "type_identifier" | "identifier" => {
            let name = simple_node_text(type_node, source)?;
            if name == "Self" {
                return impl_owner_fqn.map(str::to_string);
            }
            refs.resolve_bare(&name).map(str::to_string)
        }
        "scoped_type_identifier" | "scoped_identifier" => {
            let path = type_node
                .child_by_field_name("path")
                .and_then(|path| simple_node_text(path, source))?;
            let name = type_node
                .child_by_field_name("name")
                .and_then(|name| simple_node_text(name, source))?;
            refs.resolve_scoped(&path, &name)
        }
        "reference_type" | "pointer_type" => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(|child| type_node_fqn_with_impl(child, source, refs, impl_owner_fqn))
        }
        "generic_type" => {
            let base = type_node.child_by_field_name("type")?;
            let base_name = type_node_last_segment(base, source)?;
            if matches!(base_name.as_str(), "Box" | "Arc" | "Rc") {
                return first_generic_type_argument(type_node).and_then(|inner| {
                    type_node_fqn_with_impl(inner, source, refs, impl_owner_fqn)
                });
            }
            type_node_fqn_with_impl(base, source, refs, impl_owner_fqn)
        }
        _ => None,
    }
}

fn is_rust_type_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "type_identifier"
            | "identifier"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "generic_type"
            | "reference_type"
            | "pointer_type"
            | "array_type"
            | "slice_type"
            | "tuple_type"
            | "unit_type"
            | "never_type"
    )
}

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.id() == right.id()
}

fn simple_pattern_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "identifier").then(|| simple_node_text(node, source))?
}

fn simple_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = slice(node, source);
    (!text.is_empty()).then(|| text.to_string())
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
