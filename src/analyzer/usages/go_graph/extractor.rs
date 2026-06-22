use crate::analyzer::usages::go_graph::hits::record_hit;
use crate::analyzer::usages::go_graph::resolver::{
    GoProjectGraph, ScanBindings, TargetSpec, TypeRef, node_text,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::HashSet;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::Mutex;
use tree_sitter::Node;

const OWNER_TOKEN: &str = "__go_target_owner__";

pub(super) fn scan_files_for_target(
    analyzer: &dyn IAnalyzer,
    graph: &GoProjectGraph,
    files: HashSet<ProjectFile>,
    spec: &TargetSpec,
) -> BTreeSet<UsageHit> {
    let hits = Mutex::new(BTreeSet::new());
    let files: Vec<_> = files.into_iter().collect();

    files.par_iter().for_each(|file| {
        let Some(parsed) = graph.parsed.get(file) else {
            return;
        };
        let source = parsed.source.as_str();
        // Necessary-condition pre-filter: any structured hit requires the target's
        // identifier (or, for a method, its owner type name) to appear textually
        // in the file. Candidate sets include every importer of the target's
        // package, most of which never reference this specific symbol; skipping
        // the full tree walk for those is the dominant `usage_graph` speed-up.
        if !source.contains(spec.identifier())
            && !spec.owner().is_some_and(|owner| source.contains(owner))
        {
            return;
        }
        let scan_bindings = ScanBindings::new(graph, file, spec);
        let mut local_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            file,
            source,
            line_starts: &parsed.line_starts,
            analyzer,
            spec,
            bindings: scan_bindings,
            hits: &mut local_hits,
        };
        let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
        scan_node(parsed.tree.root_node(), &mut ctx, &mut locals);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Go graph collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Go graph collector")
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) spec: &'a TargetSpec,
    bindings: ScanBindings,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    match node.kind() {
        "import_declaration" => return,
        "function_declaration" | "method_declaration" => {
            locals.enter_scope();
            seed_parameters(node, ctx, locals);
            scan_children(node, ctx, locals);
            locals.exit_scope();
            return;
        }
        "block" | "block_statement" => {
            locals.enter_scope();
            scan_children(node, ctx, locals);
            locals.exit_scope();
            return;
        }
        "parameter_declaration" => {
            seed_parameter_declaration(node, ctx, locals);
        }
        "var_declaration" | "short_var_declaration" => {
            declare_local_names(node, ctx, locals);
            seed_local_bindings(node, ctx, locals);
        }
        "assignment_statement" => {
            seed_local_bindings(node, ctx, locals);
        }
        "selector_expression" | "qualified_type" => {
            scan_selector_like(node, ctx, locals);
        }
        "identifier" | "type_identifier" => {
            scan_direct_identifier(node, ctx, locals);
        }
        _ => {}
    }

    scan_children(node, ctx, locals);
}

fn scan_children(node: Node<'_>, ctx: &mut ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx, locals);
    }
}

fn seed_parameters(node: Node<'_>, ctx: &ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_list" {
            let mut params = child.walk();
            for param in child.named_children(&mut params) {
                if param.kind() == "parameter_declaration" {
                    seed_parameter_declaration(param, ctx, locals);
                }
            }
        }
    }
}

fn seed_parameter_declaration(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let parameter_names = parameter_names(node, ctx.source);
    let Some(type_node) = node.child_by_field_name("type") else {
        for name in parameter_names {
            locals.declare_shadow(name);
        }
        return;
    };
    if !type_ref_from_node(type_node, ctx.source)
        .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
    {
        for name in parameter_names {
            locals.declare_shadow(name);
        }
        return;
    }
    for name in parameter_names {
        locals.seed_symbol(name, OWNER_TOKEN.to_string());
    }
}

pub(super) fn parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            out.push(node_text(child, source).to_string());
        }
    }
    out
}

fn declare_local_names(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    for name in declared_names(node, ctx.source) {
        locals.declare_shadow(name);
    }
}

fn seed_local_bindings(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "var_declaration" => {
            for_each_var_spec(node, &mut |var_spec| seed_var_spec(var_spec, ctx, locals));
        }
        "var_spec" => seed_var_spec(node, ctx, locals),
        "short_var_declaration" | "assignment_statement" => seed_assignment_like(node, ctx, locals),
        _ => {}
    }
}

pub(super) fn declared_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "var_declaration" => {
            let mut out = Vec::new();
            for_each_var_spec(node, &mut |var_spec| {
                out.extend(declared_names(var_spec, source))
            });
            out
        }
        "var_spec" => var_spec_names(node, source),
        "short_var_declaration" => lhs_identifiers(node, source),
        _ => Vec::new(),
    }
}

fn seed_var_spec(node: Node<'_>, ctx: &ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    let names = var_spec_names(node, ctx.source);
    if names.is_empty() {
        return;
    }

    if node
        .child_by_field_name("type")
        .and_then(|type_node| type_ref_from_node(type_node, ctx.source))
        .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
    {
        for name in names {
            locals.seed_symbol(name, OWNER_TOKEN.to_string());
        }
        return;
    }

    seed_names_from_values(names, rhs_expressions(node), ctx, locals);
}

fn seed_assignment_like(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    seed_names_from_values(
        lhs_identifiers(node, ctx.source),
        rhs_expressions(node),
        ctx,
        locals,
    );
}

fn seed_names_from_values(
    names: Vec<String>,
    values: Vec<Node<'_>>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    if names.is_empty() || values.is_empty() {
        return;
    }

    for (name, value) in names.iter().zip(values.iter()) {
        if expression_matches_owner_type(*value, ctx)
            || call_returns_owner_type(*value, ctx, locals)
        {
            locals.seed_symbol(name.clone(), OWNER_TOKEN.to_string());
        } else if is_identifier_node(*value) {
            locals.alias_symbol(name.clone(), node_text(*value, ctx.source));
        }
    }
}

/// Whether `value` is a call to a constructor whose result is the owner type, so
/// the local it initializes carries the owner receiver. Covers a bare in-package
/// call (`NewOwner()`) and a qualified call through an import (`pkg.NewOwner()`). A
/// callee (or qualifier) shadowed by a local binding is not the package constructor.
fn call_returns_owner_type(
    value: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) -> bool {
    if value.kind() != "call_expression" {
        return false;
    }
    let Some(function) = value
        .child_by_field_name("function")
        .or_else(|| first_named_child(value))
    else {
        return false;
    };
    match function.kind() {
        "identifier" => {
            let name = node_text(function, ctx.source);
            !locals.is_shadowed(name)
                && ctx.bindings.owner_referable_directly()
                && ctx.spec.is_owner_constructor(name)
        }
        "selector_expression" => {
            let Some((qualifier, _, field)) = selector_parts(function, ctx.source) else {
                return false;
            };
            !locals.is_shadowed(&qualifier)
                && ctx.bindings.owner_namespace_contains(&qualifier)
                && ctx.spec.is_owner_constructor(node_text(field, ctx.source))
        }
        _ => false,
    }
}

pub(super) fn var_spec_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for name_node in node.children_by_field_name("name", &mut cursor) {
        let name = node_text(name_node, source);
        if name != "_" {
            out.push(name.to_string());
        }
    }
    out
}

pub(super) fn for_each_var_spec(node: Node<'_>, f: &mut impl FnMut(Node<'_>)) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "var_spec" => f(child),
            "var_spec_list" => for_each_var_spec(child, f),
            _ => {}
        }
    }
}

pub(super) fn lhs_identifiers(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(left) = node
        .child_by_field_name("left")
        .or_else(|| first_named_child(node))
    else {
        return Vec::new();
    };
    identifiers_in_node(left, source)
        .into_iter()
        .filter(|name| name != "_")
        .collect()
}

pub(super) fn rhs_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(right) = node
        .child_by_field_name("right")
        .or_else(|| last_named_child(node))
    else {
        return Vec::new();
    };
    if right.kind() == "expression_list" {
        let mut cursor = right.walk();
        let children: Vec<_> = right.named_children(&mut cursor).collect();
        if !children.is_empty() {
            return children;
        }
    }
    vec![right]
}

pub(super) fn identifiers_in_node(node: Node<'_>, source: &str) -> Vec<String> {
    if is_identifier_node(node) {
        return vec![node_text(node, source).to_string()];
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_identifier_node(child) {
            out.push(node_text(child, source).to_string());
        }
    }
    out
}

fn expression_matches_owner_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if type_ref_from_node(node, ctx.source).is_some_and(|ty| ctx.bindings.matches_owner_type(&ty)) {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| expression_matches_owner_type(child, ctx))
}

pub(super) fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "package_identifier"
    )
}

fn scan_selector_like(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) {
    let Some((qualifier, qualifier_node, field_node)) = selector_parts(node, ctx.source) else {
        return;
    };
    let field = node_text(field_node, ctx.source);
    if field != ctx.spec.identifier {
        return;
    }

    if ctx.spec.is_member() {
        let receiver = receiver_symbol_from_qualifier(&qualifier);
        if locals
            .resolve_symbol(receiver)
            .as_precise()
            .is_some_and(|targets| targets.contains(OWNER_TOKEN))
        {
            record_hit(field_node, ctx);
        }
        return;
    }

    if ctx.bindings.namespace_names.contains(&qualifier)
        && !locals.is_shadowed(&qualifier)
        && !is_definition_identifier(qualifier_node, ctx.source)
    {
        record_hit(field_node, ctx);
    }
}

fn scan_direct_identifier(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) {
    if ctx.spec.is_member() || is_definition_identifier(node, ctx.source) {
        return;
    }
    let text = node_text(node, ctx.source);
    if ctx.bindings.matches_direct_target(text) && !locals.is_shadowed(text) {
        record_hit(node, ctx);
    }
}

pub(super) fn selector_parts<'a>(
    node: Node<'a>,
    source: &str,
) -> Option<(String, Node<'a>, Node<'a>)> {
    let qualifier_node = node
        .child_by_field_name("operand")
        .or_else(|| node.child_by_field_name("package"))
        .or_else(|| first_named_child(node))?;
    let field_node = node
        .child_by_field_name("field")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| last_named_child(node))?;
    Some((
        node_text(qualifier_node, source).to_string(),
        qualifier_node,
        field_node,
    ))
}

pub(super) fn receiver_symbol_from_qualifier(qualifier: &str) -> &str {
    qualifier
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_start_matches(['*', '&'])
        .trim()
}

pub(super) fn type_ref_from_node(node: Node<'_>, source: &str) -> Option<TypeRef> {
    match node.kind() {
        "type_identifier" | "identifier" => Some(TypeRef {
            qualifier: None,
            name: Some(node_text(node, source).to_string()),
        }),
        "qualified_type" | "selector_expression" => {
            let (qualifier, _qualifier_node, field) = selector_parts(node, source)?;
            Some(TypeRef {
                qualifier: Some(qualifier),
                name: Some(node_text(field, source).to_string()),
            })
        }
        "pointer_type" | "slice_type" | "array_type" | "generic_type" | "parenthesized_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| type_ref_from_node(child, source))
        }
        _ => None,
    }
}

pub(super) fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

pub(super) fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

pub(super) fn is_definition_identifier(node: Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if has_ancestor_kind(node, "literal_value") && next_non_whitespace_is_colon(node, source) {
        return true;
    }
    if parent.kind() == "keyed_element"
        && parent
            .child_by_field_name("key")
            .is_some_and(|key| same_node(key, node))
    {
        return true;
    }
    if parent.kind() == "field_declaration"
        && parent.child_by_field_name("type").is_some_and(|ty| {
            node.start_byte() < ty.start_byte()
                && parent
                    .child_by_field_name("name")
                    .is_none_or(|name| same_node(name, node) || node.end_byte() <= ty.start_byte())
        })
    {
        return true;
    }
    matches!(
        parent.kind(),
        "package_clause"
            | "import_spec"
            | "function_declaration"
            | "method_declaration"
            | "type_spec"
            | "type_alias"
            | "var_spec"
            | "const_spec"
            | "field_declaration"
            | "method_elem"
            | "parameter_declaration"
            | "short_var_declaration"
    ) && node
        .parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        .is_some_and(|name| {
            name.start_byte() == node.start_byte() && name.end_byte() == node.end_byte()
        })
}

pub(super) fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

pub(super) fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(super) fn next_non_whitespace_is_colon(node: Node<'_>, source: &str) -> bool {
    source
        .get(node.end_byte()..)
        .and_then(|rest| rest.chars().find(|ch| !ch.is_whitespace()))
        == Some(':')
}
