use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::go_graph::hits::{record_hit, record_unproven_hit};
use crate::analyzer::usages::go_graph::reference::go_is_top_level_decl;
use crate::analyzer::usages::go_graph::resolver::{
    GoProjectGraph, ScanBindings, TargetSpec, TypeRef, node_text,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::Mutex;
use tree_sitter::Node;

pub(super) const OWNER_TOKEN: &str = "__go_target_owner__";
const FIELD_OWNER_TOKEN_PREFIX: &str = "__go_field_owner__:";

pub(super) fn scan_files_for_target(
    analyzer: &dyn IAnalyzer,
    graph: &GoProjectGraph,
    files: HashSet<ProjectFile>,
    spec: &TargetSpec,
    cancellation: Option<&CancellationToken>,
) -> GoScanResult {
    let hits = Mutex::new(BTreeSet::new());
    let unproven_hits = Mutex::new(BTreeSet::new());
    let files: Vec<_> = files.into_iter().collect();

    files.par_iter().for_each(|file| {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
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
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        let scan_bindings = ScanBindings::new(graph, file, spec);
        let mut local_hits = BTreeSet::new();
        let mut local_unproven_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            file,
            source,
            line_starts: &parsed.line_starts,
            analyzer,
            spec,
            bindings: scan_bindings,
            hits: &mut local_hits,
            unproven_hits: &mut local_unproven_hits,
        };
        let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
        scan_node(parsed.tree.root_node(), &mut ctx, &mut locals);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Go graph collector");
            sink.extend(local_hits);
        }
        if !local_unproven_hits.is_empty() {
            let mut sink = unproven_hits
                .lock()
                .expect("poisoned Go graph unproven collector");
            sink.extend(local_unproven_hits);
        }
    });

    GoScanResult {
        hits: hits.into_inner().expect("poisoned Go graph collector"),
        unproven_hits: unproven_hits
            .into_inner()
            .expect("poisoned Go graph unproven collector"),
    }
}

pub(super) struct GoScanResult {
    pub(super) hits: BTreeSet<UsageHit>,
    pub(super) unproven_hits: BTreeSet<UsageHit>,
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) spec: &'a TargetSpec,
    bindings: ScanBindings,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
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
            // A package-level `var` is not a local binding: seeding it (as a shadow
            // or a typed symbol) would hide references to the package variable.
            // Only function/block-scoped `var`/`:=` are locals.
            if !go_is_top_level_decl(node) {
                seed_local_bindings(node, ctx, locals);
            }
        }
        "assignment_statement" => {
            seed_local_bindings(node, ctx, locals);
        }
        "selector_expression" | "qualified_type" => {
            scan_selector_like(node, ctx, locals);
        }
        "identifier" | "type_identifier" if !scan_composite_literal_field_label(node, ctx) => {
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
    if node.kind() == "method_declaration"
        && let Some(receiver) = node.child_by_field_name("receiver")
    {
        seed_parameter_list(receiver, ctx, locals);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_list" {
            seed_parameter_list(child, ctx, locals);
        }
    }
}

fn seed_parameter_list(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let mut params = node.walk();
    for param in node.named_children(&mut params) {
        if param.kind() == "parameter_declaration" {
            seed_parameter_declaration(param, ctx, locals);
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
    let tokens = type_ref_from_node(type_node, ctx.source)
        .map(|ty| ctx.bindings.receiver_tokens_for_type(&ty))
        .unwrap_or_default();
    if tokens.is_empty() {
        for name in parameter_names {
            locals.declare_shadow(name);
        }
        return;
    }
    for name in parameter_names {
        locals.seed_symbol_many(name, tokens.clone());
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
        "short_var_declaration" => seed_assignment_like(node, ctx, locals, true),
        "assignment_statement" => seed_assignment_like(node, ctx, locals, false),
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

    if let Some(tokens) = node
        .child_by_field_name("type")
        .and_then(|type_node| type_ref_from_node(type_node, ctx.source))
        .map(|ty| ctx.bindings.receiver_tokens_for_type(&ty))
        .filter(|tokens| !tokens.is_empty())
    {
        for name in names {
            locals.seed_symbol_many(name, tokens.clone());
        }
        return;
    }

    let bindings = infer_names_from_values(
        var_spec_name_slots(node, ctx.source),
        rhs_expressions(node),
        ctx,
        locals,
    );
    for name in names {
        locals.declare_shadow(name);
    }
    apply_inferred_bindings(bindings, locals);
}

fn seed_assignment_like(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
    declare_lhs: bool,
) {
    let slots = lhs_identifier_slots(node, ctx.source);
    let bindings = infer_names_from_values(slots.clone(), rhs_expressions(node), ctx, locals);
    if declare_lhs {
        for name in slots.into_iter().flatten() {
            locals.declare_shadow(name);
        }
    }
    apply_inferred_bindings(bindings, locals);
}

enum InferredBinding {
    Owner,
    Alias(String),
}

fn infer_names_from_values(
    names: Vec<Option<String>>,
    values: Vec<Node<'_>>,
    ctx: &ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) -> Vec<(String, InferredBinding)> {
    if names.is_empty() || values.is_empty() {
        return Vec::new();
    }

    names
        .iter()
        .zip(values.iter())
        .filter_map(|(name, value)| {
            let name = name.as_ref()?;
            if expression_matches_owner_type(*value, ctx)
                || call_returns_owner_type(*value, ctx, locals)
            {
                Some((name.clone(), InferredBinding::Owner))
            } else if is_identifier_node(*value) {
                Some((
                    name.clone(),
                    InferredBinding::Alias(node_text(*value, ctx.source).to_string()),
                ))
            } else {
                None
            }
        })
        .collect()
}

fn apply_inferred_bindings(
    bindings: Vec<(String, InferredBinding)>,
    locals: &mut LocalInferenceEngine<String>,
) {
    for (name, binding) in bindings {
        match binding {
            InferredBinding::Owner => locals.seed_symbol(name, OWNER_TOKEN.to_string()),
            InferredBinding::Alias(source) => locals.alias_symbol(name, &source),
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

fn var_spec_name_slots(node: Node<'_>, source: &str) -> Vec<Option<String>> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for name_node in node.children_by_field_name("name", &mut cursor) {
        let name = node_text(name_node, source);
        out.push((name != "_").then(|| name.to_string()));
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

pub(super) fn lhs_identifier_slots(node: Node<'_>, source: &str) -> Vec<Option<String>> {
    let Some(left) = node
        .child_by_field_name("left")
        .or_else(|| first_named_child(node))
    else {
        return Vec::new();
    };
    identifier_slots_in_node(left, source)
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

fn identifier_slots_in_node(node: Node<'_>, source: &str) -> Vec<Option<String>> {
    if is_identifier_node(node) {
        let text = node_text(node, source);
        return vec![(text != "_").then(|| text.to_string())];
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_identifier_node(child) {
            let text = node_text(child, source);
            out.push((text != "_").then(|| text.to_string()));
        }
    }
    out
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
            || field_receiver_matches_owner(qualifier_node, ctx, locals)
            || composite_literal_receiver_matches_owner(qualifier_node, ctx)
        {
            record_hit(field_node, ctx);
        } else if !ctx.bindings.namespace_names.contains(&qualifier)
            || locals.is_shadowed(&qualifier)
        {
            record_unproven_hit(field_node, ctx);
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

/// Whether a *direct composite-literal* receiver (`e{}.field`) is typed as the
/// target owner — the receiver's literal type is the owner. The var-receiver form
/// is already handled by the seeded local symbol; this covers the case where the
/// literal is the selector operand with no intervening binding.
fn composite_literal_receiver_matches_owner(qualifier_node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    qualifier_node.kind() == "composite_literal"
        && qualifier_node
            .child_by_field_name("type")
            .and_then(|type_node| type_ref_from_node(type_node, ctx.source))
            .map(|ty| ctx.bindings.receiver_tokens_for_type(&ty))
            .is_some_and(|tokens| tokens.iter().any(|token| token == OWNER_TOKEN))
}

fn field_receiver_matches_owner(
    qualifier_node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) -> bool {
    let Some((base, _base_node, field_node)) = selector_parts(qualifier_node, ctx.source) else {
        return false;
    };
    let token = field_owner_token(node_text(field_node, ctx.source));
    locals
        .resolve_symbol(receiver_symbol_from_qualifier(&base))
        .as_precise()
        .is_some_and(|targets| targets.contains(token.as_str()))
}

pub(super) fn field_owner_token(field: &str) -> String {
    format!("{FIELD_OWNER_TOKEN_PREFIX}{field}")
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

/// Resolve a keyed struct-literal label through the literal's declared type.
///
/// Go uses the same `keyed_element` syntax for struct fields and map keys. The
/// enclosing `composite_literal` type is therefore the structured fact that
/// distinguishes `Owner{Field: value}` from `map[string]T{Field: value}` and
/// from another struct with a same-named field.
fn scan_composite_literal_field_label(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    let Some(type_node) = direct_composite_literal_type_for_key(node) else {
        return false;
    };
    if node_text(node, ctx.source) == ctx.spec.identifier
        && type_ref_from_node(type_node, ctx.source)
            .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
    {
        record_hit(node, ctx);
    }
    true
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

pub(super) fn is_definition_identifier(node: Node<'_>, _source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if keyed_element_for_key(node).is_some() {
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
        .is_some_and(|name| same_node(name, node))
}

/// Return the type syntax for a key belonging directly to a composite literal.
/// Keys in nested elided literal values intentionally return `None`: without an
/// explicit type at that literal boundary, attributing a field would require
/// additional element-type propagation rather than guessing from source text.
fn direct_composite_literal_type_for_key(node: Node<'_>) -> Option<Node<'_>> {
    let keyed = keyed_element_for_key(node)?;
    let literal = keyed
        .parent()
        .filter(|parent| parent.kind() == "literal_value")?;
    let composite = literal
        .parent()
        .filter(|parent| parent.kind() == "composite_literal")?;
    composite.child_by_field_name("type")
}

fn keyed_element_for_key(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "keyed_element" {
            let key = parent.child_by_field_name("key")?;
            if same_node(key, node) {
                return Some(parent);
            }
            let mut cursor = key.walk();
            let mut children = key.named_children(&mut cursor);
            return children
                .next()
                .filter(|child| same_node(*child, node) && children.next().is_none())
                .map(|_| parent);
        }
        current = parent.parent();
    }
    None
}
