use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::go_graph::hits::{record_hit, record_unproven_hit};
use crate::analyzer::usages::go_graph::reference::go_is_top_level_decl;
use crate::analyzer::usages::go_graph::resolver::{
    GoProjectGraph, ScanBindings, TargetSpec, TypeRef, constructor_call_type_fqns, node_text,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::Mutex;
use tree_sitter::Node;

pub(super) const OWNER_TOKEN: &str = "__go_target_owner__";
pub(super) const NON_OWNER_TOKEN: &str = "__go_known_non_target_owner__";
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
        let file_package = graph.package_name_of(file).unwrap_or_default();
        let (alias_packages, dot_packages) = graph.namespace_packages(file);
        let mut local_hits = BTreeSet::new();
        let mut local_unproven_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            graph,
            file,
            source,
            line_starts: &parsed.line_starts,
            analyzer,
            spec,
            bindings: scan_bindings,
            file_package,
            alias_packages,
            dot_packages,
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
    pub(super) graph: &'a GoProjectGraph,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) spec: &'a TargetSpec,
    bindings: ScanBindings,
    file_package: String,
    alias_packages: HashMap<String, Vec<String>>,
    dot_packages: Vec<String>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn receiver_tokens_for_type(&self, ty: &TypeRef) -> Vec<String> {
        let resolved_types = ty
            .name
            .as_deref()
            .map(|name| match ty.qualifier.as_deref() {
                None => std::iter::once(self.file_package.as_str())
                    .chain(self.dot_packages.iter().map(String::as_str))
                    .map(|package| format!("{package}.{name}"))
                    .collect::<Vec<_>>(),
                Some(qualifier) => self
                    .alias_packages
                    .get(qualifier)
                    .into_iter()
                    .flatten()
                    .map(|package| format!("{package}.{name}"))
                    .collect(),
            })
            .unwrap_or_default()
            .into_iter()
            .map(|fq_name| self.graph.edge_index.resolve_type_alias(&fq_name))
            .collect::<Vec<_>>();
        let known_non_alias_type = resolved_types
            .iter()
            .any(|fq_name| self.graph.is_known_non_alias_type(fq_name));
        let mut tokens = self
            .bindings
            .receiver_tokens_for_type(ty, known_non_alias_type);
        if resolved_types
            .iter()
            .any(|fq_name| self.spec.matches_receiver_fqn(fq_name))
            && !tokens.iter().any(|token| token == OWNER_TOKEN)
        {
            tokens.retain(|token| token != NON_OWNER_TOKEN);
            tokens.push(OWNER_TOKEN.to_string());
        }
        tokens
    }
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
        .map(|ty| ctx.receiver_tokens_for_type(&ty))
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
        .map(|ty| ctx.receiver_tokens_for_type(&ty))
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
    Targets(Vec<String>),
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
            let constructor_targets = constructor_call_receiver_targets(*value, ctx, locals);
            if !constructor_targets.is_empty() {
                Some((name.clone(), InferredBinding::Targets(constructor_targets)))
            } else if let Some(tokens) = type_ref_from_node(*value, ctx.source)
                .or_else(|| {
                    value
                        .child_by_field_name("type")
                        .and_then(|ty| type_ref_from_node(ty, ctx.source))
                })
                .map(|ty| ctx.receiver_tokens_for_type(&ty))
                .filter(|tokens| !tokens.is_empty())
            {
                Some((name.clone(), InferredBinding::Targets(tokens)))
            } else if expression_matches_owner_type(*value, ctx) {
                Some((
                    name.clone(),
                    InferredBinding::Targets(vec![OWNER_TOKEN.to_string()]),
                ))
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
            InferredBinding::Targets(targets) => locals.seed_symbol_many(name, targets),
            InferredBinding::Alias(source) => locals.alias_symbol(name, &source),
        }
    }
}

fn constructor_call_receiver_targets(
    value: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) -> Vec<String> {
    constructor_call_type_fqns(
        value,
        ctx.source,
        &ctx.file_package,
        &ctx.alias_packages,
        &ctx.dot_packages,
        &ctx.graph.edge_index,
        Some(locals),
    )
    .into_iter()
    .filter_map(|return_type| {
        if ctx.spec.matches_receiver_fqn(&return_type) {
            Some(OWNER_TOKEN.to_string())
        } else if ctx.spec.owner_is_interface() && ctx.graph.is_known_non_alias_type(&return_type) {
            Some(NON_OWNER_TOKEN.to_string())
        } else {
            None
        }
    })
    .collect()
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
        let receiver_resolution = locals.resolve_symbol(receiver);
        if receiver_resolution
            .as_precise()
            .is_some_and(|targets| targets.contains(OWNER_TOKEN))
            || field_receiver_matches_owner(qualifier_node, ctx, locals)
            || composite_literal_receiver_matches_owner(qualifier_node, ctx)
        {
            record_hit(field_node, ctx);
        } else if receiver_resolution
            .as_precise()
            .is_some_and(|targets| targets.contains(NON_OWNER_TOKEN))
        {
            return;
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
            .map(|ty| ctx.receiver_tokens_for_type(&ty))
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
    let Some(type_node) = composite_literal_owner_type_for_key(node) else {
        return false;
    };
    // A keyed element in a map literal is an ordinary key expression, not a
    // struct-field label. Let the normal identifier/selector scanners resolve
    // it (for example `map[Feature]Spec{MyFeature: {...}}`). The explicit
    // composite-literal type is the structured distinction; guessing from the
    // key spelling would conflate same-named fields and constants.
    if type_node.kind() == "map_type" {
        return false;
    }
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
        return composite_literal_owner_type_for_key(node)
            .is_none_or(|type_node| type_node.kind() != "map_type");
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

/// Return the structured owner type for a keyed composite-literal element.
///
/// An elided value such as `[1]Owner{{Field: value}}` has no type node at the
/// inner literal boundary. Its type is nevertheless explicit in the enclosing
/// array/slice element or map value. Walk through only those AST relationships
/// and peel one container type per elided boundary; do not infer an owner from
/// the field spelling.
fn composite_literal_owner_type_for_key(node: Node<'_>) -> Option<Node<'_>> {
    let keyed = keyed_element_for_key(node)?;
    let mut literal = keyed
        .parent()
        .filter(|parent| parent.kind() == "literal_value")?;
    let mut elided_depth = 0usize;

    loop {
        let parent = literal.parent()?;
        match parent.kind() {
            "composite_literal" => {
                let mut owner = parent.child_by_field_name("type")?;
                for _ in 0..elided_depth {
                    owner = go_container_element_or_value_type(owner)?;
                }
                return Some(owner);
            }
            "keyed_element" => {
                let value = parent.child_by_field_name("value")?;
                if !same_node(value, literal) {
                    return None;
                }
                literal = parent
                    .parent()
                    .filter(|ancestor| ancestor.kind() == "literal_value")?;
                elided_depth += 1;
            }
            "literal_value" => {
                literal = parent;
                elided_depth += 1;
            }
            "literal_element" => {
                let container = parent.parent()?;
                literal = match container.kind() {
                    "keyed_element" => {
                        let value = container.child_by_field_name("value")?;
                        if !same_node(value, parent) {
                            return None;
                        }
                        container
                            .parent()
                            .filter(|ancestor| ancestor.kind() == "literal_value")?
                    }
                    "literal_value" => container,
                    _ => return None,
                };
                elided_depth += 1;
            }
            _ => return None,
        }
    }
}

fn go_container_element_or_value_type(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "array_type" => node.child_by_field_name("element"),
        "slice_type" => node.named_child(0),
        "map_type" => node.child_by_field_name("value"),
        "pointer_type" | "parenthesized_type" => node
            .named_child(0)
            .and_then(go_container_element_or_value_type),
        _ => None,
    }
}

fn keyed_element_for_key(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    let keyed = if parent.kind() == "keyed_element" {
        parent
    } else {
        let keyed = parent
            .parent()
            .filter(|ancestor| ancestor.kind() == "keyed_element")?;
        let key = keyed.child_by_field_name("key")?;
        if !same_node(key, parent) {
            return None;
        }
        keyed
    };

    let key = keyed.child_by_field_name("key")?;
    if same_node(key, node) {
        return Some(keyed);
    }
    let mut cursor = key.walk();
    let mut children = key.named_children(&mut cursor);
    children
        .next()
        .filter(|child| same_node(*child, node) && children.next().is_none())
        .map(|_| keyed)
}
