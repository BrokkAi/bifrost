//! The per-symbol forward scan: walk each candidate file once looking for one
//! target's call sites.
//!
//! [`ScanCtx`] carries a [`CodeUnitIndex`] because [`super::hits`] attributes
//! every hit to its enclosing declaration; that query lives on the core
//! capability trait, so the whole scan is expressible over core types plus the
//! Go AST vocabulary in [`super::ast`].

use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::{CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::graph::ast::{
    NON_OWNER_TOKEN, OWNER_TOKEN, SELF_RECEIVER_TOKEN, composite_literal_owner_type_for_key,
    field_owner_token, for_each_var_spec, is_definition_identifier, is_identifier_node,
    is_method_receiver_parameter, is_method_receiver_type_name, lhs_identifier_slots,
    parameter_names, receiver_symbol_from_qualifier, rhs_expressions, selector_parts,
    type_ref_from_node, var_spec_name_slots, var_spec_names,
};
use crate::graph::hits::{record_hit, record_self_receiver_hit, record_unproven_hit};
use crate::graph::reference::go_is_top_level_decl;
use crate::graph::resolver::{
    GoProjectGraph, ScanBindings, TargetSpec, TypeRef, constructor_call_type_fqns, node_text,
};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::Mutex;
use tree_sitter::Node;

pub fn scan_files_for_target(
    code_units: &dyn CodeUnitIndex,
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
            code_units,
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

pub struct GoScanResult {
    pub hits: BTreeSet<UsageHit>,
    pub unproven_hits: BTreeSet<UsageHit>,
}

pub struct ScanCtx<'a> {
    pub(crate) graph: &'a GoProjectGraph,
    pub(crate) file: &'a ProjectFile,
    pub(crate) source: &'a str,
    pub(crate) line_starts: &'a [usize],
    pub(crate) code_units: &'a dyn CodeUnitIndex,
    pub(crate) spec: &'a TargetSpec,
    bindings: ScanBindings,
    file_package: String,
    alias_packages: HashMap<String, Vec<String>>,
    dot_packages: Vec<String>,
    pub(crate) hits: &'a mut BTreeSet<UsageHit>,
    pub(crate) unproven_hits: &'a mut BTreeSet<UsageHit>,
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
            seed_parameter_declaration(node, ctx, locals, is_method_receiver_parameter(node));
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
        // Mark the method's own receiver variable as the same-owner receiver.
        seed_parameter_list(receiver, ctx, locals, true);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_list" {
            seed_parameter_list(child, ctx, locals, false);
        }
    }
}

fn seed_parameter_list(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
    is_method_receiver: bool,
) {
    let mut params = node.walk();
    for param in node.named_children(&mut params) {
        if param.kind() == "parameter_declaration" {
            seed_parameter_declaration(param, ctx, locals, is_method_receiver);
        }
    }
}

fn seed_parameter_declaration(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
    is_method_receiver: bool,
) {
    let parameter_names = parameter_names(node, ctx.source);
    let Some(type_node) = node.child_by_field_name("type") else {
        for name in parameter_names {
            locals.declare_shadow(name);
        }
        return;
    };
    let mut tokens = type_ref_from_node(type_node, ctx.source)
        .map(|ty| ctx.receiver_tokens_for_type(&ty))
        .unwrap_or_default();
    if tokens.is_empty() {
        for name in parameter_names {
            locals.declare_shadow(name);
        }
        return;
    }
    // The method receiver variable, when it is the target owner, is the
    // same-owner receiver: tag it so `recv.member` is classified as a same-owner
    // site rather than an external usage.
    if is_method_receiver
        && tokens.iter().any(|token| token == OWNER_TOKEN)
        && !tokens.iter().any(|token| token == SELF_RECEIVER_TOKEN)
    {
        tokens.push(SELF_RECEIVER_TOKEN.to_string());
    }
    for name in parameter_names {
        locals.seed_symbol_many(name, tokens.clone());
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
        "short_var_declaration" => seed_assignment_like(node, ctx, locals, true),
        "assignment_statement" => seed_assignment_like(node, ctx, locals, false),
        _ => {}
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
    let mut bindings = infer_names_from_values(slots.clone(), rhs_expressions(node), ctx, locals);
    if declare_lhs {
        for name in slots.into_iter().flatten() {
            locals.declare_shadow(name);
        }
    } else {
        // Ordinary `=` updates an existing lexical binding; it must not turn an
        // otherwise unbound package name into a local shadow.
        bindings.retain(|(name, _)| locals.is_shadowed(name));
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
            } else if value.kind() == "selector_expression"
                && field_receiver_matches_owner(*value, ctx, locals)
            {
                // A field-derived local receiver: `s := pi.field` where `pi`
                // carries the field-owner token for `field`, so the field's type
                // is a compatible receiver type of the target. Calls through `s`
                // are then proven owner usages (#1611).
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

fn expression_matches_owner_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if type_ref_from_node(node, ctx.source).is_some_and(|ty| ctx.bindings.matches_owner_type(&ty)) {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| expression_matches_owner_type(child, ctx))
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
        // A call through the enclosing method's own receiver variable is a
        // same-owner site (#1014 facet B); a call through another owner-typed
        // value stays an external usage.
        let same_owner = receiver_resolution
            .as_precise()
            .is_some_and(|targets| targets.contains(SELF_RECEIVER_TOKEN));
        if receiver_resolution
            .as_precise()
            .is_some_and(|targets| targets.contains(OWNER_TOKEN))
            || field_receiver_matches_owner(qualifier_node, ctx, locals)
            || composite_literal_receiver_matches_owner(qualifier_node, ctx)
        {
            if same_owner {
                record_self_receiver_hit(field_node, ctx);
            } else {
                record_hit(field_node, ctx);
            }
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

fn scan_direct_identifier(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) {
    if ctx.spec.is_member() {
        return;
    }
    // A method receiver names its own type: `func (a AclResourceType) String()`
    // is a real occurrence of `AclResourceType` that an editor must navigate to
    // (gopls lists it), so it is recorded rather than swallowed by the
    // declaration-name guard (#1765). It is also declaration-adjacent noise for
    // usage counting -- every method of a type would otherwise make the type
    // look heavily used and defeat dead-code evidence -- so it is classified
    // `SelfReceiver`, the #1638 trade-off: visible to LspReferences, omitted
    // from ExternalUsages.
    let receiver_type = is_method_receiver_type_name(node);
    if !receiver_type && is_definition_identifier(node, ctx.source) {
        return;
    }
    let text = node_text(node, ctx.source);
    if !ctx.bindings.matches_direct_target(text) {
        return;
    }
    if receiver_type {
        // A receiver type resolves in package scope: the receiver binding is not
        // in scope for its own type, even when Go lets the two share a spelling
        // (`func (Config Config) Reload()`), so the local shadow does not apply.
        record_self_receiver_hit(node, ctx);
    } else if !locals.is_shadowed(text) {
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
