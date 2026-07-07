//! Whole-workspace inverted edge builder for `usage_graph`.
//!
//! The per-symbol path ([`super::resolve_with_graph`]) answers "who calls X" by
//! scanning every candidate file for X. Building the *whole* graph that way walks
//! each file once per symbol whose name it contains — quadratic on real repos.
//!
//! This module inverts it: walk each file's tree **once**, resolve every
//! reference to the fully qualified callee it names, and emit a `caller -> callee`
//! edge when both endpoints are nodes. Cost is linear in total source size,
//! independent of the symbol count.
//!
//! It reuses the per-symbol resolver's exact building blocks — the same AST
//! helpers, the same local type-inference engine, the same definition-site and
//! self-reference exclusions, and the same per-callee call-site cap — so the
//! resulting nodes, edges, weights, and `truncated_symbols` match the per-symbol
//! path. Where the forward scan seeds a sentinel "this local is the target's
//! owner type" token, the inverted scan seeds the local's *actual* type fqn, and
//! where the forward scan matches one target it resolves the reference's callee.

use super::extractor::{
    for_each_var_spec, is_definition_identifier, is_identifier_node, lhs_identifier_slots,
    parameter_names, receiver_symbol_from_qualifier, rhs_expressions, selector_parts,
    type_ref_from_node, var_spec_names,
};
use super::resolver::{GoEdgeIndex, TypeRef, node_text};
use crate::analyzer::usages::inverted_edges::{
    EdgeCollector, UsageEdges, build_edges, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{GoAnalyzer, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// Build every Go `caller -> callee` edge in one pass over the workspace.
///
/// All the language-agnostic accounting (parallel fan-out, enclosing attribution,
/// per-callee cap, dedup, merge) lives in [`build_edges`]; this function supplies
/// only the two Go-specific pieces: the parsed line starts and the AST walk that
/// resolves each reference to its callee fqn.
///
/// Trees are parsed on demand inside the per-file walk and dropped when the closure
/// returns, so live trees are bounded by the worker count rather than the workspace
/// size (#200). Cross-file resolution comes from the tree-free [`GoEdgeIndex`] and
/// the analyzer's per-file import info — no other file's tree is read during a scan.
pub(super) fn build_go_edges<F>(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    index: &GoEdgeIndex,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = index.files().cloned().collect();
    let language = tree_sitter_go::LANGUAGE.into();
    build_edges(&files, keep_file, |file| {
        let file_pkg = index.package_name_of(file)?;
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let (alias_packages, dot_packages) = index.namespace_packages(go, file);
            let mut ctx = FileScan {
                source: parsed.source.as_str(),
                file_pkg,
                alias_packages,
                dot_packages,
                index,
                member_callee_cache: HashMap::default(),
                collector,
            };
            let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
            scan_node(parsed.tree.root_node(), &mut ctx, &mut locals);
        })
    })
}

struct FileScan<'a, 'b> {
    source: &'a str,
    file_pkg: String,
    alias_packages: HashMap<String, Vec<String>>,
    dot_packages: Vec<String>,
    index: &'a GoEdgeIndex,
    member_callee_cache: HashMap<(String, String), Vec<String>>,
    collector: &'a mut EdgeCollector<'b>,
}

impl FileScan<'_, '_> {
    /// Candidate node fqns for a type reference used as a value's type: the type's
    /// class fqn, resolved through the file's package (bare) or imports (qualified).
    fn type_tokens(&self, ty: &TypeRef) -> Vec<String> {
        let Some(name) = ty.name.as_deref() else {
            return Vec::new();
        };
        match ty.qualifier.as_deref() {
            None => vec![format!("{}.{}", self.file_pkg, name)],
            Some(qualifier) => self
                .alias_packages
                .get(qualifier)
                .map(|packages| {
                    packages
                        .iter()
                        .map(|package| format!("{package}.{name}"))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// The class fqn(s) a value expression constructs, if any — mirrors the
    /// forward scan's `expression_matches_owner_type` recursion, but returns the
    /// concrete type instead of a yes/no against one target.
    fn expression_type_tokens(&self, node: Node<'_>) -> Vec<String> {
        if let Some(ty) = type_ref_from_node(node, self.source) {
            let tokens = self.type_tokens(&ty);
            if !tokens.is_empty() {
                return tokens;
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let tokens = self.expression_type_tokens(child);
            if !tokens.is_empty() {
                return tokens;
            }
        }
        Vec::new()
    }

    fn constructor_call_type_tokens(
        &self,
        node: Node<'_>,
        locals: Option<&LocalInferenceEngine<String>>,
    ) -> Vec<String> {
        if node.kind() != "call_expression" {
            return Vec::new();
        }
        let Some(function) = node
            .child_by_field_name("function")
            .or_else(|| super::extractor::first_named_child(node))
        else {
            return Vec::new();
        };
        match function.kind() {
            "identifier" => {
                let name = node_text(function, self.source);
                if locals.is_some_and(|locals| locals.is_shadowed(name)) {
                    return Vec::new();
                }
                self.constructor_return_types_for(name)
            }
            "selector_expression" => {
                let Some((qualifier, _, field)) = selector_parts(function, self.source) else {
                    return Vec::new();
                };
                if locals.is_some_and(|locals| locals.is_shadowed(&qualifier)) {
                    return Vec::new();
                }
                let field = node_text(field, self.source);
                let Some(packages) = self.alias_packages.get(&qualifier) else {
                    return Vec::new();
                };
                packages
                    .iter()
                    .flat_map(|package| {
                        self.constructor_return_types_for_fqn(&format!("{package}.{field}"))
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    fn constructor_return_types_for(&self, name: &str) -> Vec<String> {
        let mut tokens =
            self.constructor_return_types_for_fqn(&format!("{}.{}", self.file_pkg, name));
        for package in &self.dot_packages {
            tokens.extend(self.constructor_return_types_for_fqn(&format!("{package}.{name}")));
        }
        tokens.sort();
        tokens.dedup();
        tokens
    }

    fn constructor_return_types_for_fqn(&self, callee: &str) -> Vec<String> {
        self.index
            .constructor_return_types(callee)
            .cloned()
            .unwrap_or_default()
    }

    fn member_callees(&mut self, owner_fqn: &str, member: &str) -> Vec<String> {
        let key = (owner_fqn.to_string(), member.to_string());
        if let Some(callees) = self.member_callee_cache.get(&key) {
            return callees.clone();
        }
        let callees: Vec<String> = self
            .index
            .unique_member_fqn(owner_fqn, member)
            .into_iter()
            .collect();
        self.member_callee_cache.insert(key, callees.clone());
        callees
    }

    /// Hand a resolved reference to the shared collector, which applies the
    /// enclosing-caller attribution, cap counting, and edge dedup.
    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.collector
            .record_unproven_name(name, node.start_byte(), node.end_byte());
    }

    fn has_node(&self, node: &String) -> bool {
        self.collector.contains_node(node)
    }

    fn record_with_caller(&mut self, caller: String, callee: String, node: Node<'_>) {
        self.collector
            .record_with_caller(caller, callee, node.start_byte(), node.end_byte());
    }
}

fn scan_node(
    node: Node<'_>,
    ctx: &mut FileScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) {
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
        "parameter_declaration" => seed_parameter_declaration(node, ctx, locals),
        "const_declaration" if is_top_level_declaration(node) => {
            scan_top_level_value_initializers(node, ctx);
        }
        "var_declaration" | "short_var_declaration" => {
            if node.kind() == "var_declaration" && is_top_level_declaration(node) {
                scan_top_level_value_initializers(node, ctx);
            }
            seed_local_bindings(node, ctx, locals);
        }
        "assignment_statement" => {
            seed_local_bindings(node, ctx, locals);
        }
        "selector_expression" | "qualified_type" => scan_selector(node, ctx, locals),
        "identifier" | "type_identifier" => scan_direct(node, ctx, locals),
        _ => {}
    }
    scan_children(node, ctx, locals);
}

fn is_top_level_declaration(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "source_file")
}

fn scan_top_level_value_initializers(node: Node<'_>, ctx: &mut FileScan<'_, '_>) {
    for_each_value_spec(node, &mut |spec| {
        let names = var_spec_names(spec, ctx.source);
        let values = rhs_expressions(spec);
        if names.is_empty() || values.is_empty() {
            return;
        }
        for (name, value) in names.into_iter().zip(values) {
            let caller = format!("{}._module_.{name}", ctx.file_pkg);
            scan_top_level_initializer_value(value, caller.as_str(), ctx);
        }
    });
}

fn for_each_value_spec(node: Node<'_>, f: &mut impl FnMut(Node<'_>)) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "var_spec" | "const_spec" => f(child),
            "var_spec_list" | "const_spec_list" => for_each_value_spec(child, f),
            _ => {}
        }
    }
}

fn scan_top_level_initializer_value(node: Node<'_>, caller: &str, ctx: &mut FileScan<'_, '_>) {
    match node.kind() {
        "func_literal" | "function_declaration" | "method_declaration" => return,
        "selector_expression" | "qualified_type" => {
            scan_top_level_initializer_selector(node, caller, ctx);
            return;
        }
        "identifier" | "type_identifier" => {
            scan_top_level_initializer_direct(node, caller, ctx);
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_top_level_initializer_value(child, caller, ctx);
    }
}

fn scan_top_level_initializer_selector(node: Node<'_>, caller: &str, ctx: &mut FileScan<'_, '_>) {
    let Some((qualifier, qualifier_node, field_node)) = selector_parts(node, ctx.source) else {
        return;
    };
    if is_definition_identifier(qualifier_node, ctx.source) {
        return;
    }
    let field = node_text(field_node, ctx.source).to_string();
    if let Some(packages) = ctx.alias_packages.get(&qualifier) {
        let callees: Vec<String> = packages
            .iter()
            .map(|package| format!("{package}.{field}"))
            .collect();
        for callee in callees {
            ctx.record_with_caller(caller.to_string(), callee, field_node);
        }
    }
}

fn scan_top_level_initializer_direct(node: Node<'_>, caller: &str, ctx: &mut FileScan<'_, '_>) {
    if is_definition_identifier(node, ctx.source) {
        return;
    }
    let text = node_text(node, ctx.source).to_string();
    ctx.record_with_caller(
        caller.to_string(),
        format!("{}.{}", ctx.file_pkg, text),
        node,
    );
    let dot_callees: Vec<String> = ctx
        .dot_packages
        .iter()
        .map(|package| format!("{package}.{text}"))
        .collect();
    for callee in dot_callees {
        ctx.record_with_caller(caller.to_string(), callee, node);
    }
}

fn scan_children(
    node: Node<'_>,
    ctx: &mut FileScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx, locals);
    }
}

fn scan_selector(
    node: Node<'_>,
    ctx: &mut FileScan<'_, '_>,
    locals: &LocalInferenceEngine<String>,
) {
    let Some((qualifier, qualifier_node, field_node)) = selector_parts(node, ctx.source) else {
        return;
    };
    let field = node_text(field_node, ctx.source).to_string();

    // Member call: the qualifier is a local whose type we inferred.
    let receiver = receiver_symbol_from_qualifier(&qualifier);
    let receiver_resolution = locals.resolve_symbol(receiver);
    if let Some(types) = receiver_resolution.as_precise() {
        let callees: Vec<String> = types
            .iter()
            .flat_map(|type_fqn| ctx.member_callees(type_fqn, &field))
            .collect();
        if callees.is_empty() && types.iter().all(|type_fqn| !ctx.has_node(type_fqn)) {
            ctx.record_unproven(&field, field_node);
            return;
        }
        for callee in callees {
            ctx.record(callee, field_node);
        }
        return;
    }

    // Namespace call: the qualifier is an import binding (and not shadowed by a
    // local of the same name, nor itself a definition site).
    if locals.is_shadowed(&qualifier) || is_definition_identifier(qualifier_node, ctx.source) {
        return;
    }
    if let Some(packages) = ctx.alias_packages.get(&qualifier) {
        let callees: Vec<String> = packages
            .iter()
            .map(|package| format!("{package}.{field}"))
            .collect();
        for callee in callees {
            ctx.record(callee, field_node);
        }
    } else if receiver_resolution.is_ambiguous() || locals.is_shadowed(receiver) {
        ctx.record_unproven(&field, field_node);
    }
}

fn scan_direct(node: Node<'_>, ctx: &mut FileScan<'_, '_>, locals: &LocalInferenceEngine<String>) {
    if is_definition_identifier(node, ctx.source) {
        return;
    }
    let text = node_text(node, ctx.source).to_string();
    if locals.is_shadowed(&text) {
        return;
    }
    // A bare name resolves to a same-package symbol, or a dot-imported one.
    ctx.record(format!("{}.{}", ctx.file_pkg, text), node);
    let dot_callees: Vec<String> = ctx
        .dot_packages
        .iter()
        .map(|package| format!("{package}.{text}"))
        .collect();
    for callee in dot_callees {
        ctx.record(callee, node);
    }
}

fn seed_parameters(
    node: Node<'_>,
    ctx: &FileScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) {
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
    ctx: &FileScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let names = parameter_names(node, ctx.source);
    let tokens = node
        .child_by_field_name("type")
        .and_then(|type_node| type_ref_from_node(type_node, ctx.source))
        .map(|ty| ctx.type_tokens(&ty))
        .unwrap_or_default();
    seed_or_shadow(names, tokens, locals);
}

fn seed_local_bindings(
    node: Node<'_>,
    ctx: &FileScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "var_declaration" => {
            for_each_var_spec(node, &mut |var_spec| seed_var_spec(var_spec, ctx, locals))
        }
        "var_spec" => seed_var_spec(node, ctx, locals),
        "short_var_declaration" => seed_assignment_like(node, ctx, locals, true),
        "assignment_statement" => seed_assignment_like(node, ctx, locals, false),
        _ => {}
    }
}

fn seed_var_spec(
    node: Node<'_>,
    ctx: &FileScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let names = var_spec_names(node, ctx.source);
    if names.is_empty() {
        return;
    }
    let typed = node
        .child_by_field_name("type")
        .and_then(|type_node| type_ref_from_node(type_node, ctx.source))
        .map(|ty| ctx.type_tokens(&ty))
        .unwrap_or_default();
    if !typed.is_empty() {
        seed_or_shadow(names, typed, locals);
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
    ctx: &FileScan<'_, '_>,
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
    Types(Vec<String>),
    Alias(String),
}

fn infer_names_from_values(
    names: Vec<Option<String>>,
    values: Vec<Node<'_>>,
    ctx: &FileScan<'_, '_>,
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
            let mut tokens = ctx.constructor_call_type_tokens(*value, Some(locals));
            if tokens.is_empty() {
                tokens = ctx.expression_type_tokens(*value);
            }
            if !tokens.is_empty() {
                Some((name.clone(), InferredBinding::Types(tokens)))
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
            InferredBinding::Types(tokens) => locals.seed_symbol_many(name, tokens),
            InferredBinding::Alias(source) => locals.alias_symbol(name, &source),
        }
    }
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

/// Seed `names` with the inferred type tokens, or — when no workspace type was
/// resolved — record them as shadowing locals so they are not mistaken for import
/// bindings. Mirrors the forward scan, which shadows any typed local that is not
/// the target's owner.
fn seed_or_shadow(
    names: Vec<String>,
    tokens: Vec<String>,
    locals: &mut LocalInferenceEngine<String>,
) {
    if tokens.is_empty() {
        for name in names {
            locals.declare_shadow(name);
        }
    } else {
        for name in names {
            locals.seed_symbol_many(name, tokens.clone());
        }
    }
}
