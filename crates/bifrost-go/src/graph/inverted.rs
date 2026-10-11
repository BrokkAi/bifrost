//! The per-file half of Go's whole-workspace inverted edge pass.
//!
//! The driver in `brokk-bifrost-analysis` walks each file once, parses it, and
//! hands the result here as a [`FileEdgeScanInput`]; [`scan_go_file`] resolves
//! every reference in that file to the fully qualified callee it names and
//! returns the file's [`PerFileEdges`]. Both are core types, so nothing on this
//! path needs an analyzer handle.
//!
//! It reuses the per-symbol resolver's exact building blocks -- the same AST
//! helpers, the same local type-inference engine, the same definition-site and
//! self-reference exclusions -- so the resulting nodes, edges, weights, and
//! `truncated_symbols` match the per-symbol path. Where the forward scan seeds a
//! sentinel "this local is the target's owner type" token, the inverted scan
//! seeds the local's *actual* type fqn, and where the forward scan matches one
//! target it resolves the reference's callee.

use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    FileEdgeScanInput, PerFileEdges, classify_reference_node,
};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use crate::graph::ast::{
    SELF_RECEIVER_TOKEN, clause_binding_names, clause_statement_list,
    for_each_callable_header_node, for_each_clause_prebody_node, for_each_function_parameter_list,
    for_each_parameter_declaration, for_each_type_switch_child,
    for_each_value_spec as for_each_value_spec_ast, for_each_var_spec,
    for_each_var_spec_prebinding_node, infer_before_declaring_bindings,
    infer_before_declaring_short_var_bindings, is_clause, is_definition_identifier,
    is_identifier_node, is_method_receiver_parameter, method_receiver_parameter_list,
    parameter_names, receiver_symbol_from_qualifier, rhs_expressions, selector_parts,
    type_ref_from_node, var_spec_name_slots, var_spec_names,
};
use crate::graph::resolver::{
    GoEdgeIndex, TypeRef, constructor_call_type_fqns, node_text, resolve_type_candidates,
};
use crate::packages::GO_MODULE_SCOPE_SEGMENT;

/// Walk one Go file and return its edge contributions. Pure logic over the
/// driver-supplied [`FileEdgeScanInput`], the file's package facts, and the
/// tree-free [`GoEdgeIndex`] — no analyzer handle and no driver state.
pub fn scan_go_file(
    index: &GoEdgeIndex,
    file_pkg: String,
    alias_packages: HashMap<String, Vec<String>>,
    dot_packages: Vec<String>,
    import_binding_names: HashSet<String>,
    input: &FileEdgeScanInput<'_>,
) -> PerFileEdges {
    let mut ctx = FileScan {
        source: input.source,
        file_pkg,
        alias_packages,
        dot_packages,
        import_binding_names,
        index,
        member_callee_cache: HashMap::default(),
        input,
        edges: PerFileEdges::default(),
    };
    let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
    scan_node(input.root(), &mut ctx, &mut locals);
    ctx.edges
}

struct FileScan<'a> {
    source: &'a str,
    file_pkg: String,
    alias_packages: HashMap<String, Vec<String>>,
    dot_packages: Vec<String>,
    import_binding_names: HashSet<String>,
    index: &'a GoEdgeIndex,
    member_callee_cache: HashMap<(String, String), Vec<String>>,
    input: &'a FileEdgeScanInput<'a>,
    edges: PerFileEdges,
}

impl FileScan<'_> {
    /// Candidate node fqns for a type reference used as a value's type: the type's
    /// class fqn, resolved through the file's package (bare) or imports (qualified).
    fn type_tokens(&self, ty: &TypeRef) -> Vec<String> {
        resolve_type_candidates(
            ty,
            &self.file_pkg,
            &self.alias_packages,
            &self.dot_packages,
            self.index,
        )
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

    /// Hand a resolved reference to this file's edge accumulator, which applies the
    /// enclosing-caller attribution, cap counting, and edge dedup.
    fn record(&mut self, callee: String, node: Node<'_>) {
        self.edges.record_reference(self.input, callee, node);
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.edges
            .record_unproven_name_at_node(self.input, name, node);
    }

    /// Record a resolved callee as unproven inbound (rather than a proven edge):
    /// used for same-owner receiver calls (#1138).
    fn record_unproven_callee(&mut self, callee: String, node: Node<'_>) {
        self.edges
            .record_unproven(self.input, callee, node.start_byte(), node.end_byte());
    }

    fn has_node(&self, node: &String) -> bool {
        self.input.is_node(node)
    }

    fn record_with_caller(&mut self, caller: String, callee: String, node: Node<'_>) {
        self.edges.record_with_caller_kind(
            self.input,
            caller,
            callee,
            classify_reference_node(node),
            node.start_byte(),
            node.end_byte(),
        );
    }
}

fn scan_node(node: Node<'_>, ctx: &mut FileScan<'_>, locals: &mut LocalInferenceEngine<String>) {
    match node.kind() {
        "import_declaration" => return,
        "func_literal" | "function_declaration" | "method_declaration" => {
            locals.enter_scope();
            scan_callable_header(node, ctx, locals);
            seed_parameters(node, ctx, locals);
            if let Some(body) = node.child_by_field_name("body") {
                scan_node(body, ctx, locals);
            }
            locals.exit_scope();
            return;
        }
        "block" | "block_statement" => {
            locals.enter_scope();
            scan_children(node, ctx, locals);
            locals.exit_scope();
            return;
        }
        "type_switch_statement" => {
            scan_type_switch(node, ctx, locals);
            return;
        }
        _ if is_clause(node) => {
            scan_clause(node, ctx, locals);
            return;
        }
        "function_type" | "method_elem" => {
            // Signature binders have no body in which they can be referenced.
            // Scan every parameter/result type before considering any names so
            // a parameter named like an import cannot shadow that import in its
            // own type or leak into the enclosing file/interface scope.
            scan_callable_header(node, ctx, locals);
            return;
        }
        "parameter_declaration" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                scan_node(type_node, ctx, locals);
            }
            seed_parameter_declaration(node, ctx, locals, is_method_receiver_parameter(node));
            return;
        }
        "const_declaration" if is_top_level_declaration(node) => {
            scan_top_level_value_initializers(node, ctx);
        }
        "var_declaration" | "short_var_declaration" => {
            if node.kind() == "var_declaration" && is_top_level_declaration(node) {
                scan_top_level_value_initializers(node, ctx);
            } else if node.kind() == "short_var_declaration" {
                for value in rhs_expressions(node) {
                    scan_node(value, ctx, locals);
                }
                seed_short_var_bindings(node, ctx, locals);
                return;
            } else {
                for_each_var_spec(node, &mut |spec| {
                    scan_var_spec_before_binding(spec, ctx, locals);
                    seed_var_spec(spec, ctx, locals);
                });
                return;
            }
        }
        "selector_expression" | "qualified_type" => scan_selector(node, ctx, locals),
        "identifier" | "type_identifier" | "package_identifier" => scan_direct(node, ctx, locals),
        _ => {}
    }
    scan_children(node, ctx, locals);
}

fn scan_type_switch(
    node: Node<'_>,
    ctx: &mut FileScan<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    for_each_type_switch_child(node, |child| scan_node(child, ctx, locals));
}

fn scan_clause(node: Node<'_>, ctx: &mut FileScan<'_>, locals: &mut LocalInferenceEngine<String>) {
    let body = clause_statement_list(node);
    for_each_clause_prebody_node(node, |child| scan_node(child, ctx, locals));
    if let Some(body) = body {
        locals.enter_scope();
        for name in clause_binding_names(node, ctx.source) {
            locals.declare_shadow(name);
        }
        scan_node(body, ctx, locals);
        locals.exit_scope();
    }
}

fn scan_var_spec_before_binding(
    node: Node<'_>,
    ctx: &mut FileScan<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    for_each_var_spec_prebinding_node(node, |child| scan_node(child, ctx, locals));
}

fn scan_callable_header(
    node: Node<'_>,
    ctx: &mut FileScan<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    for_each_callable_header_node(node, |child| scan_node(child, ctx, locals));
}

fn is_top_level_declaration(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "source_file")
}

fn scan_top_level_value_initializers(node: Node<'_>, ctx: &mut FileScan<'_>) {
    for_each_value_spec_ast(node, &mut |spec| {
        let names = var_spec_names(spec, ctx.source);
        let values = rhs_expressions(spec);
        if names.is_empty() || values.is_empty() {
            return;
        }
        for (name, value) in names.into_iter().zip(values) {
            let caller = format!("{}.{}.{name}", ctx.file_pkg, GO_MODULE_SCOPE_SEGMENT);
            scan_top_level_initializer_value(value, caller.as_str(), ctx);
        }
    });
}

fn scan_top_level_initializer_value(node: Node<'_>, caller: &str, ctx: &mut FileScan<'_>) {
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

fn scan_top_level_initializer_selector(node: Node<'_>, caller: &str, ctx: &mut FileScan<'_>) {
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

fn scan_top_level_initializer_direct(node: Node<'_>, caller: &str, ctx: &mut FileScan<'_>) {
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
    ctx: &mut FileScan<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx, locals);
    }
}

fn scan_selector(node: Node<'_>, ctx: &mut FileScan<'_>, locals: &LocalInferenceEngine<String>) {
    let Some((qualifier, qualifier_node, field_node)) = selector_parts(node, ctx.source) else {
        return;
    };
    let field = node_text(field_node, ctx.source).to_string();

    // Member call: the qualifier is a local whose type we inferred.
    let receiver = receiver_symbol_from_qualifier(&qualifier);
    let receiver_resolution = locals.resolve_symbol(receiver);
    if let Some(types) = receiver_resolution.as_precise() {
        // A call through the enclosing method's own receiver variable is a
        // same-owner site (#1138): route its resolved callees to unproven inbound
        // rather than proven edges. A call through another owner-typed value stays
        // external.
        let same_owner = types.iter().any(|type_fqn| type_fqn == SELF_RECEIVER_TOKEN);
        let callees: Vec<String> = types
            .iter()
            .flat_map(|type_fqn| ctx.member_callees(type_fqn, &field))
            .collect();
        if callees.is_empty() {
            if same_owner || types.iter().all(|type_fqn| !ctx.has_node(type_fqn)) {
                ctx.record_unproven(&field, field_node);
            }
            return;
        }
        for callee in callees {
            if same_owner {
                ctx.record_unproven_callee(callee, field_node);
            } else {
                ctx.record(callee, field_node);
            }
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

fn scan_direct(node: Node<'_>, ctx: &mut FileScan<'_>, locals: &LocalInferenceEngine<String>) {
    if is_definition_identifier(node, ctx.source) {
        return;
    }
    let text = node_text(node, ctx.source).to_string();
    if ctx.import_binding_names.contains(&text) {
        return;
    }
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

fn seed_parameters(node: Node<'_>, ctx: &FileScan<'_>, locals: &mut LocalInferenceEngine<String>) {
    // Mark the method's own receiver variable as the same-owner receiver (Go has
    // no `self`/`this`; `func (s *T) f() { s.g() }` calls siblings through `s`).
    // Ported from the forward scan (extractor.rs) so `s.g()` routes to unproven
    // inbound (#1138) while `other.g()` — another `*T` value — stays external.
    if let Some(receiver) = method_receiver_parameter_list(node) {
        seed_parameter_list(receiver, ctx, locals, true);
    }
    for_each_function_parameter_list(node, |list| seed_parameter_list(list, ctx, locals, false));
}

fn seed_parameter_list(
    node: Node<'_>,
    ctx: &FileScan<'_>,
    locals: &mut LocalInferenceEngine<String>,
    is_method_receiver: bool,
) {
    for_each_parameter_declaration(node, |parameter| {
        seed_parameter_declaration(parameter, ctx, locals, is_method_receiver)
    });
}

fn seed_parameter_declaration(
    node: Node<'_>,
    ctx: &FileScan<'_>,
    locals: &mut LocalInferenceEngine<String>,
    is_method_receiver: bool,
) {
    let names = parameter_names(node, ctx.source);
    let mut tokens = node
        .child_by_field_name("type")
        .and_then(|type_node| type_ref_from_node(type_node, ctx.source))
        .map(|ty| ctx.type_tokens(&ty))
        .unwrap_or_default();
    // Tag the receiver variable so `recv.member` is recognized as same-owner in
    // `scan_selector`. Only when the receiver type resolved to a workspace type
    // (otherwise the name is a shadow with no callable siblings to route).
    if is_method_receiver
        && !tokens.is_empty()
        && !tokens.iter().any(|token| token == SELF_RECEIVER_TOKEN)
    {
        tokens.push(SELF_RECEIVER_TOKEN.to_string());
    }
    seed_or_shadow(names, tokens, locals);
}

fn seed_var_spec(node: Node<'_>, ctx: &FileScan<'_>, locals: &mut LocalInferenceEngine<String>) {
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
    infer_before_declaring_bindings(
        var_spec_name_slots(node, ctx.source),
        rhs_expressions(node),
        locals,
        |slots, values, locals| infer_names_from_values(slots, values, ctx, locals),
        |locals, name| locals.declare_shadow(name),
        |locals, bindings| apply_inferred_bindings(bindings, locals),
    );
}

fn seed_short_var_bindings(
    node: Node<'_>,
    ctx: &FileScan<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    infer_before_declaring_short_var_bindings(
        node,
        ctx.source,
        locals,
        |slots, values, locals| infer_names_from_values(slots, values, ctx, locals),
        |locals, name| locals.declare_shadow(name),
        |locals, bindings| apply_inferred_bindings(bindings, locals),
    );
}

enum InferredBinding {
    Types(Vec<String>),
    Alias(String),
}

fn infer_names_from_values(
    names: Vec<Option<String>>,
    values: Vec<Node<'_>>,
    ctx: &FileScan<'_>,
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
            let mut tokens = constructor_call_type_fqns(
                *value,
                ctx.source,
                &ctx.file_pkg,
                &ctx.alias_packages,
                &ctx.dot_packages,
                ctx.index,
                Some(locals),
            );
            if tokens.is_empty() {
                tokens = field_selector_type_tokens(*value, ctx, locals);
            }
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

/// The type fqn(s) a `base.field` initializer denotes: `base` is a local whose
/// type was precisely inferred and `field` is an indexed struct field with a
/// workspace type. Mirrors the forward scan's field-derived local receiver
/// seeding (#1611) with the actual type fqn instead of the owner sentinel.
fn field_selector_type_tokens(
    value: Node<'_>,
    ctx: &FileScan<'_>,
    locals: &LocalInferenceEngine<String>,
) -> Vec<String> {
    if value.kind() != "selector_expression" {
        return Vec::new();
    }
    let Some((qualifier, _qualifier_node, field_node)) = selector_parts(value, ctx.source) else {
        return Vec::new();
    };
    let receiver = receiver_symbol_from_qualifier(&qualifier);
    let resolution = locals.resolve_symbol(receiver);
    let Some(types) = resolution.as_precise() else {
        return Vec::new();
    };
    let field = node_text(field_node, ctx.source);
    let mut tokens: Vec<String> = types
        .iter()
        .filter(|type_fqn| type_fqn.as_str() != SELF_RECEIVER_TOKEN)
        .filter_map(|type_fqn| ctx.index.unique_field_type_fqn(type_fqn, field))
        .collect();
    tokens.sort();
    tokens.dedup();
    tokens
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
