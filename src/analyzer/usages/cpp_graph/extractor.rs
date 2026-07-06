use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::cpp_call_match::{
    CppArgType, cpp_filter_candidates_by_args, cpp_literal_type_name, cpp_signature_param_types,
    cpp_type_text_pointer_depth, normalize_cpp_type_name,
};
use crate::analyzer::usages::cpp_graph::hits::{
    enclosing_context, is_member_field_declaration_context, push_definition_hit, push_hit,
    push_self_receiver_hit,
};
use crate::analyzer::usages::cpp_graph::resolver::*;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, cpp_node_text as node_text};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) saw_unproven_match: &'a mut bool,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) struct ScanCtx<'a> {
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) visibility: &'a VisibilityIndex,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) bindings: LocalInferenceEngine<CppScanBinding>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) saw_unproven_match: &'a mut bool,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: HashMap<(usize, usize), EnclosingContext>,
}

#[derive(Clone, Default)]
pub(super) struct EnclosingContext {
    pub(super) enclosing: Option<CodeUnit>,
    pub(super) owner: Option<CodeUnit>,
}

pub(super) fn scan_file(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded || language_for_file(file) != Language::Cpp {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);
    let mut ctx = ScanCtx {
        analyzer,
        visibility,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        bindings: LocalInferenceEngine::new(LocalInferenceConfig::default()),
        hits: state.hits,
        saw_unproven_match: state.saw_unproven_match,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let enters_scope = matches!(
        node.kind(),
        "compound_statement"
            | "function_definition"
            | "lambda_expression"
            | "for_statement"
            | "while_statement"
            | "if_statement"
    );
    if enters_scope {
        ctx.bindings.enter_scope();
    }

    seed_declarations(node, ctx);
    maybe_record_hit(node, ctx);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }

    if enters_scope {
        ctx.bindings.exit_scope();
    }
}

fn seed_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration" => seed_typed_binding(node, ctx),
        "declaration" | "field_declaration" => seed_variable_declaration(node, ctx),
        _ => {}
    }
}

fn seed_variable_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
        .map(|node| node_text(node, ctx.source).to_string());
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        if declarator.kind() == "function_declarator"
            && !constructor_style_local_declaration(
                ctx.visibility,
                ctx.file,
                ctx.source,
                declarator,
                type_text.as_deref(),
                &ctx.bindings,
            )
        {
            continue;
        }
        let Some(name) = extract_variable_name(declarator, ctx.source) else {
            continue;
        };
        let value = child.child_by_field_name("value");
        seed_binding_from_type_or_value(&name, type_text.as_deref(), value, ctx);
    }
}

fn seed_typed_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
        .map(|node| node_text(node, ctx.source).to_string());
    seed_binding_from_type_or_value(&name, type_text.as_deref(), None, ctx);
}

fn seed_binding_from_type_or_value(
    name: &str,
    type_text: Option<&str>,
    value: Option<Node<'_>>,
    ctx: &mut ScanCtx<'_>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_text
        .filter(|text| normalize_type_text(text) != "auto")
        .map(|text| {
            let name = normalize_cpp_type_name(text);
            CppScanBinding::from_type_name(
                name.clone(),
                ctx.visibility.resolve_type(ctx.file, &name),
                cpp_type_text_pointer_depth(text),
            )
        })
        .or_else(|| value.and_then(|value| infer_type_from_value(value, ctx)));

    if let Some(resolved) = resolved {
        ctx.bindings.seed_symbol(name.to_string(), resolved);
    } else if let Some(value) = value
        && value.kind() == "identifier"
    {
        ctx.bindings
            .alias_symbol(name.to_string(), node_text(value, ctx.source));
    } else {
        ctx.bindings.declare_shadow(name.to_string());
    }
}

fn infer_type_from_value(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CppScanBinding> {
    match node.kind() {
        "new_expression" | "call_expression" => infer_cpp_initializer_binding(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
            Some(&|receiver, source| receiver_type_units(receiver, source, ctx)),
        ),
        "initializer_list" => None,
        "identifier" => {
            let resolved = ctx.bindings.resolve_symbol(node_text(node, ctx.source));
            resolved
                .as_precise()?
                .iter()
                .find(|binding| binding.unit.as_ref().is_some_and(CodeUnit::is_class))
                .cloned()
        }
        _ => {
            let text = node_text(node, ctx.source);
            let name = normalize_cpp_type_name(text);
            ctx.visibility
                .resolve_type(ctx.file, &name)
                .map(|unit| CppScanBinding::from_unit(unit, 0))
        }
    }
}

fn maybe_record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match ctx.spec.kind {
        TargetKind::Type => maybe_record_type_hit(node, ctx),
        TargetKind::Constructor => maybe_record_constructor_hit(node, ctx),
        TargetKind::FreeFunction => maybe_record_free_function_hit(node, ctx),
        TargetKind::Method => maybe_record_method_hit(node, ctx),
        TargetKind::GlobalField => maybe_record_global_field_hit(node, ctx),
        TargetKind::MemberField => maybe_record_member_field_hit(node, ctx),
    }
}

fn maybe_record_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "type_identifier" | "qualified_identifier" | "scoped_type_identifier" | "template_type"
    ) {
        return;
    }
    if is_declaration_name(node) {
        if let Some((scope, owner)) =
            out_of_line_member_definition_owner(ctx.visibility, ctx.file, ctx.source, node)
            && same_visible_symbol(&owner, &ctx.spec.target)
        {
            *ctx.raw_match_count += 1;
            push_hit(scope, ctx);
        }
        return;
    }
    let hit_node = node;
    let text = node_text(hit_node, ctx.source);
    if !name_mentions(text, &ctx.spec.member_name)
        && !ctx
            .visibility
            .resolves_to_type(ctx.file, text, &ctx.spec.target)
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if ctx
        .visibility
        .resolves_to_type(ctx.file, text, &ctx.spec.target)
    {
        push_hit(hit_node, ctx);
    } else if !ctx.visibility.is_visible(ctx.file, &ctx.spec.target) {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_constructor_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "function_definition" {
        return;
    }
    if !matches!(
        node.kind(),
        "call_expression"
            | "new_expression"
            | "compound_literal_expression"
            | "declaration"
            | "field_initializer"
    ) {
        return;
    }
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return;
    };
    if node.kind() == "field_initializer" {
        if field_initializer_constructs_target(node, ctx, owner)
            && ctx
                .spec
                .method_arity
                .is_none_or(|expected| call_arity(node) == expected)
        {
            push_hit(node, ctx);
        }
        return;
    }
    if node.kind() == "declaration" {
        if declaration_is_object_construction_candidate(node, ctx)
            && declaration_mentions_type(node, ctx, owner)
            && ctx
                .spec
                .method_arity
                .is_none_or(|expected| declaration_constructor_arity(node, ctx) == expected)
        {
            push_hit(node, ctx);
        }
        return;
    }
    let Some(type_node) = constructor_type_node(node) else {
        return;
    };
    let text = node_text(type_node, ctx.source);
    if !name_mentions(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.method_arity
        && call_arity(node) != expected
    {
        return;
    }
    if ctx.visibility.resolves_to_type(ctx.file, text, owner) {
        push_hit(type_node, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_free_function_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "function_definition" {
        maybe_record_free_function_definition_hit(node, ctx);
        return;
    }
    if node.kind() == "identifier" {
        maybe_record_free_function_value_reference(node, ctx);
        return;
    }
    if node.kind() != "call_expression" {
        return;
    }
    let Some(function) = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))
    else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.method_arity
        && call_arity(node) != expected
    {
        return;
    }
    if !free_function_call_may_target(node, text, ctx) {
        return;
    }
    if ctx.visibility.contains_named_symbol(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        push_hit(function, ctx);
    } else if ctx.visibility.resolve_known_non_target(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        // An explicitly namespace-qualified call to a different namespace (e.g. `other::run()` when
        // the target is `ns::run`) is a proven non-match, not an unresolved reference.
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn free_function_call_may_target(call: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.param_types.is_none() {
        return true;
    }
    let mut candidates = ctx
        .visibility
        .named_candidates(ctx.file, text, TargetKind::FreeFunction);
    if let Some(expected) = ctx.spec.method_arity {
        candidates.retain(|unit| signature_arity(unit.signature()) == expected);
    }
    if candidates.is_empty()
        || !candidates
            .iter()
            .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
    {
        return true;
    }
    let arg_types = call_argument_types(call, ctx);
    let filtered = cpp_filter_candidates_by_args(
        candidates,
        &arg_types,
        &|name| ctx.visibility.resolve_type(ctx.file, name),
        &|left, right| same_visible_symbol(left, right),
    );
    filtered
        .iter()
        .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
}

fn call_argument_types(call: Node<'_>, ctx: &ScanCtx<'_>) -> Vec<Option<CppArgType>> {
    let Some(args) = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("parameters"))
        .or_else(|| call.child_by_field_name("value"))
    else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .map(|arg| expression_arg_type(arg, ctx))
        .collect()
}

fn expression_arg_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CppArgType> {
    match node.kind() {
        "number_literal" | "true" | "false" | "char_literal" | "string_literal"
        | "unary_expression" => cpp_literal_type_name(node, ctx.source).map(|name| CppArgType {
            name: name.to_string(),
            unit: ctx.visibility.resolve_type(ctx.file, name),
            indirection: 0,
        }),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, ctx.source))
            .as_precise()
            .and_then(|bindings| bindings.iter().find_map(CppScanBinding::as_arg_type)),
        "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .and_then(|inner| expression_arg_type(inner, ctx)),
        "pointer_expression" => {
            let delta = match node.child_by_field_name("operator")?.kind() {
                "&" => 1,
                "*" => -1,
                _ => return None,
            };
            let inner = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;
            let mut arg_type = expression_arg_type(inner, ctx)?;
            arg_type.indirection += delta;
            Some(arg_type)
        }
        _ => None,
    }
}

/// Record a *non-call* reference to a free function used as a value: `&foo`,
/// `fp = foo`, `foo` passed as an argument, etc. The callee identifier of a call
/// `foo()` is recorded by the call_expression arm, and the function's own
/// declaration/definition name is not a reference.
fn maybe_record_free_function_value_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let text = node_text(node, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    if is_declaration_name(node) || cpp_reference_is_call_callee(node) {
        return;
    }
    *ctx.raw_match_count += 1;
    if ctx.visibility.contains_named_symbol(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        push_hit(node, ctx);
    } else if ctx.visibility.resolve_known_non_target(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        // A qualified reference proven to a different namespace is not a match.
    } else {
        *ctx.saw_unproven_match = true;
    }
}

/// Whether `node` is (part of) the callee expression of a call — walking through
/// the qualified/template/field wrappers so `foo`, `ns::foo`, and `obj.foo` in
/// `…()` are all recognised (and thus left to the call_expression arm).
fn cpp_reference_is_call_callee(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "call_expression" => {
                return parent
                    .child_by_field_name("function")
                    .or_else(|| parent.named_child(0))
                    == Some(node);
            }
            "qualified_identifier" | "template_function" | "field_expression" => node = parent,
            _ => return false,
        }
    }
    false
}

fn maybe_record_free_function_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(function) = function_definition_name_node(node) else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if !function_definition_signature_matches_target(node, ctx) {
        return;
    }
    if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            ctx.visibility.contains_named_symbol(
                ctx.file,
                name,
                TargetKind::FreeFunction,
                &ctx.spec.target,
            )
        })
    {
        push_definition_hit(function, ctx);
    } else if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            ctx.visibility.resolve_known_non_target(
                ctx.file,
                name,
                TargetKind::FreeFunction,
                &ctx.spec.target,
            )
        })
    {
        // A definition in another explicit namespace is a proven non-match.
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "function_definition" {
        maybe_record_method_definition_hit(node, ctx);
        return;
    }
    if node.kind() != "call_expression" {
        return;
    }
    if let Some((receiver, operator)) = explicit_operator_call(node) {
        let text = node_text(operator, ctx.source);
        if !name_matches_callable(text, &ctx.spec.member_name) {
            return;
        }
        *ctx.raw_match_count += 1;
        if let Some(expected) = ctx.spec.method_arity
            && call_arity(node) != expected
        {
            return;
        }
        if receiver_matches_target(receiver, ctx) {
            if receiver_is_self_like(receiver) {
                push_self_receiver_hit(operator, ctx);
            } else {
                push_hit(operator, ctx);
            }
        } else if !receiver_has_known_non_target(receiver, ctx) {
            *ctx.saw_unproven_match = true;
        }
        return;
    }
    let Some(function) = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))
    else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.method_arity
        && call_arity(node) != expected
    {
        return;
    }
    if !method_call_may_target(node, ctx) {
        return;
    }
    if receiver_matches_target(function, ctx) {
        if receiver_is_self_like(function) {
            push_self_receiver_hit(function_terminal_node(function), ctx);
        } else {
            push_hit(function_terminal_node(function), ctx);
        }
    } else if same_owner_context(function, ctx) {
        push_self_receiver_hit(function_terminal_node(function), ctx);
    } else if !receiver_has_known_non_target(function, ctx)
        && !known_non_target_owner_context(function, ctx)
    {
        *ctx.saw_unproven_match = true;
    }
}

fn method_call_may_target(call: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return true;
    };
    if ctx.spec.param_types.is_none() {
        return true;
    }
    let mut candidates = ctx
        .visibility
        .visible_units(ctx.file)
        .filter(|unit| {
            unit.is_function()
                && unit.fq_name() == format!("{}.{}", owner.fq_name(), ctx.spec.member_name)
        })
        .cloned()
        .collect::<Vec<_>>();
    if let Some(expected) = ctx.spec.method_arity {
        candidates.retain(|unit| signature_arity(unit.signature()) == expected);
    }
    if candidates.is_empty()
        || !candidates
            .iter()
            .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
    {
        return true;
    }
    let arg_types = call_argument_types(call, ctx);
    let filtered = cpp_filter_candidates_by_args(
        candidates,
        &arg_types,
        &|name| ctx.visibility.resolve_type(ctx.file, name),
        &|left, right| same_visible_symbol(left, right),
    );
    filtered
        .iter()
        .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
}

fn maybe_record_method_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(function) = function_definition_name_node(node) else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if !function_definition_signature_matches_target(node, ctx) {
        return;
    }
    if node_inside_target_declaration(function, ctx) {
        return;
    }
    if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            name.contains("::")
                && ctx.visibility.contains_named_symbol(
                    ctx.file,
                    name,
                    TargetKind::Method,
                    &ctx.spec.target,
                )
        })
        || qualified_owner_matches(text, ctx)
    {
        push_definition_hit(function, ctx);
    } else if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            ctx.visibility.resolve_known_non_target(
                ctx.file,
                name,
                TargetKind::Method,
                &ctx.spec.target,
            )
        })
        || known_non_target_owner_context(function, ctx)
    {
        // A method definition for another visible owner is a proven non-match.
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn node_inside_target_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.file != ctx.spec.target.source() {
        return false;
    }
    ctx.analyzer
        .ranges(&ctx.spec.target)
        .iter()
        .any(|range| node.start_byte() >= range.start_byte && node.end_byte() <= range.end_byte)
}

fn explicit_operator_call(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut receiver = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "argument_list" {
            continue;
        }
        if let Some(operator) = first_descendant_of_kind(child, "operator_name") {
            return receiver.map(|receiver| (receiver, operator));
        }
        if receiver.is_none() {
            receiver = Some(child);
        }
    }
    None
}

fn function_definition_name_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "function_definition" {
        return None;
    }
    node.child_by_field_name("declarator")
        .and_then(callable_declarator_name_node)
}

fn callable_declarator_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier"
        | "field_identifier"
        | "qualified_identifier"
        | "scoped_identifier"
        | "operator_name"
        | "destructor_name" => Some(node),
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("field"))
            .and_then(callable_declarator_name_node),
    }
}

fn function_definition_signature_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let definition = node_text(node, ctx.source);
    let Some(expected) = ctx.spec.method_arity else {
        return true;
    };
    if signature_arity(Some(definition)) != expected {
        return false;
    }
    let Some(target_signature) = ctx.spec.target.signature() else {
        return true;
    };
    cpp_signature_param_types(definition) == cpp_signature_param_types(target_signature)
}

fn definition_name_candidates(function: Node<'_>, ctx: &ScanCtx<'_>) -> Vec<String> {
    let raw = normalize_cpp_reference_text(node_text(function, ctx.source));
    if raw.is_empty() {
        return Vec::new();
    }
    let Some(namespace) = enclosing_namespace_context(function, ctx.source) else {
        return vec![raw];
    };
    if !raw.contains("::") {
        return vec![format!("{namespace}::{raw}")];
    }
    if raw
        .split("::")
        .next()
        .is_some_and(|head| head != namespace && !namespace.ends_with(&format!("::{head}")))
    {
        vec![format!("{namespace}::{raw}"), raw]
    } else {
        vec![raw]
    }
}

fn first_descendant_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_descendant_of_kind(child, kind) {
            return Some(found);
        }
    }
    None
}

fn maybe_record_global_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier"
    ) || !name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        || is_declaration_name(node)
        || is_member_field_declaration_context(node, ctx)
        || has_ancestor_kind(node, "field_expression")
        || is_nested_in_qualified_identifier(node)
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if global_field_resolves_to_target(node, ctx) {
        push_hit(node, ctx);
    } else if global_field_is_known_non_target(node, ctx) {
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn global_field_resolves_to_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let text = node_text(node, ctx.source);
    if text.contains("::") {
        return ctx.visibility.contains_named_symbol(
            ctx.file,
            text,
            TargetKind::GlobalField,
            &ctx.spec.target,
        );
    }
    if let Some(namespace) = enclosing_namespace_context(node, ctx.source)
        && cpp_namespace_for(&ctx.spec.target).as_deref() == Some(namespace.as_str())
    {
        return ctx.visibility.contains_named_symbol(
            ctx.file,
            text,
            TargetKind::GlobalField,
            &ctx.spec.target,
        );
    }
    bare_global_field_uniquely_resolves_to_target(text, ctx)
}

fn bare_global_field_uniquely_resolves_to_target(text: &str, ctx: &ScanCtx<'_>) -> bool {
    let Some(visible) = ctx.visibility.visible_by_file.get(ctx.file) else {
        return false;
    };
    let mut matched_target = false;
    for unit in visible.iter() {
        if !unit.is_field() || !name_matches_terminal(unit.identifier(), &ctx.spec.member_name) {
            continue;
        }
        if !name_matches_terminal(cpp_name_for(unit).as_str(), text) {
            continue;
        }
        if same_visible_symbol(unit, &ctx.spec.target) {
            matched_target = true;
        } else {
            return false;
        }
    }
    matched_target
}

fn global_field_is_known_non_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let text = node_text(node, ctx.source);
    if text.contains("::") {
        return ctx.visibility.resolve_known_non_target(
            ctx.file,
            text,
            TargetKind::GlobalField,
            &ctx.spec.target,
        );
    }
    let Some(namespace) = enclosing_namespace_context(node, ctx.source) else {
        return false;
    };
    cpp_namespace_for(&ctx.spec.target).as_deref() != Some(namespace.as_str())
        && ctx
            .visibility
            .visible_by_file
            .get(ctx.file)
            .is_some_and(|visible| {
                visible.iter().any(|unit| {
                    unit.is_field()
                        && unit.identifier() == ctx.spec.member_name
                        && cpp_namespace_for(unit).as_deref() == Some(namespace.as_str())
                })
            })
}

fn maybe_record_member_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "field_expression" {
        let Some(field) = node.child_by_field_name("field") else {
            return;
        };
        if node_text(field, ctx.source) != ctx.spec.member_name {
            return;
        }
        *ctx.raw_match_count += 1;
        if receiver_matches_target(node, ctx) {
            push_hit(field, ctx);
        } else if !receiver_has_known_non_target(node, ctx) {
            *ctx.saw_unproven_match = true;
        }
        return;
    }

    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier"
    ) || !name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        || is_declaration_name(node)
        || is_member_field_declaration_context(node, ctx)
        || has_ancestor_kind(node, "field_expression")
        || is_nested_in_qualified_identifier(node)
    {
        return;
    }
    *ctx.raw_match_count += 1;
    let text = node_text(node, ctx.source);
    let qualified_match = text.contains("::")
        && (ctx
            .visibility
            .resolve_named(ctx.file, text, TargetKind::MemberField)
            .is_some_and(|resolved| same_visible_symbol(&resolved, &ctx.spec.target))
            || qualified_owner_matches(text, ctx));
    let unscoped_enum_match = ctx.spec.owner.as_ref().is_some_and(|owner| {
        !text.contains("::")
            && owner_is_unscoped_enum(owner, ctx)
            && ctx.visibility.is_visible(ctx.file, &ctx.spec.target)
    });
    if qualified_match || same_owner_context(node, ctx) || unscoped_enum_match {
        push_hit(node, ctx);
    } else if ctx
        .spec
        .owner
        .as_ref()
        .is_some_and(|owner| owner_is_scoped_enum(owner, ctx) && !text.contains("::"))
    {
        // Scoped enum values must be qualified, so an unqualified same-name value is not this target.
    } else if text.contains("::") {
        // Explicitly qualified fields that do not match the target owner are known non-targets.
    } else if !known_non_target_owner_context(node, ctx) {
        *ctx.saw_unproven_match = true;
    }
}

fn is_nested_in_qualified_identifier(node: Node<'_>) -> bool {
    node.kind() != "qualified_identifier" && has_ancestor_kind(node, "qualified_identifier")
}

fn owner_is_scoped_enum(owner: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    owner
        .signature()
        .is_some_and(|signature| signature.starts_with("enum class "))
        || ctx
            .analyzer
            .get_source(owner, false)
            .is_some_and(|source| source.trim_start().starts_with("enum class "))
}

fn owner_is_unscoped_enum(owner: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    owner.signature().is_some_and(|signature| {
        signature.starts_with("enum ") && !signature.starts_with("enum class ")
    }) || ctx.analyzer.get_source(owner, false).is_some_and(|source| {
        let trimmed = source.trim_start();
        trimmed.starts_with("enum ") && !trimmed.starts_with("enum class ")
    })
}

fn receiver_type_units(node: Node<'_>, source: &str, ctx: &ScanCtx<'_>) -> Vec<CodeUnit> {
    match node.kind() {
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, source))
            .as_precise()
            .into_iter()
            .flatten()
            .filter_map(|binding| binding.unit.clone())
            .collect(),
        "pointer_expression" | "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .map(|inner| receiver_type_units(inner, source, ctx))
            .unwrap_or_default(),
        "call_expression" | "new_expression" => infer_type_from_value(node, ctx)
            .and_then(|binding| binding.unit)
            .into_iter()
            .collect(),
        "field_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"))
            .map(|receiver| receiver_type_units(receiver, source, ctx))
            .unwrap_or_default(),
        _ => ctx
            .visibility
            .resolve_type(ctx.file, node_text(node, source))
            .into_iter()
            .collect(),
    }
}

fn receiver_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    match node.kind() {
        "field_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"))
            .is_some_and(|receiver| receiver_matches_target(receiver, ctx)),
        "call_expression" => node
            .child_by_field_name("function")
            .is_some_and(|function| receiver_matches_target(function, ctx)),
        "pointer_expression" | "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .is_some_and(|child| receiver_matches_target(child, ctx)),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, ctx.source))
            .as_precise()
            .is_some_and(|targets| {
                targets
                    .iter()
                    .filter_map(|target| target.unit.as_ref())
                    .any(|target| same_symbol(target, owner))
            }),
        "this" => same_owner_context(node, ctx),
        "qualified_identifier" | "scoped_identifier" | "field_identifier" => {
            qualified_owner_matches(node_text(node, ctx.source), ctx)
        }
        _ => {
            let text = node_text(node, ctx.source);
            qualified_owner_matches(text, ctx)
        }
    }
}

fn receiver_is_self_like(node: Node<'_>) -> bool {
    match node.kind() {
        "this" => true,
        "field_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"))
            .is_some_and(receiver_is_self_like),
        "call_expression" => node
            .child_by_field_name("function")
            .is_some_and(receiver_is_self_like),
        "pointer_expression" | "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .is_some_and(receiver_is_self_like),
        _ => false,
    }
}

fn receiver_has_known_non_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    match node.kind() {
        "field_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"))
            .is_some_and(|receiver| receiver_has_known_non_target(receiver, ctx)),
        "call_expression" => node
            .child_by_field_name("function")
            .is_some_and(|function| receiver_has_known_non_target(function, ctx)),
        "pointer_expression" | "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .is_some_and(|child| receiver_has_known_non_target(child, ctx)),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, ctx.source))
            .as_precise()
            .is_some_and(|targets| {
                let units = targets
                    .iter()
                    .filter_map(|target| target.unit.as_ref())
                    .collect::<Vec<_>>();
                !units.is_empty()
                    && units
                        .iter()
                        .all(|target| !same_visible_symbol(target, owner))
            }),
        "this" => known_non_target_owner_context(node, ctx),
        "qualified_identifier" | "scoped_identifier" | "field_identifier" => {
            let text = node_text(node, ctx.source);
            !qualified_owner_matches(text, ctx) && text.contains("::")
        }
        _ => false,
    }
}

fn qualified_owner_matches(text: &str, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner_cpp_name) = ctx.spec.owner_cpp_name.as_deref() else {
        return false;
    };
    let normalized = normalize_cpp_reference_text(text);
    normalized == owner_cpp_name
        || normalized
            .strip_suffix(&format!("::{}", ctx.spec.member_name))
            .is_some_and(|owner| owner == owner_cpp_name)
}

fn same_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if let Some(owner_text) = textual_owner_context(node, ctx) {
        return ctx
            .spec
            .owner_cpp_name
            .as_deref()
            .is_some_and(|target_owner| {
                owner_text == target_owner
                    || ctx
                        .spec
                        .owner
                        .as_ref()
                        .is_some_and(|owner| owner_text == owner.identifier())
            });
    }
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    ctx.spec
        .owner_fq_name
        .as_ref()
        .is_some_and(|target_owner| target_owner == &owner.fq_name())
}

fn known_non_target_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner_text) = textual_owner_context(node, ctx) else {
        return false;
    };
    ctx.spec
        .owner_cpp_name
        .as_deref()
        .is_some_and(|target_owner| {
            owner_text != target_owner
                && ctx
                    .spec
                    .owner
                    .as_ref()
                    .is_none_or(|owner| owner_text != owner.identifier())
        })
}

fn textual_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    let before = &ctx.source[..node.start_byte()];
    textual_owner_context_at(before)
}

fn textual_owner_context_at(before: &str) -> Option<String> {
    let brace = before.rfind('{')?;
    let header_start = before[..brace]
        .rfind(['\n', ';', '}'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let header = before[header_start..brace].trim();
    let qualifier_end = header.rfind("::")?;
    let qualifier_prefix = header[..qualifier_end].trim_end();
    let qualifier_start = qualifier_prefix
        .rfind(|ch: char| !(ch == '_' || ch == ':' || ch.is_ascii_alphanumeric()))
        .map(|index| index + 1)
        .unwrap_or(0);
    let qualifier = qualifier_prefix[qualifier_start..].trim();
    (!qualifier.is_empty()).then(|| normalize_cpp_reference_text(qualifier))
}
