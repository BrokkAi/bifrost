use super::inverted::{NameResolver, ProjectTypes};
use crate::analyzer::scala::imports::parse_scala_import_infos;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::scala_graph::hits::{
    add_hit, add_import_hit, add_override_declaration_hit,
};
use crate::analyzer::usages::scala_graph::resolver::{
    TargetKind, TargetSpec, Visibility, method_call_arity_applies, method_signature_arity,
    package_name_of, scala_builtin_type_name, scala_extension_receiver_matches_resolved,
    scala_literal_type_name, scala_normalized_fq_name, scala_resolve_declared_type,
};
use crate::analyzer::usages::scala_graph::syntax::{
    call_arities_for_reference, has_ancestor_kind, has_member_qualifier,
    infix_receiver_for_operator, is_assignment_lhs, is_constructor_like_reference,
    is_identifier_node, is_owner_qualified_this, is_scala_class_reference,
    is_scala_object_reference, is_terminal_stable_field_reference, member_qualifier,
    member_qualifier_node, named_argument_invocation_owner, node_text, parenthesized_arity,
    resolve_stable_object_expression, terminal_invocation_owner_name,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, ProjectFile, Range, ScalaAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Node, Parser};

pub(super) fn scan_file(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
    max_usages: usize,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded {
        return;
    }
    let Some(source) = analyzer.indexed_source(file) else {
        return;
    };
    if source.is_empty() {
        return;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);
    let types = scala.project_types();
    let name_resolver = NameResolver::for_file(scala, file, &types);
    let visibility = Visibility::for_file(scala, file, spec, &name_resolver);
    let file_package = package_name_of(scala, file).unwrap_or_default();
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut ctx = ScanCtx {
        scala,
        analyzer,
        file,
        file_package: &file_package,
        source: &source,
        line_starts: &line_starts,
        spec,
        types,
        name_resolver,
        visibility,
        bindings: &mut bindings,
        hits,
        max_usages,
        limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

pub(super) struct ScanCtx<'a> {
    pub(super) scala: &'a ScalaAnalyzer,
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) file_package: &'a str,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) types: Arc<ProjectTypes>,
    pub(super) name_resolver: NameResolver,
    pub(super) visibility: Visibility,
    pub(super) bindings: &'a mut LocalInferenceEngine<String>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    seed_parent_scope_declarations(node, ctx);
    let enters_scope = enters_local_scope(node);
    if enters_scope {
        ctx.bindings.enter_scope();
        seed_scope_declarations(node, ctx);
    } else {
        seed_inline_declarations(node, ctx);
    }

    if node.kind() == "call_expression" {
        scan_call_expression(node, ctx);
    }
    if node.kind() == "infix_expression" {
        scan_infix_expression(node, ctx);
    }
    if matches!(node.kind(), "function_definition" | "function_declaration") {
        scan_method_declaration(node, ctx);
    }
    if node.kind() == "import_declaration" {
        scan_import_declaration(node, ctx);
    } else if is_identifier_node(node) {
        scan_identifier(node, ctx);
    }
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

fn scan_import_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let matching_names = matching_names_for_import_declaration(node, ctx);
    if matching_names.is_empty() {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_import_declaration_identifier(child, ctx, &matching_names);
    }
}

fn scan_import_declaration_identifier(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    matching_names: &HashSet<String>,
) {
    walk_tree_iterative(
        node,
        ctx,
        |current, ctx| {
            if is_identifier_node(current) {
                let text = node_text(current, ctx.source).trim();
                if !text.is_empty() && matching_names.contains(text) {
                    add_import_hit(current, ctx);
                }
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn matching_names_for_import_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> HashSet<String> {
    let import_text = node_text(node, ctx.source);
    let mut names = HashSet::default();
    for import in parse_scala_import_infos(import_text) {
        let matched = Visibility::matching_import_names(&import, ctx.spec, ctx.file_package);
        names.extend(matched.type_names);
        names.extend(matched.owner_names.into_keys());
        names.extend(matched.direct_member_names);
    }
    names
}

fn scan_call_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(ctx.spec.kind, TargetKind::Method) {
        return;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let text = node_text(function, ctx.source).trim();
    if companion_apply_call_is_proven(function, text, ctx) {
        add_hit(function, ctx);
        return;
    }
    if text != ctx.spec.member_name || has_member_qualifier(function) {
        return;
    }
    if !is_locally_shadowed(ctx, text)
        && enclosing_matches_owner(function, ctx)
        && member_call_arity_matches(function, ctx)
    {
        add_hit(function, ctx);
    }
}

fn companion_apply_call_is_proven(function: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    ctx.spec.member_name == "apply"
        && !has_member_qualifier(function)
        && !is_locally_shadowed(ctx, text)
        && member_call_arity_matches(function, ctx)
        && ctx
            .visibility
            .owner_fq_name_for(text)
            .is_some_and(|owner| ctx.spec.owner_fq_matches(owner))
}

fn scan_infix_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.kind != TargetKind::Method {
        return;
    }
    let (Some(operator), Some(left)) = (
        node.child_by_field_name("operator"),
        node.child_by_field_name("left"),
    ) else {
        return;
    };
    let text = node_text(operator, ctx.source).trim();
    if text != ctx.spec.member_name || infix_receiver_for_operator(operator) != Some(left) {
        return;
    }
    if member_call_arity_matches(operator, ctx)
        && extension_receiver_type(left, ctx)
            .is_some_and(|owner| ctx.spec.receiver_owner_fq_matches(&owner))
    {
        add_hit(operator, ctx);
    }
}

fn scan_method_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.kind != TargetKind::Method {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if node_text(name, ctx.source).trim() != ctx.spec.member_name {
        return;
    }
    if !function_arity_matches(node, ctx) {
        return;
    }
    let Some(owner_fq_name) = enclosing_owner_fq_name(name, ctx) else {
        return;
    };
    if ctx
        .spec
        .related_override_owner_fq_matches(owner_fq_name.as_str())
    {
        add_override_declaration_hit(name, ctx);
    }
}

fn seed_parent_scope_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "function_definition" || !has_ancestor_kind(node, "function_definition") {
        return;
    }
    if let Some(name) = node.child_by_field_name("name") {
        let name = node_text(name, ctx.source).trim();
        if !name.is_empty() {
            ctx.bindings.declare_shadow(name.to_string());
        }
    }
}

fn enters_local_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function"
    )
}

fn seed_scope_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            seed_class_parameter_bindings(node, ctx);
            seed_owner_field_bindings(node, ctx);
        }
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    ctx.bindings.declare_shadow(name.to_string());
                }
            }
            seed_enclosing_owner_field_bindings(node, ctx);
            seed_parameter_bindings(node, ctx);
        }
        "case_clause" => seed_case_pattern_shadow(node, ctx),
        _ => {}
    }
}

fn seed_inline_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "val_definition" | "var_definition" => seed_value_definition(node, ctx),
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    ctx.bindings.declare_shadow(name.to_string());
                }
            }
        }
        _ => {}
    }
}

fn seed_owner_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.owner.is_none() {
        return;
    }
    if !enclosing_type_matches_owner(node, ctx) {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "template_body" | "enum_body") {
            seed_direct_field_bindings(child, ctx);
        }
    }
}

fn seed_enclosing_owner_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.owner.is_none() {
        return;
    }
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                seed_owner_field_bindings(ancestor, ctx);
                return;
            }
            "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => return,
            _ => current = ancestor.parent(),
        }
    }
}

fn seed_direct_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "val_definition" | "var_definition" => seed_owner_field_definition(child, ctx),
            "function_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition" => {}
            _ => seed_direct_field_bindings(child, ctx),
        }
    }
}

fn seed_owner_field_definition(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(owner_fq_name) = ctx.spec.owner_fq_name.as_deref() else {
        return;
    };
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    for name in pattern_names(pattern, ctx.source) {
        ctx.bindings
            .seed_symbol(name.to_string(), owner_fq_name.to_string());
    }
}

fn enclosing_type_matches_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner_name) = ctx.spec.owner_name.as_deref() else {
        return false;
    };
    node.child_by_field_name("name")
        .map(|name| node_text(name, ctx.source).trim().trim_end_matches('$') == owner_name)
        .unwrap_or(false)
}

fn seed_parameter_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameters" {
            continue;
        }
        seed_parameters(child, ctx);
    }
}

fn seed_class_parameter_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let enclosing_owner = node
        .child_by_field_name("name")
        .and_then(|name| enclosing_owner_fq_name(name, ctx));
    let mut cursor = node.walk();
    for parameters in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "class_parameters")
    {
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters.named_children(&mut parameter_cursor) {
            if parameter.kind() != "class_parameter" {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, ctx.source).trim();
            if name.is_empty() {
                continue;
            }
            if class_parameter_is_field(parameter)
                && name == ctx.spec.member_name
                && let Some(owner) = enclosing_owner.as_deref()
            {
                ctx.bindings
                    .seed_symbol(name.to_string(), scala_normalized_fq_name(owner));
            } else {
                seed_parameter(parameter, ctx);
            }
        }
    }
}

fn class_parameter_is_field(parameter: Node<'_>) -> bool {
    let mut cursor = parameter.walk();
    parameter
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "val" | "var"))
}

fn seed_parameters(parameters: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if matches!(parameter.kind(), "parameter" | "class_parameter") {
            seed_parameter(parameter, ctx);
        }
    }
}

fn seed_parameter(parameter: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name, ctx.source).trim();
    if name.is_empty() {
        return;
    }
    let type_name = parameter
        .child_by_field_name("type")
        .map(|type_node| node_text(type_node, ctx.source).trim());
    seed_or_shadow_typed_symbol(name, type_name, None, ctx);
}

fn seed_value_definition(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    };
    let type_name = node
        .child_by_field_name("type")
        .map(|type_node| node_text(type_node, ctx.source).trim());
    let value = node.child_by_field_name("value");
    let value_name =
        value.and_then(|value_node| constructor_type_name(node_text(value_node, ctx.source)));
    let resolved_value_owner = value.and_then(|value| call_initializer_return_owner(value, ctx));
    if type_name.is_none() && value_name.is_none() && resolved_value_owner.is_none() {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    }
    for name in pattern_names(pattern, ctx.source) {
        if let Some(owner) = resolved_value_owner.as_deref() {
            ctx.bindings
                .seed_symbol(name.to_string(), owner.to_string());
        } else {
            seed_or_shadow_typed_symbol(name, type_name, value_name, ctx);
        }
    }
}

fn call_initializer_return_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let (owner_node, member_node) = match function.kind() {
        "field_expression" => (
            function.child_by_field_name("value")?,
            function.child_by_field_name("field")?,
        ),
        _ => return None,
    };
    let member_name = node_text(member_node, ctx.source).trim();
    if member_name.is_empty() {
        return None;
    }
    let owner = if owner_node.kind() == "field_expression" {
        stable_object_expression_fqn(owner_node, ctx)
    } else if matches!(owner_node.kind(), "identifier" | "type_identifier") {
        let owner_name = node_text(owner_node, ctx.source).trim();
        ctx.name_resolver
            .resolve_object(owner_name)
            .or_else(|| ctx.name_resolver.resolve(owner_name))
    } else {
        None
    }?;
    let call_arities = call_arities_for_reference(member_node);
    ctx.types.member_return_type_for_owner_member(
        ctx.scala,
        &ctx.name_resolver,
        &owner,
        member_name,
        call_arities.as_deref(),
    )
}

fn seed_value_definition_from_text(text: &str, ctx: &mut ScanCtx<'_>) {
    let trimmed = text.trim_start();
    let Some(after_keyword) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    else {
        return;
    };
    let name_end = after_keyword
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(after_keyword.len());
    if name_end == 0 {
        return;
    }
    let name = &after_keyword[..name_end];
    let rest = after_keyword[name_end..].trim_start();
    let type_name = rest
        .strip_prefix(':')
        .and_then(|after_colon| simple_type_name(after_colon.trim_start()));
    let value_name = rest
        .split_once('=')
        .and_then(|(_, value)| constructor_type_name(value));
    seed_or_shadow_typed_symbol(name, type_name, value_name, ctx);
}

fn seed_or_shadow_typed_symbol(
    name: &str,
    type_name: Option<&str>,
    value_name: Option<&str>,
    ctx: &mut ScanCtx<'_>,
) {
    let visible_owner = type_name
        .or(value_name)
        .and_then(|name| ctx.visibility.receiver_type_fq_name_for(name));
    if let Some(owner_fq_name) = visible_owner {
        ctx.bindings
            .seed_symbol(name.to_string(), owner_fq_name.to_string());
        return;
    }
    if let Some(type_name) = type_name
        && let Some(owner_fq_name) =
            scala_resolve_declared_type(ctx.scala, ctx.file, ctx.file_package, type_name)
    {
        ctx.bindings
            .seed_symbol(name.to_string(), owner_fq_name.to_string());
        return;
    }
    if let Some(type_name) = type_name
        && let Some(builtin) = scala_builtin_type_name(type_name)
    {
        ctx.bindings
            .seed_symbol(name.to_string(), builtin.to_string());
        return;
    }
    ctx.bindings.declare_shadow(name.to_string());
}

fn simple_type_name(type_text: &str) -> Option<&str> {
    type_text
        .split(['[', '(', '{', '.', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn constructor_type_name(value_text: &str) -> Option<&str> {
    let trimmed = value_text.trim_start();
    let trimmed = trimmed.strip_prefix("new ").unwrap_or(trimmed).trim_start();
    let end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(trimmed.len());
    (end > 0).then_some(&trimmed[..end])
}

fn pattern_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            if node.parent().is_some_and(|parent| {
                parent.kind() == "infix_pattern"
                    && parent.child_by_field_name("operator") == Some(node)
            }) {
                return Vec::new();
            }
            let name = node_text(node, source).trim();
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
        "identifiers" | "tuple_pattern" | "pattern" => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(pattern_names(child, source));
            }
            names
        }
        _ => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(pattern_names(child, source));
            }
            names
        }
    }
}

fn seed_case_pattern_shadow(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(pattern) = node.child_by_field_name("pattern") {
        for name in pattern_names(pattern, ctx.source) {
            ctx.bindings.declare_shadow(name.to_string());
        }
    }
}

fn scan_identifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "import_declaration") {
        return;
    }
    let text = node_text(node, ctx.source).trim();
    if text.is_empty() {
        return;
    }
    if seed_value_binding_identifier(node, text, ctx) {
        return;
    }

    let proven = match ctx.spec.kind {
        TargetKind::Type => {
            let terminal_object_matches = is_terminal_stable_field_reference(node)
                && node
                    .parent()
                    .and_then(|expression| stable_object_expression_fqn(expression, ctx))
                    .is_some_and(|fqn| fqn == ctx.spec.target.fq_name());
            (is_scala_class_reference(node, ctx.source)
                && !ctx.spec.is_object_type
                && ctx.visibility.class_type_name_matches(text)
                || is_scala_object_reference(node)
                    && (ctx.spec.is_object_type || ctx.spec.accepts_object_roles)
                    && ctx.visibility.object_type_name_matches(text)
                || terminal_object_matches)
                && !type_reference_is_locally_bound(text, ctx)
        }
        TargetKind::Constructor => {
            ctx.visibility.class_type_name_matches(text)
                && is_constructor_like_reference(node, ctx.source)
                && member_call_arity_matches(node, ctx)
        }
        TargetKind::Method => member_reference_is_proven(node, text, ctx),
        TargetKind::Field => {
            named_argument_field_is_proven(node, text, ctx)
                || member_reference_is_proven(node, text, ctx)
        }
    };
    if proven {
        add_hit(node, ctx);
    }
    if is_assignment_lhs(node)
        && !ctx.bindings.resolve_symbol(text).is_unknown()
        && !assignment_lhs_is_target_member_write(proven, text, ctx)
    {
        ctx.bindings.declare_shadow(text.to_string());
    }
}

fn named_argument_field_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if text != ctx.spec.member_name {
        return false;
    }
    let Some(owner) =
        named_argument_invocation_owner(node).and_then(terminal_invocation_owner_name)
    else {
        return false;
    };
    let owner_name = node_text(owner, ctx.source).trim();
    !is_locally_shadowed(ctx, owner_name)
        && ctx
            .visibility
            .owner_fq_name_for(owner_name)
            .or_else(|| ctx.visibility.receiver_type_fq_name_for(owner_name))
            .is_some_and(|owner| ctx.spec.receiver_owner_fq_matches(owner))
}

fn assignment_lhs_is_target_member_write(proven: bool, text: &str, ctx: &ScanCtx<'_>) -> bool {
    proven && ctx.spec.kind == TargetKind::Field && text == ctx.spec.member_name
}

fn type_reference_is_locally_bound(text: &str, ctx: &ScanCtx<'_>) -> bool {
    !ctx.bindings.resolve_symbol(text).is_unknown() || ctx.bindings.is_shadowed(text)
}

fn seed_value_binding_identifier(node: Node<'_>, text: &str, ctx: &mut ScanCtx<'_>) -> bool {
    if is_direct_owner_field_declaration_identifier(node, ctx) {
        return true;
    }
    if node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "parameter" | "class_parameter")
            && parent.child_by_field_name("name") == Some(node)
    }) {
        return true;
    }
    if node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "val_definition" | "var_definition")
            && parent.child_by_field_name("pattern") == Some(node)
    }) {
        return true;
    }
    let before = ctx.source[..node.start_byte()].trim_end();
    let Some(keyword) = previous_word(before) else {
        return false;
    };
    if !matches!(keyword, "val" | "var") {
        return false;
    }
    let line_end = ctx.source[node.end_byte()..]
        .find(['\n', '\r', ';'])
        .map(|offset| node.end_byte() + offset)
        .unwrap_or(ctx.source.len());
    let rest = ctx.source[node.end_byte()..line_end].trim_start();
    let type_name = rest
        .strip_prefix(':')
        .and_then(|after_colon| simple_type_name(after_colon.trim_start()));
    let value_name = rest
        .split_once('=')
        .and_then(|(_, value)| constructor_type_name(value));
    seed_or_shadow_typed_symbol(text, type_name, value_name, ctx);
    true
}

fn is_direct_owner_field_declaration_identifier(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(parent.kind(), "val_definition" | "var_definition")
        || parent.child_by_field_name("pattern") != Some(node)
    {
        return false;
    }
    let mut current = parent.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => return false,
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return enclosing_type_matches_owner(ancestor, ctx);
            }
            _ => current = ancestor.parent(),
        }
    }
    false
}

fn previous_word(value: &str) -> Option<&str> {
    value
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .find(|part| !part.is_empty())
}

fn member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.visibility.direct_member_names.contains(text)
        && !ctx.visibility.ambiguous_direct_member_names.contains(text)
        && !has_member_qualifier(node)
        && !is_locally_shadowed(ctx, text)
        && member_call_arity_matches(node, ctx)
    {
        return true;
    }

    if extension_member_reference_is_proven(node, text, ctx) {
        return true;
    }

    if text != ctx.spec.member_name {
        return false;
    }

    if ctx.spec.owner.is_none() {
        return member_qualifier(node, ctx.source)
            .is_some_and(|qualifier| qualifier == ctx.spec.target.package_name());
    }

    let Some(qualifier_node) = member_qualifier_node(node) else {
        return !is_locally_shadowed(ctx, text)
            && enclosing_matches_owner(node, ctx)
            && member_call_arity_matches(node, ctx);
    };
    if qualifier_node.kind() == "field_expression"
        && let Some(owner_fq_name) = stable_object_expression_fqn(qualifier_node, ctx)
    {
        return ctx.spec.owner_fq_matches(&owner_fq_name) && member_call_arity_matches(node, ctx);
    }
    if qualifier_node.kind() == "call_expression"
        && let Some(owner_fq_name) = call_initializer_return_owner(qualifier_node, ctx)
    {
        return ctx.spec.receiver_owner_fq_matches(&owner_fq_name)
            && member_call_arity_matches(node, ctx);
    }
    if is_owner_qualified_this(qualifier_node, ctx.source) {
        return owner_qualified_this_matches(qualifier_node, ctx)
            && member_call_arity_matches(node, ctx);
    }
    let qualifier = node_text(qualifier_node, ctx.source)
        .trim()
        .trim_end_matches('$');
    if qualifier == "this" {
        return enclosing_matches_owner(node, ctx) && member_call_arity_matches(node, ctx);
    }
    if ctx.visibility.owner_names.contains(qualifier)
        && !is_locally_shadowed(ctx, qualifier)
        && member_call_arity_matches(node, ctx)
    {
        return ctx
            .visibility
            .owner_fq_name_for(qualifier)
            .is_some_and(|owner_fq_name| ctx.spec.owner_fq_matches(owner_fq_name));
    }
    receiver_binding_matches(node, qualifier, ctx)
}

fn stable_object_expression_fqn(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    resolve_stable_object_expression(
        node,
        ctx.source,
        |root| {
            (ctx.bindings.resolve_symbol(root).is_unknown() && !ctx.bindings.is_shadowed(root))
                .then(|| ctx.name_resolver.resolve_object(root))
                .flatten()
        },
        |owner, member| ctx.types.exact_nested_object(ctx.scala, owner, member),
    )
}

fn owner_qualified_this_matches(qualifier_node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let qualifier = node_text(qualifier_node, ctx.source).trim();
    let Some(owner_name) = qualifier.strip_suffix(".this") else {
        return false;
    };
    ctx.visibility
        .receiver_type_fq_name_for(owner_name.trim().trim_end_matches('$'))
        .is_some_and(|owner_fq_name| ctx.spec.receiver_owner_fq_matches(owner_fq_name))
}

fn extension_member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.kind != TargetKind::Method
        || text != ctx.spec.member_name
        || !target_is_extension(ctx.spec)
        || !ctx.visibility.direct_member_names.contains(text)
        || !has_member_qualifier(node)
    {
        return false;
    }

    let Some(qualifier_node) = member_qualifier_node(node) else {
        return false;
    };
    let qualifier = node_text(qualifier_node, ctx.source).trim();
    if qualifier.is_empty() || is_unresolved_local_shadow(ctx, qualifier) {
        return false;
    }
    extension_receiver_matches(
        qualifier_node,
        call_arities_for_reference(node).as_deref(),
        ctx,
    )
}

fn target_is_extension(spec: &TargetSpec) -> bool {
    spec.is_extension_method
}

fn extension_receiver_matches(
    qualifier_node: Node<'_>,
    call_arities: Option<&[usize]>,
    ctx: &ScanCtx<'_>,
) -> bool {
    let Some(receiver_owner) = extension_receiver_type(qualifier_node, ctx) else {
        return false;
    };
    let matching_alternatives = ctx
        .spec
        .callable_alternatives
        .iter()
        .filter(|alternative| {
            scala_extension_receiver_matches_resolved(
                alternative.extension_receiver_type.as_deref(),
                Some(&receiver_owner),
                |type_text| {
                    ctx.name_resolver
                        .resolve(type_text)
                        .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
                },
            )
        })
        .collect::<Vec<_>>();
    let unique_callable = ctx.spec.unapplied_reference_is_unambiguous;
    if !matching_alternatives.iter().any(|alternative| {
        callable_shape_matches(&alternative.shape, call_arities, unique_callable)
    }) {
        return false;
    }
    !receiver_has_member(
        &receiver_owner,
        ctx.spec.member_name.as_str(),
        call_arities.and_then(|arities| arities.first().copied()),
        ctx,
    )
}

fn extension_receiver_type(receiver: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source).trim();
            if name == "this" {
                return enclosing_owner_fq_name(receiver, ctx);
            }
            ctx.bindings
                .resolve_symbol(name)
                .as_precise()
                .and_then(single_precise_target)
                .or_else(|| {
                    (!ctx.bindings.is_shadowed(name))
                        .then(|| ctx.visibility.owner_fq_name_for(name).map(str::to_string))
                        .flatten()
                })
                .or_else(|| {
                    (!ctx.bindings.is_shadowed(name))
                        .then(|| {
                            ctx.visibility
                                .receiver_fq_name_for(name)
                                .map(str::to_string)
                        })
                        .flatten()
                })
        }
        kind => scala_literal_type_name(kind).map(str::to_string),
    }
}

fn single_precise_target(targets: &HashSet<String>) -> Option<String> {
    (targets.len() == 1)
        .then(|| targets.iter().next().cloned())
        .flatten()
}

fn receiver_has_member(
    receiver_owner: &str,
    member: &str,
    call_arity: Option<usize>,
    ctx: &ScanCtx<'_>,
) -> bool {
    if receiver_owner == ctx.spec.owner_fq_name.as_deref().unwrap_or_default() {
        return false;
    }
    if receiver_has_direct_member(receiver_owner, member, call_arity, ctx) {
        return true;
    }
    ctx.scala
        .definitions(receiver_owner)
        .find(|unit| unit.is_class())
        .is_some_and(|owner| {
            ctx.scala.get_ancestors(&owner).into_iter().any(|ancestor| {
                receiver_has_direct_member(&ancestor.fq_name(), member, call_arity, ctx)
            })
        })
}

fn receiver_has_direct_member(
    receiver_owner: &str,
    member: &str,
    call_arity: Option<usize>,
    ctx: &ScanCtx<'_>,
) -> bool {
    let member_fqn = format!("{}.{}", scala_normalized_fq_name(receiver_owner), member);
    ctx.analyzer
        .definitions(&member_fqn)
        .any(|unit| receiver_member_applies(&unit, call_arity, ctx))
}

fn receiver_member_applies(unit: &CodeUnit, call_arity: Option<usize>, ctx: &ScanCtx<'_>) -> bool {
    if unit.is_field() {
        return true;
    }
    if !unit.is_function() || ctx.spec.kind != TargetKind::Method {
        return false;
    }
    match call_arity {
        Some(call_arity) => method_call_arity_applies(ctx.scala, unit, call_arity),
        None => method_signature_arity(ctx.scala, unit).is_none_or(|arity| arity == 0),
    }
}

fn is_locally_shadowed(ctx: &ScanCtx<'_>, name: &str) -> bool {
    if !ctx.bindings.is_shadowed(name) {
        return false;
    }
    !ctx.bindings
        .resolve_symbol(name)
        .as_precise()
        .is_some_and(|targets| {
            targets
                .iter()
                .any(|target| ctx.spec.owner_fq_matches(target))
        })
}

fn is_unresolved_local_shadow(ctx: &ScanCtx<'_>, name: &str) -> bool {
    ctx.bindings.is_shadowed(name) && ctx.bindings.resolve_symbol(name).is_unknown()
}

fn receiver_binding_matches(node: Node<'_>, qualifier: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.owner.is_none() {
        return false;
    }
    if !member_call_arity_matches(node, ctx) {
        return false;
    }
    ctx.bindings
        .resolve_symbol(qualifier)
        .as_precise()
        .is_some_and(|targets| {
            targets
                .iter()
                .any(|target| ctx.spec.receiver_owner_fq_matches(target))
        })
        || ctx
            .visibility
            .receiver_fq_name_for(qualifier)
            .is_some_and(|owner_fq_name| ctx.spec.receiver_owner_fq_matches(owner_fq_name))
}

fn enclosing_matches_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let mut current = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    while let Some(unit) = current {
        if unit.is_class() && ctx.spec.receiver_owner_fq_matches(&unit.fq_name()) {
            return true;
        }
        current = ctx.analyzer.parent_of(&unit);
    }
    false
}

fn enclosing_owner_fq_name(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range)?;
    if enclosing.is_class() {
        return Some(enclosing.fq_name());
    }
    ctx.analyzer
        .parent_of(&enclosing)
        .filter(|owner| owner.is_class())
        .map(|owner| owner.fq_name())
}

fn member_call_arity_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if !matches!(ctx.spec.kind, TargetKind::Method | TargetKind::Constructor) {
        return true;
    }
    let fallback_shape;
    let fallback_shapes;
    let shapes = if ctx.spec.callable_alternatives.is_empty() {
        fallback_shape = ctx
            .spec
            .callable_arity
            .map(|arity| vec![arity])
            .unwrap_or_default();
        fallback_shapes = vec![fallback_shape];
        fallback_shapes.as_slice()
    } else {
        return ctx.spec.callable_alternatives.iter().any(|alternative| {
            callable_shape_matches(
                &alternative.shape,
                call_arities_for_reference(node).as_deref(),
                ctx.spec.unapplied_reference_is_unambiguous,
            )
        });
    };
    let call_arities = call_arities_for_reference(node);
    shapes.iter().any(|declared| {
        callable_shape_matches(
            declared,
            call_arities.as_deref(),
            ctx.spec.unapplied_reference_is_unambiguous,
        )
    })
}

fn callable_shape_matches(
    declared: &[crate::analyzer::CallableArity],
    call_arities: Option<&[usize]>,
    unique_callable: bool,
) -> bool {
    match call_arities {
        Some(actual) => {
            actual.len() <= declared.len()
                && (actual.len() == declared.len() || unique_callable)
                && actual
                    .iter()
                    .zip(declared)
                    .all(|(actual, declared)| declared.accepts(*actual))
        }
        None => declared.first().is_none_or(|arity| arity.total() == 0) || unique_callable,
    }
}

fn function_arity_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_arity) = ctx.spec.arity else {
        return true;
    };
    let mut cursor = node.walk();
    let arity = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "parameters")
        .and_then(|parameters| parenthesized_arity(node_text(parameters, ctx.source)))
        .unwrap_or(0);
    arity == target_arity
}
