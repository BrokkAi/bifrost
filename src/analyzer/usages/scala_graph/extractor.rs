use crate::analyzer::scala::imports::parse_scala_import_infos;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::scala_graph::hits::{add_hit, add_import_hit};
use crate::analyzer::usages::scala_graph::resolver::{TargetKind, TargetSpec, Visibility};
use crate::analyzer::usages::scala_graph::syntax::{
    call_arity_for_reference, has_ancestor_kind, has_member_qualifier, is_assignment_lhs,
    is_constructor_like_reference, is_identifier_node, is_owner_qualified_this,
    is_type_like_reference, member_qualifier, member_qualifier_node, node_text,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range, ScalaAnalyzer};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
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
    let Ok(source) = file.read_to_string() else {
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
    let visibility = Visibility::for_file(scala, file, spec);
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut ctx = ScanCtx {
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
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
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
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
        let matched = Visibility::matching_import_names(&import, ctx.spec);
        names.extend(matched.type_names);
        names.extend(matched.owner_names);
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
            seed_owner_field_bindings(node, ctx);
        }
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    ctx.bindings.declare_shadow(name.to_string());
                }
            }
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

fn seed_direct_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "val_definition" | "var_definition" => seed_value_definition(child, ctx),
            "function_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition" => {}
            _ => seed_direct_field_bindings(child, ctx),
        }
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

fn seed_parameters(parameters: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if parameter.kind() == "parameter" {
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
        .and_then(|type_node| simple_type_name(node_text(type_node, ctx.source).trim()));
    seed_or_shadow_typed_symbol(name, type_name, None, ctx);
}

fn seed_value_definition(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    };
    let type_name = node
        .child_by_field_name("type")
        .and_then(|type_node| simple_type_name(node_text(type_node, ctx.source).trim()));
    let value_name = node
        .child_by_field_name("value")
        .and_then(|value_node| constructor_type_name(node_text(value_node, ctx.source)));
    if type_name.is_none() && value_name.is_none() {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    }
    for name in pattern_names(pattern, ctx.source) {
        seed_or_shadow_typed_symbol(name, type_name, value_name, ctx);
    }
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
    let visible_type = type_name
        .or(value_name)
        .filter(|name| ctx.visibility.owner_names.contains(*name));
    if let Some(_type_name) = visible_type
        && let Some(owner_fq_name) = ctx.spec.owner_fq_name.as_ref()
    {
        ctx.bindings
            .seed_symbol(name.to_string(), owner_fq_name.clone());
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
            ctx.visibility.type_names.contains(text) && is_type_like_reference(node, ctx.source)
        }
        TargetKind::Constructor => {
            ctx.visibility.type_names.contains(text)
                && is_constructor_like_reference(node, ctx.source)
        }
        TargetKind::Method | TargetKind::Field => member_reference_is_proven(node, text, ctx),
    };
    if proven {
        add_hit(node, ctx);
    }
    if is_assignment_lhs(node) && !ctx.bindings.resolve_symbol(text).is_unknown() {
        ctx.bindings.declare_shadow(text.to_string());
    }
}

fn seed_value_binding_identifier(node: Node<'_>, text: &str, ctx: &mut ScanCtx<'_>) -> bool {
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
    if is_owner_qualified_this(qualifier_node, ctx.source) {
        return enclosing_matches_owner(node, ctx) && member_call_arity_matches(node, ctx);
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
        return true;
    }
    receiver_binding_matches(node, qualifier, ctx)
}

fn extension_member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.kind != TargetKind::Method
        || text != ctx.spec.member_name
        || !target_is_extension(ctx.spec)
        || !ctx.visibility.direct_member_names.contains(text)
        || ctx.visibility.ambiguous_direct_member_names.contains(text)
        || !has_member_qualifier(node)
        || !member_call_arity_matches(node, ctx)
    {
        return false;
    }

    let Some(qualifier_node) = member_qualifier_node(node) else {
        return false;
    };
    let qualifier = node_text(qualifier_node, ctx.source).trim();
    if qualifier.is_empty() || is_locally_shadowed(ctx, qualifier) {
        return false;
    }
    extension_receiver_matches(qualifier, ctx)
}

fn target_is_extension(spec: &TargetSpec) -> bool {
    spec.is_extension_method
}

fn extension_receiver_matches(qualifier: &str, ctx: &ScanCtx<'_>) -> bool {
    let _ = (qualifier, ctx);
    true
}

fn is_locally_shadowed(ctx: &ScanCtx<'_>, name: &str) -> bool {
    ctx.bindings.is_shadowed(name) && ctx.bindings.resolve_symbol(name).is_unknown()
}

fn receiver_binding_matches(node: Node<'_>, qualifier: &str, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_owner_fq) = ctx.spec.owner_fq_name.as_ref() else {
        return false;
    };
    if !member_call_arity_matches(node, ctx) {
        return false;
    }
    ctx.bindings
        .resolve_symbol(qualifier)
        .as_precise()
        .is_some_and(|targets| targets.contains(target_owner_fq))
}

fn enclosing_matches_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return false;
    };
    if enclosing == *owner {
        return true;
    }
    enclosing.source() == owner.source()
        && enclosing.package_name() == owner.package_name()
        && enclosing
            .short_name()
            .strip_prefix(owner.short_name())
            .is_some_and(|rest| rest.starts_with('.'))
}

fn member_call_arity_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.kind != TargetKind::Method {
        return true;
    }
    let Some(target_arity) = ctx.spec.arity else {
        return true;
    };
    match call_arity_for_reference(node) {
        Some(call_arity) => call_arity == target_arity,
        None => target_arity == 0,
    }
}
