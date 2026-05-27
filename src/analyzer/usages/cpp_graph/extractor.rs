use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::cpp_graph::hits::{
    enclosing_context, is_member_field_declaration_context, push_hit, push_text_constructor_hit,
    push_text_hit,
};
use crate::analyzer::usages::cpp_graph::resolver::*;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, cpp_node_text as node_text,
    normalize_cpp_whitespace,
};
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
    pub(super) root: Node<'a>,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) bindings: LocalInferenceEngine<CodeUnit>,
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
        root: tree.root_node(),
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
    if matches!(ctx.spec.kind, TargetKind::Constructor) {
        scan_text_constructor_hits(&mut ctx);
    }
    if matches!(ctx.spec.kind, TargetKind::Method) && ctx.spec.member_name.starts_with("operator") {
        scan_text_operator_method_hits(&mut ctx);
    }
    if matches!(
        ctx.spec.kind,
        TargetKind::GlobalField | TargetKind::MemberField
    ) {
        scan_text_symbol_hits(&mut ctx);
    }
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
        .map(|node| normalize_type_text(node_text(node, ctx.source)));
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
        if declarator.kind() == "function_declarator" {
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
        .map(|node| normalize_type_text(node_text(node, ctx.source)));
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
        .filter(|text| *text != "auto")
        .and_then(|text| ctx.visibility.resolve_type(ctx.file, text))
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

fn infer_type_from_value(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    match node.kind() {
        "new_expression" => {
            let text = normalize_cpp_whitespace(node_text(node, ctx.source));
            let rest = text.strip_prefix("new ").unwrap_or(text.as_str());
            ctx.visibility
                .resolve_type(ctx.file, rest.split(['(', '{']).next().unwrap_or(rest))
        }
        "call_expression" => node.child_by_field_name("function").and_then(|function| {
            ctx.visibility
                .resolve_type(ctx.file, node_text(function, ctx.source))
        }),
        "initializer_list" => None,
        "identifier" => {
            let resolved = ctx.bindings.resolve_symbol(node_text(node, ctx.source));
            resolved
                .as_precise()?
                .iter()
                .find(|unit| unit.is_class())
                .cloned()
        }
        _ => ctx
            .visibility
            .resolve_type(ctx.file, node_text(node, ctx.source)),
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
    ) || is_declaration_name(node)
    {
        return;
    }
    let text = node_text(node, ctx.source);
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
        push_hit(node, ctx);
    } else if !ctx.visibility.is_visible(ctx.file, &ctx.spec.target) {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_constructor_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "call_expression" | "new_expression" | "declaration" | "field_initializer"
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
        if declaration_mentions_type(node, ctx, owner)
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
    if node.kind() != "call_expression" {
        return;
    }
    let Some(function) = node.child_by_field_name("function") else {
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
    if ctx.visibility.contains_named_symbol(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        push_hit(function, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "call_expression" {
        return;
    }
    let Some(function) = node.child_by_field_name("function") else {
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
    if receiver_matches_target(function, ctx) || same_owner_context(function, ctx) {
        push_hit(function_terminal_node(function), ctx);
    } else if !receiver_has_known_non_target(function, ctx)
        && !known_non_target_owner_context(function, ctx)
    {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_global_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier"
    ) || !name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        || is_declaration_name(node)
        || is_member_field_declaration_context(node, ctx)
        || has_ancestor_kind(node, "field_expression")
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if ctx
        .visibility
        .resolve_named(
            ctx.file,
            node_text(node, ctx.source),
            TargetKind::GlobalField,
        )
        .is_some_and(|resolved| same_visible_symbol(&resolved, &ctx.spec.target))
    {
        push_hit(node, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
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
    if qualified_match || same_owner_context(node, ctx) {
        push_hit(node, ctx);
    } else if !known_non_target_owner_context(node, ctx) {
        *ctx.saw_unproven_match = true;
    }
}

fn scan_text_symbol_hits(ctx: &mut ScanCtx<'_>) {
    if !ctx.visibility.is_visible(ctx.file, &ctx.spec.target) {
        return;
    }
    let symbol = ctx.spec.member_name.as_str();
    let mut start = 0usize;
    while let Some(relative) = ctx.source[start..].find(symbol) {
        let absolute = start + relative;
        let end = absolute + symbol.len();
        start = end;
        if !is_word_boundary(ctx.source, absolute, end) {
            continue;
        }
        if !field_text_qualifier_matches(ctx.source, absolute, ctx) {
            continue;
        }
        push_text_hit(absolute, end, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }
}

fn is_word_boundary(source: &str, start: usize, end: usize) -> bool {
    let before = source[..start].chars().next_back();
    let after = source[end..].chars().next();
    !before.is_some_and(is_identifier_char) && !after.is_some_and(is_identifier_char)
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn field_text_qualifier_matches(source: &str, start: usize, ctx: &ScanCtx<'_>) -> bool {
    if !matches!(ctx.spec.kind, TargetKind::MemberField) {
        return true;
    }
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return true;
    };
    let Some(owner_cpp_name) = ctx.spec.owner_cpp_name.as_deref() else {
        return true;
    };
    let prefix = &source[..start];
    if let Some(prefix) = prefix.strip_suffix("::") {
        let qualifier = prefix
            .rsplit(|ch: char| !(ch == '_' || ch == ':' || ch.is_ascii_alphanumeric()))
            .next()
            .unwrap_or("");
        return qualifier == owner_cpp_name || qualifier == owner.identifier();
    }
    if let Some(prefix) = prefix.strip_suffix('.') {
        return text_receiver_matches_target(prefix, ctx);
    }
    if let Some(prefix) = prefix.strip_suffix("->") {
        return text_receiver_matches_target(prefix, ctx);
    }
    if owner_is_class_like(owner, ctx) {
        return false;
    }
    !owner_is_scoped_enum(owner, ctx)
}

fn text_receiver_matches_target(prefix: &str, ctx: &ScanCtx<'_>) -> bool {
    let receiver = receiver_token_before(prefix, prefix.len());
    if receiver == Some("this") {
        return textual_owner_context_at(prefix)
            .zip(ctx.spec.owner_cpp_name.as_deref())
            .is_some_and(|(owner, target)| owner == target)
            || textual_owner_context_at(prefix)
                .zip(ctx.spec.owner.as_ref())
                .is_some_and(|(owner_text, owner)| owner_text == owner.identifier());
    }
    receiver.is_some_and(|receiver| text_receiver_has_target_type(ctx.source, receiver, ctx))
}

fn owner_is_class_like(owner: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    owner.signature().is_some_and(|signature| {
        signature.starts_with("class ")
            || signature.starts_with("struct ")
            || signature.starts_with("union ")
    }) || ctx.analyzer.get_source(owner, false).is_some_and(|source| {
        let trimmed = source.trim_start();
        trimmed.starts_with("class ")
            || trimmed.starts_with("struct ")
            || trimmed.starts_with("union ")
    })
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

fn scan_text_constructor_hits(ctx: &mut ScanCtx<'_>) {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return;
    };
    if !ctx.visibility.is_visible(ctx.file, owner) {
        return;
    }
    let Some(expected_arity) = ctx.spec.method_arity else {
        return;
    };
    let owner_name = ctx.spec.member_name.as_str();
    for pattern in [
        format!("{owner_name}("),
        format!("{owner_name}{{"),
        format!("new {owner_name}("),
        format!("new {owner_name};"),
    ] {
        let mut start = 0usize;
        while let Some(relative) = ctx.source[start..].find(&pattern) {
            let absolute = start + relative;
            let end = absolute + owner_name.len();
            start = absolute + pattern.len();
            if !is_word_boundary(ctx.source, absolute, end) {
                continue;
            }
            if text_constructor_arity(ctx.source, absolute, &pattern) != expected_arity {
                continue;
            }
            push_text_constructor_hit(absolute, end, ctx);
            if *ctx.limit_exceeded {
                return;
            }
        }
    }
    for field_name in constructor_member_names(ctx, owner) {
        for pattern in [format!(": {field_name}("), format!(", {field_name}(")] {
            let mut start = 0usize;
            while let Some(relative) = ctx.source[start..].find(&pattern) {
                let absolute = start + relative + 2;
                let end = absolute + field_name.len();
                start = absolute + pattern.len();
                if text_constructor_arity(ctx.source, absolute, &format!("{field_name}("))
                    != expected_arity
                {
                    continue;
                }
                push_text_constructor_hit(absolute, end, ctx);
                if *ctx.limit_exceeded {
                    return;
                }
            }
        }
    }
}

fn constructor_member_names(ctx: &ScanCtx<'_>, owner: &CodeUnit) -> Vec<String> {
    let mut names: Vec<String> = ctx
        .visibility
        .visible_by_file
        .get(ctx.file)
        .into_iter()
        .flatten()
        .filter(|unit| unit.is_field())
        .filter_map(|unit| {
            unit.signature()
                .filter(|signature| field_signature_type_matches(signature, owner, ctx))
                .map(|_| unit.identifier().to_string())
        })
        .collect();
    let fallback = lower_initial(owner.identifier());
    if !names.iter().any(|name| name == &fallback) {
        names.push(fallback);
    }
    names
}

fn field_signature_type_matches(signature: &str, owner: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    ctx.visibility.resolves_to_type(ctx.file, signature, owner)
        || signature
            .split_whitespace()
            .next()
            .is_some_and(|type_text| ctx.visibility.resolves_to_type(ctx.file, type_text, owner))
}

fn lower_initial(value: &str) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    first.to_ascii_lowercase().to_string() + chars.as_str()
}

fn text_constructor_arity(source: &str, start: usize, pattern: &str) -> usize {
    if pattern.ends_with(';') {
        return 0;
    }
    let opener = if pattern.ends_with('(') { '(' } else { '{' };
    let closer = if opener == '(' { ')' } else { '}' };
    let Some(open_index) = source[start..].find(opener).map(|index| start + index) else {
        return 0;
    };
    let Some(close_index) = source[open_index + 1..]
        .find(closer)
        .map(|index| open_index + 1 + index)
    else {
        return 0;
    };
    let inner = source[open_index + 1..close_index].trim();
    if inner.is_empty() {
        0
    } else {
        split_top_level_commas(inner).count()
    }
}
fn scan_text_operator_method_hits(ctx: &mut ScanCtx<'_>) {
    let Some(operator_suffix) = ctx.spec.member_name.strip_prefix("operator") else {
        return;
    };
    if operator_suffix.is_empty() {
        return;
    }
    let pattern = format!(".operator{operator_suffix}(");
    let mut start = 0usize;
    while let Some(relative) = ctx.source[start..].find(&pattern) {
        let dot = start + relative;
        let operator_start = dot + 1;
        let end = operator_start + ctx.spec.member_name.len();
        start = end;
        let Some(receiver) = receiver_token_before(ctx.source, dot) else {
            continue;
        };
        if ctx
            .bindings
            .resolve_symbol(receiver)
            .as_precise()
            .is_some_and(|targets| {
                ctx.spec
                    .owner
                    .as_ref()
                    .is_some_and(|owner| targets.iter().any(|target| same_symbol(target, owner)))
            })
            || text_receiver_has_target_type(ctx.source, receiver, ctx)
        {
            push_text_constructor_hit(operator_start, end, ctx);
        }
        if *ctx.limit_exceeded {
            return;
        }
    }
}

fn text_receiver_has_target_type(source: &str, receiver: &str, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner_name) = ctx.spec.owner_cpp_name.as_deref() else {
        return false;
    };
    [
        format!("{owner_name}& {receiver}"),
        format!("{owner_name} &{receiver}"),
        format!("{owner_name}* {receiver}"),
        format!("{owner_name} *{receiver}"),
        format!("{owner_name} {receiver}"),
    ]
    .iter()
    .any(|pattern| source.contains(pattern))
}

fn receiver_token_before(source: &str, end: usize) -> Option<&str> {
    let prefix = source[..end].trim_end();
    let start = prefix
        .rfind(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .map(|index| index + 1)
        .unwrap_or(0);
    let token = prefix[start..].trim();
    (!token.is_empty()).then_some(token)
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
            .is_some_and(|targets| targets.iter().any(|target| same_symbol(target, owner))),
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
                !targets.is_empty()
                    && targets
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
