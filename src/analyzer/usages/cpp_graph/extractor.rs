use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::cpp_graph::hits::{
    enclosing_context, is_member_field_declaration_context, push_hit,
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
        "new_expression" | "call_expression" => {
            infer_cpp_initializer_type(ctx.analyzer, ctx.visibility, ctx.file, ctx.source, node)
        }
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

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
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
            push_hit(operator, ctx);
        } else if !receiver_has_known_non_target(receiver, ctx) {
            *ctx.saw_unproven_match = true;
        }
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
