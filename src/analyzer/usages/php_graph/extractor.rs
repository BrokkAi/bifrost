use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::php_graph::hits::{push_hit, push_hit_range};
use crate::analyzer::usages::php_graph::resolver::{
    PhpHierarchyIndex, TargetKind, TargetSpec, is_const_declaration_name, is_function_call_name,
    is_function_declaration_name, is_member_or_scoped_access_name, is_object_creation_type_name,
    node_text, qualified_candidate_text, receiver_is_enclosing_subtype, receiver_type_matches,
    static_receiver_matches,
};
use crate::analyzer::{
    IAnalyzer, PhpAnalyzer, PhpFileContext, ProjectFile, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub(super) fn scan_file(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hierarchy: &PhpHierarchyIndex,
    hits: &mut BTreeSet<UsageHit>,
) {
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };

    let ctx = php.file_context_from_source(file, &source);

    let line_starts = compute_line_starts(&source);
    if matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
        scan_member_patterns(
            tree.root_node(),
            analyzer,
            file,
            &source,
            &line_starts,
            &ctx,
            hierarchy,
            spec,
            hits,
        );
    } else {
        scan_node(
            tree.root_node(),
            analyzer,
            file,
            &source,
            &line_starts,
            &ctx,
            spec,
            hits,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_node(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    if node.kind() == "namespace_use_declaration" || node.kind() == "comment" {
        return;
    }

    if matches!(node.kind(), "namespace_name" | "qualified_name") {
        handle_candidate(node, analyzer, file, source, line_starts, ctx, spec, hits);
        return;
    }

    if matches!(node.kind(), "name" | "variable_name") {
        handle_candidate(node, analyzer, file, source, line_starts, ctx, spec, hits);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, analyzer, file, source, line_starts, ctx, spec, hits);
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_candidate(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    match spec.kind {
        TargetKind::Type => {
            if candidate_resolves_to_type(node, source, ctx, &spec.target_fq_name) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Constructor => {
            if is_constructor_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Method | TargetKind::Field => {}
        TargetKind::Constant => {
            if node.kind() != "namespace_name" && is_constant_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Function => {
            if node.kind() != "namespace_name" && is_function_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
    }
}

fn candidate_resolves_to_type(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    target_fq_name: &str,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    resolve_php_type(&raw, ctx).is_some_and(|fq| fq == target_fq_name)
}

fn is_constructor_reference(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    spec: &TargetSpec,
) -> bool {
    let Some(owner) = spec.owner_fq_name.as_deref() else {
        return false;
    };
    if !is_reference_context(node) {
        return false;
    }
    if !is_object_creation_type_name(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    resolve_php_type(&raw, ctx).is_some_and(|fq| fq == owner)
}

fn is_constant_reference(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    spec: &TargetSpec,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    if is_function_call_name(node)
        || is_member_or_scoped_access_name(node)
        || is_const_declaration_name(node)
    {
        return false;
    }
    resolve_php_constant(&raw, ctx).is_some_and(|fq| fq == spec.target_fq_name)
}

fn is_function_reference(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    spec: &TargetSpec,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    if !is_function_call_name(node) {
        return false;
    }
    if is_member_or_scoped_access_name(node) || is_function_declaration_name(node) {
        return false;
    }
    resolve_php_function(&raw, ctx).is_some_and(|fq| fq == spec.target_fq_name)
}

fn is_reference_context(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "namespace_use_declaration"
                | "comment"
                | "string"
                | "encapsed_string"
                | "string_value"
                | "heredoc"
                | "nowdoc"
        ) {
            return false;
        }
        parent = current.parent();
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn scan_member_patterns(
    root: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    if !matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
        return;
    }
    let Some(owner) = spec.owner_fq_name.as_deref() else {
        return;
    };
    let mut engine = LocalInferenceEngine::default();
    scan_member_tree(
        root,
        analyzer,
        file,
        source,
        line_starts,
        ctx,
        hierarchy,
        owner,
        spec,
        &mut engine,
        hits,
    );
}

#[allow(clippy::too_many_arguments)]
fn scan_member_tree(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
    owner: &str,
    spec: &TargetSpec,
    engine: &mut LocalInferenceEngine<String>,
    hits: &mut BTreeSet<UsageHit>,
) {
    let enters_scope = is_php_local_scope(node);
    if enters_scope {
        engine.enter_scope();
        seed_parameter_receivers(node, source, ctx, engine);
    }

    apply_receiver_assignment(node, source, ctx, engine);
    record_member_hit(
        node,
        analyzer,
        file,
        source,
        line_starts,
        ctx,
        hierarchy,
        owner,
        spec,
        engine,
        hits,
    );

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_member_tree(
            child,
            analyzer,
            file,
            source,
            line_starts,
            ctx,
            hierarchy,
            owner,
            spec,
            engine,
            hits,
        );
    }

    if enters_scope {
        engine.exit_scope();
    }
}

const PHP_LOCAL_SCOPE_NODES: &[&str] = &[
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "anonymous_function_creation",
    "arrow_function",
];

fn is_php_local_scope(node: Node<'_>) -> bool {
    PHP_LOCAL_SCOPE_NODES.contains(&node.kind())
}

fn seed_parameter_receivers(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        match child
            .child_by_field_name("type")
            .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx))
        {
            Some(fq) => engine.seed_symbol(name.to_string(), fq),
            None => engine.declare_shadow(name.to_string()),
        }
    }
}

fn apply_receiver_assignment(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    if node.kind() != "assignment_expression" {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if left.kind() != "variable_name" {
        return;
    }
    let lhs = variable_identifier(left, source);
    if lhs.is_empty() {
        return;
    }
    let resolved = (right.kind() == "object_creation_expression")
        .then(|| object_creation_type(right))
        .flatten()
        .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx));
    match resolved {
        Some(fq) => engine.seed_symbol(lhs.to_string(), fq),
        None => {
            if right.kind() == "variable_name" {
                let rhs = variable_identifier(right, source);
                if !rhs.is_empty() {
                    engine.alias_symbol(lhs.to_string(), rhs);
                    return;
                }
            }
            engine.declare_shadow(lhs.to_string());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn record_member_hit(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
    owner: &str,
    spec: &TargetSpec,
    engine: &LocalInferenceEngine<String>,
    hits: &mut BTreeSet<UsageHit>,
) {
    match node.kind() {
        "member_access_expression" | "member_call_expression" => {
            let (Some(receiver_node), Some(member_node)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("name"),
            ) else {
                return;
            };
            if member_identifier(member_node, source) != spec.member_name {
                return;
            }
            let receiver_matches = if variable_identifier(receiver_node, source) == "this" {
                receiver_is_enclosing_subtype(
                    analyzer,
                    file,
                    member_node.start_byte(),
                    member_node.end_byte(),
                    line_starts,
                    owner,
                    hierarchy,
                )
            } else {
                precise_receiver_type(engine, variable_identifier(receiver_node, source))
                    .is_some_and(|fq| receiver_type_matches(&fq, owner, hierarchy))
            };
            if receiver_matches {
                push_member_hit(member_node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        "class_constant_access_expression"
        | "scoped_call_expression"
        | "scoped_property_access_expression" => {
            let Some((receiver_node, member_node)) = static_access_parts(node) else {
                return;
            };
            if member_identifier(member_node, source) != spec.member_name {
                return;
            }
            if !static_receiver_matches(
                analyzer,
                file,
                member_node.start_byte(),
                member_node.end_byte(),
                line_starts,
                node_text(receiver_node, source),
                owner,
                ctx,
                hierarchy,
            ) {
                return;
            }
            push_member_hit(member_node, analyzer, file, source, line_starts, spec, hits);
        }
        _ => {}
    }
}

fn static_access_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let field_parts = node
        .child_by_field_name("scope")
        .zip(node.child_by_field_name("name"));
    if field_parts.is_some() {
        return field_parts;
    }
    let mut cursor = node.walk();
    let named: Vec<_> = node.named_children(&mut cursor).collect();
    named.first().copied().zip(named.last().copied())
}

fn precise_receiver_type(engine: &LocalInferenceEngine<String>, receiver: &str) -> Option<String> {
    match engine.resolve_symbol(receiver) {
        SymbolResolution::Precise(targets) if targets.len() == 1 => targets.into_iter().next(),
        SymbolResolution::Unknown | SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => {
            None
        }
    }
}

fn object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn variable_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_text(node, source).trim_start_matches('$')
}

fn member_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_text(node, source).trim_start_matches('$')
}

#[allow(clippy::too_many_arguments)]
fn push_member_hit(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let start = node.start_byte() + usize::from(node_text(node, source).starts_with('$'));
    push_hit_range(
        start,
        node.end_byte(),
        analyzer,
        file,
        source,
        line_starts,
        spec,
        hits,
    );
}
