use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::php_graph::hits::{push_hit, push_hit_range, push_import_hit};
use crate::analyzer::usages::php_graph::resolver::{
    PhpHierarchyIndex, TargetKind, TargetSpec, is_const_declaration_name, is_function_call_name,
    is_function_declaration_name, is_member_or_scoped_access_name, is_object_creation_type_name,
    node_text, qualified_candidate_text, receiver_is_enclosing_subtype, receiver_type_matches,
    static_receiver_matches,
};
use crate::analyzer::usages::php_graph::syntax::{
    assignment_parts, is_local_scope, literal_member_identifier, object_creation_type,
    seed_parameter_types, static_member_parts, static_property_identifier, variable_identifier,
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

    if matches!(spec.kind, TargetKind::Method | TargetKind::Field)
        && !contains_member_reference_candidate(tree.root_node(), &source, spec)
    {
        return;
    }

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
    if node.kind() == "namespace_use_declaration" {
        record_namespace_use_import_hit(node, analyzer, file, source, line_starts, ctx, spec, hits);
        return;
    }
    if node.kind() == "comment" {
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
fn record_namespace_use_import_hit(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    if !matches!(spec.kind, TargetKind::Type) {
        return;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "namespace_name" | "qualified_name" | "name")
            && resolve_php_type(&qualified_candidate_text(current, source), ctx)
                .is_some_and(|fq| fq == spec.target_fq_name)
        {
            push_import_hit(current, analyzer, file, source, line_starts, spec, hits);
            continue;
        }
        if matches!(current.kind(), "name" | "identifier") {
            let text = node_text(current, source);
            if is_local_namespace_use_binding_node(current)
                && ctx
                    .aliases
                    .type_aliases
                    .get(text)
                    .is_some_and(|fq| fq == &spec.target_fq_name)
            {
                push_import_hit(current, analyzer, file, source, line_starts, spec, hits);
                continue;
            }
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn is_local_namespace_use_binding_node(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_use_declaration" {
            return true;
        }
        if parent.kind() == "namespace_use_clause" {
            return match parent.child_by_field_name("alias") {
                Some(alias) => same_node(alias, node),
                None => true,
            };
        }
        current = parent.parent();
    }
    true
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
        hits,
    );
}

#[allow(clippy::too_many_arguments)]
fn scan_member_tree<'tree>(
    node: Node<'tree>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
    owner: &str,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let mut scopes: Vec<(Node<'tree>, bool)> = vec![(node, false)];
    while let Some((scope_root, seed_parameters)) = scopes.pop() {
        let mut engine = LocalInferenceEngine::default();
        if seed_parameters {
            seed_parameter_receivers(scope_root, source, ctx, &mut engine);
        }
        scan_member_scope(
            scope_root,
            analyzer,
            file,
            source,
            line_starts,
            ctx,
            hierarchy,
            owner,
            spec,
            &mut engine,
            &mut scopes,
            hits,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_member_scope<'tree>(
    root: Node<'tree>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
    owner: &str,
    spec: &TargetSpec,
    engine: &mut LocalInferenceEngine<String>,
    scopes: &mut Vec<(Node<'tree>, bool)>,
    hits: &mut BTreeSet<UsageHit>,
) {
    let mut stack: Vec<Node<'tree>> = vec![root];
    while let Some(node) = stack.pop() {
        if node != root && is_local_scope(node) {
            scopes.push((node, true));
            continue;
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
        push_named_children(node, &mut stack);
    }
}

fn push_named_children<'tree>(node: Node<'tree>, stack: &mut Vec<Node<'tree>>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    stack.extend(children.into_iter().rev());
}

fn contains_member_reference_candidate(root: Node<'_>, source: &str, spec: &TargetSpec) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "member_access_expression" | "member_call_expression" => {
                if node
                    .child_by_field_name("name")
                    .and_then(|member| literal_member_identifier(member, source))
                    == Some(spec.member_name.as_str())
                {
                    return true;
                }
            }
            "class_constant_access_expression"
            | "scoped_call_expression"
            | "scoped_property_access_expression" => {
                if let Some((_, member)) = static_member_parts(node)
                    && static_member_identifier(node, member, source)
                        == Some(spec.member_name.as_str())
                {
                    return true;
                }
            }
            _ => {}
        }
        push_named_children(node, &mut stack);
    }
    false
}

fn seed_parameter_receivers(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    seed_parameter_types(node, source, engine, |raw| resolve_php_type(raw, ctx));
}

fn apply_receiver_assignment(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    let Some((left, right)) = assignment_parts(node) else {
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
            if literal_member_identifier(member_node, source) != Some(spec.member_name.as_str()) {
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
            let Some((receiver_node, member_node)) = static_member_parts(node) else {
                return;
            };
            if static_member_identifier(node, member_node, source)
                != Some(spec.member_name.as_str())
            {
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

fn static_member_identifier<'a>(
    parent: Node<'_>,
    member: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    if parent.kind() == "scoped_property_access_expression" {
        static_property_identifier(member, source)
    } else {
        literal_member_identifier(member, source)
    }
}

fn precise_receiver_type(engine: &LocalInferenceEngine<String>, receiver: &str) -> Option<String> {
    match engine.resolve_symbol(receiver) {
        SymbolResolution::Precise(targets) if targets.len() == 1 => targets.into_iter().next(),
        SymbolResolution::Unknown | SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => {
            None
        }
    }
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
