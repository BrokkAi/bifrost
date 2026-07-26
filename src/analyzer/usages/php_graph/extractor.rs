use crate::analyzer::tree_walk::subtree_contains;
use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::local_inference::LocalInferenceEngine;
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::php_graph::hits::{
    push_hit, push_hit_range, push_import_hit, push_self_receiver_hit_range,
};
use crate::analyzer::usages::php_graph::resolver::{
    PhpHierarchyIndex, TargetKind, TargetSpec, enclosing_owner_fq_name_at,
    is_const_declaration_name, is_function_call_name, is_function_declaration_name,
    is_member_or_scoped_access_name, is_object_creation_type_name, node_text,
    qualified_candidate_text, receiver_type_matches, static_receiver_matches,
};
use crate::analyzer::usages::php_graph::syntax::{
    assignment_parts, declared_callable_return_type_fq_name, instance_receiver_type_fq_name,
    is_local_scope, literal_member_identifier, object_creation_type, seed_parameter_types,
    static_member_parts, static_property_identifier, static_scope_type_fq_name,
    variable_identifier,
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
    if matches!(
        spec.kind,
        TargetKind::Constructor | TargetKind::Method | TargetKind::Field
    ) {
        scan_member_patterns(
            php,
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
    }
    if !matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
        scan_node(
            php,
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
    php: &PhpAnalyzer,
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

    if matches!(
        node.kind(),
        "namespace_name" | "qualified_name" | "relative_scope"
    ) {
        handle_candidate(
            php,
            node,
            analyzer,
            file,
            source,
            line_starts,
            ctx,
            spec,
            hits,
        );
        return;
    }

    if matches!(node.kind(), "name" | "variable_name") {
        handle_candidate(
            php,
            node,
            analyzer,
            file,
            source,
            line_starts,
            ctx,
            spec,
            hits,
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(
            php,
            child,
            analyzer,
            file,
            source,
            line_starts,
            ctx,
            spec,
            hits,
        );
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
    php: &PhpAnalyzer,
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
            if candidate_resolves_to_type(
                php,
                analyzer,
                file,
                node,
                source,
                line_starts,
                ctx,
                &spec.target_fq_name,
            ) {
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

#[allow(clippy::too_many_arguments)]
fn candidate_resolves_to_type(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    target_fq_name: &str,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    let enclosing_owner = matches!(raw.as_str(), "self" | "static" | "parent")
        .then(|| {
            enclosing_owner_fq_name_at(
                analyzer,
                file,
                node.start_byte(),
                node.end_byte(),
                line_starts,
            )
        })
        .flatten();
    static_scope_type_fq_name(php, analyzer, &raw, ctx, enclosing_owner.as_deref())
        .is_some_and(|fq| fq == target_fq_name)
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
    php: &PhpAnalyzer,
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
    if !matches!(
        spec.kind,
        TargetKind::Constructor | TargetKind::Method | TargetKind::Field
    ) {
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
        php,
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
    php: &PhpAnalyzer,
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
            php,
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
    php: &PhpAnalyzer,
    engine: &mut LocalInferenceEngine<String>,
    scopes: &mut Vec<(Node<'tree>, bool)>,
    hits: &mut BTreeSet<UsageHit>,
) {
    enum Visit<'tree> {
        Node(Node<'tree>),
        ApplyAssignment(Node<'tree>),
    }

    let mut stack = vec![Visit::Node(root)];
    while let Some(visit) = stack.pop() {
        let node = match visit {
            Visit::Node(node) => node,
            Visit::ApplyAssignment(node) => {
                apply_receiver_assignment(
                    node,
                    php,
                    analyzer,
                    file,
                    source,
                    line_starts,
                    ctx,
                    engine,
                );
                continue;
            }
        };
        if node != root && is_local_scope(node) {
            scopes.push((node, true));
            continue;
        }
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
            php,
            engine,
            hits,
        );
        if assignment_parts(node).is_some() {
            stack.push(Visit::ApplyAssignment(node));
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev().map(Visit::Node));
    }
}

fn contains_member_reference_candidate(root: Node<'_>, source: &str, spec: &TargetSpec) -> bool {
    subtree_contains(root, |node| match node.kind() {
        "member_access_expression"
        | "nullsafe_member_access_expression"
        | "member_call_expression"
        | "nullsafe_member_call_expression" => {
            node.child_by_field_name("name")
                .and_then(|member| literal_member_identifier(member, source))
                == Some(spec.member_name.as_str())
        }
        "class_constant_access_expression"
        | "scoped_call_expression"
        | "scoped_property_access_expression" => {
            static_member_parts(node).is_some_and(|(_, member)| {
                static_member_identifier(node, member, source) == Some(spec.member_name.as_str())
            })
        }
        _ => false,
    })
}

fn seed_parameter_receivers(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    seed_parameter_types(node, source, engine, |raw| resolve_php_type(raw, ctx));
}

#[allow(clippy::too_many_arguments)]
fn apply_receiver_assignment(
    node: Node<'_>,
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
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
    let resolved = assignment_receiver_type(right, php, analyzer, file, source, line_starts, ctx);
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

fn assignment_receiver_type(
    node: Node<'_>,
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
) -> Option<String> {
    match node.kind() {
        "object_creation_expression" => object_creation_type(node)
            .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx)),
        "function_call_expression" => {
            let function = node.child_by_field_name("function")?;
            let raw = qualified_candidate_text(function, source);
            let callable_fqn = resolve_php_function(&raw, ctx)?;
            let mut definitions = analyzer
                .definitions(&callable_fqn)
                .filter(|unit| unit.is_function());
            let callable = definitions.next()?;
            if definitions.next().is_some() {
                return None;
            }
            declared_callable_return_type_fq_name(php, analyzer, &callable)
        }
        "scoped_call_expression" => {
            let (scope, name) = static_member_parts(node)?;
            let enclosing_owner = enclosing_owner_fq_name_at(
                analyzer,
                file,
                scope.start_byte(),
                scope.end_byte(),
                line_starts,
            );
            let owner = static_scope_type_fq_name(
                php,
                analyzer,
                node_text(scope, source),
                ctx,
                enclosing_owner.as_deref(),
            )?;
            let method = node_text(name, source);
            if method.is_empty() {
                return None;
            }
            let callable_fqn = format!("{owner}.{method}");
            let mut definitions = analyzer
                .definitions(&callable_fqn)
                .filter(|unit| unit.is_function());
            let callable = definitions.next()?;
            if definitions.next().is_some() {
                return None;
            }
            declared_callable_return_type_fq_name(php, analyzer, &callable)
        }
        "parenthesized_expression" => node.named_child(0).and_then(|inner| {
            assignment_receiver_type(inner, php, analyzer, file, source, line_starts, ctx)
        }),
        _ => None,
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
    php: &PhpAnalyzer,
    engine: &LocalInferenceEngine<String>,
    hits: &mut BTreeSet<UsageHit>,
) {
    match node.kind() {
        "member_access_expression"
        | "nullsafe_member_access_expression"
        | "member_call_expression"
        | "nullsafe_member_call_expression" => {
            let (Some(receiver_node), Some(member_node)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("name"),
            ) else {
                return;
            };
            if literal_member_identifier(member_node, source) != Some(spec.member_name.as_str()) {
                return;
            }
            if receiver_expression_type(
                receiver_node,
                php,
                analyzer,
                file,
                source,
                line_starts,
                ctx,
                engine,
            )
            .is_some_and(|fq| receiver_type_matches(php, &fq, owner, hierarchy))
            {
                // `$this->m()` is a same-owner instance call on the current
                // object; a call through another object of the same type is not.
                let same_owner = node_text(receiver_node, source) == "$this";
                push_member_hit(
                    member_node,
                    analyzer,
                    file,
                    source,
                    line_starts,
                    spec,
                    hits,
                    same_owner,
                );
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
            let receiver_text = node_text(receiver_node, source);
            if !static_receiver_matches(
                php,
                analyzer,
                file,
                member_node.start_byte(),
                member_node.end_byte(),
                line_starts,
                receiver_text,
                owner,
                ctx,
                hierarchy,
            ) {
                return;
            }
            // `self::m()` / `static::m()` are same-owner own-type static calls;
            // `parent::m()` and an explicit class name are external.
            let same_owner = matches!(receiver_text, "self" | "static");
            push_member_hit(
                member_node,
                analyzer,
                file,
                source,
                line_starts,
                spec,
                hits,
                same_owner,
            );
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

#[allow(clippy::too_many_arguments)]
fn receiver_expression_type(
    node: Node<'_>,
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    engine: &LocalInferenceEngine<String>,
) -> Option<String> {
    instance_receiver_type_fq_name(php, analyzer, node, source, ctx, engine, |start, end| {
        enclosing_owner_fq_name_at(analyzer, file, start, end, line_starts)
    })
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
    same_owner: bool,
) {
    let start = node.start_byte() + usize::from(node_text(node, source).starts_with('$'));
    if same_owner {
        push_self_receiver_hit_range(
            start,
            node.end_byte(),
            analyzer,
            file,
            source,
            line_starts,
            spec,
            hits,
        );
    } else {
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
}
