use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::TypeHierarchyProvider;
use crate::analyzer::usages::php_graph::syntax::{
    assignment_parts, declared_callable_return_type_fq_name, declared_field_type_fq_name,
    is_local_scope as php_is_local_scope, object_creation_type as php_object_creation_type,
    seed_parameter_types, static_member_parts as php_static_member_parts,
    variable_identifier as php_variable_identifier,
};

pub(super) fn resolve_php(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return no_definition("php_analyzer_unavailable", "PHP analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("php_parse_failed", "PHP source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed PHP definition",
                site.text
            ),
        );
    };
    let ctx = php.file_context_from_source(file, source);
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    if php_is_declaration_name(node)
        && let Some(outcome) =
            php_interface_method_declaration_outcome(php, support, source, node, &class_ranges)
    {
        return outcome;
    }
    if php_is_non_reference_context(node) || php_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a PHP reference site", site.text),
        );
    }
    if php_is_variable_reference(node) && !php_is_static_property_name(node) {
        return no_definition(
            "local_variable_reference",
            format!(
                "`{}` is a PHP variable reference, not an indexed definition",
                site.text
            ),
        );
    }

    match php_reference_node(node) {
        Some(PhpReferenceNode::Type(type_node)) => {
            let raw = php_qualified_candidate_text(type_node, source);
            php_fqn_outcome(support, resolve_php_type(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::Function(name_node)) => {
            let raw = php_qualified_candidate_text(name_node, source);
            php_fqn_outcome(support, resolve_php_function(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::Constant(name_node)) => {
            let raw = php_qualified_candidate_text(name_node, source);
            php_fqn_outcome(support, resolve_php_constant(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::StaticMember { scope, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let owner = php_static_scope_fqn(php, support, scope, source, &ctx, &class_ranges);
            php_member_outcome(php, support, owner, member)
        }
        Some(PhpReferenceNode::InstanceMember { object, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let bindings = php_bindings_before(
                php,
                file,
                source,
                root,
                site.range.start_byte,
                &class_ranges,
                &ctx,
                support,
            );
            let owner = php_instance_receiver_fqn(
                php,
                analyzer,
                support,
                object,
                source,
                &class_ranges,
                &bindings,
                &ctx,
            );
            php_member_outcome(php, support, owner, member)
        }
        None => no_definition(
            "unsupported_php_reference_shape",
            format!(
                "`{}` is a PHP `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn php_interface_method_declaration_outcome(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    source: &str,
    node: Node<'_>,
    class_ranges: &ClassRangeIndex,
) -> Option<DefinitionLookupOutcome> {
    let method = php_method_declaration_name(node, source)?;
    let owner_fqn = class_ranges.enclosing(node.start_byte())?;
    let owner = php_fqn_candidates(support, owner_fqn).into_iter().next()?;
    let mut candidates = Vec::new();
    let mut stack = php.get_direct_ancestors(&owner);
    let mut seen = HashSet::default();
    while let Some(ancestor) = stack.pop() {
        let ancestor_fqn = ancestor.fq_name();
        if !seen.insert(ancestor_fqn.clone()) {
            continue;
        }
        if php.is_interface(&ancestor) {
            candidates.extend(php_fqn_candidates(
                support,
                &format!("{ancestor_fqn}.{method}"),
            ));
        }
        stack.extend(php.get_direct_ancestors(&ancestor));
    }
    if candidates.is_empty() {
        return None;
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates_outcome(candidates))
}

fn php_method_declaration_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let parent = node.parent()?;
    if parent.kind() != "method_declaration" || parent.child_by_field_name("name") != Some(node) {
        return None;
    }
    let name = php_node_text(node, source).trim();
    (!name.is_empty()).then_some(name)
}

pub(super) fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

enum PhpReferenceNode<'tree> {
    Type(Node<'tree>),
    Function(Node<'tree>),
    Constant(Node<'tree>),
    StaticMember {
        scope: Node<'tree>,
        name: Node<'tree>,
    },
    InstanceMember {
        object: Node<'tree>,
        name: Node<'tree>,
    },
}

fn php_reference_node<'tree>(node: Node<'tree>) -> Option<PhpReferenceNode<'tree>> {
    let node = php_qualified_reference_node(node);
    if let Some(access) = php_static_property_access_for_name(node) {
        let (scope, name) = php_static_member_parts(access)?;
        return Some(PhpReferenceNode::StaticMember { scope, name });
    }
    match node.kind() {
        "object_creation_expression" => php_object_creation_type(node).map(PhpReferenceNode::Type),
        "named_type" => (!php_is_in_object_creation(node)).then_some(PhpReferenceNode::Type(node)),
        "function_call_expression" => node
            .child_by_field_name("function")
            .filter(|name| matches!(name.kind(), "name" | "qualified_name"))
            .map(PhpReferenceNode::Function),
        "scoped_call_expression"
        | "class_constant_access_expression"
        | "scoped_property_access_expression" => {
            let (scope, name) = php_static_member_parts(node)?;
            Some(PhpReferenceNode::StaticMember { scope, name })
        }
        "member_call_expression"
        | "nullsafe_member_call_expression"
        | "member_access_expression"
        | "nullsafe_member_access_expression" => {
            let object = node.child_by_field_name("object")?;
            let name = node.child_by_field_name("name")?;
            Some(PhpReferenceNode::InstanceMember { object, name })
        }
        "name" | "qualified_name" => {
            let parent = node.parent()?;
            match parent.kind() {
                "object_creation_expression" | "named_type" => Some(PhpReferenceNode::Type(node)),
                "function_call_expression"
                    if parent.child_by_field_name("function") == Some(node) =>
                {
                    Some(PhpReferenceNode::Function(node))
                }
                "scoped_call_expression"
                | "class_constant_access_expression"
                | "scoped_property_access_expression" => php_static_access_reference(parent, node),
                "member_call_expression"
                | "nullsafe_member_call_expression"
                | "member_access_expression"
                | "nullsafe_member_access_expression"
                    if parent.child_by_field_name("name") == Some(node) =>
                {
                    let object = parent.child_by_field_name("object")?;
                    Some(PhpReferenceNode::InstanceMember { object, name: node })
                }
                _ if php_is_instanceof_type_name(node) => Some(PhpReferenceNode::Type(node)),
                _ if php_is_bare_constant_reference(node) => Some(PhpReferenceNode::Constant(node)),
                _ => None,
            }
        }
        _ => {
            let parent = node.parent()?;
            if matches!(
                parent.kind(),
                "scoped_call_expression"
                    | "class_constant_access_expression"
                    | "scoped_property_access_expression"
            ) {
                return php_static_access_reference(parent, node);
            }
            php_reference_node(parent)
        }
    }
}

/// True when `node` is the type operand of a PHP `instanceof`. The grammar models
/// `$x instanceof Foo` as a `binary_expression` whose `operator` child is the
/// `instanceof` token and whose `right` field is the class name.
fn php_is_instanceof_type_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "binary_expression"
        && parent
            .child_by_field_name("operator")
            .is_some_and(|operator| operator.kind() == "instanceof")
        && parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() <= node.start_byte() && node.end_byte() <= right.end_byte()
        })
}

fn php_static_access_reference<'tree>(
    access: Node<'tree>,
    focus: Node<'tree>,
) -> Option<PhpReferenceNode<'tree>> {
    let (scope, name) = php_static_member_parts(access)?;
    if node_contains_focus(scope, focus) {
        return Some(PhpReferenceNode::Type(focus));
    }
    if node_contains_focus(name, focus) {
        return Some(PhpReferenceNode::StaticMember { scope, name });
    }
    None
}

fn php_static_member_name(node: Node<'_>) -> Option<Node<'_>> {
    php_static_member_parts(node).map(|(_, name)| name)
}

fn php_is_static_property_name(node: Node<'_>) -> bool {
    php_static_property_access_for_name(node).is_some()
}

fn php_static_property_access_for_name(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(ancestor) = current {
        if ancestor.kind() == "scoped_property_access_expression" {
            return php_static_member_name(ancestor)
                .is_some_and(|name| {
                    name.start_byte() <= node.start_byte() && node.end_byte() <= name.end_byte()
                })
                .then_some(ancestor);
        }
        current = ancestor.parent();
    }
    None
}

fn php_qualified_reference_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "namespace_name" | "qualified_name") {
            node = parent;
        } else {
            break;
        }
    }
    node
}

fn php_fqn_outcome(
    support: &dyn BoundedDefinitionLookup,
    fqn: Option<String>,
    raw: &str,
) -> DefinitionLookupOutcome {
    let Some(fqn) = fqn else {
        return no_definition(
            "no_indexed_definition",
            format!("`{raw}` did not resolve to a PHP definition name"),
        );
    };
    let candidates = php_fqn_candidates(support, &fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if php_crosses_unindexed_boundary(support, &fqn) {
        return boundary(format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial PHP workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed PHP definition was found"),
    )
}

fn php_member_outcome(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: Option<String>,
    member: &str,
) -> DefinitionLookupOutcome {
    let Some(owner) = owner else {
        return no_definition(
            "unsupported_php_receiver",
            format!("receiver for PHP member `{member}` is not resolved"),
        );
    };
    let fqn = format!("{owner}.{member}");
    let candidates = php_fqn_candidates(support, &fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let inherited = php_inherited_member_candidates(php, support, &owner, member);
    if !inherited.is_empty() {
        return candidates_outcome(inherited);
    }
    if php_crosses_unindexed_boundary(support, &owner) {
        return boundary(format!(
            "`{member}` appears to cross a PHP boundary at `{owner}` not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{fqn}` is not indexed as a PHP definition"),
    )
}

fn php_inherited_member_candidates(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    let mut level = php_direct_member_owner_fqns(php, support, owner_fqn);
    seen.insert(owner_fqn.to_string());
    while !level.is_empty() {
        let mut level_candidates = Vec::new();
        let mut next_level = Vec::new();
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            level_candidates.extend(php_fqn_candidates(support, &format!("{ancestor}.{member}")));
            next_level.extend(php_direct_member_owner_fqns(php, support, &ancestor));
        }
        sort_units(&mut level_candidates);
        level_candidates.dedup();
        if !level_candidates.is_empty() {
            return level_candidates;
        }
        level = next_level;
    }
    Vec::new()
}

fn php_direct_member_owner_fqns(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
) -> Vec<String> {
    php_fqn_candidates(support, owner_fqn)
        .into_iter()
        .next()
        .into_iter()
        .flat_map(|child| php.get_direct_ancestors(&child))
        .map(|ancestor| ancestor.fq_name())
        .filter(|ancestor| !php_fqn_candidates(support, ancestor).is_empty())
        .collect()
}

fn php_crosses_unindexed_boundary(support: &dyn BoundedDefinitionLookup, fqn: &str) -> bool {
    let Some((namespace, _)) = fqn.rsplit_once('.') else {
        return !php_workspace_exact_namespace_exists(support, "");
    };
    !php_workspace_exact_namespace_exists(support, namespace)
}

fn php_workspace_exact_namespace_exists(
    support: &dyn BoundedDefinitionLookup,
    namespace: &str,
) -> bool {
    support.package_exists_in_language(namespace, Language::Php)
}

fn php_static_scope_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    scope: Node<'_>,
    source: &str,
    ctx: &FileContext,
    class_ranges: &ClassRangeIndex,
) -> Option<String> {
    let text = php_node_text(scope, source);
    match text {
        "self" | "static" => class_ranges
            .enclosing(scope.start_byte())
            .map(str::to_string),
        "parent" => php_parent_fqn(php, support, class_ranges.enclosing(scope.start_byte())?),
        _ => resolve_php_type(text, ctx),
    }
}

fn php_parent_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    enclosing_fqn: &str,
) -> Option<String> {
    let child = php_fqn_candidates(support, enclosing_fqn)
        .into_iter()
        .next()?;
    php.direct_declared_class_parent(&child)
        .map(|parent| parent.fq_name())
}

fn php_fqn_candidates(support: &dyn BoundedDefinitionLookup, fqn: &str) -> Vec<CodeUnit> {
    support.fqn_in_language(fqn, Language::Php)
}

#[allow(clippy::too_many_arguments)]
fn php_instance_receiver_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    object: Node<'_>,
    source: &str,
    class_ranges: &ClassRangeIndex,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
) -> Option<String> {
    match object.kind() {
        "variable_name" => {
            let name = php_variable_identifier(object, source);
            if name == "this" {
                return class_ranges
                    .enclosing(object.start_byte())
                    .map(str::to_string);
            }
            first_precise(bindings, name)
        }
        // `(new Foo())->member` — the receiver is typed by the constructed class.
        "object_creation_expression" => php_object_creation_type(object)
            .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx)),
        "parenthesized_expression" => object.named_child(0).and_then(|inner| {
            php_instance_receiver_fqn(
                php,
                analyzer,
                support,
                inner,
                source,
                class_ranges,
                bindings,
                ctx,
            )
        }),
        "member_call_expression" | "nullsafe_member_call_expression" => {
            php_member_call_return_type_fqn(
                php,
                analyzer,
                support,
                object,
                source,
                class_ranges,
                bindings,
                ctx,
            )
        }
        "member_access_expression" | "nullsafe_member_access_expression" => {
            php_member_access_receiver_fqn(
                php,
                analyzer,
                support,
                object,
                source,
                class_ranges,
                bindings,
                ctx,
            )
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn php_member_call_return_type_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    call: Node<'_>,
    source: &str,
    class_ranges: &ClassRangeIndex,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
) -> Option<String> {
    let object = call.child_by_field_name("object")?;
    let name = call.child_by_field_name("name")?;
    let owner = php_instance_receiver_fqn(
        php,
        analyzer,
        support,
        object,
        source,
        class_ranges,
        bindings,
        ctx,
    )?;
    let member = php_node_text(name, source).trim_start_matches('$');
    if member.is_empty() {
        return None;
    }
    let mut candidates = php_fqn_candidates(support, &format!("{owner}.{member}"));
    if candidates.is_empty() {
        candidates = php_inherited_member_candidates(php, support, &owner, member);
    }
    candidates.retain(CodeUnit::is_function);
    sort_units(&mut candidates);
    candidates.dedup();
    let [callable] = candidates.as_slice() else {
        return None;
    };
    declared_callable_return_type_fq_name(php, analyzer, callable)
}

#[allow(clippy::too_many_arguments)]
fn php_member_access_receiver_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    access: Node<'_>,
    source: &str,
    class_ranges: &ClassRangeIndex,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
) -> Option<String> {
    let object = access.child_by_field_name("object")?;
    let name = access.child_by_field_name("name")?;
    let owner = php_instance_receiver_fqn(
        php,
        analyzer,
        support,
        object,
        source,
        class_ranges,
        bindings,
        ctx,
    )?;
    let member = php_node_text(name, source).trim_start_matches('$');
    let field = support
        .fqn(&format!("{owner}.{member}"))
        .into_iter()
        .find(|unit| unit.is_field())?;
    declared_field_type_fq_name(php, analyzer, &field)
}

#[allow(clippy::too_many_arguments)]
fn php_bindings_before(
    php: &PhpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
    class_ranges: &ClassRangeIndex,
    ctx: &FileContext,
    support: &dyn BoundedDefinitionLookup,
) -> LocalInferenceEngine<String> {
    let scope = php_enclosing_scope(root, byte).unwrap_or(root);
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= byte {
            continue;
        }
        if node != scope && php_is_local_scope(node) {
            continue;
        }
        php_seed_parameters(node, source, ctx, &mut bindings);
        if node.end_byte() <= byte {
            php_seed_assignment(
                php,
                file,
                node,
                source,
                class_ranges,
                ctx,
                support,
                &mut bindings,
            );
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            if child.start_byte() < byte {
                stack.push(child);
            }
        }
    }
    bindings
}

fn php_enclosing_scope<'tree>(root: Node<'tree>, byte: usize) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= byte && byte < node.end_byte() {
            if php_is_local_scope(node) {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    best
}

fn php_seed_parameters(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_parameter_types(node, source, bindings, |raw| resolve_php_type(raw, ctx));
}

#[allow(clippy::too_many_arguments)]
fn php_seed_assignment(
    php: &PhpAnalyzer,
    _file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    class_ranges: &ClassRangeIndex,
    ctx: &FileContext,
    support: &dyn BoundedDefinitionLookup,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some((left, right)) = assignment_parts(node) else {
        return;
    };
    if left.kind() != "variable_name" {
        return;
    }
    let name = php_variable_identifier(left, source);
    if name.is_empty() {
        return;
    }
    let resolved = php_assignment_receiver_fqn(php, support, right, source, class_ranges, ctx);
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn php_assignment_receiver_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    right: Node<'_>,
    source: &str,
    class_ranges: &ClassRangeIndex,
    ctx: &FileContext,
) -> Option<String> {
    match right.kind() {
        "object_creation_expression" => php_object_creation_type(right)
            .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx)),
        "function_call_expression" => {
            let function = right.child_by_field_name("function")?;
            let raw = php_qualified_candidate_text(function, source);
            let callable_fqn = resolve_php_function(&raw, ctx)?;
            php_declared_callable_return_type_fqn(php, support, &callable_fqn)
        }
        "scoped_call_expression" => {
            let (scope, name) = php_static_member_parts(right)?;
            let owner = php_static_scope_fqn(php, support, scope, source, ctx, class_ranges)?;
            let method = php_node_text(name, source);
            if method.is_empty() {
                return None;
            }
            php_declared_callable_return_type_fqn(php, support, &format!("{owner}.{method}"))
        }
        "parenthesized_expression" => right.named_child(0).and_then(|inner| {
            php_assignment_receiver_fqn(php, support, inner, source, class_ranges, ctx)
        }),
        _ => None,
    }
}

fn php_declared_callable_return_type_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    callable_fqn: &str,
) -> Option<String> {
    if let Some(return_type) = php.usage_facts_index().callable_return_type(callable_fqn) {
        return Some(return_type.to_string());
    }
    let mut definitions = support
        .fqn(callable_fqn)
        .into_iter()
        .filter(|unit| unit.is_function());
    let callable = definitions.next()?;
    if definitions.next().is_some() {
        return None;
    }
    declared_callable_return_type_fq_name(php, php, &callable)
}

fn php_is_in_object_creation(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "object_creation_expression")
}

fn php_is_bare_constant_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    !matches!(
        parent.kind(),
        "function_call_expression"
            | "member_access_expression"
            | "nullsafe_member_access_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
            | "class_constant_access_expression"
            | "named_type"
            | "object_creation_expression"
            | "function_definition"
            | "method_declaration"
            | "const_element"
            | "namespace_use_clause"
            | "namespace_definition"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "qualified_name"
            | "base_clause"
            | "class_interface_clause"
    )
}

fn php_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "trait_declaration"
                | "function_definition"
                | "method_declaration"
                | "enum_declaration"
                | "enum_case"
                | "const_element"
                | "property_element"
                | "simple_parameter"
                | "property_promotion_parameter"
        )
}

fn php_is_variable_reference(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "variable_name" {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn php_is_non_reference_context(node: Node<'_>) -> bool {
    let mut parent = Some(node);
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "namespace_use_declaration"
                | "namespace_use_clause"
                | "comment"
                | "string"
                | "encapsed_string"
                | "string_value"
                | "heredoc"
                | "nowdoc"
        ) {
            return true;
        }
        parent = current.parent();
    }
    false
}
