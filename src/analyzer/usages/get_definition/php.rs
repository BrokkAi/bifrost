use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::ForwardQueryProvider;
use crate::analyzer::TypeHierarchyProvider;
use crate::analyzer::php::{
    php_file_context_from_tree_at, resolve_php_constant_node, resolve_php_function_node,
    resolve_php_type_node,
};
use crate::analyzer::usages::php_graph::syntax::{
    assignment_parts, declared_callable_return_type_fq_name, declared_field_type_fq_name,
    is_local_scope as php_is_local_scope, object_creation_type as php_object_creation_type,
    seed_parameter_types, static_member_parts as php_static_member_parts,
    variable_identifier as php_variable_identifier,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;

const PHP_BOUNDED_AUXILIARY_MAX_SOURCE_BYTES: usize =
    crate::analyzer::usages::receiver_analysis::DEFAULT_RECEIVER_MAX_SCOPE_NODES * 256;

pub(crate) struct PhpDefinitionProvider<'a> {
    php: &'a PhpAnalyzer,
    session: &'a ResolutionSession,
}

impl<'a> PhpDefinitionProvider<'a> {
    pub(crate) fn new(php: &'a PhpAnalyzer, session: &'a ResolutionSession) -> Self {
        Self { php, session }
    }
}

impl BoundedDefinitionLookup for PhpDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.fqn_in_language(fqn, Language::Php)
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        if language != Language::Php {
            return Vec::new();
        }
        let mut units = self.session.query_limited_rows(|limit| {
            self.php
                .declaration_candidates_by_fqn_limited(fqn, limit, || {
                    self.session.observe_cancellation()
                })
        });
        units.retain(|unit| {
            unit.fq_name() == fqn && language_for_file(unit.source()) == Language::Php
        });
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.php
                .declaration_candidates_by_identifier_limited(ident, limit, || {
                    self.session.observe_cancellation()
                })
        });
        units.retain(|unit| unit.source() == file && unit.identifier() == ident);
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut children = Vec::new();
        for owner in self.fqn(fqn) {
            children.extend(
                self.session
                    .query_limited_rows(|limit| self.php.direct_children_limited(&owner, limit)),
            );
        }
        sort_units(&mut children);
        children.dedup();
        children
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !self.fqn(fqn).is_empty()
    }

    fn package_exists(&self, package: &str) -> bool {
        self.package_exists_in_language(package, Language::Php)
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        language == Language::Php
            && self
                .session
                .query(|| self.php.forward_package_exists(package))
                .unwrap_or(false)
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.session
            .query(|| self.php.forward_fqn_prefix_exists(prefix))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PhpTypeLookupResolution {
    pub(crate) fqn: String,
    pub(crate) target_kind: TypeLookupTargetKind,
}

#[derive(Debug, Clone, Default)]
struct PhpEnclosingType {
    fqn: Option<String>,
    direct_parent_fqn: Option<String>,
}

impl PhpEnclosingType {
    fn from_index(class_ranges: &ClassRangeIndex, byte: usize) -> Self {
        Self {
            fqn: class_ranges.enclosing(byte).map(str::to_string),
            direct_parent_fqn: None,
        }
    }

    fn fqn(&self) -> Option<&str> {
        self.fqn.as_deref()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn php_type_lookup_resolution_bounded(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    session: &ResolutionSession,
) -> Option<PhpTypeLookupResolution> {
    let php = resolve_analyzer::<PhpAnalyzer>(analyzer)?;
    let root = tree?.root_node();
    let node = php_smallest_named_node_covering(
        session,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let ctx = php_file_context_from_tree_at(root, source, site.range.start_byte, || {
        session.scope_step()
    })?;
    let enclosing = php_enclosing_type_from_tree(support, node, source, &ctx, session)?;
    let bindings = php_bindings_before(
        php,
        file,
        source,
        root,
        site.range.start_byte,
        &enclosing,
        &ctx,
        support,
        Some(session),
    );
    let target_kind = if php_is_static_receiver(node) {
        TypeLookupTargetKind::TypeReference
    } else {
        TypeLookupTargetKind::ValueExpression
    };
    let fqn = if target_kind == TypeLookupTargetKind::TypeReference {
        php_static_scope_fqn(php, support, node, source, &ctx, &enclosing, Some(session))
    } else {
        php_expression_type_fqn(
            php,
            analyzer,
            support,
            node,
            source,
            &enclosing,
            &bindings,
            &ctx,
            Some(session),
        )
    }?;
    Some(PhpTypeLookupResolution { fqn, target_kind })
}

fn php_is_static_receiver(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "scoped_call_expression"
                | "scoped_property_access_expression"
                | "class_constant_access_expression"
        ) && parent
            .child_by_field_name("scope")
            .is_some_and(|scope| scope.id() == node.id())
    })
}

#[allow(clippy::too_many_arguments)]
fn php_expression_type_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    node: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if let Some(session) = session {
        return php_expression_type_fqn_bounded(
            php, support, node, source, enclosing, bindings, ctx, session,
        );
    }
    match node.kind() {
        "variable_name" => {
            let name = php_variable_identifier(node, source);
            if name == "this" {
                enclosing.fqn.clone()
            } else {
                first_precise(bindings, name)
            }
        }
        "object_creation_expression" => php_object_creation_type_with_session(node, session)
            .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx)),
        "parenthesized_expression" => node.named_child(0).and_then(|inner| {
            php_expression_type_fqn(
                php, analyzer, support, inner, source, enclosing, bindings, ctx, session,
            )
        }),
        "function_call_expression" | "scoped_call_expression" => {
            php_assignment_receiver_fqn(php, support, node, source, enclosing, ctx, session)
        }
        "member_call_expression" | "nullsafe_member_call_expression" => {
            php_member_call_return_type_fqn(
                php, analyzer, support, node, source, enclosing, bindings, ctx, session,
            )
        }
        "member_access_expression" | "nullsafe_member_access_expression" => {
            php_member_access_receiver_fqn(
                php, analyzer, support, node, source, enclosing, bindings, ctx, session,
            )
        }
        "name" | "qualified_name" | "relative_scope" if php_is_static_receiver(node) => {
            php_static_scope_fqn(php, support, node, source, ctx, enclosing, session)
        }
        _ => None,
    }
}

pub(super) fn resolve_php(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    resolve_php_with_session(analyzer, support, file, source, tree, site, None)
}

pub(crate) fn resolve_php_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "php_analyzer_unavailable",
            "PHP analyzer is unavailable",
        ));
    };
    let support = PhpDefinitionProvider::new(php, &session);
    let outcome =
        resolve_php_with_session(analyzer, &support, file, source, tree, site, Some(&session));
    session.finish(outcome)
}

#[allow(clippy::too_many_arguments)]
fn resolve_php_with_session(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    session: Option<&ResolutionSession>,
) -> DefinitionLookupOutcome {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return no_definition("php_analyzer_unavailable", "PHP analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("php_parse_failed", "PHP source could not be parsed");
    };
    let root = tree.root_node();
    let node = match session {
        Some(session) => php_smallest_named_node_covering(
            session,
            root,
            site.focus_start_byte,
            site.focus_end_byte,
        ),
        None => smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte),
    };
    let Some(node) = node else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed PHP definition",
                site.text
            ),
        );
    };
    let (ctx, enclosing) = match session {
        Some(session) => {
            let Some(ctx) =
                php_file_context_from_tree_at(root, source, site.range.start_byte, || {
                    session.scope_step()
                })
            else {
                return no_definition(
                    "php_resolution_interrupted",
                    "PHP namespace/import lookup was interrupted",
                );
            };
            let Some(enclosing) =
                php_enclosing_type_from_tree(support, node, source, &ctx, session)
            else {
                return no_definition(
                    "php_resolution_interrupted",
                    "PHP enclosing-type lookup was interrupted",
                );
            };
            (ctx, enclosing)
        }
        None => {
            let ctx = php.file_context_from_source(file, source);
            let class_ranges = ClassRangeIndex::build(analyzer, file);
            let enclosing = PhpEnclosingType::from_index(&class_ranges, site.range.start_byte);
            (ctx, enclosing)
        }
    };
    if php_is_declaration_name(node, session)
        && let Some(outcome) = php_interface_method_declaration_outcome(
            php, support, source, node, &enclosing, session,
        )
    {
        return outcome;
    }
    if php_is_non_reference_context(node, session) || php_is_declaration_name(node, session) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a PHP reference site", site.text),
        );
    }
    if php_is_variable_reference(node, session) && !php_is_static_property_name(node, session) {
        return no_definition(
            "local_variable_reference",
            format!(
                "`{}` is a PHP variable reference, not an indexed definition",
                site.text
            ),
        );
    }

    match php_reference_node(node, session) {
        Some(PhpReferenceNode::Type(type_node)) => {
            let raw = php_qualified_candidate_text_with_session(type_node, source, session);
            let relative_class_keyword = ["self", "static", "parent"]
                .into_iter()
                .any(|keyword| raw.eq_ignore_ascii_case(keyword));
            let owner = if type_node.kind() == "relative_scope" || relative_class_keyword {
                php_static_scope_fqn(php, support, type_node, source, &ctx, &enclosing, session)
            } else if let Some(session) = session {
                resolve_php_type_node(type_node, source, &ctx, || session.scope_step())
            } else {
                resolve_php_type(&raw, &ctx)
            };
            php_fqn_outcome(support, owner, &raw)
        }
        Some(PhpReferenceNode::Function(name_node)) => {
            let raw = php_qualified_candidate_text_with_session(name_node, source, session);
            let fqn = if let Some(session) = session {
                resolve_php_function_node(name_node, source, &ctx, || session.scope_step())
            } else {
                resolve_php_function(&raw, &ctx)
            };
            php_fqn_outcome(support, fqn, &raw)
        }
        Some(PhpReferenceNode::Constant(name_node)) => {
            let raw = php_qualified_candidate_text_with_session(name_node, source, session);
            let fqn = if let Some(session) = session {
                resolve_php_constant_node(name_node, source, &ctx, || session.scope_step())
            } else {
                resolve_php_constant(&raw, &ctx)
            };
            php_fqn_outcome(support, fqn, &raw)
        }
        Some(PhpReferenceNode::StaticMember { scope, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let owner =
                php_static_scope_fqn(php, support, scope, source, &ctx, &enclosing, session);
            php_member_outcome(php, support, owner, member, session)
        }
        Some(PhpReferenceNode::InstanceMember { object, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let bindings = php_bindings_before(
                php,
                file,
                source,
                root,
                site.range.start_byte,
                &enclosing,
                &ctx,
                support,
                session,
            );
            let owner = php_instance_receiver_fqn(
                php, analyzer, support, object, source, &enclosing, &bindings, &ctx, session,
            );
            php_member_outcome(php, support, owner, member, session)
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

fn php_smallest_named_node_covering<'tree>(
    session: &ResolutionSession,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if !session.scope_step() || node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    loop {
        let mut cursor = node.walk();
        let mut containing = None;
        for child in node.named_children(&mut cursor) {
            if !session.scope_step() {
                return None;
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing = Some(child);
                break;
            }
        }
        match containing {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

fn php_enclosing_type_from_tree(
    support: &dyn BoundedDefinitionLookup,
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    session: &ResolutionSession,
) -> Option<PhpEnclosingType> {
    let mut type_nodes = Vec::new();
    let mut current = Some(node);
    while let Some(candidate) = current {
        if !session.scope_step() {
            return None;
        }
        if matches!(
            candidate.kind(),
            "class_declaration"
                | "interface_declaration"
                | "trait_declaration"
                | "enum_declaration"
        ) {
            type_nodes.push(candidate);
        }
        current = candidate.parent();
    }
    if type_nodes.is_empty() {
        return Some(PhpEnclosingType::default());
    }

    type_nodes.reverse();
    let mut names = Vec::with_capacity(type_nodes.len());
    for declaration in &type_nodes {
        if !session.scope_step() {
            return None;
        }
        let name = declaration.child_by_field_name("name")?;
        if !session.scope_step() {
            return None;
        }
        let name = php_node_text(name, source).trim();
        if name.is_empty() {
            return Some(PhpEnclosingType::default());
        }
        names.push(name.to_string());
    }
    let short_name = names.join("$");
    let fqn = if ctx.namespace.is_empty() {
        short_name
    } else {
        format!("{}.{}", ctx.namespace, short_name)
    };
    let candidates = php_fqn_candidates(support, &fqn);
    let [candidate] = candidates.as_slice() else {
        return Some(PhpEnclosingType::default());
    };
    if !candidate.is_class() {
        return Some(PhpEnclosingType::default());
    }

    let innermost = *type_nodes.last()?;
    let mut direct_parent_fqn = None;
    let mut cursor = innermost.walk();
    for child in innermost.named_children(&mut cursor) {
        if !session.scope_step() {
            return None;
        }
        if child.kind() != "base_clause" {
            continue;
        }
        let mut base_cursor = child.walk();
        for base in child.named_children(&mut base_cursor) {
            if !session.scope_step() {
                return None;
            }
            if matches!(
                base.kind(),
                "name" | "namespace_name" | "qualified_name" | "fully_qualified_name"
            ) {
                direct_parent_fqn =
                    resolve_php_type_node(base, source, ctx, || session.scope_step());
                break;
            }
        }
        break;
    }
    Some(PhpEnclosingType {
        fqn: Some(fqn),
        direct_parent_fqn,
    })
}

fn php_interface_method_declaration_outcome(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    source: &str,
    node: Node<'_>,
    enclosing: &PhpEnclosingType,
    session: Option<&ResolutionSession>,
) -> Option<DefinitionLookupOutcome> {
    let method = php_method_declaration_name(node, source)?;
    let owner_fqn = enclosing.fqn()?;
    let owner = php_fqn_candidates(support, owner_fqn).into_iter().next()?;
    let mut candidates = Vec::new();
    let mut stack = if let Some(session) = session {
        php_direct_ancestor_units_bounded(php, support, &owner, session)
    } else {
        php.get_direct_ancestors(&owner)
    };
    let mut seen = HashSet::default();
    while let Some(ancestor) = stack.pop() {
        if session.is_some_and(|session| !session.scope_step()) {
            return None;
        }
        let ancestor_fqn = ancestor.fq_name();
        if !seen.insert(ancestor_fqn.clone()) {
            continue;
        }
        let is_interface = if let Some(session) = session {
            php_declaration_kind_bounded(php, &ancestor, session)
                .is_some_and(|kind| kind == "interface_declaration")
        } else {
            php.is_interface(&ancestor)
        };
        if is_interface {
            candidates.extend(php_fqn_candidates(
                support,
                &format!("{ancestor_fqn}.{method}"),
            ));
        }
        stack.extend(if let Some(session) = session {
            php_direct_ancestor_units_bounded(php, support, &ancestor, session)
        } else {
            php.get_direct_ancestors(&ancestor)
        });
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

fn php_reference_node<'tree>(
    node: Node<'tree>,
    session: Option<&ResolutionSession>,
) -> Option<PhpReferenceNode<'tree>> {
    if session.is_some_and(|session| !session.scope_step()) {
        return None;
    }
    let node = php_qualified_reference_node(node, session)?;
    if let Some(access) = php_static_property_access_for_name(node, session) {
        let (scope, name) = php_static_member_parts(access)?;
        return Some(PhpReferenceNode::StaticMember { scope, name });
    }
    match node.kind() {
        "object_creation_expression" => {
            php_object_creation_type_with_session(node, session).map(PhpReferenceNode::Type)
        }
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
        "name" | "qualified_name" | "relative_scope" => {
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
            php_reference_node(parent, session)
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

fn php_object_creation_type_with_session<'tree>(
    node: Node<'tree>,
    session: Option<&ResolutionSession>,
) -> Option<Node<'tree>> {
    if session.is_none() {
        return php_object_creation_type(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if session.is_some_and(|session| !session.scope_step()) {
            return None;
        }
        if matches!(child.kind(), "name" | "qualified_name" | "relative_scope") {
            return Some(child);
        }
    }
    None
}

fn php_static_member_name(node: Node<'_>) -> Option<Node<'_>> {
    php_static_member_parts(node).map(|(_, name)| name)
}

fn php_is_static_property_name(node: Node<'_>, session: Option<&ResolutionSession>) -> bool {
    php_static_property_access_for_name(node, session).is_some()
}

fn php_static_property_access_for_name<'tree>(
    node: Node<'tree>,
    session: Option<&ResolutionSession>,
) -> Option<Node<'tree>> {
    let mut current = Some(node);
    while let Some(ancestor) = current {
        if session.is_some_and(|session| !session.scope_step()) {
            return None;
        }
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

fn php_qualified_reference_node<'tree>(
    mut node: Node<'tree>,
    session: Option<&ResolutionSession>,
) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if session.is_some_and(|session| !session.scope_step()) {
            return None;
        }
        if matches!(parent.kind(), "namespace_name" | "qualified_name") {
            node = parent;
        } else {
            break;
        }
    }
    Some(node)
}

fn php_qualified_candidate_text_with_session(
    node: Node<'_>,
    source: &str,
    session: Option<&ResolutionSession>,
) -> String {
    if session.is_none() {
        return php_qualified_candidate_text(node, source);
    }
    let mut candidate = node;
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        if session.is_some_and(|session| !session.scope_step()) {
            return String::new();
        }
        if matches!(ancestor.kind(), "namespace_name" | "qualified_name") {
            candidate = ancestor;
            parent = ancestor.parent();
        } else {
            break;
        }
    }
    php_node_text(candidate, source).trim().to_string()
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
    session: Option<&ResolutionSession>,
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
    let inherited = php_inherited_member_candidates(php, support, &owner, member, session);
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
    session: Option<&ResolutionSession>,
) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    let mut level = php_direct_member_owner_fqns(php, support, owner_fqn, session);
    seen.insert(owner_fqn.to_string());
    while !level.is_empty() {
        let mut level_candidates = Vec::new();
        let mut next_level = Vec::new();
        for ancestor in level {
            if session.is_some_and(|session| !session.scope_step()) {
                return Vec::new();
            }
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            level_candidates.extend(php_fqn_candidates(support, &format!("{ancestor}.{member}")));
            next_level.extend(php_direct_member_owner_fqns(
                php, support, &ancestor, session,
            ));
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
    session: Option<&ResolutionSession>,
) -> Vec<String> {
    if session.is_some_and(|session| !session.summary_step()) {
        return Vec::new();
    }
    let Some(child) = php_fqn_candidates(support, owner_fqn).into_iter().next() else {
        return Vec::new();
    };
    let ancestors = if let Some(session) = session {
        php_direct_ancestor_units_bounded(php, support, &child, session)
    } else {
        php.get_direct_ancestors(&child)
    };
    ancestors
        .into_iter()
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
    enclosing: &PhpEnclosingType,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if session.is_some_and(|session| !session.scope_step()) {
        return None;
    }
    let text = php_node_text(scope, source);
    if text.eq_ignore_ascii_case("self") || text.eq_ignore_ascii_case("static") {
        enclosing.fqn.clone()
    } else if text.eq_ignore_ascii_case("parent") {
        enclosing
            .direct_parent_fqn
            .clone()
            .or_else(|| php_parent_fqn(php, support, enclosing.fqn()?, session))
    } else if let Some(session) = session {
        resolve_php_type_node(scope, source, ctx, || session.scope_step())
    } else {
        resolve_php_type(text, ctx)
    }
}

fn php_parent_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    enclosing_fqn: &str,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    let child = php_fqn_candidates(support, enclosing_fqn)
        .into_iter()
        .next()?;
    if let Some(session) = session {
        php_direct_class_parent_fqn_bounded(php, support, &child, session)
    } else {
        php.direct_declared_class_parent(&child)
            .map(|parent| parent.fq_name())
    }
}

fn php_direct_ancestor_fqns_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    session: &ResolutionSession,
) -> Vec<String> {
    if !session.summary_step() {
        return Vec::new();
    }
    let Some((prepared, range)) = php_prepared_declaration_bounded(php, owner, session) else {
        return Vec::new();
    };
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let Some(declaration) = php_declaration_node_bounded(root, source, owner, &range, session)
    else {
        return Vec::new();
    };
    let Some(ctx) = php_file_context_from_tree_at(root, source, declaration.start_byte(), || {
        session.scope_step()
    }) else {
        return Vec::new();
    };
    let Some(type_nodes) = php_direct_supertype_nodes_bounded(declaration, session) else {
        return Vec::new();
    };
    let mut ancestors = Vec::new();
    for type_node in type_nodes {
        if !session.scope_step() {
            return Vec::new();
        }
        let Some(fqn) = resolve_php_type_node(type_node, source, &ctx, || session.scope_step())
        else {
            continue;
        };
        if php_fqn_candidates(support, &fqn)
            .iter()
            .any(CodeUnit::is_class)
        {
            ancestors.push(fqn);
        }
    }
    ancestors.sort();
    ancestors.dedup();
    ancestors
}

fn php_direct_class_parent_fqn_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    session: &ResolutionSession,
) -> Option<String> {
    if !session.summary_step() {
        return None;
    }
    let (prepared, range) = php_prepared_declaration_bounded(php, owner, session)?;
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let declaration = php_declaration_node_bounded(root, source, owner, &range, session)?;
    let ctx = php_file_context_from_tree_at(root, source, declaration.start_byte(), || {
        session.scope_step()
    })?;
    let mut cursor = declaration.walk();
    for clause in declaration.named_children(&mut cursor) {
        if !session.scope_step() {
            return None;
        }
        if clause.kind() != "base_clause" {
            continue;
        }
        let mut bases = clause.walk();
        for base in clause.named_children(&mut bases) {
            if !session.scope_step() {
                return None;
            }
            if !matches!(
                base.kind(),
                "name" | "qualified_name" | "namespace_name" | "fully_qualified_name"
            ) {
                continue;
            }
            let fqn = resolve_php_type_node(base, source, &ctx, || session.scope_step())?;
            return php_fqn_candidates(support, &fqn)
                .iter()
                .any(CodeUnit::is_class)
                .then_some(fqn);
        }
        return None;
    }
    None
}

fn php_direct_ancestor_units_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    let mut ancestors = Vec::new();
    for fqn in php_direct_ancestor_fqns_bounded(php, support, owner, session) {
        if !session.scope_step() {
            return Vec::new();
        }
        ancestors.extend(
            php_fqn_candidates(support, &fqn)
                .into_iter()
                .filter(CodeUnit::is_class),
        );
    }
    sort_units(&mut ancestors);
    ancestors.dedup();
    ancestors
}

fn php_prepared_declaration_bounded(
    php: &PhpAnalyzer,
    owner: &CodeUnit,
    session: &ResolutionSession,
) -> Option<(
    Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>,
    Range,
)> {
    let ranges = session.query_limited_rows(|limit| php.ranges_limited(owner, limit));
    let [range] = ranges.as_slice() else {
        return None;
    };
    let prepared = php_prepared_syntax_bounded(php, owner.source(), session)?;
    Some((prepared, *range))
}

fn php_declaration_node_bounded<'tree>(
    root: Node<'tree>,
    source: &str,
    owner: &CodeUnit,
    range: &Range,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !session.scope_step() {
            return None;
        }
        if node.end_byte() < range.start_byte || node.start_byte() > range.end_byte {
            continue;
        }
        if node.end_byte() == range.end_byte
            && node.start_byte() >= range.start_byte
            && php_declaration_node_matches_owner(node, source, owner, session)?
        {
            return Some(node);
        }
        for index in (0..node.named_child_count()).rev() {
            if !session.scope_step() {
                return None;
            }
            if let Some(child) = node.named_child(index)
                && child.end_byte() >= range.start_byte
                && child.start_byte() <= range.end_byte
            {
                stack.push(child);
            }
        }
    }
    None
}

fn php_declaration_node_matches_owner(
    node: Node<'_>,
    source: &str,
    owner: &CodeUnit,
    session: &ResolutionSession,
) -> Option<bool> {
    let expected = owner.identifier();
    if owner.is_function() {
        if !matches!(node.kind(), "function_definition" | "method_declaration") {
            return Some(false);
        }
        let name = node.child_by_field_name("name")?;
        if !session.scope_step() {
            return None;
        }
        return Some(php_node_text(name, source) == expected);
    }
    if owner.is_class() {
        if !matches!(
            node.kind(),
            "class_declaration"
                | "interface_declaration"
                | "trait_declaration"
                | "enum_declaration"
        ) {
            return Some(false);
        }
        let name = node.child_by_field_name("name")?;
        if !session.scope_step() {
            return None;
        }
        return Some(php_node_text(name, source) == expected);
    }
    if !owner.is_field() {
        return Some(false);
    }
    match node.kind() {
        "property_promotion_parameter" => {
            let name = node.child_by_field_name("name")?;
            if !session.scope_step() {
                return None;
            }
            Some(php_variable_identifier(name, source) == expected)
        }
        "property_declaration" => {
            let mut cursor = node.walk();
            for element in node.named_children(&mut cursor) {
                if !session.scope_step() {
                    return None;
                }
                if element.kind() != "property_element" {
                    continue;
                }
                let Some(name) = element.child_by_field_name("name") else {
                    continue;
                };
                if !session.scope_step() {
                    return None;
                }
                if php_variable_identifier(name, source) == expected {
                    return Some(true);
                }
            }
            Some(false)
        }
        _ => Some(false),
    }
}

fn php_direct_supertype_nodes_bounded<'tree>(
    declaration: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Vec<Node<'tree>>> {
    let mut type_nodes = Vec::new();
    let mut body = None;
    let mut cursor = declaration.walk();
    for child in declaration.named_children(&mut cursor) {
        if !session.scope_step() {
            return None;
        }
        if matches!(child.kind(), "base_clause" | "class_interface_clause") {
            let mut types = child.walk();
            for type_node in child.named_children(&mut types) {
                if !session.scope_step() {
                    return None;
                }
                if matches!(
                    type_node.kind(),
                    "name" | "qualified_name" | "namespace_name" | "fully_qualified_name"
                ) {
                    type_nodes.push(type_node);
                }
            }
        } else if child.kind() == "declaration_list" {
            body = Some(child);
        }
    }
    if declaration.kind() != "class_declaration" {
        return Some(type_nodes);
    }
    let Some(body) = body else {
        return Some(type_nodes);
    };
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if !session.scope_step() {
            return None;
        }
        if child.kind() != "use_declaration" {
            continue;
        }
        let mut traits = child.walk();
        for type_node in child.named_children(&mut traits) {
            if !session.scope_step() {
                return None;
            }
            if matches!(
                type_node.kind(),
                "name" | "qualified_name" | "namespace_name" | "fully_qualified_name"
            ) {
                type_nodes.push(type_node);
            }
        }
    }
    Some(type_nodes)
}

fn php_declaration_kind_bounded(
    php: &PhpAnalyzer,
    owner: &CodeUnit,
    session: &ResolutionSession,
) -> Option<&'static str> {
    let ranges = session.query_limited_rows(|limit| php.ranges_limited(owner, limit));
    let start = ranges.iter().map(|range| range.start_byte).min()?;
    let end = ranges.iter().map(|range| range.end_byte).max()?;
    let prepared = php_prepared_syntax_bounded(php, owner.source(), session)?;
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        if !session.scope_step() {
            return None;
        }
        if matches!(
            node.kind(),
            "class_declaration" | "interface_declaration" | "trait_declaration"
        ) && node.start_byte() >= start
            && node.end_byte() <= end
        {
            return Some(node.kind());
        }
        for index in (0..node.named_child_count()).rev() {
            if !session.scope_step() {
                return None;
            }
            if let Some(child) = node.named_child(index)
                && child.end_byte() >= start
                && child.start_byte() <= end
            {
                stack.push(child);
            }
        }
    }
    None
}

fn php_prepared_syntax_bounded(
    php: &PhpAnalyzer,
    file: &ProjectFile,
    session: &ResolutionSession,
) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
    use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome;

    if !session.scope_step() {
        return None;
    }
    match php.prepared_syntax_limited_cancellable(
        file,
        PHP_BOUNDED_AUXILIARY_MAX_SOURCE_BYTES,
        session.cancellation(),
    ) {
        PreparedSyntaxLimitedOutcome::Available(prepared) => {
            session.observe_cancellation().then_some(prepared)
        }
        PreparedSyntaxLimitedOutcome::Exceeded(_) => {
            session.mark_scope_incomplete();
            None
        }
        PreparedSyntaxLimitedOutcome::Cancelled => {
            session.observe_cancellation();
            None
        }
        PreparedSyntaxLimitedOutcome::Unavailable => None,
    }
}

fn php_fqn_candidates(support: &dyn BoundedDefinitionLookup, fqn: &str) -> Vec<CodeUnit> {
    support.fqn_in_language(fqn, Language::Php)
}

#[derive(Clone, Copy)]
enum PhpExpressionTypeFrame<'tree> {
    Evaluate(Node<'tree>),
    FinishMemberCall(Node<'tree>),
    FinishMemberAccess(Node<'tree>),
}

#[allow(clippy::too_many_arguments)]
fn php_expression_type_fqn_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    node: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: &ResolutionSession,
) -> Option<String> {
    let mut frames = vec![PhpExpressionTypeFrame::Evaluate(node)];
    let mut values = Vec::new();
    while let Some(frame) = frames.pop() {
        if !session.scope_step() {
            return None;
        }
        match frame {
            PhpExpressionTypeFrame::Evaluate(expression) => match expression.kind() {
                "variable_name" => {
                    let name = php_variable_identifier(expression, source);
                    let value = if name == "this" {
                        enclosing.fqn.clone()
                    } else {
                        first_precise(bindings, name)
                    }?;
                    values.push(value);
                }
                "object_creation_expression" => {
                    let type_node =
                        php_object_creation_type_with_session(expression, Some(session))?;
                    values.push(php_bounded_type_reference_fqn(
                        php, support, type_node, source, ctx, enclosing, session,
                    )?);
                }
                "parenthesized_expression" => {
                    let inner = expression.named_child(0)?;
                    frames.push(PhpExpressionTypeFrame::Evaluate(inner));
                }
                "function_call_expression" => {
                    let function = expression.child_by_field_name("function")?;
                    let callable_fqn =
                        resolve_php_function_node(function, source, ctx, || session.scope_step())?;
                    values.push(php_declared_callable_return_type_fqn(
                        php,
                        support,
                        &callable_fqn,
                        Some(session),
                    )?);
                }
                "scoped_call_expression" => {
                    let (scope, name) = php_static_member_parts(expression)?;
                    let owner = php_static_scope_fqn(
                        php,
                        support,
                        scope,
                        source,
                        ctx,
                        enclosing,
                        Some(session),
                    )?;
                    let member = php_literal_member_name(name, source, session)?;
                    values.push(php_declared_callable_return_type_fqn(
                        php,
                        support,
                        &format!("{owner}.{member}"),
                        Some(session),
                    )?);
                }
                "member_call_expression" | "nullsafe_member_call_expression" => {
                    let object = expression.child_by_field_name("object")?;
                    frames.push(PhpExpressionTypeFrame::FinishMemberCall(expression));
                    frames.push(PhpExpressionTypeFrame::Evaluate(object));
                }
                "member_access_expression" | "nullsafe_member_access_expression" => {
                    let object = expression.child_by_field_name("object")?;
                    frames.push(PhpExpressionTypeFrame::FinishMemberAccess(expression));
                    frames.push(PhpExpressionTypeFrame::Evaluate(object));
                }
                "name" | "qualified_name" | "relative_scope"
                    if php_is_static_receiver(expression) =>
                {
                    values.push(php_static_scope_fqn(
                        php,
                        support,
                        expression,
                        source,
                        ctx,
                        enclosing,
                        Some(session),
                    )?);
                }
                _ => return None,
            },
            PhpExpressionTypeFrame::FinishMemberCall(call) => {
                let owner = values.pop()?;
                let name = call.child_by_field_name("name")?;
                let member = php_literal_member_name(name, source, session)?;
                let callable = php_unique_member_candidate_bounded(
                    php,
                    support,
                    &owner,
                    member,
                    CodeUnit::is_function,
                    session,
                )?;
                values.push(php_declared_unit_type_fqn_bounded(
                    php, support, &callable, session,
                )?);
            }
            PhpExpressionTypeFrame::FinishMemberAccess(access) => {
                let owner = values.pop()?;
                let name = access.child_by_field_name("name")?;
                let member = php_literal_member_name(name, source, session)?;
                let field = php_unique_member_candidate_bounded(
                    php,
                    support,
                    &owner,
                    member,
                    CodeUnit::is_field,
                    session,
                )?;
                values.push(php_declared_unit_type_fqn_bounded(
                    php, support, &field, session,
                )?);
            }
        }
    }
    let [value] = values.as_slice() else {
        return None;
    };
    session.observe_cancellation().then(|| value.clone())
}

fn php_bounded_type_reference_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    type_node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    enclosing: &PhpEnclosingType,
    session: &ResolutionSession,
) -> Option<String> {
    if type_node.kind() == "relative_scope"
        || php_relative_type_keyword_bounded(type_node, source, session).is_some()
    {
        php_static_scope_fqn(
            php,
            support,
            type_node,
            source,
            ctx,
            enclosing,
            Some(session),
        )
    } else {
        resolve_php_type_node(type_node, source, ctx, || session.scope_step())
    }
}

fn php_literal_member_name<'a>(
    node: Node<'_>,
    source: &'a str,
    session: &ResolutionSession,
) -> Option<&'a str> {
    if !session.scope_step() || node.kind() != "name" {
        return None;
    }
    let member = php_node_text(node, source);
    (!member.is_empty()).then_some(member)
}

fn php_unique_member_candidate_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &str,
    member: &str,
    kind: fn(&CodeUnit) -> bool,
    session: &ResolutionSession,
) -> Option<CodeUnit> {
    let mut candidates = php_fqn_candidates(support, &format!("{owner}.{member}"));
    if candidates.is_empty() {
        candidates = php_inherited_member_candidates(php, support, owner, member, Some(session));
    }
    candidates.retain(kind);
    sort_units(&mut candidates);
    candidates.dedup();
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some(candidate.clone())
}

fn php_declared_unit_type_fqn_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    session: &ResolutionSession,
) -> Option<String> {
    if !unit.is_function() && !unit.is_field() {
        return None;
    }
    let (prepared, range) = php_prepared_declaration_bounded(php, unit, session)?;
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let declaration = php_declaration_node_bounded(root, source, unit, &range, session)?;
    let field_name = match declaration.kind() {
        "function_definition" | "method_declaration" => "return_type",
        "property_declaration" | "property_promotion_parameter" => "type",
        _ => return None,
    };
    let type_node = declaration.child_by_field_name(field_name)?;
    if !session.scope_step() {
        return None;
    }
    let ctx = php_file_context_from_tree_at(root, source, declaration.start_byte(), || {
        session.scope_step()
    })?;
    if let Some(keyword) = php_relative_type_keyword_bounded(type_node, source, session) {
        let enclosing = php_enclosing_type_from_tree(support, declaration, source, &ctx, session)?;
        return if keyword.eq_ignore_ascii_case("self") || keyword.eq_ignore_ascii_case("static") {
            enclosing.fqn().map(str::to_string)
        } else if keyword.eq_ignore_ascii_case("parent") {
            let parent_fqn = enclosing.direct_parent_fqn?;
            let candidates = php_fqn_candidates(support, &parent_fqn);
            let [parent] = candidates.as_slice() else {
                return None;
            };
            parent.is_class().then_some(parent_fqn)
        } else {
            None
        };
    }
    resolve_php_type_node(type_node, source, &ctx, || session.scope_step())
}

fn php_relative_type_keyword_bounded<'a>(
    mut node: Node<'_>,
    source: &'a str,
    session: &ResolutionSession,
) -> Option<&'a str> {
    if !session.scope_step() {
        return None;
    }
    if node.kind() == "named_type" {
        if node.named_child_count() != 1 || !session.scope_step() {
            return None;
        }
        node = node.named_child(0)?;
    }
    if node.kind() != "name" && node.kind() != "relative_scope" {
        return None;
    }
    if !session.scope_step() {
        return None;
    }
    let text = php_node_text(node, source);
    ["self", "static", "parent"]
        .into_iter()
        .find(|keyword| text.eq_ignore_ascii_case(keyword))
}

#[allow(clippy::too_many_arguments)]
fn php_instance_receiver_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    object: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if let Some(session) = session {
        return php_expression_type_fqn_bounded(
            php, support, object, source, enclosing, bindings, ctx, session,
        );
    }
    match object.kind() {
        "variable_name" => {
            let name = php_variable_identifier(object, source);
            if name == "this" {
                return enclosing.fqn.clone();
            }
            first_precise(bindings, name)
        }
        // `(new Foo())->member` — the receiver is typed by the constructed class.
        "object_creation_expression" => php_object_creation_type_with_session(object, session)
            .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx)),
        "parenthesized_expression" => object.named_child(0).and_then(|inner| {
            php_instance_receiver_fqn(
                php, analyzer, support, inner, source, enclosing, bindings, ctx, session,
            )
        }),
        "member_call_expression" | "nullsafe_member_call_expression" => {
            php_member_call_return_type_fqn(
                php, analyzer, support, object, source, enclosing, bindings, ctx, session,
            )
        }
        "member_access_expression" | "nullsafe_member_access_expression" => {
            php_member_access_receiver_fqn(
                php, analyzer, support, object, source, enclosing, bindings, ctx, session,
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
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    let object = call.child_by_field_name("object")?;
    let name = call.child_by_field_name("name")?;
    let owner = php_instance_receiver_fqn(
        php, analyzer, support, object, source, enclosing, bindings, ctx, session,
    )?;
    let member = php_node_text(name, source).trim_start_matches('$');
    if member.is_empty() {
        return None;
    }
    let mut candidates = php_fqn_candidates(support, &format!("{owner}.{member}"));
    if candidates.is_empty() {
        candidates = php_inherited_member_candidates(php, support, &owner, member, session);
    }
    candidates.retain(CodeUnit::is_function);
    sort_units(&mut candidates);
    candidates.dedup();
    let [callable] = candidates.as_slice() else {
        return None;
    };
    php_callable_return_type_fqn(php, analyzer, support, callable, session)
}

#[allow(clippy::too_many_arguments)]
fn php_member_access_receiver_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    access: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    let object = access.child_by_field_name("object")?;
    let name = access.child_by_field_name("name")?;
    let owner = php_instance_receiver_fqn(
        php, analyzer, support, object, source, enclosing, bindings, ctx, session,
    )?;
    let member = php_node_text(name, source).trim_start_matches('$');
    let field = support
        .fqn(&format!("{owner}.{member}"))
        .into_iter()
        .find(|unit| unit.is_field())?;
    php_field_type_fqn(php, analyzer, support, &field, session)
}

#[allow(clippy::too_many_arguments)]
fn php_bindings_before(
    php: &PhpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
    enclosing: &PhpEnclosingType,
    ctx: &FileContext,
    support: &dyn BoundedDefinitionLookup,
    session: Option<&ResolutionSession>,
) -> LocalInferenceEngine<String> {
    let scope = php_enclosing_scope(root, byte, session).unwrap_or(root);
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if session.is_some_and(|session| !session.scope_step()) {
            break;
        }
        if node.start_byte() >= byte {
            continue;
        }
        if node != scope && php_is_local_scope(node) {
            continue;
        }
        php_seed_parameters(node, source, ctx, session, &mut bindings);
        if node.end_byte() <= byte {
            php_seed_assignment(
                php,
                file,
                node,
                source,
                enclosing,
                ctx,
                support,
                session,
                &mut bindings,
            );
        }
        let mut cursor = node.walk();
        let mut children = Vec::new();
        for child in node.named_children(&mut cursor) {
            if session.is_some_and(|session| !session.scope_step()) {
                return bindings;
            }
            if child.start_byte() < byte {
                children.push(child);
            }
        }
        stack.extend(children.into_iter().rev());
    }
    bindings
}

fn php_enclosing_scope<'tree>(
    root: Node<'tree>,
    byte: usize,
    session: Option<&ResolutionSession>,
) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if session.is_some_and(|session| !session.scope_step()) {
            return None;
        }
        if node.start_byte() <= byte && byte < node.end_byte() {
            if php_is_local_scope(node) {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if session.is_some_and(|session| !session.scope_step()) {
                    return None;
                }
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
    session: Option<&ResolutionSession>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if session.is_none() {
        seed_parameter_types(node, source, bindings, |raw| resolve_php_type(raw, ctx));
        return;
    }
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if session.is_some_and(|session| !session.scope_step()) {
            return;
        }
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = php_variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        match child.child_by_field_name("type").and_then(|type_node| {
            resolve_php_type_node(type_node, source, ctx, || {
                session.is_some_and(ResolutionSession::scope_step)
            })
        }) {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => bindings.declare_shadow(name.to_string()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn php_seed_assignment(
    php: &PhpAnalyzer,
    _file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    ctx: &FileContext,
    support: &dyn BoundedDefinitionLookup,
    session: Option<&ResolutionSession>,
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
    let resolved = if let Some(session) = session {
        php_expression_type_fqn_bounded(
            php, support, right, source, enclosing, bindings, ctx, session,
        )
    } else {
        php_assignment_receiver_fqn(php, support, right, source, enclosing, ctx, None)
    };
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
    enclosing: &PhpEnclosingType,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if session.is_some() {
        return None;
    }
    match right.kind() {
        "object_creation_expression" => php_object_creation_type_with_session(right, session)
            .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx)),
        "function_call_expression" => {
            let function = right.child_by_field_name("function")?;
            let raw = php_qualified_candidate_text_with_session(function, source, session);
            let callable_fqn = resolve_php_function(&raw, ctx)?;
            php_declared_callable_return_type_fqn(php, support, &callable_fqn, session)
        }
        "scoped_call_expression" => {
            let (scope, name) = php_static_member_parts(right)?;
            let owner = php_static_scope_fqn(php, support, scope, source, ctx, enclosing, session)?;
            let method = php_node_text(name, source);
            if method.is_empty() {
                return None;
            }
            php_declared_callable_return_type_fqn(
                php,
                support,
                &format!("{owner}.{method}"),
                session,
            )
        }
        "parenthesized_expression" => right.named_child(0).and_then(|inner| {
            php_assignment_receiver_fqn(php, support, inner, source, enclosing, ctx, session)
        }),
        _ => None,
    }
}

fn php_declared_callable_return_type_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    callable_fqn: &str,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if let Some(session) = session {
        let mut definitions = support
            .fqn(callable_fqn)
            .into_iter()
            .filter(CodeUnit::is_function);
        let callable = definitions.next()?;
        if definitions.next().is_some() {
            return None;
        }
        return php_declared_unit_type_fqn_bounded(php, support, &callable, session);
    }
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

fn php_callable_return_type_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    callable: &CodeUnit,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if let Some(session) = session {
        return php_declared_unit_type_fqn_bounded(php, support, callable, session);
    }
    if let Some(return_type) = analyzer
        .usage_facts_index()
        .fact_for_declaration(callable)
        .and_then(|facts| facts.return_type_fqn.as_deref())
    {
        return Some(return_type.to_string());
    }
    session
        .is_none()
        .then(|| declared_callable_return_type_fq_name(php, analyzer, callable))
        .flatten()
}

fn php_field_type_fqn(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    field: &CodeUnit,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if let Some(session) = session {
        return php_declared_unit_type_fqn_bounded(php, support, field, session);
    }
    if let Some(field_type) = analyzer
        .usage_facts_index()
        .fact_for_declaration(field)
        .and_then(|facts| facts.return_type_fqn.as_deref())
    {
        return Some(field_type.to_string());
    }
    session
        .is_none()
        .then(|| declared_field_type_fq_name(php, analyzer, field))
        .flatten()
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

fn php_is_declaration_name(node: Node<'_>, session: Option<&ResolutionSession>) -> bool {
    if session.is_some_and(|session| !session.scope_step()) {
        return false;
    }
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

fn php_is_variable_reference(node: Node<'_>, session: Option<&ResolutionSession>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if session.is_some_and(|session| !session.scope_step()) {
            return false;
        }
        if candidate.kind() == "variable_name" {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn php_is_non_reference_context(node: Node<'_>, session: Option<&ResolutionSession>) -> bool {
    let mut parent = Some(node);
    while let Some(current) = parent {
        if session.is_some_and(|session| !session.scope_step()) {
            return false;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::analyzer::{Language, Range};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    fn php_site(
        source: &str,
        file: &ProjectFile,
        needle: &str,
        text: &str,
    ) -> ResolvedReferenceSite {
        let needle_start = source.find(needle).expect("reference marker");
        let within = needle.find(text).expect("focus within marker");
        let start_byte = needle_start + within;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: text.to_string(),
            range: Range {
                start_byte,
                end_byte: start_byte + text.len(),
                start_line: source[..start_byte]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count(),
                end_line: source[..start_byte]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count(),
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + text.len(),
        }
    }

    fn declared_php_type_outcome(
        fixture: &AnalyzerFixture,
        callable_fqn: &str,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> BoundedResolution<Option<String>> {
        let php =
            resolve_analyzer::<PhpAnalyzer>(fixture.analyzer.analyzer()).expect("PHP analyzer");
        let definitions = php.get_definitions(callable_fqn);
        let [callable] = definitions.as_slice() else {
            panic!("expected one definition for {callable_fqn}: {definitions:#?}");
        };
        let session = ResolutionSession::bounded(budget, cancellation);
        let support = PhpDefinitionProvider::new(php, &session);
        let resolved = php_declared_unit_type_fqn_bounded(php, &support, callable, &session);
        session.finish(resolved)
    }

    #[test]
    fn bounded_context_extracts_structured_group_type_function_and_const_aliases() {
        let source = r#"<?php
namespace App;
use Vendor\Package\Target as DirectTarget;
use function Vendor\Package\make as build;
use const Vendor\Package\READY as IS_READY;
use Vendor\Package\{
    Helper as GroupHelper,
    function render as group_render,
    const LIMIT as GROUP_LIMIT
};
new DirectTarget();
"#;
        let tree = parse_php_tree(source).expect("PHP tree");
        let byte = source.find("new DirectTarget").expect("reference");
        let ctx = php_file_context_from_tree_at(tree.root_node(), source, byte, || true)
            .expect("complete structured context");

        assert_eq!(ctx.namespace, "App");
        assert_eq!(
            ctx.aliases.type_aliases.get("DirectTarget"),
            Some(&"Vendor.Package.Target".to_string())
        );
        assert_eq!(
            ctx.aliases.type_aliases.get("GroupHelper"),
            Some(&"Vendor.Package.Helper".to_string())
        );
        assert_eq!(
            ctx.aliases.function_aliases.get("build"),
            Some(&"Vendor.Package.make".to_string())
        );
        assert_eq!(
            ctx.aliases.function_aliases.get("group_render"),
            Some(&"Vendor.Package.render".to_string())
        );
        assert_eq!(
            ctx.aliases.const_aliases.get("IS_READY"),
            Some(&"Vendor.Package.READY".to_string())
        );
        assert_eq!(
            ctx.aliases.const_aliases.get("GROUP_LIMIT"),
            Some(&"Vendor.Package.LIMIT".to_string())
        );
    }

    #[test]
    fn bounded_lookup_resolves_structured_direct_and_group_alias_kinds() {
        let library = r#"<?php
namespace Vendor\Package;
class Target {}
class Helper {}
function make(): void {}
function render(): void {}
const READY = true;
const LIMIT = 10;
"#;
        let consumer = r#"<?php
namespace App;
use Vendor\Package\Target as DirectTarget;
use function Vendor\Package\make as build;
use const Vendor\Package\READY as IS_READY;
use Vendor\Package\{
    Helper as GroupHelper,
    function render as group_render,
    const LIMIT as GROUP_LIMIT
};
new DirectTarget();
build();
echo IS_READY;
new GroupHelper();
group_render();
echo GROUP_LIMIT;
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Php,
            &[("Library.php", library), ("Consumer.php", consumer)],
        );
        let file = ProjectFile::new(fixture.project_root(), "Consumer.php");
        let tree = parse_php_tree(consumer).expect("PHP tree");
        for (needle, text, expected) in [
            (
                "new DirectTarget()",
                "DirectTarget",
                "Vendor.Package.Target",
            ),
            ("build()", "build", "Vendor.Package.make"),
            ("echo IS_READY", "IS_READY", "Vendor.Package._module_.READY"),
            ("new GroupHelper()", "GroupHelper", "Vendor.Package.Helper"),
            ("group_render()", "group_render", "Vendor.Package.render"),
            (
                "echo GROUP_LIMIT",
                "GROUP_LIMIT",
                "Vendor.Package._module_.LIMIT",
            ),
        ] {
            let site = php_site(consumer, &file, needle, text);
            let outcome = resolve_php_bounded(
                fixture.analyzer.analyzer(),
                &file,
                consumer,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("bounded `{needle}` lookup did not complete: {outcome:#?}");
            };
            assert!(
                value
                    .definitions
                    .iter()
                    .any(|definition| definition.fq_name() == expected),
                "{needle}: {value:#?}"
            );
        }
    }

    #[test]
    fn bounded_lookup_uses_structured_enclosing_self_parent_and_this_owners() {
        let source = r#"<?php
namespace Demo;
class Base {
    public function baseRun(): void {}
}
class Service extends Base {
    public function ownRun(): void {}
    public function exercise(): void {
        $this->ownRun();
        self::ownRun();
        parent::baseRun();
    }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("Receiver.php", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Receiver.php");
        let tree = parse_php_tree(source).expect("PHP tree");
        for (needle, text, expected) in [
            ("$this->ownRun()", "ownRun", "Demo.Service.ownRun"),
            ("self::ownRun()", "ownRun", "Demo.Service.ownRun"),
            ("parent::baseRun()", "baseRun", "Demo.Base.baseRun"),
        ] {
            let site = php_site(source, &file, needle, text);
            let outcome = resolve_php_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("bounded `{needle}` lookup did not complete: {outcome:#?}");
            };
            assert!(
                value
                    .definitions
                    .iter()
                    .any(|definition| definition.fq_name() == expected),
                "{needle}: {value:#?}"
            );
        }
    }

    #[test]
    fn bounded_relative_returns_resolve_only_members_of_the_declaring_owner() {
        let source = r#"<?php
namespace Demo;
class Base {
    public function baseOnly(): void {}
}
class RelativeFactory extends Base {
    public function owned(): void {}
    public static function makeSelf(): self { return new self(); }
    public static function makeStatic(): static { return new static(); }
    public static function makeParent(): parent { return new Base(); }
}
class Unrelated {
    public function owned(): void {}
    public function baseOnly(): void {}
}
function exercise(): void {
    RelativeFactory::makeSelf()->owned();
    RelativeFactory::makeStatic()->owned();
    RelativeFactory::makeParent()->baseOnly();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("Returns.php", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Returns.php");
        let tree = parse_php_tree(source).expect("PHP tree");
        for (needle, text, expected) in [
            (
                "RelativeFactory::makeSelf()->owned()",
                "owned",
                "Demo.RelativeFactory.owned",
            ),
            (
                "RelativeFactory::makeStatic()->owned()",
                "owned",
                "Demo.RelativeFactory.owned",
            ),
            (
                "RelativeFactory::makeParent()->baseOnly()",
                "baseOnly",
                "Demo.Base.baseOnly",
            ),
        ] {
            let site = php_site(source, &file, needle, text);
            let outcome = resolve_php_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("bounded `{needle}` lookup did not complete: {outcome:#?}");
            };
            assert!(
                matches!(
                    value.definitions.as_slice(),
                    [definition] if definition.fq_name() == expected
                ),
                "{needle}: {value:#?}"
            );
        }
    }

    #[test]
    fn bounded_relative_return_rejects_an_ambiguous_enclosing_owner() {
        let first = r#"<?php
namespace Demo;
class BaseA {}
class Duplicate extends BaseA {
    public static function make(): self { return new self(); }
}
"#;
        let second = r#"<?php
namespace Demo;
class BaseB {}
class Duplicate extends BaseB {}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Php,
            &[("First.php", first), ("Second.php", second)],
        );
        let outcome = declared_php_type_outcome(
            &fixture,
            "Demo.Duplicate.make",
            ReceiverAnalysisBudget::default(),
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Complete { value: None, .. }
        ));
    }

    #[test]
    fn bounded_relative_return_stops_at_tiny_budget_and_on_cancellation() {
        let source = r#"<?php
namespace Demo;
class RelativeFactory {
    public static function make(): self { return new self(); }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("Relative.php", source)]);

        let budget = ReceiverAnalysisBudget::tiny();
        let budget_outcome =
            declared_php_type_outcome(&fixture, "Demo.RelativeFactory.make", budget, None);
        assert!(matches!(
            budget_outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));

        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let cancellation_outcome = declared_php_type_outcome(
            &fixture,
            "Demo.RelativeFactory.make",
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );
        assert!(matches!(
            cancellation_outcome,
            BoundedResolution::Cancelled { work } if work.scope_nodes > 0
        ));
    }

    #[test]
    fn bounded_lookup_stops_on_deep_wide_scope_budget_without_partial_result() {
        let mut source = String::from(
            "<?php\nnamespace Demo;\nclass Service { public function run(): void {} }\n",
        );
        source.push_str("class Consumer { public function exercise(): void {\n");
        for _ in 0..48 {
            source.push_str("if (true) {\n");
        }
        for index in 0..96 {
            source.push_str(&format!("$value{index} = new Service();\n"));
        }
        source.push_str("$target = new Service();\n$target->run();\n");
        for _ in 0..48 {
            source.push_str("}\n");
        }
        source.push_str("} }\n");
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("Wide.php", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "Wide.php");
        let tree = parse_php_tree(&source).expect("PHP tree");
        let site = php_site(&source, &file, "$target->run()", "run");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 32,
            ..ReceiverAnalysisBudget::default()
        };
        let outcome = resolve_php_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            budget,
            None,
        );
        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }

    #[test]
    fn bounded_lookup_stops_on_cancellation() {
        let source = r#"<?php
namespace Demo;
class Service {
    public function run(): void {}
    public function exercise(): void { $this->run(); }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Php, &[("Cancelled.php", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Cancelled.php");
        let tree = parse_php_tree(source).expect("PHP tree");
        let site = php_site(source, &file, "$this->run()", "run");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let outcome = resolve_php_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );
        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }
}
