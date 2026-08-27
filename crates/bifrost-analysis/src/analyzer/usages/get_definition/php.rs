use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::ForwardQueryProvider;
use crate::analyzer::TypeHierarchyProvider;
use crate::analyzer::php::{
    PhpDeclaredType, php_dynamic_type_keyword_node, php_file_context_from_tree_at,
    resolve_php_constant_node, resolve_php_function_node, resolve_php_type_node,
    resolve_php_type_node_arms,
};
use crate::analyzer::usages::local_inference::SymbolResolution;
use crate::analyzer::usages::php_graph::syntax::{
    PhpMagicSurface, anonymous_function_capture_names, captured_local_scope_bindings,
    collection_element_type_fq_name, constructor_parameter_type_node, declaration_doc_comment,
    declared_callable_return_type_fq_name, declared_field_type_fq_name, declared_type_of,
    dominating_instanceof_type_node, enclosing_array_map_collection,
    enclosing_class_declaration_for_field, enclosing_foreach_collection,
    foreach_value_reassigned_before, infer_constructor_assigned_field_type,
    infer_indexed_field_element_type, infer_indexed_local_element_type,
    infer_static_assigned_field_type, is_local_scope as php_is_local_scope, magic_member_names,
    object_creation_type as php_object_creation_type, parameter_doc_element_type,
    parameter_type_node, promoted_property_doc_element_type, relative_declared_type_keyword,
    seed_assignment_binding, seed_parameter_types, static_member_parts as php_static_member_parts,
    unwrap_parenthesized as php_unwrap_parenthesized,
    variable_identifier as php_variable_identifier,
};
use crate::analyzer::usages::php_graph::{
    PhpAnalyzerFacts, php_dynamic_type_keyword, php_graph_source, resolve_php_type_arms,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use brokk_bifrost_php::graph::PhpCallableFacts;
use brokk_bifrost_php::graph_support::{
    php_direct_declared_class_parent, php_file_context_from_source, php_is_interface,
};
use brokk_bifrost_php::phpdoc::{
    return_element_type as phpdoc_return_element_type,
    return_nominal_type as phpdoc_return_nominal_type, var_element_type as phpdoc_var_element_type,
    var_nominal_type as phpdoc_var_nominal_type,
};

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
        analyzer,
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
            &bindings.engine,
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
        "variable_name" => php_instance_receiver_fqn(
            php, analyzer, support, node, source, enclosing, bindings, ctx, session,
        ),
        "object_creation_expression" => php_object_creation_type_with_session(node, session)
            .and_then(|type_node| {
                php_static_scope_fqn(php, support, type_node, source, ctx, enclosing, session)
            }),
        "parenthesized_expression" | "clone_expression" => node.named_child(0).and_then(|inner| {
            php_expression_type_fqn(
                php, analyzer, support, inner, source, enclosing, bindings, ctx, session,
            )
        }),
        "subscript_expression" => php_instance_receiver_fqn(
            php, analyzer, support, node, source, enclosing, bindings, ctx, session,
        ),
        "function_call_expression" | "scoped_call_expression" => {
            php_assignment_receiver_fqn(php, support, node, source, enclosing, ctx)
        }
        "scoped_property_access_expression" => {
            let (scope, name) = php_static_member_parts(node)?;
            let owner = php_static_scope_fqn(php, support, scope, source, ctx, enclosing, session)?;
            let member = php_variable_identifier(name, source);
            let mut fields = php_fqn_candidates(support, &format!("{owner}.{member}"));
            fields.retain(CodeUnit::is_field);
            sort_units(&mut fields);
            fields.dedup();
            let [field] = fields.as_slice() else {
                return None;
            };
            php_field_type_fqn(php, analyzer, support, field, session)
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
            let ctx = php_file_context_from_source(php, file, source);
            let class_ranges = analyzer.class_range_index(file);
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
    // A member spelled `$obj->$name` or `$obj->{$expr}` names its member at run
    // time. That is proven dynamism of the SITE, whatever the receiver's type
    // is, and it is checked before the variable-reference gate below because
    // the member position of such a site is itself a variable.
    if php_dynamic_member_name_access(node, session).is_some() {
        return php_dynamic_member_name_outcome(&site.text);
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
            let candidates = if let Some(session) = session {
                resolve_php_function_node(name_node, source, &ctx, || session.scope_step())
            } else {
                resolve_php_function(&raw, &ctx)
            };
            php_callable_outcome(support, candidates, &raw)
        }
        Some(PhpReferenceNode::Constant(name_node)) => {
            let raw = php_qualified_candidate_text_with_session(name_node, source, session);
            let candidates = if let Some(session) = session {
                resolve_php_constant_node(name_node, source, &ctx, || session.scope_step())
            } else {
                resolve_php_constant(&raw, &ctx)
            };
            php_callable_outcome(support, candidates, &raw)
        }
        Some(PhpReferenceNode::StaticMember { scope, name, kind }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            // `self::`, `static::` and `parent::` spell the enclosing
            // hierarchy rather than a named class's companion side, so only an
            // explicitly named scope is the static access form.
            let scope_text = php_node_text(scope, source);
            let access = if ["self", "static", "parent"]
                .into_iter()
                .any(|keyword| scope_text.eq_ignore_ascii_case(keyword))
            {
                PhpMemberAccess::Instance
            } else {
                PhpMemberAccess::StaticScope
            };
            let owner =
                php_static_scope_fqn(php, support, scope, source, &ctx, &enclosing, session);
            php_member_outcome(
                php,
                support,
                PhpReceiverOwners::nominal(owner.into_iter().collect()),
                member,
                access,
                kind,
                session,
            )
        }
        Some(PhpReferenceNode::InstanceMember { object, name, kind }) => {
            // The same proven-dynamic member name as above, reached when the
            // site covers the whole access instead of its member position.
            if name.kind() != "name" {
                return php_dynamic_member_name_outcome(&site.text);
            }
            let member = php_node_text(name, source).trim_start_matches('$');
            let bindings = php_bindings_before(
                php,
                analyzer,
                file,
                source,
                root,
                site.range.start_byte,
                &enclosing,
                &ctx,
                support,
                session,
            );
            let owners = php_instance_receiver_owners(
                php, analyzer, support, object, source, &enclosing, &bindings, &ctx, session,
            );
            php_member_outcome(
                php,
                support,
                owners,
                member,
                PhpMemberAccess::Instance,
                kind,
                session,
            )
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
            php_is_interface(php, &ancestor)
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

#[cfg(test)]
fn parse_php_tree(source: &str) -> Option<Tree> {
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
        kind: PhpMemberKind,
    },
    InstanceMember {
        object: Node<'tree>,
        name: Node<'tree>,
        kind: PhpMemberKind,
    },
}

#[derive(Debug, Clone, Copy)]
enum PhpMemberKind {
    Callable,
    Field,
    Any,
}

impl PhpMemberKind {
    fn accepts(self, unit: &CodeUnit) -> bool {
        match self {
            Self::Callable => unit.is_function(),
            Self::Field => unit.is_field(),
            Self::Any => true,
        }
    }
}

fn php_member_kind(access: Node<'_>) -> PhpMemberKind {
    match access.kind() {
        "member_call_expression" | "nullsafe_member_call_expression" | "scoped_call_expression" => {
            PhpMemberKind::Callable
        }
        "member_access_expression"
        | "nullsafe_member_access_expression"
        | "scoped_property_access_expression"
        | "class_constant_access_expression" => PhpMemberKind::Field,
        _ => PhpMemberKind::Any,
    }
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
        return Some(PhpReferenceNode::StaticMember {
            scope,
            name,
            kind: PhpMemberKind::Field,
        });
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
            Some(PhpReferenceNode::StaticMember {
                scope,
                name,
                kind: php_member_kind(node),
            })
        }
        "member_call_expression"
        | "nullsafe_member_call_expression"
        | "member_access_expression"
        | "nullsafe_member_access_expression" => {
            let object = node.child_by_field_name("object")?;
            let name = node.child_by_field_name("name")?;
            Some(PhpReferenceNode::InstanceMember {
                object,
                name,
                kind: php_member_kind(node),
            })
        }
        "name" | "qualified_name" | "relative_scope" => {
            let parent = node.parent()?;
            match parent.kind() {
                "object_creation_expression"
                | "named_type"
                | "base_clause"
                | "class_interface_clause" => Some(PhpReferenceNode::Type(node)),
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
                    Some(PhpReferenceNode::InstanceMember {
                        object,
                        name: node,
                        kind: php_member_kind(parent),
                    })
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
        return Some(PhpReferenceNode::StaticMember {
            scope,
            name,
            kind: php_member_kind(access),
        });
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
    php_unindexed_fqn_outcome(support, &fqn, raw)
}

/// [`php_fqn_outcome`] over PHP's ordered function/constant candidates.
///
/// The candidates are tried in PHP's own lookup order, so a declaration in the
/// caller's namespace shadows the global one. When the workspace indexes
/// neither, the report names the LAST candidate, which is where PHP's lookup
/// actually ends: a bare `substr(...)` inside `namespace Monolog` was reported
/// against `Monolog.substr`, a name PHP never looks for (#1866).
fn php_callable_outcome(
    support: &dyn BoundedDefinitionLookup,
    candidates: Option<PhpCallableCandidates>,
    raw: &str,
) -> DefinitionLookupOutcome {
    let Some(candidates) = candidates else {
        return no_definition(
            "no_indexed_definition",
            format!("`{raw}` did not resolve to a PHP definition name"),
        );
    };
    for candidate in candidates.iter() {
        let units = php_fqn_candidates(support, candidate);
        if !units.is_empty() {
            return candidates_outcome(units);
        }
    }
    php_unindexed_fqn_outcome(support, candidates.last(), raw)
}

fn php_unindexed_fqn_outcome(
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    // `php_crosses_unindexed_boundary` fuses the external signal with the
    // workspace-namespace check, so its negation is exactly the workspace-
    // internal gate `gated_boundary` wants.
    gated_boundary(
        || !php_crosses_unindexed_boundary(support, fqn),
        format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial PHP workspace analysis"
        ),
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed PHP definition was found"),
    )
}

/// The one candidate the workspace indexes, preferring the shadowing namespace
/// spelling, so every non-definition consumer of a PHP callable reference reads
/// the same target the definition lookup answers (#1866).
fn php_bound_callable<'a>(
    support: &dyn BoundedDefinitionLookup,
    candidates: &'a PhpCallableCandidates,
) -> &'a str {
    candidates.first_indexed(|candidate| !php_fqn_candidates(support, candidate).is_empty())
}

/// The access form the PHP resolver reached a member through.
///
/// PHP's `::` scope access is the language's own static/companion seam, and it
/// is the one bucket fact the reference site itself states. Every other access
/// takes its bucket from the owner the walk found the member on. The relative
/// scopes (`self`, `static`, `parent`) are deliberately *not* static access
/// here: they name the enclosing hierarchy, not a companion side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhpMemberAccess {
    Instance,
    StaticScope,
}

/// The diagnostic kind for a PHP member site whose dynamism is *proven*.
///
/// It is deliberately not the same kind as `unsupported_php_receiver`. That one
/// means "this receiver shape is not followed yet", which proves nothing about
/// the program; the census refuses to grade such a kind as an answer, exactly
/// as it refuses Scala's `unsupported_scala_receiver`
/// (`src/reference_differential/mod.rs`, the "Deliberately NOT mapped" block).
/// This kind carries proof: the declaration says `object`/`mixed`, the member
/// name is an expression, the receiver is a variable-variable, or the resolved
/// owner answers the member through a magic method at run time.
const PHP_DYNAMIC_RECEIVER: &str = "php_dynamic_receiver";

/// What a PHP member reference's receiver proves about its owner.
///
/// The three cases are distinct answers. `Nominal` names classes to look the
/// member up on. `ProvenDynamic` states that no class can be named because the
/// program itself decides the receiver's member surface at run time, and
/// carries the proof phrase to report. `Unknown` is the honest "this resolver
/// does not follow this shape yet", which is a gap in Bifrost, not a fact about
/// the code.
enum PhpReceiverOwners {
    /// At least one class the receiver can be. Never empty.
    Nominal(Vec<String>),
    /// A member-call chain entered a nominal owner outside this workspace.
    UnindexedBoundary { owner: String, member: String },
    /// Proven dynamic, with the phrase naming the proof.
    ProvenDynamic(String),
    /// The receiver shape or type is not followed.
    Unknown,
}

impl PhpReceiverOwners {
    /// The nominal reading of `owners`, which is [`PhpReceiverOwners::Unknown`]
    /// when the receiver proved no class.
    fn nominal(owners: Vec<String>) -> Self {
        if owners.is_empty() {
            Self::Unknown
        } else {
            Self::Nominal(owners)
        }
    }
}

/// The definition outcome for one PHP member reference, given what its receiver
/// proves.
///
/// One owner is the ordinary case and keeps the walk it always had. Two or more
/// owners is a finite union receiver (`A|B $m`), which forward lookup answers as
/// an explicit ambiguity carrying the competing declarations rather than as a
/// silent choice of one arm. A proven-dynamic receiver is a typed refusal; an
/// unproven one stays the untyped miss it always was.
fn php_member_outcome(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owners: PhpReceiverOwners,
    member: &str,
    access: PhpMemberAccess,
    kind: PhpMemberKind,
    session: Option<&ResolutionSession>,
) -> DefinitionLookupOutcome {
    let owners = match owners {
        PhpReceiverOwners::Unknown => {
            return no_definition(
                "unsupported_php_receiver",
                format!("receiver for PHP member `{member}` is not resolved"),
            );
        }
        PhpReceiverOwners::ProvenDynamic(proof) => {
            return no_definition(
                PHP_DYNAMIC_RECEIVER,
                format!("PHP member `{member}` is resolved at run time: {proof}"),
            );
        }
        PhpReceiverOwners::UnindexedBoundary {
            owner,
            member: boundary_member,
        } => {
            return gated_boundary(
                || !php_crosses_unindexed_boundary(support, &owner),
                format!(
                    "`{member}` appears to cross a PHP boundary through `{owner}.{boundary_member}`, whose receiver type is not indexed in this workspace"
                ),
                "unsupported_php_receiver",
                format!(
                    "receiver for PHP member `{member}` is not resolved after `{owner}.{boundary_member}`"
                ),
            );
        }
        PhpReceiverOwners::Nominal(owners) => owners,
    };
    debug_assert!(
        !owners.is_empty(),
        "PhpReceiverOwners::Nominal is constructed only from a non-empty owner set"
    );
    match owners.as_slice() {
        [owner] => {
            php_single_owner_member_outcome(php, support, owner, member, access, kind, session)
        }
        _ => php_union_owner_member_outcome(php, support, &owners, member, kind, session),
    }
}

/// Every member candidate a finite union receiver's arms offer, merged.
///
/// Each arm answers with its own direct candidates, or -- when it declares none
/// -- with its inherited ones, exactly as a single owner would. One total
/// candidate across all arms is still one answer. Two or more is the ambiguity
/// the declaration itself states, and the competing declarations travel on the
/// row (#2167).
///
/// No member attribution is staged here: `PhpMemberTrace` is rooted at one base
/// owner and its hierarchy routes are relative to that root, so a merged
/// multi-owner answer has no single route to record.
fn php_union_owner_member_outcome(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owners: &[String],
    member: &str,
    kind: PhpMemberKind,
    session: Option<&ResolutionSession>,
) -> DefinitionLookupOutcome {
    let mut candidates = Vec::new();
    for owner in owners {
        let mut direct = php_fqn_candidates(support, &format!("{owner}.{member}"));
        direct.retain(|candidate| kind.accepts(candidate));
        if direct.is_empty() {
            direct = php_inherited_member_candidates(php, support, owner, member, session, None);
            direct.retain(|candidate| kind.accepts(candidate));
        }
        candidates.extend(direct);
    }
    sort_units(&mut candidates);
    candidates.dedup();
    let arms = owners.join("`, `");
    match candidates.len() {
        0 => gated_boundary(
            // gated on the owner's workspace-namespace check fused into
            // `php_crosses_unindexed_boundary`. One workspace-internal arm keeps
            // the miss actionable: an external arm must not hide it.
            || {
                owners
                    .iter()
                    .any(|owner| !php_crosses_unindexed_boundary(support, owner))
            },
            format!(
                "`{member}` appears to cross a PHP boundary at every declared receiver type (`{arms}`) not indexed in this workspace"
            ),
            "no_indexed_definition",
            format!("`{member}` is not indexed as a PHP definition on any of `{arms}`"),
        ),
        1 => candidates_outcome(candidates),
        _ => ambiguous_candidates_outcome_of_kind(
            candidates,
            "ambiguous_definition",
            format!(
                "`{member}` is declared by more than one arm of the union receiver type `{arms}`"
            ),
        ),
    }
}

fn php_single_owner_member_outcome(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &str,
    member: &str,
    access: PhpMemberAccess,
    kind: PhpMemberKind,
    session: Option<&ResolutionSession>,
) -> DefinitionLookupOutcome {
    let owner = owner.to_string();
    let fqn = format!("{owner}.{member}");
    let mut candidates = php_fqn_candidates(support, &fqn);
    candidates.retain(|candidate| kind.accepts(candidate));
    // Attribution is built only while a trace records (#1477); the walk itself
    // consumes nothing from it.
    let mut member_trace = trace::recording().then(|| PhpMemberTrace::rooted(support, &owner));
    if !candidates.is_empty() {
        if let Some(state) = member_trace.as_mut() {
            state.record_found(&candidates, &owner, 0);
            state.stage(php, &candidates, access);
        }
        return candidates_outcome(candidates);
    }
    let mut inherited = php_inherited_member_candidates(
        php,
        support,
        &owner,
        member,
        session,
        member_trace.as_mut(),
    );
    inherited.retain(|candidate| kind.accepts(candidate));
    if !inherited.is_empty() {
        if let Some(state) = member_trace.as_mut() {
            state.stage(php, &inherited, access);
        }
        return candidates_outcome(inherited);
    }
    // The owner is indexed and declares the member nowhere on its hierarchy,
    // but declares the magic hook PHP dispatches an absent member through, so
    // the site really is resolved at run time. This is checked before the
    // boundary gate because it is a fact about the owner's own declarations,
    // not about what this workspace happens to index.
    if let Some(magic) = php_magic_member_resolver(php, support, &owner, access, kind, session) {
        return no_definition(
            PHP_DYNAMIC_RECEIVER,
            format!(
                "PHP member `{member}` is resolved at run time: `{owner}` declares no `{member}` and resolves absent members through `{magic}`"
            ),
        );
    }
    // gated on the owner's workspace-namespace check fused into
    // `php_crosses_unindexed_boundary` (its negation is the workspace gate).
    gated_boundary(
        || !php_crosses_unindexed_boundary(support, &owner),
        format!(
            "`{member}` appears to cross a PHP boundary at `{owner}` not indexed in this workspace"
        ),
        "no_indexed_definition",
        format!("`{fqn}` is not indexed as a PHP definition"),
    )
}

/// The magic method through which `owner` -- or an ancestor on the same
/// bounded walk the member lookup itself takes -- resolves an absent member of
/// this access form at run time.
///
/// The magic-method table is the shared one in `graph/syntax.rs`, which the
/// semantic-diagnostics pass reads too, so both surfaces agree on what "the
/// owner answers this at run time" means.
fn php_magic_member_resolver(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &str,
    access: PhpMemberAccess,
    kind: PhpMemberKind,
    session: Option<&ResolutionSession>,
) -> Option<&'static str> {
    let surfaces: &[PhpMagicSurface] = match (access, kind) {
        (PhpMemberAccess::StaticScope, PhpMemberKind::Callable) => &[PhpMagicSurface::StaticCall],
        (PhpMemberAccess::StaticScope, _) => &[PhpMagicSurface::StaticData],
        (PhpMemberAccess::Instance, PhpMemberKind::Callable) => &[PhpMagicSurface::InstanceCall],
        (PhpMemberAccess::Instance, PhpMemberKind::Field) => &[PhpMagicSurface::InstanceProperty],
        // The access node did not state which form it is, so either hook can
        // be the one that answers the member.
        (PhpMemberAccess::Instance, PhpMemberKind::Any) => &[
            PhpMagicSurface::InstanceCall,
            PhpMagicSurface::InstanceProperty,
        ],
    };
    surfaces
        .iter()
        .flat_map(|surface| magic_member_names(*surface))
        .copied()
        .find(|magic| {
            let mut declared = php_fqn_candidates(support, &format!("{owner}.{magic}"));
            if declared.is_empty() {
                // A receiver-surface probe, not the reference's own answer, so
                // it stages no attribution.
                declared =
                    php_inherited_member_candidates(php, support, owner, magic, session, None);
            }
            declared.iter().any(CodeUnit::is_function)
        })
}

fn php_inherited_member_candidates(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    member: &str,
    session: Option<&ResolutionSession>,
    mut member_trace: Option<&mut PhpMemberTrace>,
) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    let mut level = php_direct_member_owner_fqns(php, support, owner_fqn, session);
    if let Some(state) = member_trace.as_deref_mut() {
        state.record_level(owner_fqn, &level);
    }
    seen.insert(owner_fqn.to_string());
    let mut depth = 0usize;
    while !level.is_empty() {
        depth += 1;
        let mut level_candidates = Vec::new();
        let mut next_level = Vec::new();
        for (ancestor, unit) in level {
            if session.is_some_and(|session| !session.scope_step()) {
                return Vec::new();
            }
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            let found = php_fqn_candidates(support, &format!("{ancestor}.{member}"));
            if let Some(state) = member_trace.as_deref_mut() {
                state.record_owner(&ancestor, unit);
                state.record_found(&found, &ancestor, depth);
            }
            level_candidates.extend(found);
            let expanded = php_direct_member_owner_fqns(php, support, &ancestor, session);
            if let Some(state) = member_trace.as_deref_mut() {
                state.record_level(&ancestor, &expanded);
            }
            next_level.extend(expanded);
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

/// The indexed direct ancestors of `owner_fqn`, each paired with the
/// fully-qualified name the walk addresses it by.
///
/// The declaration travels with the name because the walk already holds it:
/// the fq name is derived from that very unit, and the indexed-ness filter
/// below is the same lookup the untraced walk always performed.
fn php_direct_member_owner_fqns(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    session: Option<&ResolutionSession>,
) -> Vec<(String, CodeUnit)> {
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
        .filter_map(|ancestor| {
            let fqn = ancestor.fq_name();
            (!php_fqn_candidates(support, &fqn).is_empty()).then_some((fqn, ancestor))
        })
        .collect()
}

/// The per-candidate attribution the PHP member walk records while it runs
/// (#1477): which hierarchy owner each candidate was found on, at which BFS
/// depth, and through which first-discovery parent chain.
///
/// It is an emission of facts the walk already holds. The walk decides nothing
/// from it, and it is constructed only while [`trace::recording`] is true, so
/// an untraced lookup allocates none of these maps.
#[derive(Default)]
struct PhpMemberTrace {
    /// The receiver's own owner: the fq name the direct lookup asked about and,
    /// where the workspace indexes it, its declaration. Without the
    /// declaration there is no route base, so every candidate stays
    /// unattributed rather than attributed to an owner this seam cannot name.
    base_fqn: String,
    base_unit: Option<CodeUnit>,
    /// First-discovery parent of each ancestor fq name the walk expanded.
    parents: HashMap<String, String>,
    /// The indexed declaration each ancestor fq name on the walk names.
    units: HashMap<String, CodeUnit>,
    /// Candidate declaration -> (owner fq name it was found on, BFS depth).
    found: HashMap<CodeUnit, (String, usize)>,
}

impl PhpMemberTrace {
    fn rooted(support: &dyn BoundedDefinitionLookup, owner_fqn: &str) -> Self {
        Self {
            base_fqn: owner_fqn.to_owned(),
            base_unit: php_fqn_candidates(support, owner_fqn).into_iter().next(),
            ..Self::default()
        }
    }

    /// Retain the first-discovery parent of every ancestor one expansion
    /// produced, which is what makes the route a bounded walk back to the base.
    fn record_level(&mut self, parent_fqn: &str, level: &[(String, CodeUnit)]) {
        for (fqn, unit) in level {
            self.parents
                .entry(fqn.clone())
                .or_insert_with(|| parent_fqn.to_owned());
            self.units
                .entry(fqn.clone())
                .or_insert_with(|| unit.clone());
        }
    }

    fn record_owner(&mut self, fqn: &str, unit: CodeUnit) {
        self.units.entry(fqn.to_owned()).or_insert(unit);
    }

    fn record_found(&mut self, candidates: &[CodeUnit], owner_fqn: &str, depth: usize) {
        for candidate in candidates {
            self.found
                .entry(candidate.clone())
                .or_insert_with(|| (owner_fqn.to_owned(), depth));
        }
    }

    /// The exact hierarchy route from the base owner to `owner_fqn`, as
    /// first-discovery hops. PHP indexes `extends`, `implements` and `use`
    /// through one undifferentiated raw-supertype list, so no hop may claim to
    /// be more than [`HierarchyRelation::Supertype`].
    fn route(&self, owner_fqn: &str, depth: usize) -> Option<Vec<trace::HierarchyHopRecord>> {
        use crate::analyzer::structural::HierarchyRelation;

        let base = self.base_unit.as_ref()?;
        let mut chain = vec![owner_fqn.to_owned()];
        while chain.last().is_some_and(|last| *last != self.base_fqn) {
            let parent = self
                .parents
                .get(chain.last().expect("chain is never empty"))?;
            chain.push(parent.clone());
        }
        chain.reverse();
        debug_assert_eq!(
            chain.len(),
            depth + 1,
            "the first-discovery chain must be exactly the walk's hop distance"
        );
        let mut route = Vec::with_capacity(depth);
        for (hop, pair) in chain.windows(2).enumerate() {
            let from = if pair[0] == self.base_fqn {
                base.clone()
            } else {
                self.units.get(&pair[0])?.clone()
            };
            route.push(trace::HierarchyHopRecord {
                hop,
                from,
                to: self.units.get(&pair[1])?.clone(),
                relation: HierarchyRelation::Supertype,
            });
        }
        Some(route)
    }

    /// The bucket a find belongs to.
    ///
    /// A `::` access is PHP's static/companion seam whatever the walk found,
    /// and says so. Otherwise the owner's own declaration decides: a member
    /// composed in from a trait or declared by an interface is the
    /// trait/interface bucket, and a member of a base class is the inherited
    /// one. Depth is the independent axis and is never folded into the bucket.
    fn dispatch_tier(
        &self,
        php: &PhpAnalyzer,
        owner: &CodeUnit,
        depth: usize,
        access: PhpMemberAccess,
    ) -> crate::analyzer::structural::MemberDispatchTier {
        use crate::analyzer::structural::MemberDispatchTier;
        use brokk_bifrost_php::graph_support::php_is_trait;

        if access == PhpMemberAccess::StaticScope {
            return MemberDispatchTier::StaticOrCompanion;
        }
        if depth == 0 {
            return MemberDispatchTier::InherentOrDirect;
        }
        if php_is_interface(php, owner) || php_is_trait(php, owner) {
            MemberDispatchTier::TraitOrInterface
        } else {
            MemberDispatchTier::InheritedOrPromoted
        }
    }

    fn enrichment(
        &self,
        php: &PhpAnalyzer,
        candidate: &CodeUnit,
        access: PhpMemberAccess,
    ) -> Option<trace::MemberEnrichment> {
        use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

        let (owner_fqn, depth) = self.found.get(candidate)?;
        let owner = if *depth == 0 {
            self.base_unit.clone()?
        } else {
            self.units.get(owner_fqn)?.clone()
        };
        let route = self.route(owner_fqn, *depth)?;
        Some(trace::MemberEnrichment {
            owner: owner.clone(),
            hierarchy_depth: *depth,
            dispatch_tier: self.dispatch_tier(php, &owner, *depth, access),
            // The PHP member seams select by owner and name and never inspect
            // the call shape, so the callable axis (#1478) stays unclaimed.
            applicability: ApplicabilityVerdict::Unknown,
            route,
        })
    }

    /// Stage the attribution for the outcome constructor the caller is about to
    /// reach. The PHP walk returns the whole level it first found candidates
    /// on and discards nothing, so it records no rejected rows.
    fn stage(&self, php: &PhpAnalyzer, winners: &[CodeUnit], access: PhpMemberAccess) {
        use crate::analyzer::structural::PrecedenceTier;

        let winner_tier = winners
            .iter()
            .filter_map(|unit| self.found.get(unit))
            .map(|(_, depth)| *depth)
            .min()
            .map(|depth| {
                if depth == 0 {
                    PrecedenceTier::OwnMember
                } else {
                    PrecedenceTier::InheritedMember
                }
            });
        if let Some(tier) = winner_tier {
            trace::stage_tier(tier, winners.iter().map(CodeUnit::fq_name).collect());
        }
        trace::stage_member_context(
            winners
                .iter()
                .filter_map(|unit| {
                    self.enrichment(php, unit, access)
                        .map(|enrichment| (unit.fq_name(), enrichment))
                })
                .collect(),
        );
    }
}

fn php_crosses_unindexed_boundary(support: &dyn BoundedDefinitionLookup, fqn: &str) -> bool {
    // `fqn` is already a resolved, `.`-joined PHP fqn (namespace segments are
    // `.`-joined; a nested type's `$` boundary, if present, is untouched by
    // this splitter's delimiter set, exactly like the string `rsplit_once`
    // it replaces). Re-tokenizing with the shared structured splitter and
    // rejoining every part but the last with `.` reproduces
    // `rsplit_once('.')`'s (namespace, _) split exactly, including the
    // no-dot case (an empty namespace, which the exists-check always rejects).
    let segments = crate::analyzer::symbol_lookup::parse_symbol_path(Language::Php, fqn);
    let namespace = segments[..segments.len().saturating_sub(1)].join(".");
    if namespace.is_empty() {
        // The global namespace is where PHP's own builtins live (`PDO`,
        // `Redis`, `substr`), and it is not a package any workspace declares,
        // so asking whether the repository happens to contain a global-
        // namespace symbol made the answer flip per-repository (#2030). The
        // owner's own indexed-ness is the fact that decides it: a global-
        // namespace name this workspace declares is internal, and one it does
        // not declare is outside the analysis.
        return php_fqn_candidates(support, fqn).is_empty();
    }
    !php_workspace_exact_namespace_exists(support, &namespace)
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
        php_direct_declared_class_parent(php, &child).map(|parent| parent.fq_name())
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
    let scope = crate::analyzer::AnalyzerQueryScope::new(php);
    match php.prepared_syntax_limited_cancellable(
        scope.token(),
        file,
        PHP_BOUNDED_AUXILIARY_MAX_SOURCE_BYTES,
        session.cancellation(),
    ) {
        PreparedSyntaxLimitedOutcome::Available(_, prepared) => {
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
fn php_collection_element_type_fqn_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    collection: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: &ResolutionSession,
) -> Option<String> {
    match collection.kind() {
        "variable_name" => infer_indexed_local_element_type(
            collection,
            source,
            collection.start_byte(),
            &mut |right| {
                php_expression_type_fqn_bounded(
                    php, support, right, source, enclosing, bindings, ctx, session,
                )
            },
        ),
        "member_access_expression" | "nullsafe_member_access_expression" => {
            let object = collection.child_by_field_name("object")?;
            if object.kind() != "variable_name" || php_variable_identifier(object, source) != "this"
            {
                return None;
            }
            let member = collection.child_by_field_name("name")?;
            let member = php_literal_member_name(member, source, session)?;
            let owner = enclosing.fqn()?;
            let field = php_unique_member_candidate_bounded(
                php,
                support,
                owner,
                member,
                CodeUnit::is_field,
                session,
            )?;
            php_declared_field_element_type_fqn_bounded(php, support, &field, session)
        }
        "member_call_expression" | "nullsafe_member_call_expression" => {
            let object = collection.child_by_field_name("object")?;
            let owner = php_expression_type_fqn_bounded(
                php, support, object, source, enclosing, bindings, ctx, session,
            )?;
            let member = collection.child_by_field_name("name")?;
            let member = php_literal_member_name(member, source, session)?;
            let callable = php_unique_member_candidate_bounded(
                php,
                support,
                &owner,
                member,
                CodeUnit::is_function,
                session,
            )?;
            php_declared_callable_return_element_type_fqn_bounded(php, &callable, session)
        }
        _ => None,
    }
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
                    let value = if let Some(type_node) =
                        dominating_instanceof_type_node(expression, source, || session.scope_step())
                    {
                        resolve_php_type_node(type_node, source, ctx, || session.scope_step())
                    } else if name == "this" {
                        enclosing.fqn.clone()
                    } else if let Some(collection) =
                        enclosing_foreach_collection(expression, source, || session.scope_step())
                    {
                        php_collection_element_type_fqn_bounded(
                            php, support, collection, source, enclosing, bindings, ctx, session,
                        )
                        .or_else(|| {
                            foreach_value_reassigned_before(expression, source)
                                .then(|| php_precise_owner(bindings, name))
                                .flatten()
                        })
                    } else if let Some(owner) = php_precise_owner(bindings, name) {
                        Some(owner)
                    } else if let Some(collection) = enclosing_array_map_collection(
                        expression,
                        source,
                        ctx,
                        || session.scope_step(),
                        |candidate| {
                            php_fqn_candidates(support, candidate)
                                .iter()
                                .any(CodeUnit::is_function)
                        },
                    ) {
                        php_collection_element_type_fqn_bounded(
                            php, support, collection, source, enclosing, bindings, ctx, session,
                        )
                    } else {
                        None
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
                "parenthesized_expression" | "clone_expression" => {
                    let inner = expression.named_child(0)?;
                    frames.push(PhpExpressionTypeFrame::Evaluate(inner));
                }
                "subscript_expression" => {
                    let collection = expression.named_child(0)?;
                    values.push(php_collection_element_type_fqn_bounded(
                        php, support, collection, source, enclosing, bindings, ctx, session,
                    )?);
                }
                "function_call_expression" => {
                    let function = expression.child_by_field_name("function")?;
                    let candidates =
                        resolve_php_function_node(function, source, ctx, || session.scope_step())?;
                    values.push(php_declared_callable_return_type_fqn(
                        php,
                        support,
                        php_bound_callable(support, &candidates),
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
                "scoped_property_access_expression" => {
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
                    let member = php_variable_identifier(name, source);
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
        // A receiver-type probe, not the reference's own member answer: its
        // candidates never become the outcome, so it stages no attribution.
        candidates =
            php_inherited_member_candidates(php, support, owner, member, Some(session), None);
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
    let mut arms = php_declared_unit_type_bounded(php, support, unit, session).arms();
    (arms.len() == 1).then(|| arms.remove(0))
}

fn php_declared_callable_return_element_type_fqn_bounded(
    php: &PhpAnalyzer,
    callable: &CodeUnit,
    session: &ResolutionSession,
) -> Option<String> {
    if !callable.is_function() {
        return None;
    }
    let (prepared, range) = php_prepared_declaration_bounded(php, callable, session)?;
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let declaration = php_declaration_node_bounded(root, source, callable, &range, session)?;
    let raw = phpdoc_return_element_type(declaration_doc_comment(declaration, source)?)?;
    let ctx = php_file_context_from_tree_at(root, source, declaration.start_byte(), || {
        session.scope_step()
    })?;
    let mut arms = resolve_php_type_arms(&raw, &ctx);
    (arms.len() == 1).then(|| arms.remove(0))
}

/// What the declared return or field type of `unit` proves, read from the
/// declaration's own parser nodes.
///
/// [`php_declared_unit_type_fqn_bounded`] is this computation's exactly-one-arm
/// case, so a chain step that must hand on one owner and a final receiver that
/// may carry a union read the same declaration the same way.
fn php_declared_unit_type_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    session: &ResolutionSession,
) -> PhpDeclaredType {
    php_declared_unit_type_bounded_inner(php, support, unit, session)
        .unwrap_or(PhpDeclaredType::Unknown)
}

fn php_declared_unit_type_bounded_inner(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    session: &ResolutionSession,
) -> Option<PhpDeclaredType> {
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
    let Some(type_node) = declaration.child_by_field_name(field_name) else {
        if unit.is_function() {
            let raw = phpdoc_return_nominal_type(declaration_doc_comment(declaration, source)?)?;
            let ctx =
                php_file_context_from_tree_at(root, source, declaration.start_byte(), || {
                    session.scope_step()
                })?;
            return Some(PhpDeclaredType::nominal(resolve_php_type_arms(&raw, &ctx)));
        }
        if !unit.is_field() {
            return None;
        }
        let owner = php.parent_of(unit).filter(CodeUnit::is_class)?;
        let class = enclosing_class_declaration_for_field(
            root,
            source,
            &owner,
            std::slice::from_ref(&range),
            || session.scope_step(),
        )?;
        let ctx = php_file_context_from_tree_at(root, source, class.start_byte(), || {
            session.scope_step()
        })?;
        let enclosing = php_enclosing_type_from_tree(support, declaration, source, &ctx, session)?;
        if let Some(raw) = phpdoc_var_nominal_type(declaration_doc_comment(declaration, source)?) {
            return Some(PhpDeclaredType::nominal(resolve_php_type_arms(&raw, &ctx)));
        }
        let inferred = infer_constructor_assigned_field_type(
            class,
            source,
            unit.identifier(),
            || session.scope_step(),
            |right| {
                let right = php_unwrap_parenthesized(right);
                if right.kind() == "object_creation_expression" {
                    let type_node = php_object_creation_type_with_session(right, Some(session))?;
                    return php_bounded_type_reference_fqn(
                        php, support, type_node, source, &ctx, &enclosing, session,
                    );
                }
                let type_node =
                    constructor_parameter_type_node(right, source, || session.scope_step())?;
                let mut arms =
                    resolve_php_type_node_arms(type_node, source, &ctx, || session.scope_step());
                (arms.len() == 1).then(|| arms.remove(0))
            },
        )
        .or_else(|| {
            infer_static_assigned_field_type(
                class,
                source,
                unit.identifier(),
                || session.scope_step(),
                |right| {
                    let right = php_unwrap_parenthesized(right);
                    let type_node = (right.kind() == "object_creation_expression")
                        .then(|| php_object_creation_type_with_session(right, Some(session)))
                        .flatten()?;
                    php_bounded_type_reference_fqn(
                        php, support, type_node, source, &ctx, &enclosing, session,
                    )
                },
            )
        });
        return inferred.map(|fqn| PhpDeclaredType::Nominal(vec![fqn]));
    };
    if !session.scope_step() {
        return None;
    }
    let ctx = php_file_context_from_tree_at(root, source, declaration.start_byte(), || {
        session.scope_step()
    })?;
    if let Some(keyword) = php_relative_type_keyword_bounded(type_node, source, session) {
        let enclosing = php_enclosing_type_from_tree(support, declaration, source, &ctx, session)?;
        let relative =
            if keyword.eq_ignore_ascii_case("self") || keyword.eq_ignore_ascii_case("static") {
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
        return Some(PhpDeclaredType::nominal(relative.into_iter().collect()));
    }
    if let Some(builtin) = php_dynamic_type_keyword_node(type_node, source, || session.scope_step())
    {
        return Some(PhpDeclaredType::Dynamic(builtin));
    }
    Some(PhpDeclaredType::nominal(resolve_php_type_node_arms(
        type_node,
        source,
        &ctx,
        || session.scope_step(),
    )))
}

fn php_declared_field_element_type_fqn_bounded(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    field: &CodeUnit,
    session: &ResolutionSession,
) -> Option<String> {
    if !field.is_field() {
        return None;
    }
    let owner = php.parent_of(field).filter(CodeUnit::is_class)?;
    let (prepared, range) = php_prepared_declaration_bounded(php, field, session)?;
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let declaration = php_declaration_node_bounded(root, source, field, &range, session)?;
    let class = enclosing_class_declaration_for_field(
        root,
        source,
        &owner,
        std::slice::from_ref(&range),
        || session.scope_step(),
    )?;
    let ctx =
        php_file_context_from_tree_at(root, source, class.start_byte(), || session.scope_step())?;
    let enclosing = php_enclosing_type_from_tree(support, class, source, &ctx, session)?;
    infer_indexed_field_element_type(
        class,
        source,
        field.identifier(),
        || session.scope_step(),
        |right| {
            let right = php_unwrap_parenthesized(right);
            if right.kind() == "object_creation_expression" {
                let type_node = php_object_creation_type_with_session(right, Some(session))?;
                return php_bounded_type_reference_fqn(
                    php, support, type_node, source, &ctx, &enclosing, session,
                );
            }
            let type_node = parameter_type_node(right, source, || session.scope_step())?;
            let mut arms =
                resolve_php_type_node_arms(type_node, source, &ctx, || session.scope_step());
            (arms.len() == 1).then(|| arms.remove(0))
        },
    )
    .or_else(|| {
        let raw = phpdoc_var_element_type(declaration_doc_comment(declaration, source)?)?;
        resolve_php_type(&raw, &ctx)
    })
    .or_else(|| {
        let raw = promoted_property_doc_element_type(declaration, source, || session.scope_step())?;
        resolve_php_type(&raw, &ctx)
    })
    .or_else(|| {
        infer_constructor_assigned_field_type(
            class,
            source,
            field.identifier(),
            || session.scope_step(),
            |right| {
                let raw = parameter_doc_element_type(right, source, || session.scope_step())?;
                resolve_php_type(&raw, &ctx)
            },
        )
    })
}

fn php_relative_type_keyword_bounded<'a>(
    node: Node<'_>,
    source: &'a str,
    session: &ResolutionSession,
) -> Option<&'a str> {
    relative_declared_type_keyword(node, source, || session.scope_step())
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
            if let Some(type_node) = dominating_instanceof_type_node(object, source, || true) {
                return resolve_php_type_node(type_node, source, ctx, || true);
            }
            if name == "this" {
                return enclosing.fqn.clone();
            }
            if let Some(collection) = enclosing_foreach_collection(object, source, || true) {
                let facts = PhpAnalyzerFacts::new(php);
                return collection_element_type_fq_name(
                    php,
                    php_graph_source(php, &facts),
                    collection,
                    source,
                    ctx,
                    bindings,
                    &mut |_, _| enclosing.fqn.clone(),
                );
            }
            if let Some(collection) = enclosing_array_map_collection(
                object,
                source,
                ctx,
                || true,
                |candidate| {
                    php_fqn_candidates(support, candidate)
                        .iter()
                        .any(CodeUnit::is_function)
                },
            ) {
                let facts = PhpAnalyzerFacts::new(php);
                return collection_element_type_fq_name(
                    php,
                    php_graph_source(php, &facts),
                    collection,
                    source,
                    ctx,
                    bindings,
                    &mut |_, _| enclosing.fqn.clone(),
                );
            }
            php_precise_owner(bindings, name)
        }
        // `(new Foo())->member` — the receiver is typed by the constructed class.
        "object_creation_expression" => php_object_creation_type_with_session(object, session)
            .and_then(|type_node| {
                php_static_scope_fqn(php, support, type_node, source, ctx, enclosing, session)
            }),
        "parenthesized_expression" => object.named_child(0).and_then(|inner| {
            php_instance_receiver_fqn(
                php, analyzer, support, inner, source, enclosing, bindings, ctx, session,
            )
        }),
        "subscript_expression" => {
            let collection = object.named_child(0)?;
            let facts = PhpAnalyzerFacts::new(php);
            collection_element_type_fq_name(
                php,
                php_graph_source(php, &facts),
                collection,
                source,
                ctx,
                bindings,
                &mut |_, _| enclosing.fqn.clone(),
            )
        }
        "function_call_expression" | "scoped_call_expression" => {
            php_assignment_receiver_fqn(php, support, object, source, enclosing, ctx)
        }
        "scoped_property_access_expression" => php_expression_type_fqn(
            php, analyzer, support, object, source, enclosing, bindings, ctx, session,
        ),
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

/// The one class a local binding proves for `name`, or `None` when it proves
/// none or more than one.
///
/// The shared `first_precise` helper answers with an arbitrary member of a
/// multi-target precise set, which for a union-typed PHP local would be
/// first-arm-wins under another name. Every single-owner reader here must fail
/// closed on a union instead.
fn php_precise_owner(bindings: &LocalInferenceEngine<String>, name: &str) -> Option<String> {
    let mut owners = php_precise_owners(bindings, name);
    (owners.len() == 1).then(|| owners.remove(0))
}

/// Every class a local binding proves for `name`, in a stable order.
fn php_precise_owners(bindings: &LocalInferenceEngine<String>, name: &str) -> Vec<String> {
    let Some(targets) = bindings
        .resolve_symbol_ref(name)
        .and_then(SymbolResolution::as_precise)
    else {
        return Vec::new();
    };
    let mut owners = targets.iter().cloned().collect::<Vec<_>>();
    owners.sort();
    owners
}

/// The owner set the receiver of one member reference proves.
///
/// A receiver that types to exactly one class is the ordinary case and stays a
/// single owner. A receiver whose declared type is a finite union of nominal
/// arms is the bounded-ambiguity case: forward definition lookup is the one PHP
/// surface whose answer can carry the competing declarations, so the arms
/// travel to [`php_member_outcome`] instead of being dropped.
///
/// Unions are read at the FINAL receiver position only -- the expression
/// directly left of the queried member. An interior chain step that is
/// union-typed still fails closed, because each step must hand exactly one
/// owner to the next.
///
/// A receiver whose declaration proves dynamism -- the builtin `object` or
/// `mixed`, or PHP's variable-variable spelling -- is answered as such rather
/// than as an unresolved shape, because the two are different facts (#2030).
#[allow(clippy::too_many_arguments)]
fn php_instance_receiver_owners(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    object: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &PhpLocalBindings,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> PhpReceiverOwners {
    if let Some(single) = php_instance_receiver_fqn(
        php,
        analyzer,
        support,
        object,
        source,
        enclosing,
        &bindings.engine,
        ctx,
        session,
    ) {
        return PhpReceiverOwners::Nominal(vec![single]);
    }
    let object = php_unwrap_parenthesized(object);
    match object.kind() {
        // `$$name->m()`: the receiver is whichever variable the inner
        // expression spells at run time, which is dynamism the source states.
        "dynamic_variable_name" => PhpReceiverOwners::ProvenDynamic(
            "the receiver is a variable-variable, whose variable is chosen at run time".to_string(),
        ),
        "variable_name" => {
            let name = php_variable_identifier(object, source);
            if name == "this" {
                return PhpReceiverOwners::Unknown;
            }
            let owners = php_precise_owners(&bindings.engine, name);
            if owners.is_empty()
                && let Some(builtin) = bindings.dynamic.get(name)
            {
                return PhpReceiverOwners::ProvenDynamic(format!(
                    "`${name}` is declared `{builtin}`, which names no class"
                ));
            }
            PhpReceiverOwners::nominal(owners)
        }
        "member_access_expression" | "nullsafe_member_access_expression" => {
            php_receiver_member_unit(
                php,
                analyzer,
                support,
                object,
                source,
                enclosing,
                &bindings.engine,
                ctx,
                session,
                CodeUnit::is_field,
            )
            .map(|field| php_declared_unit_receiver_owners(php, analyzer, support, &field, session))
            .unwrap_or(PhpReceiverOwners::Unknown)
        }
        "member_call_expression" | "nullsafe_member_call_expression" => {
            if let Some(callable) = php_receiver_member_unit(
                php,
                analyzer,
                support,
                object,
                source,
                enclosing,
                &bindings.engine,
                ctx,
                session,
                CodeUnit::is_function,
            ) {
                php_declared_unit_receiver_owners(php, analyzer, support, &callable, session)
            } else if let Some((owner, member)) = php_unindexed_member_call_boundary(
                php,
                analyzer,
                support,
                object,
                source,
                enclosing,
                &bindings.engine,
                ctx,
                session,
            ) {
                PhpReceiverOwners::UnindexedBoundary { owner, member }
            } else {
                PhpReceiverOwners::Unknown
            }
        }
        "function_call_expression" | "scoped_call_expression" => {
            php_direct_callable_unit(php, support, object, source, enclosing, ctx, session)
                .map(|callable| {
                    php_declared_unit_receiver_owners(php, analyzer, support, &callable, session)
                })
                .unwrap_or(PhpReceiverOwners::Unknown)
        }
        _ => PhpReceiverOwners::Unknown,
    }
}

#[allow(clippy::too_many_arguments)]
fn php_unindexed_member_call_boundary(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    call: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> Option<(String, String)> {
    let object = call.child_by_field_name("object")?;
    let owner = php_instance_receiver_fqn(
        php, analyzer, support, object, source, enclosing, bindings, ctx, session,
    )?;
    if !php_crosses_unindexed_boundary(support, &owner) {
        return None;
    }
    let name = call.child_by_field_name("name")?;
    let member = if let Some(session) = session {
        php_literal_member_name(name, source, session)?.to_string()
    } else if name.kind() == "name" {
        php_node_text(name, source).to_string()
    } else {
        return None;
    };
    Some((owner, member))
}

/// The receiver reading of one declaration's declared type: its classes, or the
/// builtin it names when that builtin proves the value is dynamic.
fn php_declared_unit_receiver_owners(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    session: Option<&ResolutionSession>,
) -> PhpReceiverOwners {
    match php_declared_unit_type(php, analyzer, support, unit, session) {
        PhpDeclaredType::Nominal(arms) => PhpReceiverOwners::Nominal(arms),
        PhpDeclaredType::Dynamic(builtin) => PhpReceiverOwners::ProvenDynamic(format!(
            "`{}` is declared `{builtin}`, which names no class",
            unit.fq_name()
        )),
        PhpDeclaredType::Unknown => PhpReceiverOwners::Unknown,
    }
}

/// The one indexed declaration a member step on an instance receiver names.
///
/// This is the shared step both the receiver-typing chain and the union-arm
/// reader take: resolve the step's own receiver to one owner, then take the
/// owner's direct member of the wanted kind, or its inherited one when the
/// owner declares none. Anything ambiguous fails closed.
#[allow(clippy::too_many_arguments)]
fn php_receiver_member_unit(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    access: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    bindings: &LocalInferenceEngine<String>,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
    wanted: fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let object = access.child_by_field_name("object")?;
    let name = access.child_by_field_name("name")?;
    let owner = php_instance_receiver_fqn(
        php, analyzer, support, object, source, enclosing, bindings, ctx, session,
    )?;
    let member = php_node_text(name, source).trim_start_matches('$');
    if member.is_empty() {
        return None;
    }
    let mut candidates = php_fqn_candidates(support, &format!("{owner}.{member}"));
    if candidates.is_empty() {
        // A receiver-type probe, not the reference's own member answer, so it
        // stages no attribution.
        candidates = php_inherited_member_candidates(php, support, &owner, member, session, None);
    }
    candidates.retain(wanted);
    sort_units(&mut candidates);
    candidates.dedup();
    let [unit] = candidates.as_slice() else {
        return None;
    };
    Some(unit.clone())
}

/// The one indexed callable a literal free or scoped call names.
#[allow(clippy::too_many_arguments)]
fn php_direct_callable_unit(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    call: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    ctx: &FileContext,
    session: Option<&ResolutionSession>,
) -> Option<CodeUnit> {
    let callable_fqn = match call.kind() {
        "function_call_expression" => {
            let function = call.child_by_field_name("function")?;
            let candidates = match session {
                Some(session) => {
                    resolve_php_function_node(function, source, ctx, || session.scope_step())?
                }
                None => resolve_php_function(
                    &php_qualified_candidate_text_with_session(function, source, None),
                    ctx,
                )?,
            };
            php_bound_callable(support, &candidates).to_string()
        }
        "scoped_call_expression" => {
            let (scope, name) = php_static_member_parts(call)?;
            let owner = php_static_scope_fqn(php, support, scope, source, ctx, enclosing, session)?;
            let member = php_literal_member_name_unbounded(name, source)?;
            format!("{owner}.{member}")
        }
        _ => return None,
    };
    let mut definitions = php_fqn_candidates(support, &callable_fqn)
        .into_iter()
        .filter(CodeUnit::is_function);
    let callable = definitions.next()?;
    definitions.next().is_none().then_some(callable)
}

fn php_literal_member_name_unbounded<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "name")
        .then(|| php_node_text(node, source))
        .filter(|member| !member.is_empty())
}

/// What one declaration's declared type proves, on whichever path is active.
/// [`php_field_type_fqn`] and [`php_callable_return_type_fqn`] are the
/// exactly-one-arm readers of the same declarations.
fn php_declared_unit_type(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    session: Option<&ResolutionSession>,
) -> PhpDeclaredType {
    if let Some(session) = session {
        return php_declared_unit_type_bounded(php, support, unit, session);
    }
    let facts = PhpAnalyzerFacts::new(analyzer);
    declared_type_of(php, php_graph_source(analyzer, &facts), unit)
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
    let callable = php_receiver_member_unit(
        php,
        analyzer,
        support,
        call,
        source,
        enclosing,
        bindings,
        ctx,
        session,
        CodeUnit::is_function,
    )?;
    php_callable_return_type_fqn(php, analyzer, support, &callable, session)
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

/// The local bindings in force at one PHP reference site.
///
/// `engine` is the ordinary nominal binding state. `dynamic` records the
/// parameters whose declared type is the builtin `object` or `mixed`, mapped to
/// that builtin's spelling: those parameters bind no class, so the engine can
/// only shadow them, yet the declaration still proves the value's member
/// surface is decided at run time. Keeping the proof beside the engine is what
/// lets a receiver read of such a parameter refuse with a reason instead of a
/// generic miss (#2030).
struct PhpLocalBindings {
    engine: LocalInferenceEngine<String>,
    dynamic: HashMap<String, &'static str>,
}

#[allow(clippy::too_many_arguments)]
fn php_bindings_before(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
    enclosing: &PhpEnclosingType,
    ctx: &FileContext,
    support: &dyn BoundedDefinitionLookup,
    session: Option<&ResolutionSession>,
) -> PhpLocalBindings {
    let scopes = php_enclosing_scopes(root, byte, session);
    let mut bindings = PhpLocalBindings {
        engine: LocalInferenceEngine::new(LocalInferenceConfig::default()),
        dynamic: HashMap::default(),
    };
    for (scope_index, scope) in scopes.into_iter().enumerate() {
        if scope_index > 0 {
            bindings.engine = captured_local_scope_bindings(scope, source, &bindings.engine);
            match scope.kind() {
                "arrow_function" => {}
                "anonymous_function" | "anonymous_function_creation" => {
                    let captured = anonymous_function_capture_names(scope, source);
                    bindings.dynamic.retain(|name, _| captured.contains(name));
                }
                _ => bindings.dynamic.clear(),
            }
        }
        let mut stack = vec![scope];
        while let Some(node) = stack.pop() {
            if session.is_some_and(|session| !session.scope_step()) {
                return bindings;
            }
            if node.start_byte() >= byte {
                continue;
            }
            if node != scope && php_is_local_scope(node) {
                continue;
            }
            php_seed_parameters(node, source, ctx, enclosing, session, &mut bindings);
            if node.end_byte() <= byte {
                php_seed_assignment(
                    php,
                    analyzer,
                    file,
                    node,
                    source,
                    enclosing,
                    ctx,
                    support,
                    session,
                    &mut bindings.engine,
                );
            }
            let mut cursor = node.walk();
            let children = node
                .named_children(&mut cursor)
                .filter(|child| child.start_byte() < byte)
                .collect::<Vec<_>>();
            stack.extend(children.into_iter().rev());
        }
    }
    bindings
}

fn php_enclosing_scopes<'tree>(
    root: Node<'tree>,
    byte: usize,
    session: Option<&ResolutionSession>,
) -> Vec<Node<'tree>> {
    let mut scopes = vec![root];
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if session.is_some_and(|session| !session.scope_step()) {
            return scopes;
        }
        if node.start_byte() <= byte && byte < node.end_byte() {
            if node.id() != root.id() && php_is_local_scope(node) {
                scopes.push(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if session.is_some_and(|session| !session.scope_step()) {
                    return scopes;
                }
                stack.push(child);
            }
        }
    }
    scopes.sort_by_key(|scope| std::cmp::Reverse(scope.end_byte() - scope.start_byte()));
    scopes
}

/// Seed one scope's parameters, recording both what their declared types name
/// and which of them are declared with a builtin that names no class.
fn php_seed_parameters(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    enclosing: &PhpEnclosingType,
    session: Option<&ResolutionSession>,
    bindings: &mut PhpLocalBindings,
) {
    if session.is_none() {
        let dynamic = &mut bindings.dynamic;
        seed_parameter_types(node, source, &mut bindings.engine, |name, raw| {
            dynamic.remove(name);
            if let Some(builtin) = php_dynamic_type_keyword(raw) {
                dynamic.insert(name.to_string(), builtin);
            }
            if raw.eq_ignore_ascii_case("self") || raw.eq_ignore_ascii_case("static") {
                enclosing.fqn.clone().into_iter().collect()
            } else {
                resolve_php_type_arms(raw, ctx)
            }
        });
        return;
    }
    let session = session.expect("bounded parameter path");
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !session.scope_step() {
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
        bindings.dynamic.remove(name);
        let type_node = child.child_by_field_name("type");
        if let Some(builtin) = type_node.and_then(|type_node| {
            php_dynamic_type_keyword_node(type_node, source, || session.scope_step())
        }) {
            bindings.dynamic.insert(name.to_string(), builtin);
        }
        let arms = type_node
            .map(|type_node| {
                if php_relative_type_keyword_bounded(type_node, source, session).is_some_and(
                    |keyword| {
                        keyword.eq_ignore_ascii_case("self")
                            || keyword.eq_ignore_ascii_case("static")
                    },
                ) {
                    enclosing.fqn.clone().into_iter().collect()
                } else {
                    resolve_php_type_node_arms(type_node, source, ctx, || session.scope_step())
                }
            })
            .unwrap_or_default();
        if arms.is_empty() {
            bindings.engine.declare_shadow(name.to_string());
        } else {
            bindings.engine.seed_symbol_many(name.to_string(), arms);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn php_seed_assignment(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    _file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    ctx: &FileContext,
    support: &dyn BoundedDefinitionLookup,
    session: Option<&ResolutionSession>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    // The bounded evaluator is the session path's whole interpretation of a
    // right-hand side; only the unbounded legacy walk is restricted to the
    // shapes below. Both feed the one shared seeding rule, which decides
    // seed/alias/shadow.
    seed_assignment_binding(node, source, bindings, |right, bindings| {
        if let Some(session) = session {
            php_expression_type_fqn_bounded(
                php, support, right, source, enclosing, bindings, ctx, session,
            )
        } else {
            php_expression_type_fqn(
                php, analyzer, support, right, source, enclosing, bindings, ctx, None,
            )
        }
    });
}

/// The declared type of a right-hand side or direct call receiver on the
/// unbounded forward path. Parentheses are unwrapped by the caller.
fn php_assignment_receiver_fqn(
    php: &PhpAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    right: Node<'_>,
    source: &str,
    enclosing: &PhpEnclosingType,
    ctx: &FileContext,
) -> Option<String> {
    match right.kind() {
        "object_creation_expression" => php_object_creation_type_with_session(right, None)
            .and_then(|type_node| {
                php_static_scope_fqn(php, support, type_node, source, ctx, enclosing, None)
            }),
        "function_call_expression" => {
            let function = right.child_by_field_name("function")?;
            let raw = php_qualified_candidate_text_with_session(function, source, None);
            let candidates = resolve_php_function(&raw, ctx)?;
            php_declared_callable_return_type_fqn(
                php,
                support,
                php_bound_callable(support, &candidates),
                None,
            )
        }
        "scoped_call_expression" => {
            let (scope, name) = php_static_member_parts(right)?;
            let owner = php_static_scope_fqn(php, support, scope, source, ctx, enclosing, None)?;
            let method = php_node_text(name, source);
            if method.is_empty() {
                return None;
            }
            php_declared_callable_return_type_fqn(php, support, &format!("{owner}.{method}"), None)
        }
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
    if let Some(return_type) = PhpAnalyzerFacts::new(php).callable_return_type_fqn(callable_fqn) {
        return Some(return_type);
    }
    let mut definitions = support
        .fqn(callable_fqn)
        .into_iter()
        .filter(|unit| unit.is_function());
    let callable = definitions.next()?;
    if definitions.next().is_some() {
        return None;
    }
    let facts = PhpAnalyzerFacts::new(php);
    declared_callable_return_type_fq_name(php, php_graph_source(php, &facts), &callable)
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
    if let Some(return_type) = PhpAnalyzerFacts::new(analyzer).declaration_return_type_fqn(callable)
    {
        return Some(return_type);
    }
    session
        .is_none()
        .then(|| {
            let facts = PhpAnalyzerFacts::new(analyzer);
            declared_callable_return_type_fq_name(php, php_graph_source(analyzer, &facts), callable)
        })
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
    if let Some(field_type) = PhpAnalyzerFacts::new(analyzer).declaration_return_type_fqn(field) {
        return Some(field_type);
    }
    session
        .is_none()
        .then(|| {
            let facts = PhpAnalyzerFacts::new(analyzer);
            declared_field_type_fq_name(php, php_graph_source(analyzer, &facts), field)
        })
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

/// The one refusal both dynamic-member-name checks report.
fn php_dynamic_member_name_outcome(site_text: &str) -> DefinitionLookupOutcome {
    no_definition(
        PHP_DYNAMIC_RECEIVER,
        format!(
            "`{site_text}` names its PHP member with an expression, so which member it reaches is decided at run time"
        ),
    )
}

/// The instance member access whose member NAME `node` sits inside, when that
/// name is an expression rather than a literal identifier.
///
/// The walk stops at the FIRST access whose `name` field it reaches, so a
/// literal member nested inside a dynamic one (`$obj->{$this->key()}` queried
/// at `key`) answers for itself and is not swallowed by the outer site.
fn php_dynamic_member_name_access<'tree>(
    node: Node<'tree>,
    session: Option<&ResolutionSession>,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if session.is_some_and(|session| !session.scope_step()) {
            return None;
        }
        if matches!(
            parent.kind(),
            "member_call_expression"
                | "nullsafe_member_call_expression"
                | "member_access_expression"
                | "nullsafe_member_access_expression"
        ) && parent.child_by_field_name("name") == Some(current)
        {
            return (current.kind() != "name").then_some(parent);
        }
        current = parent;
    }
    None
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
    use crate::analyzer::CodeUnitIndex;
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
    fn bounded_lookup_respects_php_closure_capture_and_parameter_shadowing() {
        let source = r#"<?php
namespace Demo;
class Captured { public function run(): void {} }
class Wrong { public function run(): void {} }
class Consumer {
    private Captured $service;
    public function exercise(Captured $parameter): void {
        $local = $this->service;
        $arrow = fn () => $parameter->run();
        $assigned = fn () => $local->run();
        $explicit = function () use ($parameter) { $parameter->run(); };
        $byReference = function () use (&$local) { $local->run(); };
        $shadowed = fn (Wrong $parameter) => $parameter->run();
        $uncaptured = function () { $parameter->run(); };
    }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("Closures.php", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Closures.php");
        let tree = parse_php_tree(source).expect("PHP tree");

        for (needle, expected) in [
            ("$arrow = fn () => $parameter->run()", "Demo.Captured.run"),
            ("$assigned = fn () => $local->run()", "Demo.Captured.run"),
            (
                "$explicit = function () use ($parameter) { $parameter->run()",
                "Demo.Captured.run",
            ),
            (
                "$byReference = function () use (&$local) { $local->run()",
                "Demo.Captured.run",
            ),
            (
                "$shadowed = fn (Wrong $parameter) => $parameter->run()",
                "Demo.Wrong.run",
            ),
        ] {
            let site = php_site(source, &file, needle, "run");
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

        let needle = "$uncaptured = function () { $parameter->run()";
        let site = php_site(source, &file, needle, "run");
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
            panic!("bounded uncaptured lookup did not complete: {outcome:#?}");
        };
        assert!(value.definitions.is_empty(), "{value:#?}");
    }

    #[test]
    fn bounded_lookup_uses_exiting_negative_instanceof_guards() {
        let source = r#"<?php
namespace Demo;
class Stub { public int $position = 0; }
class Wrong { public int $position = 0; }
class Reader {
    private function value(mixed $value): mixed { return $value; }
    public function simple(mixed $item): void {
        if (!($item = $this->value($item)) instanceof Stub) { return; }
        echo $item->position;
    }
    public function disjunction(mixed $item): void {
        if (!($item = $this->value($item)) instanceof Stub || !$item->position) { return; }
        echo $item->position;
    }
    public function nonExiting(mixed $item): void {
        if (!($item = $this->value($item)) instanceof Stub) { echo 'no'; }
        echo $item->position;
    }
    public function reassigned(mixed $item): void {
        if (!($item = $this->value($item)) instanceof Stub) { return; }
        $item = new Wrong();
        echo $item->position;
    }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("Guards.php", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Guards.php");
        let tree = parse_php_tree(source).expect("PHP tree");

        for (needle, expected) in [
            (
                "echo $item->position;\n    }\n    public function disjunction",
                "Demo.Stub.position",
            ),
            ("|| !$item->position", "Demo.Stub.position"),
            (
                "echo $item->position;\n    }\n    public function nonExiting",
                "Demo.Stub.position",
            ),
            ("echo $item->position;\n    }\n}\n", "Demo.Wrong.position"),
        ] {
            let site = php_site(source, &file, needle, "position");
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

        let needle = "echo $item->position;\n    }\n    public function reassigned";
        let site = php_site(source, &file, needle, "position");
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
            panic!("bounded non-exiting guard lookup did not complete: {outcome:#?}");
        };
        assert!(value.definitions.is_empty(), "{value:#?}");
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
