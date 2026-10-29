use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupDiagnostic;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupType;

use brokk_bifrost_analysis::analyzer::usages::get_type::candidates_outcome;

use brokk_bifrost_analysis::analyzer::usages::get_type::candidates_outcome_with_target_kind;

use brokk_bifrost_analysis::analyzer::usages::get_type::no_type;

use brokk_bifrost_analysis::analyzer::usages::get_type::semantic_model_lookup_type;

use brokk_bifrost_analysis::analyzer::usages::get_type::type_reference_outcome;

use crate::analyzer::js_ts::providers::resolve_js_ts_source;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use brokk_bifrost_js_ts::syntax::compute_import_binder as compute_jsts_import_binder;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_js_ts::tsconfig::AliasResolver;

use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_js_ts::providers::JsTsSource;
use brokk_bifrost_js_ts::scope_source::is_core_binding_scope;
use brokk_bifrost_js_ts::syntax::{JsTsImportBinder, pattern_binder_identifiers};
use brokk_bifrost_js_ts::ts_owners::{
    jsts_identifier_candidates_unfiltered, node_text_matches, ts_function_return_property_owners,
    ts_namespace_import_member_candidates, ts_receiver_owner_candidates_at_byte,
    ts_resolve_type_text_to_property_owners,
};
use brokk_bifrost_js_ts::type_text::{jsts_type_space_candidates, ts_type_annotation_text};
use tree_sitter::{Node, Tree};

/// Bounded JS/TS type resolution: the same resolver, with every definition-index
/// lookup charged to the session through [`SessionChargedLookup`]. The tree
/// walks between lookups stay uncharged -- they are bounded by the file the
/// caller already read -- so the budget meters exactly the work that can fan
/// out across the workspace.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_js_ts_type_bounded(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    ResolutionSession::run_bounded(budget, cancellation, |session| {
        let charged = SessionChargedLookup { support, session };
        resolve_js_ts_type(analyzer, &charged, file, language, source, tree, site)
    })
}

/// Charges every [`BoundedDefinitionLookup`] question to a resolution session.
/// Once the session stops, every answer is empty; `finish` then reports the
/// terminal condition instead of the partial value, so exhaustion cannot be
/// mistaken for "no type".
struct SessionChargedLookup<'a> {
    support: &'a dyn BoundedDefinitionLookup,
    session: &'a ResolutionSession,
}

impl SessionChargedLookup<'_> {
    fn query_bool(&self, query: impl FnOnce() -> bool) -> bool {
        self.session.query(query).unwrap_or(false)
    }
}

impl BoundedDefinitionLookup for SessionChargedLookup<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.session.query_rows(|| self.support.fqn(fqn))
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        self.session
            .query_rows(|| self.support.fqn_in_language(fqn, language))
    }

    fn fqn_in_any_language(&self, fqn: &str) -> Vec<CodeUnit> {
        self.session
            .query_rows(|| self.support.fqn_in_any_language(fqn))
    }

    fn package_exists_in_any_language(&self, package: &str) -> bool {
        self.query_bool(|| self.support.package_exists_in_any_language(package))
    }

    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        self.session
            .query_rows(|| self.support.types_in_package(package, simple))
    }

    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        self.session
            .query_rows(|| self.support.by_normalized_fqn(normalized))
    }

    fn identifier(&self, ident: &str) -> Vec<CodeUnit> {
        self.session.query_rows(|| self.support.identifier(ident))
    }

    fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        self.session.query_rows(|| {
            self.support
                .members_for_owner_name(owner_fqn, normalized_owner_fqn, name)
        })
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.session
            .query_rows(|| self.support.file_identifier(file, ident))
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        self.session
            .query_rows(|| self.support.fqn_direct_children(fqn))
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        self.session
            .query(|| self.support.fqn_exists(fqn))
            .unwrap_or(false)
    }

    fn package_exists(&self, package: &str) -> bool {
        self.query_bool(|| self.support.package_exists(package))
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        self.query_bool(|| self.support.package_exists_in_language(package, language))
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.session
            .query(|| self.support.fqn_prefix_exists(prefix))
            .unwrap_or(false)
    }
}

fn resolve_js_ts_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("jsts_parse_failed", "JS/TS source could not be parsed");
    };
    if language == Language::JavaScript {
        return no_type(
            "javascript_declared_type_unsupported",
            "JavaScript type lookup only supports structured TypeScript declarations",
        );
    }
    // The one downcast for this route; see `get_definition::js_ts::resolve_js_ts`.
    let Some(host) = resolve_js_ts_source(analyzer, language) else {
        return no_type(
            "jsts_analyzer_unavailable",
            "no TypeScript analyzer is registered for this workspace",
        );
    };

    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_type(
            "no_reference_node",
            "no JS/TS syntax node at reference location",
        );
    };
    if is_callable_declaration_name(node) {
        return no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        );
    }

    let imports = compute_jsts_import_binder(source, tree);
    // The analyzer's shared resolver, so this route reuses its warm config and
    // workspace-package memos instead of building cold ones per call.
    let aliases = host.alias_resolver().as_ref();

    if let Some(type_node) = type_reference_node(node)
        && let Some(type_name) = type_reference_name(type_node, source)
    {
        let candidates = identifier_candidates(
            host, support, file, language, &imports, aliases, type_name, false,
        );
        if candidates.is_empty() {
            return model_type_outcome(
                analyzer,
                file,
                type_name,
                TypeLookupTargetKind::TypeReference,
            )
            .unwrap_or_else(|| {
                no_type(
                    "no_indexed_type_definition",
                    format!("`{type_name}` did not resolve to an indexed TypeScript type"),
                )
            });
        }
        return type_reference_outcome(type_name.to_string(), candidates);
    }

    if let Some(type_node) = declaration_type_node_for_reference(node, source, site) {
        return resolve_declared_type_text(
            analyzer,
            host,
            support,
            file,
            source,
            &imports,
            aliases,
            type_node,
            TypeLookupTargetKind::ValueExpression,
        );
    }

    let expression = semantic_expression(node);
    if expression.kind() == "call_expression"
        && let Some(callee_name) = call_expression_name(expression, source)
    {
        let candidates = identifier_candidates(
            host,
            support,
            file,
            language,
            &imports,
            aliases,
            &callee_name,
            true,
        );
        let mut owners = Vec::new();
        for candidate in candidates {
            owners.extend(ts_function_return_property_owners(
                host, support, &candidate, 0,
            ));
        }
        if !owners.is_empty() {
            return candidates_outcome(type_lookup_name(&owners, &callee_name), owners);
        }
    }

    if let Some(receiver) = selected_member_receiver(expression, source, site)
        .or_else(|| call_member_receiver(expression, source, site))
    {
        let owners = ts_receiver_owner_candidates_at_byte(
            host,
            support,
            file,
            source,
            tree.root_node(),
            &imports,
            aliases,
            receiver,
            site.focus_start_byte,
        );
        if owners.is_empty()
            && let Some(type_node) = local_binding_type_node_before(
                tree.root_node(),
                source,
                receiver,
                site.focus_start_byte,
            )
        {
            return resolve_declared_type_text(
                analyzer,
                host,
                support,
                file,
                source,
                &imports,
                aliases,
                type_node,
                TypeLookupTargetKind::ValueExpression,
            );
        }
        if !owners.is_empty() {
            return candidates_outcome(type_lookup_name(&owners, receiver), owners);
        }
    }

    if let Some(name) = identifier_text(expression, source)
        && let Some(type_node) =
            local_binding_type_node_before(tree.root_node(), source, name, site.focus_start_byte)
    {
        return resolve_declared_type_text(
            analyzer,
            host,
            support,
            file,
            source,
            &imports,
            aliases,
            type_node,
            TypeLookupTargetKind::ValueExpression,
        );
    }

    no_type(
        "no_explicit_type",
        format!(
            "`{}` does not have a supported explicit TypeScript type",
            site.text
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_declared_type_text(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    type_node: Node<'_>,
    target_kind: TypeLookupTargetKind,
) -> TypeLookupOutcome {
    let type_text = ts_type_annotation_text(type_node, source);
    // A union or intersection annotation names more than one type. Its arms
    // come from the annotation's own `union_type`/`intersection_type` nodes, so
    // every arm stays visible rather than reporting one precise type (#1477).
    if let Some(outcome) = multi_arm_annotation_outcome(
        host,
        support,
        file,
        source,
        imports,
        aliases,
        type_node,
        target_kind.clone(),
    ) {
        return outcome;
    }
    if let Some((type_name, candidates)) =
        qualified_imported_type_candidates(host, support, file, type_node, source, imports, aliases)
    {
        return candidates_outcome_with_target_kind(type_name, candidates, target_kind);
    }

    if let Some((type_name, candidates)) =
        named_type_candidates(host, support, file, imports, aliases, type_node, source)
    {
        return candidates_outcome_with_target_kind(type_name, candidates, target_kind);
    }
    if let Some(type_name) =
        brokk_bifrost_js_ts::type_text::ts_named_type_identifier(type_node, source)
        && let Some(outcome) = model_type_outcome(analyzer, file, type_name, target_kind.clone())
    {
        return outcome;
    }

    let owners = ts_resolve_type_text_to_property_owners(
        host, support, file, source, imports, aliases, &type_text, 0,
    );
    let owners = prefer_type_definitions(owners);
    if !owners.is_empty() {
        return candidates_outcome_with_target_kind(
            type_lookup_name(&owners, &type_text),
            owners,
            target_kind,
        );
    }

    no_type(
        "unsupported_type_annotation",
        format!("`{type_text}` is not a supported named TypeScript type"),
    )
}

fn model_type_outcome(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    type_name: &str,
    target_kind: TypeLookupTargetKind,
) -> Option<TypeLookupOutcome> {
    let overlay = analyzer.semantic_model_overlay()?;
    let matched = overlay.symbols_named(type_name);
    let records = matched
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.owner_id.is_none()
                && symbol.language == Language::TypeScript.config_label()
                && (symbol.name == type_name || symbol.qualified_name == type_name)
        })
        .collect::<Vec<Arc<SemanticModelSymbol>>>();
    if records.is_empty() {
        return None;
    }
    let complete = matched.disposition == SemanticModelOverlayDisposition::Unique
        && records.len() == 1
        && !records[0].provenance.ambiguous
        && records[0].provenance.completeness == SemanticModelCompleteness::Complete;
    let types = records
        .into_iter()
        .map(|symbol| semantic_model_lookup_type(file, &symbol))
        .collect::<Vec<_>>();
    let mut outcome = TypeLookupOutcome {
        status: if types.len() == 1 {
            TypeLookupStatus::Resolved
        } else {
            TypeLookupStatus::Ambiguous
        },
        reference: None,
        types,
        diagnostics: Vec::new(),
        target_kind,
    };
    if !complete {
        outcome.status = TypeLookupStatus::Ambiguous;
        outcome.diagnostics.push(TypeLookupDiagnostic {
            kind: "semantic_model_type_incomplete".to_string(),
            message: format!(
                "active semantic models do not publish one complete `{type_name}` type identity"
            ),
        });
    }
    Some(outcome)
}

#[allow(clippy::too_many_arguments)]
fn identifier_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = jsts_identifier_candidates_unfiltered(
        host,
        support,
        language,
        file,
        imports,
        aliases,
        name,
        value_position,
    );
    if !value_position {
        candidates = jsts_type_space_candidates(host, candidates);
    }
    candidates
}

fn type_reference_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(node.kind(), "type_identifier" | "predefined_type")
            && node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "type_annotation"
                        | "generic_type"
                        | "union_type"
                        | "intersection_type"
                        | "type_arguments"
                        | "extends_type_clause"
                        | "implements_clause"
                        | "constraint"
                )
            })
        {
            return Some(node);
        }
        if matches!(
            node.kind(),
            "statement_block"
                | "program"
                | "call_expression"
                | "member_expression"
                | "variable_declarator"
                | "function_declaration"
                | "method_definition"
        ) {
            return None;
        }
        node = node.parent()?;
    }
}

fn type_reference_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    source
        .get(node.start_byte()..node.end_byte())
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn is_callable_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    brokk_bifrost_core::analyzer::tree_walk::is_field_child(parent, node, "name")
        && matches!(
            parent.kind(),
            "function_declaration"
                | "function_signature"
                | "method_definition"
                | "method_signature"
                | "abstract_method_signature"
        )
}

fn declaration_type_node_for_reference<'tree>(
    mut node: Node<'tree>,
    source: &str,
    _site: &ResolvedReferenceSite,
) -> Option<Node<'tree>> {
    let name = _site.text.split('.').next().unwrap_or(_site.text.as_str());
    loop {
        match node.kind() {
            "required_parameter" | "optional_parameter" | "formal_parameter"
                if declaration_name_matches(node, source, name) =>
            {
                return node.child_by_field_name("type");
            }
            "variable_declarator" if declaration_name_matches(node, source, name) => {
                return node.child_by_field_name("type");
            }
            "public_field_definition" | "property_signature"
                if declaration_name_matches(node, source, name) =>
            {
                return node.child_by_field_name("type");
            }
            "function_declaration" | "method_definition" | "method_signature"
                if declaration_name_matches(node, source, name) =>
            {
                return node.child_by_field_name("return_type");
            }
            _ => {}
        }
        if matches!(node.kind(), "program" | "statement_block") {
            return None;
        }
        node = node.parent()?;
    }
}

fn local_binding_type_node_before<'tree>(
    root: Node<'tree>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> Option<Node<'tree>> {
    let focus = smallest_named_node_covering(root, before_byte, before_byte)?;
    let ancestor_ids = ancestor_ids(focus);
    let mut cursor = Some(focus);
    while let Some(scope) = cursor.and_then(nearest_binding_scope) {
        match local_binding_in_scope(scope, source, name, before_byte, &ancestor_ids) {
            BindingLookup::Found(type_node) => return Some(type_node),
            BindingLookup::Shadowed => return None,
            BindingLookup::NotFound => {}
        }
        cursor = scope.parent();
    }
    None
}

fn nearest_binding_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if is_binding_scope(node) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn is_binding_scope(node: Node<'_>) -> bool {
    is_core_binding_scope(node)
}

fn ancestor_ids(mut node: Node<'_>) -> Vec<usize> {
    let mut ids = Vec::new();
    loop {
        ids.push(node.id());
        let Some(parent) = node.parent() else {
            return ids;
        };
        node = parent;
    }
}

enum BindingLookup<'tree> {
    Found(Node<'tree>),
    Shadowed,
    NotFound,
}

fn local_binding_in_scope<'tree>(
    scope: Node<'tree>,
    source: &str,
    name: &str,
    before_byte: usize,
    ancestor_ids: &[usize],
) -> BindingLookup<'tree> {
    let scope_id = scope.id();
    let mut stack = vec![scope];
    let mut latest = None;
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node.id() != scope_id
            && is_binding_scope_boundary(node)
            && !ancestor_ids.contains(&node.id())
        {
            continue;
        }
        if binding_declaration_matches(node, source, name) {
            latest = latest_binding(latest, source, name, node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.start_byte() < before_byte {
                stack.push(child);
            }
        }
    }
    latest
        .map(|(_, binding)| binding)
        .unwrap_or(BindingLookup::NotFound)
}

fn is_binding_scope_boundary(node: Node<'_>) -> bool {
    is_binding_scope(node)
        || matches!(
            node.kind(),
            "class_declaration" | "abstract_class_declaration" | "interface_declaration"
        )
}

fn latest_binding<'tree>(
    current: Option<(usize, BindingLookup<'tree>)>,
    source: &str,
    name: &str,
    node: Node<'tree>,
) -> Option<(usize, BindingLookup<'tree>)> {
    if current
        .as_ref()
        .is_some_and(|(start_byte, _)| *start_byte > node.start_byte())
    {
        return current;
    }
    Some((
        node.start_byte(),
        binding_type_node(source, name, node)
            .map(BindingLookup::Found)
            .unwrap_or(BindingLookup::Shadowed),
    ))
}

fn binding_declaration_matches(node: Node<'_>, source: &str, name: &str) -> bool {
    match node.kind() {
        "required_parameter"
        | "optional_parameter"
        | "formal_parameter"
        | "variable_declarator" => declaration_name_matches(node, source, name),
        "assignment_expression" => node
            .child_by_field_name("left")
            .is_some_and(|left| identifier_text(left, source) == Some(name)),
        _ => false,
    }
}

fn binding_type_node<'tree>(source: &str, name: &str, node: Node<'tree>) -> Option<Node<'tree>> {
    let type_node = node.child_by_field_name("type")?;
    if child_text_matches(node, "name", source, name)
        || declaration_pattern_node(node)
            .is_some_and(|pattern| identifier_text(pattern, source) == Some(name))
    {
        return Some(type_node);
    }
    declaration_pattern_node(node)
        .filter(|pattern| pattern_binds_name(*pattern, source, name))
        .and_then(|_| object_type_property_type_node(type_node, source, name))
}

fn semantic_expression(mut node: Node<'_>) -> Node<'_> {
    loop {
        let Some(parent) = node.parent() else {
            return node;
        };
        let node_id = node.id();
        let parent_is_expression = match parent.kind() {
            "call_expression" => parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node_id),
            "member_expression" => {
                parent
                    .child_by_field_name("object")
                    .is_some_and(|object| object.id() == node_id)
                    || parent
                        .child_by_field_name("property")
                        .is_some_and(|property| property.id() == node_id)
            }
            "parenthesized_expression" | "await_expression" => true,
            _ => false,
        };
        if !parent_is_expression {
            return node;
        }
        node = parent;
    }
}

fn selected_member_receiver<'source>(
    node: Node<'_>,
    source: &'source str,
    site: &ResolvedReferenceSite,
) -> Option<&'source str> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    if !(object.start_byte() <= site.focus_start_byte && site.focus_end_byte <= object.end_byte()) {
        return None;
    }
    identifier_text(object, source)
}

fn call_member_receiver<'source>(
    node: Node<'_>,
    source: &'source str,
    site: &ResolvedReferenceSite,
) -> Option<&'source str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child_by_field_name("function")?;
    selected_member_receiver(callee, source, site)
}

fn call_expression_name(node: Node<'_>, source: &str) -> Option<String> {
    let callee = node.child_by_field_name("function")?;
    identifier_text(callee, source).map(str::to_string)
}

fn identifier_text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    match node.kind() {
        "identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern"
        | "type_identifier" => source
            .get(node.start_byte()..node.end_byte())
            .map(str::trim)
            .filter(|text| !text.is_empty()),
        _ => None,
    }
}

fn child_text_matches(node: Node<'_>, field: &str, source: &str, expected: &str) -> bool {
    node.child_by_field_name(field)
        .is_some_and(|child| node_text_matches(child, source, expected))
}

fn declaration_name_matches(node: Node<'_>, source: &str, expected: &str) -> bool {
    child_text_matches(node, "name", source, expected)
        || declaration_pattern_node(node)
            .is_some_and(|pattern| pattern_binds_name(pattern, source, expected))
}

fn declaration_pattern_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("pattern").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "identifier"
                    | "object_pattern"
                    | "array_pattern"
                    | "assignment_pattern"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            )
        })
    })
}

/// The outcome for an annotation that names more than one type, or `None` when
/// the annotation is not a union/intersection at all.
///
/// Returning `None` only for the one-arm case is what keeps every ordinary
/// annotation on exactly the path it took before: this seam only adds the arms
/// a single-name answer was hiding.
///
/// Once the tree says the annotation names two or more arms, this function
/// always answers rather than collapsing multiple receiver alternatives into
/// one precise type. A partly resolved union
/// (`ServiceA | ExternalLibService` with only `ServiceA` indexed) therefore
/// stays `Ambiguous`, and an `unresolved_type_arm` diagnostic names the arms
/// that no indexed definition backs, so the open arm is stated rather than
/// erased (#1477).
#[allow(clippy::too_many_arguments)]
fn multi_arm_annotation_outcome(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    type_node: Node<'_>,
    target_kind: TypeLookupTargetKind,
) -> Option<TypeLookupOutcome> {
    let arms = annotation_type_arms(type_node);
    if arms.len() < 2 {
        return None;
    }
    let mut types: Vec<TypeLookupType> = Vec::new();
    let mut open_arms: Vec<String> = Vec::new();
    for arm in arms {
        let Some((fqn, definitions)) =
            arm_type_candidates(host, support, file, source, imports, aliases, arm)
        else {
            if arm_can_denote_a_definition(arm) {
                open_arms.push(ts_type_annotation_text(arm, source));
            }
            continue;
        };
        if types
            .iter()
            .any(|existing| existing.fqn == fqn && existing.definitions == definitions)
        {
            continue;
        }
        types.push(TypeLookupType {
            fqn,
            definitions,
            semantic_model_id: None,
        });
    }

    if types.is_empty() {
        if open_arms.is_empty() {
            // Every arm is a primitive or literal: nothing nominal was hidden,
            // so the annotation keeps the path it had before this seam existed.
            return None;
        }
        return Some(TypeLookupOutcome {
            status: TypeLookupStatus::NoType,
            reference: None,
            types,
            diagnostics: vec![TypeLookupDiagnostic {
                kind: "unresolved_type_arm".to_string(),
                message: format!(
                    "no arm of this multi-arm type annotation resolved to an indexed \
                     TypeScript type: {open_arms:?}"
                ),
            }],
            target_kind,
        });
    }

    // `A | A`, or `A | null`, is the only way two arms collapse to one type with
    // nothing left open, and that answer really is precise.
    let ambiguous = types.len() > 1 || !open_arms.is_empty();
    let mut diagnostics = Vec::new();
    if ambiguous {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "ambiguous_type".to_string(),
            message: "reference resolved to multiple possible types".to_string(),
        });
    }
    if !open_arms.is_empty() {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "unresolved_type_arm".to_string(),
            message: format!(
                "these arms of the type annotation did not resolve to an indexed \
                 TypeScript type, so the resolved arms are not the complete set: \
                 {open_arms:?}"
            ),
        });
    }
    Some(TypeLookupOutcome {
        status: if ambiguous {
            TypeLookupStatus::Ambiguous
        } else {
            TypeLookupStatus::Resolved
        },
        reference: None,
        types,
        diagnostics,
        target_kind,
    })
}

/// Whether an unresolved arm could still name something the index does not
/// hold.
///
/// A primitive (`string`), a literal (`null`, `undefined`, `"a"`), `this`, and a
/// template literal type each denote a shape the grammar itself fixes -- no
/// class or interface hides behind them, so their failure to resolve leaves the
/// remaining arms complete. Every other arm shape can denote a declaration
/// (a nominal name, an unindexed dependency, a structural `{ run(): void }`),
/// so an unresolved one keeps the answer open.
fn arm_can_denote_a_definition(arm: Node<'_>) -> bool {
    !matches!(
        arm.kind(),
        "predefined_type"
            | "literal_type"
            | "existential_type"
            | "this_type"
            | "template_literal_type"
    )
}

/// The arms one type annotation names, read from the tree.
///
/// A `union_type` or `intersection_type` contributes each of its arms (nested
/// ones flattened, since `A | (B | C)` names three types); every other
/// annotation is one arm, which is what makes the single-type case indexable
/// by the same helper without changing its answer.
fn annotation_type_arms<'tree>(type_node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut pending = vec![unwrap_type_annotation(type_node)];
    let mut arms = Vec::new();
    let mut index = 0usize;
    while index < pending.len() {
        let node = pending[index];
        index += 1;
        match node.kind() {
            "union_type" | "intersection_type" | "parenthesized_type" => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                pending.extend(children);
            }
            _ => arms.push(node),
        }
    }
    arms
}

/// Strip the `type_annotation` wrapper (`: T`) so the arms come from the type
/// itself rather than from the colon-prefixed annotation node.
fn unwrap_type_annotation(node: Node<'_>) -> Node<'_> {
    if !matches!(
        node.kind(),
        "type_annotation" | "opting_type_annotation" | "omitting_type_annotation"
    ) {
        return node;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next().unwrap_or(node)
}

/// The named type one arm resolves to, through the same three lookups the
/// single-type path uses on a whole annotation: a namespace-qualified imported
/// type first, then the arm's own type name, then the property owners its type
/// text expands to (which is what unwraps a `Promise<Service>` arm).
///
/// Running all three per arm is what lets the multi-arm seam answer for every
/// annotation it claims: an arm is unresolved only when the single-type path
/// would also have failed on that arm alone.
fn arm_type_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    arm: Node<'_>,
) -> Option<(String, Vec<CodeUnit>)> {
    if let Some(qualified) =
        qualified_imported_type_candidates(host, support, file, arm, source, imports, aliases)
    {
        return Some(qualified);
    }
    let arm_text = ts_type_annotation_text(arm, source);
    if let Some(candidates) =
        named_type_candidates(host, support, file, imports, aliases, arm, source)
    {
        return Some(candidates);
    }
    let owners = prefer_type_definitions(ts_resolve_type_text_to_property_owners(
        host, support, file, source, imports, aliases, &arm_text, 0,
    ));
    (!owners.is_empty()).then(|| (type_lookup_name(&owners, &arm_text), owners))
}

#[allow(clippy::too_many_arguments)]
fn named_type_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    type_node: Node<'_>,
    source: &str,
) -> Option<(String, Vec<CodeUnit>)> {
    let type_name = brokk_bifrost_js_ts::type_text::ts_named_type_identifier(type_node, source)?;
    let candidates = identifier_candidates(
        host,
        support,
        file,
        Language::TypeScript,
        imports,
        aliases,
        type_name,
        false,
    );
    (!candidates.is_empty()).then(|| (type_name.to_string(), candidates))
}

#[allow(clippy::too_many_arguments)]
fn qualified_imported_type_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    type_node: Node<'_>,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
) -> Option<(String, Vec<CodeUnit>)> {
    let identifiers = type_identifier_texts(type_node, source);
    let namespace = identifiers.first()?;
    let type_name = identifiers.last()?;
    if namespace == type_name {
        return None;
    }
    let binding = imports.binding(namespace)?;
    let candidates = ts_namespace_import_member_candidates(
        host, support, file, binding, aliases, type_name, false,
    )?;
    (!candidates.is_empty()).then_some((type_name.clone(), candidates))
}

fn type_identifier_texts(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "identifier"
                | "type_identifier"
                | "property_identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) && let Some(text) = source
            .get(node.start_byte()..node.end_byte())
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            out.push(text.to_string());
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    out
}

fn prefer_type_definitions(owners: Vec<CodeUnit>) -> Vec<CodeUnit> {
    let type_definitions: Vec<_> = owners
        .iter()
        .filter(|unit| !unit.is_function())
        .cloned()
        .collect();
    if type_definitions.is_empty() {
        owners
    } else {
        type_definitions
    }
}

fn pattern_binds_name(node: Node<'_>, source: &str, name: &str) -> bool {
    pattern_binder_identifiers(node)
        .into_iter()
        .any(|binder| identifier_text(binder, source) == Some(name))
}

fn object_type_property_type_node<'tree>(
    type_node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![type_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "property_signature"
            && property_signature_name_matches(node, source, name)
            && let Some(property_type) = node.child_by_field_name("type")
        {
            return Some(property_type);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn property_signature_name_matches(node: Node<'_>, source: &str, name: &str) -> bool {
    child_text_matches(node, "name", source, name) || {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).any(|child| {
            matches!(
                child.kind(),
                "identifier"
                    | "property_identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) && identifier_text(child, source) == Some(name)
        })
    }
}

fn type_lookup_name(candidates: &[CodeUnit], fallback: &str) -> String {
    candidates
        .first()
        .map(|unit| unit.identifier().to_string())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod quicksilver_grammar_tests {
    use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex};
    use brokk_bifrost_js_ts::type_text::{jsts_type_space_candidates, jsts_value_space_candidates};

    #[test]
    fn merged_type_and_value_declarations_keep_their_spaces() {
        let (_dir, file, analyzer) = crate::test_typescript_project(
            "export interface Token {x:number} export const Token={make(){return 1;}};",
        );
        let candidates: Vec<_> = analyzer
            .top_level_declarations(&file)
            .into_iter()
            .filter(|unit| unit.terminal_name() == "Token")
            .collect();
        assert!(candidates.iter().any(CodeUnit::is_class), "{candidates:?}");
        assert!(candidates.iter().any(CodeUnit::is_field), "{candidates:?}");
        let values = jsts_value_space_candidates(&analyzer, candidates.clone());
        let types = jsts_type_space_candidates(&analyzer, candidates);
        assert!(!values.is_empty(), "{values:?}");
        assert_eq!(types.len(), 1, "{types:?}");
        assert!(values.iter().all(CodeUnit::is_field), "{values:?}");
        assert!(types[0].is_class(), "{types:?}");
        assert_ne!(values[0], types[0]);
    }
}
