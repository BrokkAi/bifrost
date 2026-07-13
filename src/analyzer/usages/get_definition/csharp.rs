use super::*;
use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{
    csharp_attribute_name_node, csharp_attribute_type_names, csharp_normalize_full_name,
};

pub(super) struct CSharpDefinitionProvider<'a> {
    csharp: &'a CSharpAnalyzer,
}

impl<'a> CSharpDefinitionProvider<'a> {
    pub(super) fn new(csharp: &'a CSharpAnalyzer) -> Self {
        Self { csharp }
    }

    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let exact: Vec<_> = self
            .csharp
            .declaration_candidates_by_fqn(fqn, false)
            .into_iter()
            .collect();
        if !exact.is_empty() {
            return exact;
        }
        self.csharp
            .declaration_candidates_by_fqn(fqn, true)
            .into_iter()
            .collect()
    }

    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        self.csharp
            .member_candidates_for_owner(owner_fqn, name)
            .into_iter()
            .collect()
    }

    fn package_exists(&self, package: &str) -> bool {
        self.csharp.workspace_namespace_exists(package)
    }

    fn type_exists(&self, fqn: &str) -> bool {
        self.fqn(fqn).into_iter().any(|unit| unit.is_class())
    }
}

pub(crate) enum CSharpTypeLookupResolution {
    Type {
        fqn: String,
        candidates: Vec<CodeUnit>,
        target_kind: TypeLookupTargetKind,
        ambiguous: bool,
    },
    InappropriateSymbolContext,
}

pub(crate) fn csharp_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<CSharpTypeLookupResolution> {
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
    let definitions = CSharpDefinitionProvider::new(csharp);
    let node = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    csharp_type_lookup_node_resolution(analyzer, csharp, &definitions, file, source, root, node)
}

pub(super) fn resolve_csharp(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return no_definition("csharp_analyzer_unavailable", "C# analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("csharp_parse_failed", "C# source could not be parsed");
    };
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C# definition",
                site.text
            ),
        );
    };
    if csharp_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a C# reference site", site.text),
        );
    }

    match csharp_reference_node(node) {
        Some(CSharpReferenceNode::Attribute(name)) => {
            csharp_attribute_outcome(csharp, definitions, file, name, source)
        }
        Some(CSharpReferenceNode::Type(type_node)) => {
            let reference = csharp_reference_type_text(type_node, source);
            // Prefer a type in the lexically enclosing scope (namespace/class) over
            // the scope-blind type resolver, so a bare `Config` inside `namespace B`
            // resolves to `B.Config` rather than a same-named sibling namespace's
            // (#431).
            if let Some(unit) = resolve_in_enclosing_scopes(
                analyzer,
                file,
                &reference,
                type_node.start_byte(),
                CodeUnit::is_class,
            ) {
                return candidates_outcome(vec![unit]);
            }
            csharp_type_outcome(csharp, definitions, file, &reference)
        }
        Some(CSharpReferenceNode::Constructor(creation)) => {
            resolve_csharp_constructor(csharp, definitions, file, source, creation)
        }
        Some(CSharpReferenceNode::Member { receiver, name }) => {
            let member = csharp_member_name_text(name, source);
            if member.is_empty() {
                return no_definition("no_member_name", "C# member reference is blank");
            }
            let owners = csharp_receiver_type_units(
                analyzer,
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                receiver,
            );
            let arity = csharp_invocation_arity(name, source);
            let outcome =
                csharp_member_outcome(analyzer, definitions, owners.clone(), member, arity, false);
            if outcome.status == DefinitionLookupStatus::NoDefinition {
                let extensions = csharp_extension_method_candidates(
                    csharp, analyzer, file, &owners, member, arity, false,
                );
                if !extensions.is_empty() {
                    return candidates_outcome(extensions);
                }
                let fallback = csharp_member_outcome(
                    analyzer,
                    definitions,
                    owners.clone(),
                    member,
                    arity,
                    true,
                );
                if fallback.status != DefinitionLookupStatus::NoDefinition {
                    return fallback;
                }
                let extensions = csharp_extension_method_candidates(
                    csharp, analyzer, file, &owners, member, arity, true,
                );
                if !extensions.is_empty() {
                    return candidates_outcome(extensions);
                }
                return fallback;
            }
            outcome
        }
        Some(CSharpReferenceNode::UnqualifiedMember(name)) => {
            let member = csharp_member_name_text(name, source);
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                name.start_byte(),
            );
            if bindings.is_shadowed(member) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{member}` is a local C# value or local function"),
                );
            }
            let owners = csharp_enclosing_class(analyzer, file, name.start_byte())
                .into_iter()
                .collect();
            let arity = csharp_invocation_arity(name, source);
            let outcome = csharp_member_outcome(analyzer, definitions, owners, member, arity, true);
            if outcome.status == DefinitionLookupStatus::NoDefinition
                && csharp_static_using_boundary_for_member(csharp, definitions, file)
            {
                return boundary(format!(
                    "`{member}` appears to cross a C# static using boundary not indexed in this workspace"
                ));
            }
            outcome
        }
        Some(CSharpReferenceNode::Identifier(identifier)) => {
            let text = csharp_node_text(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C# identifier is blank");
            }
            if let Some(outcome) = csharp_object_initializer_label_outcome(
                analyzer,
                csharp,
                definitions,
                file,
                source,
                identifier,
            ) {
                return outcome;
            }
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                identifier.start_byte(),
            );
            if csharp_is_type_reference_node(identifier) {
                let reference = csharp_reference_type_text(identifier, source);
                return csharp_type_outcome(csharp, definitions, file, &reference);
            }
            if !bindings.is_shadowed(text) {
                if csharp_is_unqualified_member_reference(identifier)
                    && let Some(owner) =
                        csharp_enclosing_class(analyzer, file, identifier.start_byte())
                {
                    let outcome =
                        csharp_member_outcome(analyzer, definitions, vec![owner], text, None, true);
                    if outcome.status != DefinitionLookupStatus::NoDefinition {
                        return outcome;
                    }
                }
                let outcome = csharp_type_outcome(csharp, definitions, file, text);
                if outcome.status != DefinitionLookupStatus::NoDefinition {
                    return outcome;
                }
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C# definition"),
            )
        }
        None => no_definition(
            "unsupported_csharp_reference_shape",
            format!(
                "`{}` is a C# `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn csharp_type_lookup_node_resolution(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<CSharpTypeLookupResolution> {
    if let Some(name) = csharp_attribute_name_node(node) {
        let names = csharp_attribute_type_names(name, source);
        let (candidates, ambiguous) = csharp.attribute_type_candidates_with_ambiguity(file, &names);
        return csharp_type_candidates_resolution_with_kind(
            names.first().map(String::as_str).unwrap_or_default(),
            candidates,
            TypeLookupTargetKind::TypeReference,
            ambiguous,
        );
    }

    if node.kind() == "member_access_expression"
        && let Some(receiver) = csharp_member_access_receiver(node)
    {
        let candidates =
            csharp_receiver_type_lookup_units(csharp, definitions, file, source, root, receiver);
        return csharp_type_candidates_resolution(csharp_node_text(receiver, source), candidates);
    }

    if csharp_is_type_reference_node(node) {
        let reference = csharp_reference_type_text(node, source);
        return csharp_type_candidates_resolution_with_kind(
            &reference,
            csharp_visible_type_output_candidates(csharp, definitions, file, &reference),
            TypeLookupTargetKind::TypeReference,
            false,
        );
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "member_access_expression"
            && csharp_member_access_receiver(parent) == Some(node)
        {
            let candidates =
                csharp_receiver_type_lookup_units(csharp, definitions, file, source, root, node);
            return csharp_type_candidates_resolution(csharp_node_text(node, source), candidates);
        }
        if csharp_is_callable_declaration_name(parent, node) {
            return Some(CSharpTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(resolution) = csharp_declaration_name_type_resolution(
            analyzer,
            csharp,
            definitions,
            file,
            source,
            root,
            parent,
            node,
        ) {
            return Some(resolution);
        }
    }

    if node.kind() != "identifier" {
        return None;
    }

    let name = csharp_node_text(node, source);
    let bindings = csharp_type_bindings_before_scoped(
        csharp,
        definitions,
        file,
        source,
        root,
        node.start_byte(),
    );
    let candidates = bindings
        .resolve_symbol(name)
        .as_precise()
        .map(|targets| targets.iter().cloned().collect())
        .unwrap_or_default();
    csharp_type_candidates_resolution(name, candidates)
}

fn csharp_receiver_type_lookup_units(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    if receiver.kind() == "identifier" {
        let name = csharp_node_text(receiver, source);
        let bindings = csharp_type_bindings_before_scoped(
            csharp,
            definitions,
            file,
            source,
            root,
            receiver.start_byte(),
        );
        if let Some(targets) = bindings.resolve_symbol(name).as_precise() {
            return targets.iter().cloned().collect();
        }
        if bindings.is_shadowed(name) {
            return Vec::new();
        }
    }
    csharp_receiver_type_units(
        csharp as &dyn IAnalyzer,
        csharp,
        definitions,
        file,
        source,
        root,
        receiver,
    )
}

#[allow(clippy::too_many_arguments)]
fn csharp_declaration_name_type_resolution(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    parent: Node<'_>,
    name: Node<'_>,
) -> Option<CSharpTypeLookupResolution> {
    match parent.kind() {
        "parameter" if parent.child_by_field_name("name") == Some(name) => {
            parent.child_by_field_name("type").and_then(|type_node| {
                csharp_type_node_resolution(
                    csharp,
                    definitions,
                    file,
                    &csharp_reference_type_text(type_node, source),
                )
            })
        }
        "variable_declarator" if parent.child_by_field_name("name") == Some(name) => {
            parent.parent().and_then(|declaration| {
                (declaration.kind() == "variable_declaration")
                    .then(|| declaration.child_by_field_name("type"))
                    .flatten()
                    .and_then(|type_node| {
                        csharp_type_node_resolution(
                            csharp,
                            definitions,
                            file,
                            &csharp_reference_type_text(type_node, source),
                        )
                    })
            })
        }
        _ if matches!(parent.kind(), "property_declaration" | "field_declaration")
            && parent.child_by_field_name("name") == Some(name) =>
        {
            let owner = csharp_enclosing_class(analyzer, file, name.start_byte())?;
            let fqn = csharp_member_declared_type_fq_name(
                csharp,
                file,
                &owner,
                csharp_node_text(name, source),
            )?;
            csharp_type_candidates_resolution(csharp_node_text(name, source), definitions.fqn(&fqn))
        }
        _ => {
            let name_text = csharp_node_text(name, source);
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                definitions,
                file,
                source,
                root,
                name.end_byte(),
            );
            let candidates = bindings
                .resolve_symbol(name_text)
                .as_precise()
                .map(|targets| targets.iter().cloned().collect())
                .unwrap_or_default();
            csharp_type_candidates_resolution(name_text, candidates)
        }
    }
}

fn csharp_is_callable_declaration_name(parent: Node<'_>, name: Node<'_>) -> bool {
    parent.child_by_field_name("name") == Some(name)
        && matches!(
            parent.kind(),
            "method_declaration" | "local_function_statement" | "constructor_declaration"
        )
}

fn csharp_type_node_resolution(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> Option<CSharpTypeLookupResolution> {
    csharp_type_candidates_resolution_with_kind(
        reference,
        csharp_visible_type_output_candidates(csharp, definitions, file, reference),
        TypeLookupTargetKind::ValueExpression,
        false,
    )
}

fn csharp_type_candidates_resolution(
    reference: &str,
    candidates: Vec<CodeUnit>,
) -> Option<CSharpTypeLookupResolution> {
    csharp_type_candidates_resolution_with_kind(
        reference,
        candidates,
        TypeLookupTargetKind::ValueExpression,
        false,
    )
}

fn csharp_type_candidates_resolution_with_kind(
    reference: &str,
    candidates: Vec<CodeUnit>,
    target_kind: TypeLookupTargetKind,
    ambiguous: bool,
) -> Option<CSharpTypeLookupResolution> {
    if candidates.is_empty() {
        return None;
    }
    let fqn = if candidates.len() == 1 {
        candidates[0].fq_name().to_string()
    } else {
        reference.to_string()
    };
    Some(CSharpTypeLookupResolution::Type {
        fqn,
        candidates,
        target_kind,
        ambiguous,
    })
}

fn csharp_type_bindings_before_scoped(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CodeUnit> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_type_active_path(
        csharp,
        definitions,
        file,
        source,
        root,
        cutoff_start,
        &mut bindings,
    );
    bindings
}

fn csharp_seed_type_active_path(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }

    if node.kind() == "local_function_statement"
        && let Some(name) = node.child_by_field_name("name")
        && name.start_byte() < cutoff_start
    {
        bindings.declare_shadow(csharp_node_text(name, source));
    }

    let enters_scope = CSHARP_SCOPE_NODES.contains(&node.kind());
    if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }

    if (node.kind() == "parameter" || csharp_is_local_variable_declaration(node))
        && node.end_byte() <= cutoff_start
    {
        csharp_seed_type_binding(node, csharp, definitions, file, source, bindings);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        csharp_seed_type_active_path(
            csharp,
            definitions,
            file,
            source,
            child,
            cutoff_start,
            bindings,
        );
    }
}

fn csharp_seed_type_binding(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    match node.kind() {
        "parameter" => {
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            let Some(type_node) = node.child_by_field_name("type") else {
                return;
            };
            csharp_seed_symbol_for_type(
                name,
                type_node,
                csharp,
                definitions,
                file,
                source,
                bindings,
            );
        }
        "variable_declaration" => {
            let Some(type_node) = node.child_by_field_name("type") else {
                return;
            };
            let inferred = csharp_node_text(type_node, source) == "var";
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                if inferred {
                    let candidates = csharp_object_created_type(child)
                        .map(|type_node| csharp_reference_type_text(type_node, source))
                        .map(|reference| {
                            csharp_logical_visible_type_candidates(
                                csharp,
                                definitions,
                                file,
                                &reference,
                            )
                        })
                        .unwrap_or_default();
                    if candidates.is_empty() {
                        bindings.declare_shadow(csharp_node_text(name, source));
                    } else {
                        bindings.seed_symbol_many(csharp_node_text(name, source), candidates);
                    }
                    continue;
                }
                csharp_seed_symbol_for_type(
                    name,
                    type_node,
                    csharp,
                    definitions,
                    file,
                    source,
                    bindings,
                );
            }
        }
        _ => {}
    }
}

fn csharp_seed_symbol_for_type(
    name: Node<'_>,
    type_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let binding_name = csharp_node_text(name, source);
    let reference = csharp_reference_type_text(type_node, source);
    let candidates = csharp_logical_visible_type_candidates(csharp, definitions, file, &reference);
    if candidates.is_empty() {
        bindings.declare_shadow(binding_name);
    } else {
        bindings.seed_symbol_many(binding_name, candidates);
    }
}

pub(super) fn parse_csharp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

enum CSharpReferenceNode<'tree> {
    Attribute(Node<'tree>),
    Type(Node<'tree>),
    Constructor(Node<'tree>),
    Member {
        receiver: Node<'tree>,
        name: Node<'tree>,
    },
    UnqualifiedMember(Node<'tree>),
    Identifier(Node<'tree>),
}

fn csharp_reference_node(node: Node<'_>) -> Option<CSharpReferenceNode<'_>> {
    if let Some(name) = csharp_attribute_name_node(node) {
        return Some(CSharpReferenceNode::Attribute(name));
    }

    let original = node;
    let mut current = node;
    while let Some(parent) = current.parent() {
        if (matches!(parent.kind(), "generic_name" | "qualified_name")
            && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte())
            || (parent.kind() == "member_access_expression"
                && !csharp_member_access_receiver(parent)
                    .is_some_and(|receiver| same_node(receiver, current))
                && !csharp_member_access_receiver(parent)
                    .is_some_and(|receiver| same_node(receiver, original))
                && (csharp_member_access_name(parent).is_some_and(|name| same_node(name, current))
                    || csharp_member_access_name(parent)
                        .is_some_and(|name| same_node(name, original))))
            || (parent.kind() == "object_creation_expression"
                && (parent.child_by_field_name("type") == Some(current)
                    || csharp_first_type_child(parent) == Some(current)))
        {
            current = parent;
        } else {
            break;
        }
    }

    match current.kind() {
        "member_access_expression" => Some(CSharpReferenceNode::Member {
            receiver: csharp_member_access_receiver(current)?,
            name: csharp_member_access_name(current)?,
        }),
        "object_creation_expression" => Some(CSharpReferenceNode::Constructor(current)),
        "identifier" | "type" => {
            if csharp_is_unqualified_invocation_target(current) {
                return Some(CSharpReferenceNode::UnqualifiedMember(current));
            }
            if csharp_is_type_reference_node(current) {
                return Some(CSharpReferenceNode::Type(current));
            }
            if csharp_is_unqualified_member_reference(current) {
                return Some(CSharpReferenceNode::Identifier(current));
            }
            Some(CSharpReferenceNode::Identifier(current))
        }
        "qualified_name" | "generic_name" | "nullable_type" | "array_type" => {
            Some(CSharpReferenceNode::Type(current))
        }
        _ => None,
    }
}

fn csharp_is_unqualified_invocation_target(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(node)
    })
}

fn csharp_invocation_arity(node: Node<'_>, source: &str) -> Option<usize> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "member_access_expression" | "qualified_name") {
            current = parent;
            continue;
        }
        if parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            return Some(csharp_argument_count(parent, source));
        }
        break;
    }
    None
}

fn csharp_member_name_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    csharp_node_text(node, source)
        .split('<')
        .next()
        .unwrap_or_default()
        .trim()
}

fn resolve_csharp_constructor(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    creation: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(type_node) = creation
        .child_by_field_name("type")
        .or_else(|| csharp_first_type_child(creation))
    else {
        return no_definition("no_reference_text", "C# constructor call has no type");
    };
    let reference = csharp_reference_type_text(type_node, source);
    if csharp.using_aliases_of(file).contains_key(&reference) {
        return csharp_type_outcome(csharp, definitions, file, &reference);
    }
    let owners = csharp_logical_visible_type_candidates(csharp, definitions, file, &reference);
    let mut constructors = Vec::new();
    for owner in &owners {
        constructors.extend(definitions.members_for_owner_name(
            &owner.fq_name(),
            crate::analyzer::csharp_source_identifier(owner),
        ));
    }
    sort_units(&mut constructors);
    constructors.dedup();
    let applicable = csharp_filter_candidates_by_arity(
        csharp,
        &constructors,
        Some(csharp_argument_count(creation, source)),
    );
    if !applicable.is_empty() {
        return candidates_outcome(applicable);
    }
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }
    csharp_type_outcome(csharp, definitions, file, &reference)
}

fn csharp_type_outcome(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> DefinitionLookupOutcome {
    let mut candidates =
        csharp_visible_type_output_candidates(csharp, definitions, file, reference);
    if candidates.is_empty() {
        candidates = definitions.fqn(reference);
    }
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if csharp_import_boundary_for_type(csharp, definitions, file, reference) {
        return boundary(format!(
            "`{reference}` appears to cross a C# using boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# type"),
    )
}

fn csharp_attribute_outcome(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let names = csharp_attribute_type_names(name, source);
    let (candidates, ambiguous_spelling) =
        csharp.attribute_type_candidates_with_ambiguity(file, &names);
    if !candidates.is_empty() {
        let mut outcome = candidates_outcome(candidates);
        if ambiguous_spelling {
            outcome.status = DefinitionLookupStatus::Ambiguous;
            outcome.diagnostics = vec![DefinitionLookupDiagnostic {
                kind: "ambiguous_definition".to_string(),
                message: "C# attribute name has multiple successful type-name spellings"
                    .to_string(),
            }];
        }
        return outcome;
    }
    if csharp_attribute_alias_boundary(csharp, definitions, file, name, source)
        || names
            .iter()
            .any(|name| csharp_import_boundary_for_type(csharp, definitions, file, name))
    {
        let reference = names.first().map(String::as_str).unwrap_or_default();
        return boundary(format!(
            "`{reference}` appears to cross a C# using boundary not indexed in this workspace"
        ));
    }
    let reference = names.first().map(String::as_str).unwrap_or_default();
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# attribute type"),
    )
}

fn csharp_attribute_alias_boundary(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: Node<'_>,
    source: &str,
) -> bool {
    let mut stack = vec![name];
    while let Some(current) = stack.pop() {
        if current.kind() == "alias_qualified_name" {
            let Some(alias) = current
                .child_by_field_name("alias")
                .or_else(|| current.child_by_field_name("qualifier"))
                .or_else(|| current.named_child(0))
            else {
                return false;
            };
            let alias = csharp_node_text(alias, source);
            return csharp
                .using_aliases_of(file)
                .get(alias)
                .is_some_and(|target| {
                    !definitions.type_exists(target) && !definitions.package_exists(target)
                });
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn csharp_member_outcome(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    fallback_when_inapplicable: bool,
) -> DefinitionLookupOutcome {
    if owners.is_empty() {
        return no_definition(
            "unsupported_csharp_receiver",
            format!("receiver for C# member `{member}` is not resolved"),
        );
    };

    let mut direct_candidates = Vec::new();
    if let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) {
        let mut seen_owner_fqns = HashSet::default();
        for owner in &owners {
            let mut parts = csharp.partial_type_parts(owner);
            if parts.is_empty() {
                parts.push(owner.clone());
            }
            for part in parts {
                let owner_fqn = part.fq_name();
                if seen_owner_fqns.insert(owner_fqn.clone()) {
                    direct_candidates
                        .extend(definitions.members_for_owner_name(&owner_fqn, member));
                }
            }
        }
    } else {
        for owner in &owners {
            direct_candidates.extend(definitions.members_for_owner_name(&owner.fq_name(), member));
        }
    }
    sort_units(&mut direct_candidates);
    direct_candidates.dedup();
    let applicable = csharp_filter_candidates_by_arity(analyzer, &direct_candidates, arity);
    if !applicable.is_empty() {
        return candidates_outcome(applicable);
    }
    if !direct_candidates.is_empty() {
        return if fallback_when_inapplicable {
            candidates_outcome(direct_candidates)
        } else {
            no_definition(
                "no_applicable_overload",
                format!("no C# member `{member}` overload accepts this call"),
            )
        };
    }

    if let Some(provider) = analyzer.type_hierarchy_provider() {
        let mut seen = HashSet::default();
        let mut level = Vec::new();
        for owner in owners {
            seen.insert(owner.clone());
            level.extend(provider.get_direct_ancestors(&owner));
        }
        while !level.is_empty() {
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates
                    .extend(definitions.members_for_owner_name(&ancestor.fq_name(), member));
                next_level.extend(provider.get_direct_ancestors(&ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            let applicable = csharp_filter_candidates_by_arity(analyzer, &level_candidates, arity);
            if !applicable.is_empty() {
                return candidates_outcome(applicable);
            }
            if !level_candidates.is_empty() {
                return if fallback_when_inapplicable {
                    candidates_outcome(level_candidates)
                } else {
                    no_definition(
                        "no_applicable_overload",
                        format!("no inherited C# member `{member}` overload accepts this call"),
                    )
                };
            }
            level = next_level;
        }
    }
    no_definition(
        "no_indexed_definition",
        format!("C# member `{member}` is not indexed as a definition"),
    )
}

fn csharp_object_initializer_label_outcome(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    label: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let initializer = csharp_object_initializer_for_label(label)?;
    let object_creation = initializer.parent()?;
    if object_creation.kind() != "object_creation_expression" {
        return None;
    }
    let type_node = object_creation
        .child_by_field_name("type")
        .or_else(|| csharp_first_type_child(object_creation))?;
    let type_name = csharp_reference_type_text(type_node, source);
    let mut owners = csharp_logical_visible_type_candidates(csharp, definitions, file, &type_name);
    if owners.len() != 1 {
        return None;
    }
    let owner = owners.remove(0);
    Some(csharp_member_outcome(
        analyzer,
        definitions,
        vec![owner],
        csharp_node_text(label, source),
        None,
        true,
    ))
}

fn csharp_is_unqualified_member_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "member_access_expression" {
        return csharp_member_access_receiver(parent)
            .is_some_and(|receiver| same_node(receiver, node));
    }
    if matches!(parent.kind(), "argument" | "attribute_argument")
        && parent.child_by_field_name("name") == Some(node)
    {
        return false;
    }
    !matches!(
        parent.kind(),
        "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "method_declaration"
            | "local_function_statement"
            | "constructor_declaration"
            | "property_declaration"
            | "parameter"
            | "variable_declarator"
            | "using_directive"
    )
}

fn csharp_filter_candidates_by_arity(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates.to_vec();
    };
    let applicable: Vec<_> = candidates
        .iter()
        .filter_map(|unit| {
            if !unit.is_function() {
                return None;
            }
            let callable_arity = csharp_callable_arity(analyzer, unit);
            callable_arity
                .accepts(expected)
                .then(|| (unit.clone(), callable_arity))
        })
        .collect();
    applicable.into_iter().map(|(unit, _)| unit).collect()
}

fn csharp_extension_method_candidates(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    receiver_owners: &[CodeUnit],
    member: &str,
    arity: Option<usize>,
    fallback_when_inapplicable: bool,
) -> Vec<CodeUnit> {
    let mut namespaces = csharp.using_namespaces_of(file);
    let static_using_types = csharp.static_using_types_of(file);
    let file_namespace = csharp.namespace_of_file(file);
    if !file_namespace.is_empty() {
        namespaces.push(file_namespace);
    }
    namespaces.sort();
    namespaces.dedup();
    let receiver_type_names = csharp_compatible_receiver_type_names(analyzer, receiver_owners);

    let mut candidates: Vec<_> = csharp
        .declaration_candidates_by_identifier(member)
        .into_iter()
        .filter(|unit| unit.is_function() && unit.identifier() == member)
        .filter(|unit| {
            csharp_extension_declaring_type_is_visible(
                analyzer,
                &namespaces,
                &static_using_types,
                unit,
            )
        })
        .filter(|unit| csharp_is_extension_method(analyzer, unit))
        .filter(|unit| {
            csharp_extension_receiver_is_compatible(analyzer, &receiver_type_names, unit)
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();

    if let Some(call_arity) = arity {
        let expected = call_arity + 1;
        let applicable = csharp_filter_candidates_by_arity(analyzer, &candidates, Some(expected));
        if !applicable.is_empty() {
            return applicable;
        }
        return if fallback_when_inapplicable {
            candidates
        } else {
            Vec::new()
        };
    }

    candidates
}

fn csharp_extension_declaring_type_is_visible(
    analyzer: &dyn IAnalyzer,
    namespaces: &[String],
    static_using_types: &[CodeUnit],
    unit: &CodeUnit,
) -> bool {
    namespaces
        .iter()
        .any(|namespace| unit.package_name() == namespace)
        || analyzer.parent_of(unit).is_some_and(|owner| {
            let owner = csharp_normalize_full_name(&owner.fq_name());
            static_using_types
                .iter()
                .any(|target| csharp_normalize_full_name(&target.fq_name()) == owner)
        })
}

fn csharp_extension_receiver_is_compatible(
    analyzer: &dyn IAnalyzer,
    receiver_type_names: &HashSet<String>,
    extension: &CodeUnit,
) -> bool {
    if receiver_type_names.is_empty() {
        return true;
    }
    let Some(extension_receiver) = csharp_extension_method_receiver_type(analyzer, extension)
    else {
        return true;
    };
    receiver_type_names.contains(&csharp_normalize_full_name(&extension_receiver))
}

fn csharp_compatible_receiver_type_names(
    analyzer: &dyn IAnalyzer,
    receiver_owners: &[CodeUnit],
) -> HashSet<String> {
    let mut compatible = HashSet::default();
    for owner in receiver_owners {
        compatible.insert(csharp_normalize_full_name(&owner.fq_name()));
        if let Some(provider) = analyzer.type_hierarchy_provider() {
            compatible.extend(
                provider
                    .get_ancestors(owner)
                    .into_iter()
                    .map(|ancestor| csharp_normalize_full_name(&ancestor.fq_name())),
            );
        }
    }
    compatible
}

fn csharp_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = csharp_node_text(receiver, source);
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                definitions,
                file,
                source,
                root,
                receiver.start_byte(),
            );
            if let Some(targets) = bindings.resolve_symbol(name).as_precise() {
                return targets.iter().cloned().collect();
            }
            if bindings.is_shadowed(name) {
                let legacy = csharp_legacy_bindings_before_scoped(
                    csharp,
                    file,
                    source,
                    root,
                    receiver.start_byte(),
                );
                first_precise(&legacy, name)
                    .map(|fqn| definitions.fqn(&fqn))
                    .unwrap_or_default()
            } else {
                let mut candidates = csharp_enclosing_member_type_units(
                    analyzer,
                    csharp,
                    definitions,
                    file,
                    receiver,
                    name,
                );
                if candidates.is_empty() {
                    candidates =
                        csharp_logical_visible_type_candidates(csharp, definitions, file, name);
                }
                candidates
            }
        }
        "this" => csharp_enclosing_class(analyzer, file, receiver.start_byte())
            .into_iter()
            .collect(),
        "base" => csharp_enclosing_class(analyzer, file, receiver.start_byte())
            .and_then(|owner| {
                analyzer
                    .type_hierarchy_provider()
                    .and_then(|provider| provider.get_ancestors(&owner).into_iter().next())
            })
            .into_iter()
            .collect(),
        "qualified_name" | "generic_name" => csharp_logical_visible_type_candidates(
            csharp,
            definitions,
            file,
            &csharp_reference_type_text(receiver, source),
        ),
        // `new Foo().Member` — the receiver is typed by the class being constructed.
        "object_creation_expression" => receiver
            .child_by_field_name("type")
            .map(|type_node| {
                csharp_logical_visible_type_candidates(
                    csharp,
                    definitions,
                    file,
                    &csharp_reference_type_text(type_node, source),
                )
            })
            .unwrap_or_default(),
        // `GetFoo().Member` / `obj.GetFoo().Member` — the receiver is typed by the
        // called method's declared return type.
        "invocation_expression" => csharp_invocation_return_type_units(
            analyzer,
            csharp,
            definitions,
            file,
            source,
            root,
            receiver,
        ),
        _ => Vec::new(),
    }
}

/// Type an `invocation_expression` receiver by the callee's declared return
/// type: resolve the invoked method's owner(s), then resolve the return type of
/// `owner.Method` (walking the type hierarchy) to a type CodeUnit.
fn csharp_invocation_return_type_units(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    invocation: Node<'_>,
) -> Vec<CodeUnit> {
    let Some(function) = invocation.child_by_field_name("function") else {
        return Vec::new();
    };
    let (owners, method): (Vec<CodeUnit>, &str) = match function.kind() {
        // `obj.Method()` — type the sub-receiver, look up `Method` on it.
        "member_access_expression" => {
            let Some(sub_receiver) = csharp_member_access_receiver(function) else {
                return Vec::new();
            };
            let Some(name_node) = function.child_by_field_name("name") else {
                return Vec::new();
            };
            let owners = csharp_receiver_type_units(
                analyzer,
                csharp,
                definitions,
                file,
                source,
                root,
                sub_receiver,
            );
            (owners, csharp_node_text(name_node, source))
        }
        // `Method()` — an unqualified call resolves against the enclosing class.
        "identifier" => {
            let owners = csharp_enclosing_class(analyzer, file, function.start_byte())
                .into_iter()
                .collect();
            (owners, csharp_node_text(function, source))
        }
        _ => return Vec::new(),
    };
    if owners.is_empty() || method.is_empty() {
        return Vec::new();
    }

    let mut return_type_units = Vec::new();
    for owner in csharp_owners_with_ancestors(analyzer, owners) {
        if let Some(type_fqn) = csharp_method_return_type_fq_name(csharp, file, &owner, method) {
            return_type_units.extend(definitions.fqn(&type_fqn));
        }
    }
    sort_units(&mut return_type_units);
    return_type_units.dedup();
    return_type_units
}

/// Expand a set of owner types to include their ancestors (for inherited
/// methods), preserving order and de-duplicating.
fn csharp_owners_with_ancestors(analyzer: &dyn IAnalyzer, owners: Vec<CodeUnit>) -> Vec<CodeUnit> {
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return owners;
    };
    let mut seen = HashSet::default();
    let mut expanded = Vec::new();
    for owner in owners {
        if seen.insert(owner.clone()) {
            expanded.push(owner.clone());
        }
        for ancestor in provider.get_ancestors(&owner) {
            if seen.insert(ancestor.clone()) {
                expanded.push(ancestor);
            }
        }
    }
    expanded
}

fn csharp_enclosing_member_type_units(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    receiver: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    let Some(owner) = csharp_enclosing_class(analyzer, file, receiver.start_byte()) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    csharp_collect_member_type_units(csharp, definitions, file, &owner, name, &mut candidates);
    if let Some(provider) = analyzer.type_hierarchy_provider() {
        for ancestor in provider.get_ancestors(&owner) {
            csharp_collect_member_type_units(
                csharp,
                definitions,
                file,
                &ancestor,
                name,
                &mut candidates,
            );
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_collect_member_type_units(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    owner: &CodeUnit,
    name: &str,
    candidates: &mut Vec<CodeUnit>,
) {
    if let Some(type_fqn) = csharp_member_declared_type_fq_name(csharp, file, owner, name) {
        candidates.extend(definitions.fqn(&type_fqn));
    }
}

fn csharp_visible_type_output_candidates(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp_visible_type_candidates(csharp, definitions, file, name);
    csharp.sort_type_candidates(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_logical_visible_type_candidates(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp_visible_type_candidates(csharp, definitions, file, name);
    csharp.sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn csharp_visible_type_candidates(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let _ = definitions;
    csharp.visible_type_candidates(file, name)
}

fn csharp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    if let Some(unit) = ClassRangeIndex::build(analyzer, file).enclosing_unit(byte) {
        return Some(unit.clone());
    }

    let range = Range {
        start_byte: byte,
        end_byte: byte.saturating_add(1),
        start_line: 0,
        end_line: 0,
    };
    let mut current = analyzer.enclosing_code_unit(file, &range)?;
    loop {
        if current.is_class() {
            return Some(current);
        }
        current = analyzer.parent_of(&current)?;
    }
}

fn csharp_import_boundary_for_type(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if csharp_alias_using_boundary_for_type(csharp, definitions, file, reference) {
        return true;
    }
    let simple = reference.rsplit('.').next().unwrap_or(reference);
    csharp
        .using_namespaces_of(file)
        .into_iter()
        .any(|namespace| {
            !definitions.package_exists(&namespace)
                && (reference == simple || reference.starts_with(&format!("{namespace}.")))
        })
}

fn csharp_alias_using_boundary_for_type(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    csharp
        .using_aliases_of(file)
        .get(reference)
        .is_some_and(|target| !definitions.type_exists(target))
}

fn csharp_static_using_boundary_for_member(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
) -> bool {
    csharp.import_statements(file).iter().any(|raw| {
        raw.trim()
            .trim_start_matches("global ")
            .trim_start_matches("using ")
            .trim_end_matches(';')
            .trim()
            .strip_prefix("static ")
            .is_some_and(|target| !definitions.type_exists(target.trim()))
    })
}

const CSHARP_SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "block",
    "for_statement",
    "for_each_statement",
    "using_statement",
    "catch_clause",
];

fn csharp_legacy_bindings_before_scoped(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<String> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_legacy_active_path(root, cutoff_start, csharp, file, source, &mut bindings);
    bindings
}

fn csharp_seed_legacy_active_path(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }
    let enters_scope = CSHARP_SCOPE_NODES.contains(&node.kind());
    if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }
    if (node.kind() == "parameter" || csharp_is_local_variable_declaration(node))
        && node.end_byte() <= cutoff_start
    {
        seed_csharp_bindings_before(node, cutoff_start, csharp, file, source, bindings);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        csharp_seed_legacy_active_path(child, cutoff_start, csharp, file, source, bindings);
    }
}

fn csharp_is_local_variable_declaration(node: Node<'_>) -> bool {
    node.kind() == "variable_declaration"
        && node
            .parent()
            .is_none_or(|parent| parent.kind() != "field_declaration")
}
