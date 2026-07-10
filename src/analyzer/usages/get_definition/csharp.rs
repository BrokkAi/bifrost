use super::*;
use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;

pub(crate) enum CSharpTypeLookupResolution {
    Type {
        fqn: String,
        candidates: Vec<CodeUnit>,
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

pub(crate) fn csharp_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<CSharpTypeLookupResolution> {
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
    let node = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    csharp_type_lookup_node_resolution(analyzer, csharp, support, file, source, root, node)
}

pub(super) fn resolve_csharp(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
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
            csharp_type_outcome(csharp, support, file, &reference)
        }
        Some(CSharpReferenceNode::Constructor(creation)) => {
            resolve_csharp_constructor(csharp, support, file, source, creation)
        }
        Some(CSharpReferenceNode::Member { receiver, name }) => {
            let member = csharp_member_name_text(name, source);
            if member.is_empty() {
                return no_definition("no_member_name", "C# member reference is blank");
            }
            let owners = csharp_receiver_type_units(
                analyzer,
                csharp,
                support,
                file,
                source,
                tree.root_node(),
                receiver,
            );
            let arity = csharp_invocation_arity(name, source);
            let outcome = csharp_member_outcome(analyzer, support, owners, member, arity);
            if outcome.status == DefinitionLookupStatus::NoDefinition {
                let extensions =
                    csharp_extension_method_candidates(csharp, analyzer, file, member, arity);
                if !extensions.is_empty() {
                    return candidates_outcome(extensions);
                }
            }
            outcome
        }
        Some(CSharpReferenceNode::UnqualifiedMember(name)) => {
            let member = csharp_member_name_text(name, source);
            let bindings = csharp_bindings_before_scoped(
                csharp,
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
            let outcome = csharp_member_outcome(analyzer, support, owners, member, arity);
            if outcome.status == DefinitionLookupStatus::NoDefinition
                && csharp_static_using_boundary_for_member(csharp, support, file)
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
                analyzer, csharp, support, file, source, identifier,
            ) {
                return outcome;
            }
            let bindings = csharp_bindings_before_scoped(
                csharp,
                file,
                source,
                tree.root_node(),
                identifier.start_byte(),
            );
            if csharp_is_type_reference_node(identifier) {
                let reference = csharp_reference_type_text(identifier, source);
                return csharp_type_outcome(csharp, support, file, &reference);
            }
            if !bindings.is_shadowed(text) {
                if csharp_is_unqualified_member_reference(identifier)
                    && let Some(owner) =
                        csharp_enclosing_class(analyzer, file, identifier.start_byte())
                {
                    let outcome = csharp_member_outcome(analyzer, support, vec![owner], text, None);
                    if outcome.status != DefinitionLookupStatus::NoDefinition {
                        return outcome;
                    }
                }
                let outcome = csharp_type_outcome(csharp, support, file, text);
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
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<CSharpTypeLookupResolution> {
    if node.kind() == "member_access_expression"
        && let Some(receiver) = csharp_member_access_receiver(node)
    {
        let candidates =
            csharp_receiver_type_lookup_units(csharp, support, file, source, root, receiver);
        return csharp_type_candidates_resolution(csharp_node_text(receiver, source), candidates);
    }

    if csharp_is_type_reference_node(node) {
        let reference = csharp_reference_type_text(node, source);
        return csharp_type_candidates_resolution_with_kind(
            &reference,
            csharp_visible_type_output_candidates(csharp, file, &reference),
            TypeLookupTargetKind::TypeReference,
        );
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "member_access_expression"
            && csharp_member_access_receiver(parent) == Some(node)
        {
            let candidates =
                csharp_receiver_type_lookup_units(csharp, support, file, source, root, node);
            return csharp_type_candidates_resolution(csharp_node_text(node, source), candidates);
        }
        if csharp_is_callable_declaration_name(parent, node) {
            return Some(CSharpTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(resolution) = csharp_declaration_name_type_resolution(
            analyzer, csharp, support, file, source, root, parent, node,
        ) {
            return Some(resolution);
        }
    }

    if node.kind() != "identifier" {
        return None;
    }

    let name = csharp_node_text(node, source);
    let bindings =
        csharp_type_bindings_before_scoped(csharp, file, source, root, node.start_byte());
    let candidates = bindings
        .resolve_symbol(name)
        .as_precise()
        .map(|targets| targets.iter().cloned().collect())
        .unwrap_or_default();
    csharp_type_candidates_resolution(name, candidates)
}

fn csharp_receiver_type_lookup_units(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    if receiver.kind() == "identifier" {
        let name = csharp_node_text(receiver, source);
        let bindings =
            csharp_type_bindings_before_scoped(csharp, file, source, root, receiver.start_byte());
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
        support,
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
    support: &DefinitionLookupIndex,
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
            csharp_type_candidates_resolution(csharp_node_text(name, source), support.fqn(&fqn))
        }
        _ => {
            let name_text = csharp_node_text(name, source);
            let bindings =
                csharp_type_bindings_before_scoped(csharp, file, source, root, name.end_byte());
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
    file: &ProjectFile,
    reference: &str,
) -> Option<CSharpTypeLookupResolution> {
    csharp_type_candidates_resolution_with_kind(
        reference,
        csharp_visible_type_output_candidates(csharp, file, reference),
        TypeLookupTargetKind::ValueExpression,
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
    )
}

fn csharp_type_candidates_resolution_with_kind(
    reference: &str,
    candidates: Vec<CodeUnit>,
    target_kind: TypeLookupTargetKind,
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
    })
}

fn csharp_type_bindings_before_scoped(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CodeUnit> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_type_active_path(csharp, file, source, root, cutoff_start, &mut bindings);
    bindings
}

fn csharp_seed_type_active_path(
    csharp: &CSharpAnalyzer,
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

    if matches!(node.kind(), "parameter" | "variable_declaration")
        && node.end_byte() <= cutoff_start
    {
        csharp_seed_type_binding(node, csharp, file, source, bindings);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        csharp_seed_type_active_path(csharp, file, source, child, cutoff_start, bindings);
    }
}

fn csharp_seed_type_binding(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
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
            csharp_seed_symbol_for_type(name, type_node, csharp, file, source, bindings);
        }
        "variable_declaration" => {
            let Some(type_node) = node.child_by_field_name("type") else {
                return;
            };
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                csharp_seed_symbol_for_type(name, type_node, csharp, file, source, bindings);
            }
        }
        _ => {}
    }
}

fn csharp_seed_symbol_for_type(
    name: Node<'_>,
    type_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let binding_name = csharp_node_text(name, source);
    if csharp_node_text(type_node, source) == "var" {
        bindings.declare_shadow(binding_name);
        return;
    }
    let reference = csharp_reference_type_text(type_node, source);
    let candidates = csharp_logical_visible_type_candidates(csharp, file, &reference);
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
    support: &DefinitionLookupIndex,
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
        return csharp_type_outcome(csharp, support, file, &reference);
    }
    let owners = csharp_logical_visible_type_candidates(csharp, file, &reference);
    let mut constructors = Vec::new();
    for owner in &owners {
        constructors.extend(support.fqn(&format!("{}.{}", owner.fq_name(), owner.identifier())));
    }
    sort_units(&mut constructors);
    constructors.dedup();
    constructors = csharp_filter_candidates_by_arity(
        constructors,
        Some(csharp_argument_count(creation, source)),
    );
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }
    csharp_type_outcome(csharp, support, file, &reference)
}

fn csharp_type_outcome(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = csharp_visible_type_output_candidates(csharp, file, reference);
    if candidates.is_empty() {
        candidates = support.fqn(reference);
    }
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if csharp_import_boundary_for_type(csharp, support, file, reference) {
        return boundary(format!(
            "`{reference}` appears to cross a C# using boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# type"),
    )
}

fn csharp_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
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
                    direct_candidates.extend(support.fqn(&format!("{owner_fqn}.{member}")));
                }
            }
        }
    } else {
        for owner in &owners {
            direct_candidates.extend(support.fqn(&format!("{}.{}", owner.fq_name(), member)));
        }
    }
    sort_units(&mut direct_candidates);
    direct_candidates.dedup();
    let direct_candidates = csharp_filter_candidates_by_arity(direct_candidates, arity);
    if !direct_candidates.is_empty() {
        return candidates_outcome(direct_candidates);
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
                level_candidates.extend(support.fqn(&format!("{}.{}", ancestor.fq_name(), member)));
                next_level.extend(provider.get_direct_ancestors(&ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            let level_candidates = csharp_filter_candidates_by_arity(level_candidates, arity);
            if !level_candidates.is_empty() {
                return candidates_outcome(level_candidates);
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
    support: &DefinitionLookupIndex,
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
    let type_name = csharp_node_text(type_node, source);
    let mut owners = csharp_logical_visible_type_candidates(csharp, file, type_name);
    if owners.len() != 1 {
        return None;
    }
    let owner = owners.remove(0);
    Some(csharp_member_outcome(
        analyzer,
        support,
        vec![owner],
        csharp_node_text(label, source),
        None,
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
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| unit.is_function() && csharp_signature_arity(unit.signature()) == expected)
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn csharp_extension_method_candidates(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    member: &str,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let mut namespaces = csharp.using_namespaces_of(file);
    let file_namespace = csharp.namespace_of_file(file);
    if !file_namespace.is_empty() {
        namespaces.push(file_namespace);
    }
    namespaces.sort();
    namespaces.dedup();

    let mut candidates: Vec<_> = csharp
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.is_function() && unit.identifier() == member)
        .filter(|unit| csharp_extension_declaring_type_is_visible(csharp, &namespaces, unit))
        .filter(|unit| csharp_is_extension_method(analyzer, unit))
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();

    if let Some(call_arity) = arity {
        let expected = call_arity + 1;
        let exact: Vec<_> = candidates
            .iter()
            .filter(|unit| csharp_signature_arity(unit.signature()) == expected)
            .cloned()
            .collect();
        if !exact.is_empty() {
            return exact;
        }
    }

    candidates
}

fn csharp_extension_declaring_type_is_visible(
    analyzer: &dyn IAnalyzer,
    namespaces: &[String],
    unit: &CodeUnit,
) -> bool {
    analyzer.parent_of(unit).is_some_and(|owner| {
        namespaces
            .iter()
            .any(|namespace| owner.package_name() == namespace)
    })
}

fn csharp_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = csharp_node_text(receiver, source);
            let bindings =
                csharp_bindings_before_scoped(csharp, file, source, root, receiver.start_byte());
            if let Some(fqn) = first_precise(&bindings, name) {
                return support.fqn(&fqn);
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else {
                let mut candidates = csharp_enclosing_member_type_units(
                    analyzer, csharp, support, file, receiver, name,
                );
                if candidates.is_empty() {
                    candidates = csharp_logical_visible_type_candidates(csharp, file, name);
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
        "qualified_name" | "generic_name" => {
            csharp_logical_visible_type_candidates(csharp, file, csharp_node_text(receiver, source))
        }
        // `new Foo().Member` — the receiver is typed by the class being constructed.
        "object_creation_expression" => receiver
            .child_by_field_name("type")
            .map(|type_node| {
                csharp_logical_visible_type_candidates(
                    csharp,
                    file,
                    csharp_node_text(type_node, source),
                )
            })
            .unwrap_or_default(),
        // `GetFoo().Member` / `obj.GetFoo().Member` — the receiver is typed by the
        // called method's declared return type.
        "invocation_expression" => csharp_invocation_return_type_units(
            analyzer, csharp, support, file, source, root, receiver,
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
    support: &DefinitionLookupIndex,
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
                support,
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
            return_type_units.extend(support.fqn(&type_fqn));
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
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    receiver: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    let Some(owner) = csharp_enclosing_class(analyzer, file, receiver.start_byte()) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    csharp_collect_member_type_units(csharp, support, file, &owner, name, &mut candidates);
    if let Some(provider) = analyzer.type_hierarchy_provider() {
        for ancestor in provider.get_ancestors(&owner) {
            csharp_collect_member_type_units(
                csharp,
                support,
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
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    owner: &CodeUnit,
    name: &str,
    candidates: &mut Vec<CodeUnit>,
) {
    if let Some(type_fqn) = csharp_member_declared_type_fq_name(csharp, file, owner, name) {
        candidates.extend(support.fqn(&type_fqn));
    }
}

fn csharp_visible_type_output_candidates(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp.visible_type_candidates(file, name);
    csharp.sort_type_candidates(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_logical_visible_type_candidates(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp.visible_type_candidates(file, name);
    csharp.sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn csharp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    if let Some(fqn) = ClassRangeIndex::build(analyzer, file).enclosing(byte) {
        return analyzer.definitions(fqn).next();
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
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if csharp_alias_using_boundary_for_type(csharp, support, file, reference) {
        return true;
    }
    let simple = reference.rsplit('.').next().unwrap_or(reference);
    csharp
        .using_namespaces_of(file)
        .into_iter()
        .any(|namespace| {
            !csharp_workspace_namespace_exists(support, &namespace)
                && (reference == simple || reference.starts_with(&format!("{namespace}.")))
        })
}

fn csharp_workspace_namespace_exists(support: &DefinitionLookupIndex, namespace: &str) -> bool {
    support.package_exists(namespace)
}

fn csharp_alias_using_boundary_for_type(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    csharp
        .using_aliases_of(file)
        .get(reference)
        .is_some_and(|target| !csharp_workspace_type_exists(support, target))
}

fn csharp_static_using_boundary_for_member(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
) -> bool {
    csharp.import_statements(file).iter().any(|raw| {
        raw.trim()
            .trim_start_matches("global ")
            .trim_start_matches("using ")
            .trim_end_matches(';')
            .trim()
            .strip_prefix("static ")
            .is_some_and(|target| !csharp_workspace_type_exists(support, target.trim()))
    })
}

fn csharp_workspace_type_exists(support: &DefinitionLookupIndex, reference: &str) -> bool {
    support.fqn_exists(reference) || support.normalized_fqn_exists(reference)
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

fn csharp_bindings_before_scoped(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<String> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_active_path(root, cutoff_start, csharp, file, source, &mut bindings);
    bindings
}

fn csharp_seed_active_path(
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
        seed_csharp_bindings_before(node, cutoff_start, csharp, file, source, bindings);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        csharp_seed_active_path(child, cutoff_start, csharp, file, source, bindings);
    }
}

fn csharp_is_local_variable_declaration(node: Node<'_>) -> bool {
    node.kind() == "variable_declaration"
        && node
            .parent()
            .is_none_or(|parent| parent.kind() != "field_declaration")
}
