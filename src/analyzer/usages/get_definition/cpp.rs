use super::*;
use crate::analyzer::resolve_include_targets_with_index;
use crate::analyzer::usages::cpp_call_match::{
    CppArgType, cpp_filter_candidates_by_args, cpp_literal_type_name, cpp_parameter_type_text,
    cpp_type_text_pointer_depth, normalize_cpp_type_name,
};

pub(crate) const CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC: &str = "unproven_cpp_link_unit";

pub(super) fn resolve_cpp(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return no_definition("cpp_analyzer_unavailable", "C++ analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("cpp_parse_failed", "C++ source could not be parsed");
    };
    let visibility = context.cpp_visibility(cpp, analyzer, file);
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C++ definition",
                site.text
            ),
        );
    };
    let reference = cpp_reference_node(node);
    if let Some(CppReferenceNode::Type(type_node)) = reference {
        if cpp_is_type_declaration_name(node) {
            return no_definition(
                "declaration_or_import_site",
                format!("`{}` is not a C++ reference site", site.text),
            );
        }
        return resolve_cpp_type(
            analyzer,
            context,
            file,
            visibility.as_ref(),
            source,
            type_node,
        );
    }

    let support = context.bounded_support();
    let ctx = CppLookupCtx {
        analyzer,
        support,
        file,
        visibility: visibility.as_ref(),
        source,
        root,
    };
    match reference {
        Some(CppReferenceNode::Type(_)) => unreachable!("type references returned above"),
        Some(CppReferenceNode::Constructor(constructor)) => {
            resolve_cpp_constructor(ctx, constructor)
        }
        Some(CppReferenceNode::Call(call)) => resolve_cpp_call(ctx, call),
        Some(CppReferenceNode::Field(field)) => resolve_cpp_field(ctx, field, None, None),
        Some(CppReferenceNode::Identifier(identifier)) => {
            if let Some(designator_owner) =
                cpp_designated_initializer_owner(ctx.visibility, ctx.file, ctx.source, identifier)
            {
                let member = cpp_node_text(identifier, ctx.source);
                let CppDesignatedInitializerOwner::Resolved(owner) = designator_owner else {
                    return no_definition(
                        "unresolved_designated_initializer_owner",
                        format!("aggregate owner for designated field `{member}` is unresolved"),
                    );
                };
                let candidates = cpp_member_candidates(ctx, vec![owner], member, None, None)
                    .into_iter()
                    .filter(CodeUnit::is_field)
                    .collect::<Vec<_>>();
                return if candidates.is_empty() {
                    no_definition(
                        "no_indexed_definition",
                        format!("`{member}` did not resolve to an indexed C++ field"),
                    )
                } else {
                    candidates_outcome(candidates)
                };
            }
            if cpp_is_declaration_name(node) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a C++ reference site", site.text),
                );
            }
            let text = cpp_node_text(identifier, ctx.source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C++ identifier is blank");
            }
            let bindings = cpp_local_bindings_before(ctx, identifier, identifier.start_byte());
            if bindings.is_shadowed(text) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local C++ value"),
                );
            }
            if let Some(owner) = cpp_enclosing_class(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                identifier.start_byte(),
            ) {
                let member_candidates = cpp_member_candidates(ctx, vec![owner], text, None, None)
                    .into_iter()
                    .filter(|unit| unit.is_field())
                    .collect::<Vec<_>>();
                if !member_candidates.is_empty() {
                    return candidates_outcome(member_candidates);
                }
            }
            let candidates = ctx
                .support
                .file_identifier(ctx.file, text)
                .into_iter()
                .filter(|unit| {
                    cpp_unit_matches_kind(
                        ctx.analyzer,
                        ctx.support,
                        unit,
                        CppTargetKind::GlobalField,
                    )
                })
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            let candidates = cpp_visible_name_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                text,
                Some(CppTargetKind::GlobalField),
                cpp_lexical_namespace(identifier, ctx.source).as_deref(),
            );
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C++ definition"),
            )
        }
        None => no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "`{}` is a C++ `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

pub(super) fn parse_cpp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

#[derive(Clone, Copy)]
enum CppReferenceNode<'tree> {
    Type(Node<'tree>),
    Constructor(Node<'tree>),
    Call(Node<'tree>),
    Field(Node<'tree>),
    Identifier(Node<'tree>),
}

#[derive(Clone, Copy)]
struct CppLookupCtx<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    visibility: &'a CppVisibilityIndex,
    source: &'a str,
    root: Node<'tree>,
}

fn cpp_reference_node(node: Node<'_>) -> Option<CppReferenceNode<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "ERROR"
            && parent.parent().is_some_and(|call| {
                call.kind() == "call_expression"
                    && cpp_explicit_operator_name(call) == Some(current)
            })
        {
            current = parent.parent()?;
            continue;
        }
        if matches!(
            parent.kind(),
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
        ) && qualified_access_focus(current, parent, &["scope"], &["name"])
            == Some(QualifiedAccessFocus::Member)
        {
            current = parent;
            continue;
        }
        if matches!(
            parent.kind(),
            "dependent_name" | "template_function" | "template_method" | "template_type"
        ) && parent.child_by_field_name("name") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "new_expression"
            && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte()
        {
            current = parent;
            continue;
        }
        if parent.kind() == "compound_literal_expression"
            && parent.child_by_field_name("type") == Some(current)
        {
            current = parent;
            continue;
        }
        break;
    }

    match current.kind() {
        "new_expression" | "compound_literal_expression" => {
            Some(CppReferenceNode::Constructor(current))
        }
        "call_expression" => Some(CppReferenceNode::Call(current)),
        "field_expression" => Some(CppReferenceNode::Field(current)),
        "type_identifier"
        | "namespace_identifier"
        | "qualified_identifier"
        | "template_type"
        | "scoped_type_identifier" => Some(CppReferenceNode::Type(current)),
        "identifier"
        | "field_identifier"
        | "operator_name"
        | "operator_cast"
        | "destructor_name"
        | "literal_operator_name" => Some(CppReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn cpp_is_type_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
                | "alias_declaration"
                | "type_definition"
        )
}

fn resolve_cpp_type(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    visibility: &CppVisibilityIndex,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = normalize_cpp_type_text(cpp_node_text(node, source));
    if text.is_empty() {
        return no_definition("no_reference_text", "C++ type reference is blank");
    }
    if cpp_qualified_identifier_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{text}` is not a C++ reference site"),
        );
    }
    if let Some(template_node) = cpp_template_application_node(node) {
        match visibility.resolve_type_node_result(file, template_node, source) {
            Ok(Some(unit))
                if visibility.external_type_candidate_visible_at(
                    file,
                    &unit,
                    node.start_byte(),
                ) =>
            {
                return candidates_outcome(cpp_type_definition_candidates(
                    analyzer,
                    visibility,
                    file,
                    context.bounded_support(),
                    unit,
                ));
            }
            Err(()) => {
                return ambiguous_definition(format!(
                    "`{text}` has an ambiguous C++ template specialization"
                ));
            }
            Ok(Some(_)) | Ok(None) => {}
        }
    }
    if let Some(qualifier) = cpp_focused_type_qualifier(node, source) {
        let namespace = cpp_lexical_namespace(node, source);
        let mut root = node;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        let enclosing_owner = {
            let class_ranges = context.cpp_class_ranges(file);
            let support = context.bounded_support();
            cpp_enclosing_class_with_ranges(
                analyzer,
                support,
                visibility,
                file,
                source,
                root,
                node.start_byte(),
                &class_ranges,
            )
        };
        let enclosing_classes = enclosing_owner
            .map(|owner| context.cpp_enclosing_class_chain(owner))
            .unwrap_or_default();
        let candidates = cpp_focused_type_qualifier_candidates(
            analyzer,
            context,
            visibility,
            file,
            &qualifier,
            namespace.as_deref(),
            &enclosing_classes,
        )
        .into_iter()
        .filter(|candidate| {
            visibility.external_type_candidate_visible_at(file, candidate, node.start_byte())
        })
        .collect::<Vec<_>>();
        if !candidates.is_empty() {
            let support = context.bounded_support();
            let candidates = candidates
                .into_iter()
                .flat_map(|unit| {
                    cpp_type_definition_candidates(analyzer, visibility, file, support, unit)
                })
                .collect();
            return candidates_outcome(candidates);
        }
        if cpp_unresolved_include_boundary(analyzer, file, &qualifier.reference) {
            return boundary(format!(
                "`{}` appears to cross a C++ include boundary not indexed in this workspace",
                qualifier.reference
            ));
        }
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C++ type qualifier",
                qualifier.reference
            ),
        );
    }
    resolve_cpp_type_without_focused_qualifier(
        analyzer,
        context.bounded_support(),
        file,
        visibility,
        source,
        node,
        &text,
    )
}

fn cpp_template_application_node(mut node: Node<'_>) -> Option<Node<'_>> {
    let mut application = (node.kind() == "template_type").then_some(node);
    while let Some(parent) = node.parent() {
        if parent.kind() == "template_type" && parent.child_by_field_name("name") == Some(node) {
            node = parent;
            application = Some(node);
            continue;
        }
        if application.is_some()
            && matches!(
                parent.kind(),
                "qualified_identifier" | "scoped_type_identifier"
            )
            && parent.child_by_field_name("name") == Some(node)
        {
            node = parent;
            application = Some(node);
            continue;
        }
        break;
    }
    application
}

fn resolve_cpp_type_without_focused_qualifier(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    visibility: &CppVisibilityIndex,
    source: &str,
    node: Node<'_>,
    text: &str,
) -> DefinitionLookupOutcome {
    if node.kind() == "qualified_identifier"
        && let (Some(scope), Some(name)) = (
            node.child_by_field_name("scope"),
            node.child_by_field_name("name"),
        )
        && let Some(owner) = visibility.resolve_type(file, cpp_node_text(scope, source))
        && visibility.external_type_candidate_visible_at(file, &owner, node.start_byte())
    {
        let candidates =
            cpp_direct_member_candidates(analyzer, support, &[owner], cpp_node_text(name, source));
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    // Prefer a type declared in the lexically enclosing scope (namespace/class)
    // over the scope-blind visibility index, so a bare `Config` inside `namespace B`
    // resolves to `B::Config` rather than a same-named sibling namespace's (#431).
    if node.kind() == "type_identifier" {
        match cpp_enclosing_lexical_scope_components(node, analyzer, visibility, file, source) {
            CppLexicalScopeResolution::Resolved(scope) => {
                match visibility.resolve_type_components_lexically_for_forward(
                    analyzer,
                    file,
                    &[text.to_string()],
                    false,
                    &scope,
                ) {
                    CppLexicalTypeResolution::Resolved { unit, .. }
                        if visibility.external_type_candidate_visible_at(
                            file,
                            &unit,
                            node.start_byte(),
                        ) =>
                    {
                        return candidates_outcome(cpp_type_definition_candidates(
                            analyzer, visibility, file, support, unit,
                        ));
                    }
                    CppLexicalTypeResolution::Ambiguous => {
                        return ambiguous_definition(format!(
                            "`{text}` resolves ambiguously in its enclosing C++ class or namespace"
                        ));
                    }
                    CppLexicalTypeResolution::Resolved { .. }
                    | CppLexicalTypeResolution::Missing => {}
                }
            }
            CppLexicalScopeResolution::Ambiguous => {
                return ambiguous_definition(format!(
                    "the enclosing C++ owner of `{text}` resolves ambiguously"
                ));
            }
            CppLexicalScopeResolution::Missing => {}
        }
        if let Some(unit) =
            resolve_in_enclosing_scopes(analyzer, file, text, node.start_byte(), CodeUnit::is_class)
        {
            return candidates_outcome(vec![unit]);
        }
    }
    if let Some(unit) = visibility.resolve_type(file, text)
        && visibility.external_type_candidate_visible_at(file, &unit, node.start_byte())
    {
        return candidates_outcome(cpp_type_definition_candidates(
            analyzer, visibility, file, support, unit,
        ));
    }
    let namespace = cpp_lexical_namespace(node, source);
    let candidates = cpp_visible_name_candidates(
        analyzer,
        visibility,
        file,
        support,
        text,
        Some(CppTargetKind::Type),
        namespace.as_deref(),
    )
    .into_iter()
    .filter(|candidate| {
        visibility.external_type_candidate_visible_at(file, candidate, node.start_byte())
    })
    .collect::<Vec<_>>();
    if !candidates.is_empty() {
        let candidates = candidates
            .into_iter()
            .flat_map(|unit| {
                cpp_type_definition_candidates(analyzer, visibility, file, support, unit)
            })
            .collect();
        return candidates_outcome(candidates);
    }
    if cpp_unresolved_include_boundary(analyzer, file, text) {
        return boundary(format!(
            "`{text}` appears to cross a C++ include boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed C++ type"),
    )
}

struct CppFocusedQualifier {
    reference: String,
    identifier: String,
    components: Vec<String>,
    globally_qualified: bool,
}

/// Returns the type path denoted by a focused `::` qualifier. Tree-sitter nests
/// the components after the first one through successive `name` fields, so walk
/// those structural parents and prepend each preceding `scope` field. A terminal
/// member is deliberately excluded from the returned path.
fn cpp_focused_type_qualifier(node: Node<'_>, source: &str) -> Option<CppFocusedQualifier> {
    let mut current = node.parent();
    let access = loop {
        let parent = current?;
        if parent.kind() == "qualified_identifier"
            && qualified_access_focus(node, parent, &["scope"], &["name"])
                == Some(QualifiedAccessFocus::Qualifier)
        {
            break parent;
        }
        current = parent.parent();
    };

    let focused = cpp_qualifier_scope_component(node, source)?;
    let mut scopes = Vec::new();
    let mut nested_access = access;
    let mut globally_qualified = false;
    while let Some(parent) = nested_access.parent() {
        if parent.kind() != "qualified_identifier"
            || qualified_access_focus(nested_access, parent, &["scope"], &["name"])
                != Some(QualifiedAccessFocus::Member)
        {
            break;
        }
        if let Some(scope) = parent.child_by_field_name("scope") {
            scopes.push(cpp_qualifier_scope_component(scope, source)?);
        } else {
            globally_qualified = true;
        }
        nested_access = parent;
    }
    scopes.reverse();
    scopes.push(focused);
    let components = scopes.iter().map(|scope| (*scope).to_string()).collect();
    Some(CppFocusedQualifier {
        reference: scopes.join("::"),
        identifier: focused.to_string(),
        components,
        globally_qualified,
    })
}

fn cpp_qualifier_scope_component<'a>(scope: Node<'_>, source: &'a str) -> Option<&'a str> {
    let scope = if scope.kind() == "template_type" {
        scope.child_by_field_name("name")?
    } else {
        scope
    };
    let component = cpp_node_text(scope, source).trim();
    (!component.is_empty()).then_some(component)
}

fn cpp_focused_type_qualifier_candidates(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    qualifier: &CppFocusedQualifier,
    lexical_namespace: Option<&str>,
    enclosing_classes: &[CodeUnit],
) -> Vec<CodeUnit> {
    let candidates = visibility
        .visible_identifier_candidates(file, &qualifier.identifier)
        .filter(|unit| unit.is_class() || cpp_unit_is_type_alias(analyzer, unit))
        .cloned()
        .collect::<Vec<_>>();
    for lookup_path in cpp_qualifier_lookup_tiers(qualifier, lexical_namespace, enclosing_classes) {
        let mut tier = candidates
            .iter()
            .filter(|unit| {
                cpp_type_qualifier_matches_exact_path(analyzer, context, unit, &lookup_path)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !tier.is_empty() {
            sort_units(&mut tier);
            tier.dedup();
            return tier;
        }
    }
    Vec::new()
}

fn cpp_qualifier_lookup_tiers(
    qualifier: &CppFocusedQualifier,
    lexical_namespace: Option<&str>,
    enclosing_classes: &[CodeUnit],
) -> Vec<String> {
    if qualifier.globally_qualified {
        return vec![qualifier.reference.clone()];
    }

    let mut tiers = Vec::new();
    for owner in enclosing_classes {
        let owner_name = cpp_name_for(owner);
        let path = if qualifier
            .components
            .first()
            .is_some_and(|component| component == owner.identifier())
        {
            let suffix = qualifier.components[1..].join("::");
            if suffix.is_empty() {
                owner_name
            } else {
                format!("{owner_name}::{suffix}")
            }
        } else {
            format!("{owner_name}::{}", qualifier.reference)
        };
        if !tiers.contains(&path) {
            tiers.push(path);
        }
    }
    let mut namespace = lexical_namespace;
    while let Some(current) = namespace {
        let path = format!("{current}::{}", qualifier.reference);
        if !tiers.contains(&path) {
            tiers.push(path);
        }
        namespace = current.rsplit_once("::").map(|(parent, _)| parent);
    }
    if !tiers.contains(&qualifier.reference) {
        tiers.push(qualifier.reference.clone());
    }
    tiers
}

fn cpp_type_qualifier_matches_exact_path(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    unit: &CodeUnit,
    lookup_path: &str,
) -> bool {
    if cpp_name_for(unit) == lookup_path {
        return true;
    }
    if !cpp_unit_is_type_alias(analyzer, unit) {
        return false;
    }
    cpp_structural_alias_paths(context, analyzer, unit)
        .iter()
        .any(|path| path == lookup_path)
}

fn cpp_structural_alias_paths(
    context: &mut DefinitionBatchContext<'_>,
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Vec<String> {
    if let Some(paths) = context.cpp_structural_alias_paths.get(unit) {
        return paths.clone();
    }
    let Some(source) = context.cpp_indexed_source(unit.source()) else {
        context
            .cpp_structural_alias_paths
            .insert(unit.clone(), Vec::new());
        return Vec::new();
    };
    let Some(tree) = context.cpp_indexed_tree(unit.source()) else {
        context
            .cpp_structural_alias_paths
            .insert(unit.clone(), Vec::new());
        return Vec::new();
    };
    let root = tree.root_node();
    let mut paths = Vec::new();
    for range in analyzer.ranges(unit) {
        let Some(mut declaration) =
            smallest_named_node_covering(root, range.start_byte, range.end_byte)
        else {
            continue;
        };
        while !matches!(declaration.kind(), "alias_declaration" | "type_definition") {
            let Some(parent) = declaration.parent() else {
                break;
            };
            declaration = parent;
        }
        if !matches!(declaration.kind(), "alias_declaration" | "type_definition") {
            continue;
        }

        let mut owners = Vec::new();
        let mut current = declaration.parent();
        while let Some(parent) = current {
            if matches!(
                parent.kind(),
                "namespace_definition"
                    | "class_specifier"
                    | "struct_specifier"
                    | "union_specifier"
                    | "enum_specifier"
            ) && let Some(name) = parent.child_by_field_name("name")
            {
                let name = cpp_node_text(name, &source).trim();
                if !name.is_empty() {
                    owners.push(name);
                }
            }
            current = parent.parent();
        }
        owners.reverse();
        owners.push(unit.identifier());
        paths.push(owners.join("::"));
    }
    paths.sort();
    paths.dedup();
    context
        .cpp_structural_alias_paths
        .insert(unit.clone(), paths.clone());
    paths
}

fn cpp_type_definition_candidates(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    support: &dyn BoundedDefinitionLookup,
    unit: CodeUnit,
) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    let target =
        cpp_alias_target_unit(analyzer, visibility, file, &unit, &mut seen).unwrap_or(unit);
    let indexed = support
        .fqn(&target.fq_name())
        .into_iter()
        .filter(|candidate| {
            cpp_unit_matches_kind(analyzer, support, candidate, CppTargetKind::Type)
        })
        .collect::<Vec<_>>();
    if indexed.is_empty() {
        vec![target]
    } else {
        indexed
    }
}

fn resolve_cpp_call(ctx: CppLookupCtx<'_, '_>, call: Node<'_>) -> DefinitionLookupOutcome {
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "C++ call expression has no function");
    };
    let call_arity = ctx
        .visibility
        .call_arity_evidence(ctx.file, call, ctx.source)
        .exact();
    if let Some(operator) = cpp_explicit_operator_name(call) {
        let member = cpp_node_text(operator, ctx.source);
        let owners = cpp_receiver_type_units(ctx, function, false);
        let candidates = cpp_member_candidates_lazy(ctx, owners, member, call_arity, || {
            cpp_call_argument_types(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                call,
            )
        });
        return if candidates.is_empty() {
            no_definition(
                "unsupported_cpp_receiver",
                format!("receiver for C++ operator `{member}` is not resolved"),
            )
        } else {
            cpp_callable_candidates_outcome(candidates)
        };
    }
    match function.kind() {
        "field_expression" => {
            let call_arg_types = cpp_call_argument_types(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                call,
            );
            resolve_cpp_field(ctx, function, call_arity, call_arg_types.as_deref())
        }
        "type_identifier" | "template_type" | "scoped_type_identifier" => {
            resolve_cpp_constructor(ctx, call)
        }
        "qualified_identifier" => {
            let text = cpp_callable_reference_text(function, ctx.source);
            let mut candidates = cpp_visible_name_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                &text,
                Some(CppTargetKind::FreeFunction),
                cpp_lexical_namespace(function, ctx.source).as_deref(),
            );
            candidates.retain(|candidate| {
                ctx.visibility.declaration_visible_at(
                    ctx.analyzer,
                    ctx.file,
                    candidate,
                    call.start_byte(),
                )
            });
            if !candidates.is_empty() {
                candidates = cpp_filter_candidates_by_call_lazy(
                    candidates,
                    call_arity,
                    || {
                        cpp_call_argument_types(
                            ctx.analyzer,
                            ctx.support,
                            ctx.visibility,
                            ctx.file,
                            ctx.source,
                            ctx.root,
                            call,
                        )
                    },
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                );
                return cpp_callable_candidates_outcome(candidates);
            }
            let constructor = resolve_cpp_constructor(ctx, call);
            if constructor.status != DefinitionLookupStatus::NoDefinition {
                return constructor;
            }
            if let Some(scope) = function.child_by_field_name("scope")
                && let Some(name) = function
                    .child_by_field_name("name")
                    .and_then(cpp_callable_name_node)
            {
                let member = cpp_node_text(name, ctx.source);
                if let Some(owner) = ctx
                    .visibility
                    .resolve_type(ctx.file, cpp_node_text(scope, ctx.source))
                {
                    candidates =
                        cpp_member_candidates_lazy(ctx, vec![owner], member, call_arity, || {
                            cpp_call_argument_types(
                                ctx.analyzer,
                                ctx.support,
                                ctx.visibility,
                                ctx.file,
                                ctx.source,
                                ctx.root,
                                call,
                            )
                        });
                    if !candidates.is_empty() {
                        return cpp_callable_candidates_outcome(candidates);
                    }
                }
            }
            if cpp_unresolved_include_boundary(ctx.analyzer, ctx.file, &text) {
                return boundary(format!(
                    "`{text}` appears to cross a C++ include boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C++ callable"),
            )
        }
        "identifier"
        | "field_identifier"
        | "dependent_name"
        | "template_function"
        | "template_method"
        | "operator_name"
        | "operator_cast"
        | "destructor_name"
        | "literal_operator_name" => {
            let Some(name_node) = cpp_callable_name_node(function) else {
                return no_definition("no_function_name", "C++ call name is blank");
            };
            let name = cpp_node_text(name_node, ctx.source);
            if name.is_empty() {
                return no_definition("no_function_name", "C++ call name is blank");
            }
            let bindings = cpp_bindings_before(ctx, ctx.root, name_node.start_byte());
            if bindings.is_shadowed(name) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local C++ value"),
                );
            }
            if let Some(owner) = cpp_enclosing_class(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                name_node.start_byte(),
            ) {
                let member_candidates = if call_arity.is_none() {
                    cpp_member_candidates_lazy(ctx, vec![owner], name, None, || None)
                } else {
                    cpp_member_candidates_lazy(ctx, vec![owner], name, call_arity, || {
                        cpp_call_argument_types(
                            ctx.analyzer,
                            ctx.support,
                            ctx.visibility,
                            ctx.file,
                            ctx.source,
                            ctx.root,
                            call,
                        )
                    })
                };
                if !member_candidates.is_empty() {
                    if call_arity.is_none() {
                        return ambiguous_definition(format!(
                            "the argument count for C++ call `{name}` is unknown after macro expansion"
                        ));
                    }
                    return cpp_callable_candidates_outcome(member_candidates);
                }
            }
            let imports = cpp_initialized_effective_using_imports(
                ctx.root,
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
            );
            match cpp_resolve_bare_call_target(
                call,
                function,
                ctx.analyzer,
                ctx.visibility,
                &imports,
                ctx.file,
                ctx.source,
            ) {
                CppBareCallTargetResolution::FreeFunctions(units) => {
                    let mut candidates = cpp_bare_free_function_definition_candidates(ctx, units);
                    candidates = cpp_filter_candidates_by_call_lazy(
                        candidates,
                        call_arity,
                        || {
                            cpp_call_argument_types(
                                ctx.analyzer,
                                ctx.support,
                                ctx.visibility,
                                ctx.file,
                                ctx.source,
                                ctx.root,
                                call,
                            )
                        },
                        ctx.analyzer,
                        ctx.visibility,
                        ctx.file,
                    );
                    return cpp_callable_candidates_outcome(candidates);
                }
                CppBareCallTargetResolution::UnprovenFreeFunctions(units) => {
                    if units.len() < 2 {
                        return ambiguous_definition(format!(
                            "the argument count for C++ call `{name}` is unknown after macro expansion"
                        ));
                    }
                    let candidates = cpp_bare_free_function_definition_candidates(ctx, units);
                    return ambiguous_candidates_outcome(
                        candidates,
                        format!(
                            "the argument count for C++ call `{name}` is unknown after macro expansion"
                        ),
                    );
                }
                CppBareCallTargetResolution::Type(unit) => {
                    let owners = cpp_type_definition_candidates(
                        ctx.analyzer,
                        ctx.visibility,
                        ctx.file,
                        ctx.support,
                        unit,
                    );
                    for owner in &owners {
                        let constructors =
                            cpp_prefer_declaration_candidates(cpp_member_candidates_lazy(
                                ctx,
                                vec![owner.clone()],
                                owner.identifier(),
                                call_arity,
                                || {
                                    cpp_call_argument_types(
                                        ctx.analyzer,
                                        ctx.support,
                                        ctx.visibility,
                                        ctx.file,
                                        ctx.source,
                                        ctx.root,
                                        call,
                                    )
                                },
                            ));
                        if !constructors.is_empty() {
                            return cpp_callable_candidates_outcome(constructors);
                        }
                    }
                    return candidates_outcome(owners);
                }
                CppBareCallTargetResolution::CallableShadow => {
                    return no_definition(
                        "no_applicable_overload",
                        format!("`{name}` is declared but has no applicable overload"),
                    );
                }
                CppBareCallTargetResolution::Ambiguous => {
                    return ambiguous_definition(format!(
                        "C++ bare call `{name}` has ambiguous lookup candidates"
                    ));
                }
                CppBareCallTargetResolution::Missing => {}
            }
            no_definition(
                "no_indexed_definition",
                format!("`{name}` did not resolve to an indexed C++ callable"),
            )
        }
        _ => no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "C++ `{}` call targets are not resolved by get_definition yet",
                function.kind()
            ),
        ),
    }
}

fn cpp_bare_free_function_definition_candidates(
    ctx: CppLookupCtx<'_, '_>,
    units: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    units
        .into_iter()
        .flat_map(|unit| {
            let indexed = ctx
                .support
                .fqn(&unit.fq_name())
                .into_iter()
                .filter(|candidate| {
                    cpp_unit_matches_kind(
                        ctx.analyzer,
                        ctx.support,
                        candidate,
                        CppTargetKind::FreeFunction,
                    ) && cpp_callable_definitions_share_identity_evidence(
                        ctx.analyzer,
                        &unit,
                        candidate,
                    )
                })
                .collect::<Vec<_>>();
            if indexed.is_empty() {
                vec![unit]
            } else {
                indexed
            }
        })
        .collect()
}

fn cpp_explicit_operator_name(call: Node<'_>) -> Option<Node<'_>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let arguments = call.child_by_field_name("arguments");
    let mut cursor = call.walk();
    let errors = call
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR" && Some(*child) != arguments);
    for error in errors {
        let mut stack = vec![error];
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "operator_name" | "operator_cast" | "literal_operator_name"
            ) {
                return Some(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    None
}

fn cpp_callable_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        current = match current.kind() {
            "identifier"
            | "field_identifier"
            | "type_identifier"
            | "namespace_identifier"
            | "operator_name"
            | "operator_cast"
            | "destructor_name"
            | "literal_operator_name"
            | "primitive_type" => return Some(current),
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current.child_by_field_name("name")?
            }
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = current.walk();
                current
                    .children_by_field_name("name", &mut cursor)
                    .filter(|child| child.is_named())
                    .last()?
            }
            "field_expression" => current.child_by_field_name("field")?,
            "parenthesized_expression" => {
                let mut cursor = current.walk();
                let mut children = current.named_children(&mut cursor);
                let child = children.next()?;
                if children.next().is_some() {
                    return None;
                }
                child
            }
            _ => return None,
        };
    }
}

fn cpp_callable_reference_text(node: Node<'_>, source: &str) -> String {
    if node.kind() == "qualified_identifier"
        && let (Some(scope), Some(name)) = (
            node.child_by_field_name("scope"),
            node.child_by_field_name("name")
                .and_then(cpp_callable_name_node),
        )
    {
        return format!(
            "{}::{}",
            cpp_node_text(scope, source),
            cpp_node_text(name, source)
        );
    }
    let name = cpp_callable_name_node(node).unwrap_or(node);
    cpp_node_text(name, source).to_string()
}

fn resolve_cpp_constructor(
    ctx: CppLookupCtx<'_, '_>,
    constructor: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(type_node) = cpp_constructor_type_node(constructor) else {
        return no_definition("no_reference_text", "C++ constructor call has no type");
    };
    let text = normalize_cpp_type_text(cpp_node_text(type_node, ctx.source));
    if text.is_empty() {
        return no_definition("no_reference_text", "C++ constructor type is blank");
    }

    let mut owners = Vec::new();
    if let Some(owner) = ctx.visibility.resolve_type(ctx.file, &text) {
        owners.push(owner);
    }
    owners.extend(cpp_visible_name_candidates(
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        ctx.support,
        &text,
        Some(CppTargetKind::Type),
        cpp_lexical_namespace(type_node, ctx.source).as_deref(),
    ));
    owners = owners
        .into_iter()
        .flat_map(|unit| {
            cpp_type_definition_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                unit,
            )
        })
        .filter(|unit| cpp_unit_matches_kind(ctx.analyzer, ctx.support, unit, CppTargetKind::Type))
        .collect();
    sort_units(&mut owners);
    owners.dedup();

    for owner in &owners {
        let constructors = cpp_member_candidates_lazy(
            ctx,
            vec![owner.clone()],
            owner.identifier(),
            ctx.visibility
                .call_arity_evidence(ctx.file, constructor, ctx.source)
                .exact(),
            || {
                cpp_call_argument_types(
                    ctx.analyzer,
                    ctx.support,
                    ctx.visibility,
                    ctx.file,
                    ctx.source,
                    ctx.root,
                    constructor,
                )
            },
        );
        let constructors = cpp_prefer_declaration_candidates(constructors);
        if !constructors.is_empty() {
            return candidates_outcome(constructors);
        }
    }

    if !owners.is_empty() {
        return candidates_outcome(owners);
    }
    let text = normalize_cpp_type_text(cpp_node_text(type_node, ctx.source));
    if text.is_empty() {
        return no_definition("no_reference_text", "C++ type reference is blank");
    }
    resolve_cpp_type_without_focused_qualifier(
        ctx.analyzer,
        ctx.support,
        ctx.file,
        ctx.visibility,
        ctx.source,
        type_node,
        &text,
    )
}

fn cpp_prefer_declaration_candidates(candidates: Vec<CodeUnit>) -> Vec<CodeUnit> {
    let preferred: Vec<_> = candidates
        .iter()
        .filter(|unit| cpp_source_is_header(unit))
        .cloned()
        .collect();
    if preferred.is_empty() {
        candidates
    } else {
        preferred
    }
}

fn cpp_source_is_header(unit: &CodeUnit) -> bool {
    cpp_source_path_is_header(unit.source())
}

fn cpp_source_path_is_header(source: &ProjectFile) -> bool {
    let path = rel_path_string(source).to_ascii_lowercase();
    matches!(path.rsplit('.').next(), Some("h" | "hh" | "hpp" | "hxx"))
}

fn resolve_cpp_field(
    ctx: CppLookupCtx<'_, '_>,
    field: Node<'_>,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = field.child_by_field_name("field") else {
        return no_definition("no_member_name", "C++ field expression has no member name");
    };
    let Some(name_node) = cpp_callable_name_node(name_node) else {
        return no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "C++ `{}` member names are not resolved by get_definition yet",
                name_node.kind()
            ),
        );
    };
    let member = cpp_node_text(name_node, ctx.source);
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return no_definition("no_member_receiver", "C++ field expression has no receiver");
    };
    let owners = cpp_field_receiver_type_units(
        ctx.analyzer,
        ctx.support,
        ctx.visibility,
        ctx.file,
        ctx.source,
        ctx.root,
        field,
        receiver,
    );
    let candidates = cpp_member_candidates(ctx, owners, member, arity, arg_types);
    if candidates.is_empty() {
        no_definition(
            "unsupported_cpp_receiver",
            format!("receiver for C++ member `{member}` is not resolved"),
        )
    } else {
        if arity.is_some() {
            cpp_callable_candidates_outcome(candidates)
        } else {
            candidates_outcome(candidates)
        }
    }
}

fn cpp_visible_name_candidates(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    support: &dyn BoundedDefinitionLookup,
    raw_name: &str,
    kind: Option<CppTargetKind>,
    lexical_namespace: Option<&str>,
) -> Vec<CodeUnit> {
    let normalized = raw_name.trim().trim_start_matches("::");
    let namespace_relative = lexical_namespace
        .filter(|namespace| !namespace.is_empty() && normalized.contains("::"))
        .map(|namespace| format!("{namespace}::{normalized}"));

    let mut candidates: Vec<CodeUnit> = if normalized.contains("::") {
        let mut fqns = Vec::new();
        for reference in [Some(normalized), namespace_relative.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(kind) = kind {
                fqns.extend(cpp_reference_fqn_candidates(reference, kind));
            } else {
                for candidate_kind in [
                    CppTargetKind::Type,
                    CppTargetKind::Constructor,
                    CppTargetKind::FreeFunction,
                    CppTargetKind::Method,
                    CppTargetKind::GlobalField,
                    CppTargetKind::MemberField,
                ] {
                    fqns.extend(cpp_reference_fqn_candidates(reference, candidate_kind));
                }
            }
        }
        fqns.sort();
        fqns.dedup();
        support
            .fqn_candidates(fqns)
            .into_iter()
            .filter(|unit| visibility.is_physically_visible(file, unit))
            .filter(|unit| {
                let cpp_name = cpp_name_for(unit);
                cpp_name == normalized
                    || namespace_relative
                        .as_deref()
                        .is_some_and(|relative| cpp_name == relative)
            })
            .collect()
    } else {
        visibility
            .visible_identifier_candidates(file, normalized)
            .filter(|unit| unit.identifier() == normalized)
            .cloned()
            .collect()
    };

    if let Some(kind) = kind {
        candidates.retain(|unit| cpp_unit_matches_kind(analyzer, support, unit, kind));
    }
    candidates = candidates
        .into_iter()
        .flat_map(|unit| {
            let mut indexed = support.fqn(&unit.fq_name());
            indexed.retain(|candidate| {
                cpp_callable_definitions_share_identity_evidence(analyzer, &unit, candidate)
            });
            if indexed.is_empty() {
                vec![unit]
            } else {
                indexed
            }
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_callable_definitions_share_identity_evidence(
    analyzer: &dyn IAnalyzer,
    visible: &CodeUnit,
    candidate: &CodeUnit,
) -> bool {
    visible.source() == candidate.source()
        || (matches!(
            cpp_indexed_callable_linkage(analyzer, visible),
            Some(crate::analyzer::CallableLinkage::External)
        ) && matches!(
            cpp_indexed_callable_linkage(analyzer, candidate),
            Some(crate::analyzer::CallableLinkage::External)
        ) && cpp_header_body_files_are_related(analyzer, visible.source(), candidate.source()))
}

/// The include graph can relate one declaration header to one implementation
/// file, but it cannot prove that every external definition with the same FQN
/// belongs to the same binary. Keep only a direct header/body include edge;
/// broader workspace-global linkage is deliberately rejected.
fn cpp_header_body_files_are_related(
    analyzer: &dyn IAnalyzer,
    left: &ProjectFile,
    right: &ProjectFile,
) -> bool {
    let (header, implementation) = if cpp_source_path_is_header(left) {
        (left, right)
    } else if cpp_source_path_is_header(right) {
        (right, left)
    } else {
        return false;
    };
    if cpp_source_path_is_header(implementation) {
        return false;
    }
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return false;
    };
    let include_targets = cpp.include_target_index();
    analyzer
        .import_statements(implementation)
        .into_iter()
        .flat_map(|import| cpp_include_paths(std::slice::from_ref(&import)))
        .any(|include| {
            let targets =
                resolve_include_targets_with_index(implementation, &include, include_targets);
            targets.len() == 1 && targets.first() == Some(header)
        })
}

/// Cross-file C/C++ callable bodies selected from include evidence are useful
/// targets, but their link-unit identity remains unproven without build graph
/// metadata. Preserve the candidates while making that uncertainty explicit.
fn cpp_callable_candidates_outcome(candidates: Vec<CodeUnit>) -> DefinitionLookupOutcome {
    let mut callable_sources = HashSet::default();
    for candidate in &candidates {
        if candidate.is_callable() {
            callable_sources.insert(candidate.source().clone());
        }
    }
    let link_unit_unproven = callable_sources.len() > 1;
    let mut outcome = candidates_outcome(candidates);
    if link_unit_unproven {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC.to_string(),
            message: "the include graph relates this C/C++ declaration and body, but no build graph proves one link unit"
                .to_string(),
        });
    }
    outcome
}

pub(crate) fn cpp_indexed_callable_linkage(
    analyzer: &dyn IAnalyzer,
    callable: &CodeUnit,
) -> Option<crate::analyzer::CallableLinkage> {
    let mut external = false;
    for metadata in analyzer.signature_metadata(callable) {
        match metadata.callable_linkage() {
            Some(crate::analyzer::CallableLinkage::Internal) => {
                return Some(crate::analyzer::CallableLinkage::Internal);
            }
            Some(crate::analyzer::CallableLinkage::External) => external = true,
            None => {}
        }
    }
    external.then_some(crate::analyzer::CallableLinkage::External)
}

fn cpp_unit_matches_kind(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    kind: CppTargetKind,
) -> bool {
    match kind {
        CppTargetKind::FreeFunction => unit.is_function() && !cpp_parent_is_class(support, unit),
        CppTargetKind::Type => unit.is_class() || cpp_unit_is_type_alias(analyzer, unit),
        CppTargetKind::GlobalField => {
            unit.is_field() && cpp_is_unqualified_field(analyzer, support, unit)
        }
        CppTargetKind::MemberField => unit.is_field(),
        CppTargetKind::Constructor | CppTargetKind::Method => true,
    }
}

fn cpp_qualified_identifier_is_declaration_name(node: Node<'_>) -> bool {
    node.kind() == "qualified_identifier"
        && node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "function_declarator" | "pointer_declarator" | "reference_declarator"
            ) && parent.child_by_field_name("declarator") == Some(node)
        })
}

fn cpp_parent_is_class(support: &dyn BoundedDefinitionLookup, unit: &CodeUnit) -> bool {
    let fqn = unit.fq_name();
    let Some((parent_fqn, _)) = fqn.rsplit_once('.') else {
        return false;
    };
    support
        .fqn(parent_fqn)
        .into_iter()
        .any(|parent| parent.is_class())
}

fn cpp_is_unqualified_field(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
) -> bool {
    if !unit.short_name().contains('.') {
        return true;
    }
    let fqn = unit.fq_name();
    let Some((parent_fqn, _)) = fqn.rsplit_once('.') else {
        return false;
    };
    support.fqn(parent_fqn).into_iter().any(|parent| {
        parent
            .signature()
            .is_some_and(|signature| signature.trim_start().starts_with("enum "))
            || analyzer
                .signatures(&parent)
                .iter()
                .any(|signature| signature.trim_start().starts_with("enum "))
    })
}

fn cpp_unit_is_type_alias(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(unit))
        || unit.signature().is_some_and(cpp_signature_is_type_alias)
}

fn cpp_signature_is_type_alias(signature: &str) -> bool {
    let signature = signature.trim_start();
    signature.starts_with("typedef ")
        || signature.starts_with("using ") && signature.contains('=')
        || signature.starts_with("template ")
            && signature.contains(" using ")
            && signature.contains('=')
}

fn cpp_member_candidates(
    ctx: CppLookupCtx<'_, '_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
) -> Vec<CodeUnit> {
    let mut candidates = cpp_direct_member_candidates(ctx.analyzer, ctx.support, &owners, member);
    if candidates.is_empty() {
        let mut seen = HashSet::default();
        candidates = cpp_inherited_member_candidates(ctx, &owners, member, &mut seen);
    }
    candidates = cpp_filter_candidates_by_call(
        candidates,
        arity,
        arg_types,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
    );
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_member_candidates_lazy<F>(
    ctx: CppLookupCtx<'_, '_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    resolve_arg_types: F,
) -> Vec<CodeUnit>
where
    F: FnOnce() -> Option<Vec<Option<CppType>>>,
{
    let mut candidates = cpp_direct_member_candidates(ctx.analyzer, ctx.support, &owners, member);
    if candidates.is_empty() {
        let mut seen = HashSet::default();
        candidates = cpp_inherited_member_candidates(ctx, &owners, member, &mut seen);
    }
    candidates = cpp_filter_candidates_by_call_lazy(
        candidates,
        arity,
        resolve_arg_types,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
    );
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_direct_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owners: &[CodeUnit],
    member: &str,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for owner in owners {
        candidates.extend(
            support
                .fqn(&format!("{}.{}", owner.fq_name(), member))
                .into_iter()
                .filter(|candidate| {
                    candidate.source() == owner.source()
                        || (matches!(
                            cpp_indexed_callable_linkage(analyzer, candidate),
                            Some(crate::analyzer::CallableLinkage::External)
                        ) && cpp_header_body_files_are_related(
                            analyzer,
                            owner.source(),
                            candidate.source(),
                        ))
                }),
        );
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_inherited_member_candidates(
    ctx: CppLookupCtx<'_, '_>,
    owners: &[CodeUnit],
    member: &str,
    seen: &mut HashSet<String>,
) -> Vec<CodeUnit> {
    let mut bases = Vec::new();
    for owner in owners {
        for base in cpp_direct_base_types(ctx.analyzer, ctx.visibility, ctx.file, owner) {
            if seen.insert(base.fq_name()) {
                bases.push(base);
            }
        }
    }
    if bases.is_empty() {
        return Vec::new();
    }
    let direct = cpp_direct_member_candidates(ctx.analyzer, ctx.support, &bases, member);
    if !direct.is_empty() {
        return direct;
    }
    let mut inherited = cpp_inherited_member_candidates(ctx, &bases, member, seen);
    sort_units(&mut inherited);
    inherited.dedup();
    inherited
}

fn cpp_filter_candidates_by_call(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit> {
    let arity_filtered = cpp_filter_candidates_by_arity(candidates, arity);
    let Some(arg_types) = arg_types else {
        return arity_filtered;
    };
    cpp_filter_candidates_by_call_arg_types(arity_filtered, arg_types, analyzer, visibility, file)
}

fn cpp_filter_candidates_by_call_lazy<F>(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    resolve_arg_types: F,
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit>
where
    F: FnOnce() -> Option<Vec<Option<CppType>>>,
{
    let arity_filtered = cpp_filter_candidates_by_arity(candidates, arity);
    if arity_filtered.len() <= 1 {
        return arity_filtered;
    }
    let Some(arg_types) = resolve_arg_types() else {
        return arity_filtered;
    };
    cpp_filter_candidates_by_call_arg_types(arity_filtered, &arg_types, analyzer, visibility, file)
}

fn cpp_filter_candidates_by_call_arg_types(
    candidates: Vec<CodeUnit>,
    arg_types: &[Option<CppType>],
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit> {
    let shared_arg_types: Vec<_> = arg_types
        .iter()
        .map(|arg| arg.as_ref().map(CppType::as_arg_type))
        .collect();
    cpp_filter_candidates_by_args(
        candidates,
        &shared_arg_types,
        &|name| cpp_resolve_type_unit(analyzer, visibility, file, name),
        &|arg_type, param_type| {
            cpp_type_assignable_to(
                analyzer,
                visibility,
                file,
                arg_type,
                param_type,
                &mut HashSet::default(),
            )
        },
    )
}

fn cpp_filter_candidates_by_arity(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| {
            unit.is_function()
                && unit
                    .signature()
                    .is_some_and(|signature| cpp_signature_arity(Some(signature)) == expected)
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn cpp_type_assignable_to(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    arg_type: &CodeUnit,
    param_type: &CodeUnit,
    seen: &mut HashSet<String>,
) -> bool {
    if arg_type.fq_name() == param_type.fq_name() {
        return true;
    }
    if !seen.insert(arg_type.fq_name()) {
        return false;
    }
    cpp_direct_base_types(analyzer, visibility, file, arg_type)
        .into_iter()
        .any(|base| {
            base.fq_name() == param_type.fq_name()
                || cpp_type_assignable_to(analyzer, visibility, file, &base, param_type, seen)
        })
}

fn cpp_direct_base_types(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    unit: &CodeUnit,
) -> Vec<CodeUnit> {
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.get_source(unit, false));
    let Some(signature) = signature else {
        return Vec::new();
    };
    let Some((_, bases)) = signature.split_once(':') else {
        return Vec::new();
    };
    let bases = bases.split('{').next().unwrap_or(bases);
    cpp_split_top_level_commas(bases)
        .filter_map(|base| {
            cpp_resolve_type_unit(analyzer, visibility, file, &cpp_base_type_text(base))
        })
        .collect()
}

fn cpp_base_type_text(base: &str) -> String {
    let filtered = base
        .split_whitespace()
        .filter(|token| !matches!(*token, "public" | "private" | "protected" | "virtual"))
        .collect::<Vec<_>>()
        .join(" ");
    normalize_cpp_type_text(&filtered)
}

/// A C++ value type paired with its pointer indirection depth: 0 for a value or
/// reference, 1 for `T*`, 2 for `T**`, and so on. References bind from values, so
/// they contribute depth 0; only `*` levels must agree between an argument and a
/// parameter for overload matching.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CppType {
    name: String,
    unit: Option<CodeUnit>,
    indirection: i32,
    alias_unit: Option<CodeUnit>,
}

impl CppType {
    fn from_text(
        analyzer: &dyn IAnalyzer,
        visibility: &CppVisibilityIndex,
        file: &ProjectFile,
        type_text: &str,
        indirection: i32,
    ) -> Self {
        let name = normalize_cpp_type_name(type_text);
        Self {
            name: name.clone(),
            unit: cpp_resolve_type_unit(analyzer, visibility, file, &name),
            indirection,
            alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &name),
        }
    }

    fn from_unit(unit: CodeUnit, indirection: i32) -> Self {
        Self {
            name: cpp_name_for(&unit),
            unit: Some(unit),
            indirection,
            alias_unit: None,
        }
    }

    fn as_arg_type(&self) -> CppArgType {
        CppArgType {
            name: self.name.clone(),
            unit: self.unit.clone(),
            indirection: self.indirection,
        }
    }
}

/// Pointer depth contributed by a declarator: one per `pointer_declarator`
/// wrapping the name. `reference_declarator` contributes nothing.
fn cpp_declarator_pointer_depth(declarator: Node<'_>) -> i32 {
    let mut depth = 0;
    let mut current = declarator;
    loop {
        if current.kind() == "pointer_declarator" {
            depth += 1;
        }
        match current.child_by_field_name("declarator") {
            Some(inner) => current = inner,
            None => return depth,
        }
    }
}

/// Indirection change of a `pointer_expression`: `&x` adds a pointer level, `*x`
/// removes one. `None` for any other unary operator sharing this node kind.
fn cpp_pointer_expression_delta(node: Node<'_>) -> Option<i32> {
    match node.child_by_field_name("operator")?.kind() {
        "&" => Some(1),
        "*" => Some(-1),
        _ => None,
    }
}

fn cpp_call_argument_types(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Option<Vec<Option<CppType>>> {
    let args = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("parameters"))
        .or_else(|| call.child_by_field_name("value"))?;
    Some(
        cpp_argument_children(args)
            .map(|arg| cpp_expression_type(analyzer, support, visibility, file, source, root, arg))
            .collect(),
    )
}

fn cpp_expression_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<CppType> {
    match node.kind() {
        "number_literal" | "true" | "false" | "char_literal" | "string_literal"
        | "unary_expression" => cpp_literal_type_name(node, source)
            .map(|name| CppType::from_text(analyzer, visibility, file, name, 0)),
        "identifier" => {
            let name = cpp_node_text(node, source);
            let ctx = CppLookupCtx {
                analyzer,
                support,
                file,
                visibility,
                source,
                root,
            };
            let bindings = cpp_bindings_before(ctx, root, node.start_byte());
            first_precise(&bindings, name)
        }
        "field_expression" => {
            cpp_field_expression_type(analyzer, support, visibility, file, source, root, node)
        }
        "new_expression" | "call_expression" => cpp_infer_type_from_value(
            analyzer,
            support,
            visibility,
            file,
            source,
            Some(root),
            node,
        ),
        "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .and_then(|inner| {
                cpp_expression_type(analyzer, support, visibility, file, source, root, inner)
            }),
        "pointer_expression" => {
            let delta = cpp_pointer_expression_delta(node)?;
            let inner = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;
            let mut inner_type =
                cpp_expression_type(analyzer, support, visibility, file, source, root, inner)?;
            inner_type.indirection += delta;
            Some(inner_type)
        }
        _ => None,
    }
}

fn cpp_field_expression_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
) -> Option<CppType> {
    let member = field
        .child_by_field_name("field")
        .map(|field| cpp_node_text(field, source))?;
    let receiver = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))?;
    let owners = cpp_field_receiver_type_units(
        analyzer, support, visibility, file, source, root, field, receiver,
    );
    let candidates = cpp_member_candidates(
        CppLookupCtx {
            analyzer,
            support,
            file,
            visibility,
            source,
            root,
        },
        owners,
        member,
        None,
        None,
    );
    candidates
        .into_iter()
        .filter(|unit| unit.is_field())
        .find_map(|unit| cpp_field_declared_type(analyzer, visibility, file, &unit))
}

fn cpp_field_declared_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    field: &CodeUnit,
) -> Option<CppType> {
    let (name, unit, indirection) =
        cpp_field_declared_type_binding(analyzer, visibility, file, field)?;
    Some(CppType {
        alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &name),
        name,
        unit,
        indirection,
    })
}

fn cpp_receiver_type_units(
    ctx: CppLookupCtx<'_, '_>,
    receiver: Node<'_>,
    unwrap_template_alias: bool,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = cpp_node_text(receiver, ctx.source);
            let bindings = cpp_bindings_before(ctx, ctx.root, receiver.start_byte());
            if let Some(cpp_type) = first_precise(&bindings, name) {
                return cpp_receiver_unit_for_access(ctx, cpp_type, unwrap_template_alias)
                    .into_iter()
                    .collect();
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else if let Some(cpp_type) = cpp_enclosing_member_field_type(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                receiver,
                name,
            ) {
                cpp_receiver_unit_for_access(ctx, cpp_type, unwrap_template_alias)
                    .into_iter()
                    .collect()
            } else {
                ctx.visibility
                    .resolve_type(ctx.file, name)
                    .into_iter()
                    .collect()
            }
        }
        "this" => cpp_enclosing_class(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            ctx.root,
            receiver.start_byte(),
        )
        .into_iter()
        .collect(),
        "field_expression" => cpp_field_expression_type(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            ctx.root,
            receiver,
        )
        .and_then(|cpp_type| cpp_type.unit)
        .into_iter()
        .collect(),
        // `Foo().member` / `(new Foo())->member` — a temporary-construction or
        // call receiver is typed by the constructed class or the call's return.
        "call_expression" | "new_expression" => cpp_expression_type(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            ctx.root,
            receiver,
        )
        .and_then(|cpp_type| cpp_type.unit)
        .into_iter()
        .collect(),
        "parenthesized_expression" | "pointer_expression" => receiver
            .child_by_field_name("argument")
            .or_else(|| receiver.named_child(0))
            .map(|inner| cpp_receiver_type_units(ctx, inner, unwrap_template_alias))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn cpp_field_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    let ctx = CppLookupCtx {
        analyzer,
        support,
        file,
        visibility,
        source,
        root,
    };
    cpp_receiver_type_units(
        ctx,
        receiver,
        cpp_field_expression_uses_arrow(field, source),
    )
}

fn cpp_receiver_unit_for_access(
    ctx: CppLookupCtx<'_, '_>,
    cpp_type: CppType,
    unwrap_template_alias: bool,
) -> Option<CodeUnit> {
    if unwrap_template_alias
        && let Some(alias) = cpp_type.alias_unit.as_ref()
        && let Some(target) = cpp_alias_arrow_target_unit(ctx, alias)
    {
        return Some(target);
    }
    cpp_type.unit
}

fn cpp_field_expression_uses_arrow(field: Node<'_>, source: &str) -> bool {
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return false;
    };
    let Some(name) = field.child_by_field_name("field") else {
        return false;
    };
    source
        .get(receiver.end_byte()..name.start_byte())
        .is_some_and(|between| between.contains("->"))
}

fn cpp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
) -> Option<CodeUnit> {
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    cpp_enclosing_class_with_ranges(
        analyzer,
        support,
        visibility,
        file,
        source,
        root,
        byte,
        &class_ranges,
    )
}

#[allow(clippy::too_many_arguments)]
fn cpp_enclosing_class_with_ranges(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
    class_ranges: &ClassRangeIndex,
) -> Option<CodeUnit> {
    if let Some(fqn) = class_ranges.enclosing(byte) {
        return support.fqn(fqn).into_iter().next();
    }
    if let Some(owner) = cpp_out_of_line_function_owner(visibility, file, source, root, byte) {
        return Some(owner);
    }

    let line_starts = compute_line_starts(source);
    let line = find_line_index_for_offset(&line_starts, byte) + 1;
    let range = Range {
        start_byte: byte,
        end_byte: byte.saturating_add(1),
        start_line: line,
        end_line: line,
    };
    let enclosing = analyzer.enclosing_code_unit(file, &range)?;
    let enclosing_fqn = enclosing.fq_name();
    let owner_fqn = enclosing_fqn.rsplit_once('.')?.0;
    support
        .fqn(owner_fqn)
        .into_iter()
        .find(|unit| unit.is_class())
}

fn cpp_out_of_line_function_owner(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
) -> Option<CodeUnit> {
    let mut node = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if node.kind() == "function_definition" {
            let declarator = node.child_by_field_name("declarator")?;
            let qualified = cpp_declarator_qualified_name(declarator, source)?;
            let (owner, _) = qualified.rsplit_once("::")?;
            return cpp_resolve_owner_type_in_lexical_namespace(
                visibility, file, source, node, owner,
            );
        }
        node = node.parent()?;
    }
}

fn cpp_declarator_qualified_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "qualified_identifier" | "scoped_identifier" => {
            let text = cpp_node_text(node, source).trim().to_string();
            text.contains("::").then_some(text)
        }
        _ => node
            .child_by_field_name("declarator")
            .and_then(|inner| cpp_declarator_qualified_name(inner, source)),
    }
}

fn cpp_resolve_owner_type_in_lexical_namespace(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    owner: &str,
) -> Option<CodeUnit> {
    cpp_lexical_namespace(node, source)
        .into_iter()
        .flat_map(|namespace| cpp_namespace_relative_names(&namespace, owner))
        .find_map(|name| visibility.resolve_type(file, &name))
        .or_else(|| visibility.resolve_type(file, owner))
}

#[allow(clippy::too_many_arguments)]
fn cpp_enclosing_member_field_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<CppType> {
    let owner = cpp_enclosing_class(
        analyzer,
        support,
        visibility,
        file,
        source,
        root,
        node.start_byte(),
    )?;
    let ctx = CppLookupCtx {
        analyzer,
        support,
        file,
        visibility,
        source,
        root,
    };
    cpp_member_candidates(ctx, vec![owner], name, None, None)
        .into_iter()
        .filter(|unit| unit.is_field())
        .find_map(|unit| cpp_field_declared_type(analyzer, visibility, file, &unit))
}

const CPP_SCOPE_NODES: &[&str] = &[
    "compound_statement",
    "function_definition",
    "lambda_expression",
    "for_range_loop",
    "for_statement",
    "while_statement",
    "if_statement",
];

fn cpp_bindings_before(
    ctx: CppLookupCtx<'_, '_>,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CppType> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    cpp_seed_active_path(ctx, root, cutoff_start, &mut bindings);
    bindings
}

fn cpp_local_bindings_before(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CppType> {
    let Some(local_root) = cpp_enclosing_local_scope(node) else {
        return LocalInferenceEngine::new(LocalInferenceConfig::default());
    };
    cpp_bindings_before(ctx, local_root, cutoff_start)
}

fn cpp_enclosing_local_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    let mut fallback = None;
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
            return Some(parent);
        }
        if fallback.is_none() && parent.kind() == "compound_statement" {
            fallback = Some(parent);
        }
        node = parent;
    }
    fallback
}

fn cpp_seed_active_path(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }
    let enters_scope = CPP_SCOPE_NODES.contains(&node.kind());
    if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration"
            if node.end_byte() <= cutoff_start =>
        {
            cpp_seed_typed_binding(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                node,
                bindings,
            )
        }
        "for_range_loop" if node.start_byte() < cutoff_start => {
            cpp_seed_for_range_binding(ctx, node, cutoff_start, bindings)
        }
        "declaration" | "field_declaration" if node.start_byte() < cutoff_start => {
            cpp_seed_variable_declaration(ctx, node, cutoff_start, bindings)
        }
        "expression_statement" if node.end_byte() <= cutoff_start => {
            cpp_seed_recovered_statement_declaration(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                node,
                bindings,
            )
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        cpp_seed_active_path(ctx, child, cutoff_start, bindings);
    }
}

fn cpp_seed_typed_binding(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, source) else {
        return;
    };
    let type_text =
        cpp_declaration_type_text_for_declarator(visibility, file, node, declarator, source)
            .or_else(|| cpp_declaration_type_text(visibility, file, node, source));
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node));
    cpp_seed_binding(
        analyzer,
        support,
        visibility,
        file,
        source,
        cpp_lexical_namespace(node, source).as_deref(),
        &name,
        type_text.as_deref(),
        type_node,
        cpp_declarator_pointer_depth(declarator),
        None,
        None,
        bindings,
    );
}

fn cpp_seed_for_range_binding(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if node
        .child_by_field_name("body")
        .is_none_or(|body| body.start_byte() > cutoff_start)
    {
        return;
    }
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node))
        .map(|type_node| cpp_normalize_declared_type_text(cpp_node_text(type_node, ctx.source)));
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node));
    cpp_seed_binding(
        ctx.analyzer,
        ctx.support,
        ctx.visibility,
        ctx.file,
        ctx.source,
        cpp_lexical_namespace(node, ctx.source).as_deref(),
        &name,
        type_text.as_deref(),
        type_node,
        cpp_declarator_pointer_depth(declarator),
        None,
        None,
        bindings,
    );
}

fn cpp_seed_variable_declaration(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    let declaration_type_text =
        cpp_declaration_type_text(ctx.visibility, ctx.file, node, ctx.source);
    let declaration_type_node = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node));
    let mut seeded_structured_declarator = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if cpp_is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        if declarator.start_byte() >= cutoff_start {
            continue;
        }
        let type_text = cpp_declaration_type_text_for_declarator(
            ctx.visibility,
            ctx.file,
            node,
            declarator,
            ctx.source,
        )
        .or_else(|| declaration_type_text.clone());
        if declarator.kind() == "function_declarator"
            && !cpp_constructor_style_local_declaration(
                ctx.visibility,
                ctx.file,
                ctx.source,
                declarator,
                type_text.as_deref(),
                bindings,
            )
        {
            if cpp_enclosing_local_scope(node).is_some()
                && let Some(name) = extract_variable_name(declarator, ctx.source)
            {
                bindings.declare_shadow(name);
            }
            continue;
        }
        if let Some(name) = extract_variable_name(declarator, ctx.source) {
            seeded_structured_declarator = true;
            let value = child
                .child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start);
            cpp_seed_binding(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                cpp_lexical_namespace(node, ctx.source).as_deref(),
                &name,
                type_text.as_deref(),
                declaration_type_node,
                cpp_declarator_pointer_depth(declarator),
                Some(ctx.root),
                value,
                bindings,
            );
        }
    }
    // An object-like annotation macro is parsed as the declaration's type,
    // the real type as a structured declarator, and the actual variable tail
    // as a direct ERROR child. Preserve recovery for that explicit AST gap,
    // while ordinary fully structured declarations must not be reseeded by
    // the less precise statement recovery path.
    let has_direct_declarator_error = (0..node.named_child_count()).any(|index| {
        node.named_child(index)
            .is_some_and(|child| child.kind() == "ERROR")
    });
    if (!seeded_structured_declarator || has_direct_declarator_error)
        && node.end_byte() <= cutoff_start
    {
        cpp_seed_recovered_statement_declaration(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
            bindings,
        );
    }
}

fn cpp_seed_recovered_statement_declaration(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    for (name, type_text, pointer_depth) in
        cpp_recover_macro_decorated_statement_declarations(visibility, file, node, source)
    {
        cpp_seed_binding(
            analyzer,
            support,
            visibility,
            file,
            source,
            cpp_lexical_namespace(node, source).as_deref(),
            &name,
            Some(&type_text),
            None,
            pointer_depth,
            None,
            None,
            bindings,
        );
    }
}

fn cpp_recover_macro_decorated_statement_declarations(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
) -> Vec<(String, String, i32)> {
    let statement = cpp_node_text(node, source)
        .trim()
        .trim_end_matches(';')
        .trim();
    if statement.is_empty()
        || statement.contains(['=', '{', '}'])
        || statement.starts_with("return ")
    {
        return Vec::new();
    }
    let declarators: Vec<_> = cpp_split_top_level_commas(statement).collect();
    let Some(first) = declarators.first().map(|part| part.trim()) else {
        return Vec::new();
    };
    let Some((first_name, first_start, first_end)) = cpp_last_identifier_span(first) else {
        return Vec::new();
    };
    if !first[first_end..]
        .trim()
        .chars()
        .all(|ch| matches!(ch, '*' | '&'))
    {
        return Vec::new();
    }
    let prefix = first[..first_start].trim();
    if prefix.is_empty() {
        return Vec::new();
    }
    let shared_prefix = prefix.trim_end_matches(['*', '&', ' ', '\t', '\n', '\r']);
    let first_declarator_prefix = prefix[shared_prefix.len()..].trim();
    if first_declarator_prefix
        .chars()
        .any(|ch| !matches!(ch, '*' | '&' | ' ' | '\t' | '\n' | '\r'))
    {
        return Vec::new();
    }
    let normalized = cpp_normalize_declared_type_text(shared_prefix);
    let Some(type_text) = cpp_resolvable_declared_type_suffix(visibility, file, &normalized) else {
        return Vec::new();
    };
    let mut recovered = vec![(
        first_name.to_string(),
        type_text.clone(),
        cpp_type_text_pointer_depth(first_declarator_prefix),
    )];

    for declarator in declarators.iter().skip(1).map(|part| part.trim()) {
        let Some((name, start, end)) = cpp_last_identifier_span(declarator) else {
            continue;
        };
        if !declarator[end..]
            .trim()
            .chars()
            .all(|ch| matches!(ch, '*' | '&'))
        {
            continue;
        }
        let declarator_prefix = declarator[..start].trim();
        if declarator_prefix
            .chars()
            .any(|ch| !matches!(ch, '*' | '&' | ' ' | '\t' | '\n' | '\r'))
        {
            continue;
        }
        recovered.push((
            name.to_string(),
            type_text.clone(),
            cpp_type_text_pointer_depth(declarator_prefix),
        ));
    }

    recovered
}

fn cpp_last_identifier_span(text: &str) -> Option<(&str, usize, usize)> {
    let (end_start, end_ch) = text
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')?;
    let end = end_start + end_ch.len_utf8();
    let start = text[..end]
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_'))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let ident = &text[start..end];
    ident
        .chars()
        .next()
        .filter(|ch| ch.is_ascii_alphabetic() || *ch == '_')?;
    Some((ident, start, end))
}

fn cpp_declaration_type_text(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    cpp_declaration_prefix_before_first_declarator(node, source)
        .or_else(|| {
            node.child_by_field_name("type")
                .or_else(|| cpp_first_type_child(node))
                .map(|type_node| cpp_node_text(type_node, source).to_string())
        })
        .map(|text| cpp_normalize_declared_type_for_visibility(visibility, file, &text))
        .filter(|text| !text.is_empty())
}

fn cpp_declaration_type_text_for_declarator(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    declaration: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let name = cpp_declarator_name_node(declarator)?;
    let prefix = source
        .get(declaration.start_byte()..name.start_byte())?
        .trim();
    if prefix.contains(',') {
        return cpp_declaration_type_text(visibility, file, declaration, source);
    }
    (!prefix.is_empty())
        .then(|| cpp_normalize_declared_type_for_visibility(visibility, file, prefix))
        .filter(|text| !text.is_empty())
}

fn cpp_declarator_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "field_identifier" => Some(node),
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))
            .and_then(cpp_declarator_name_node),
    }
}

fn cpp_normalize_declared_type_for_visibility(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    text: &str,
) -> String {
    let normalized = cpp_normalize_declared_type_text(text);
    cpp_resolvable_declared_type_suffix(visibility, file, &normalized).unwrap_or(normalized)
}

fn cpp_resolvable_declared_type_suffix(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    text: &str,
) -> Option<String> {
    if visibility.resolve_type(file, text).is_some() {
        return Some(text.to_string());
    }
    let tokens: Vec<_> = text.split_whitespace().collect();
    for index in 1..tokens.len() {
        let suffix = tokens[index..].join(" ");
        if visibility.resolve_type(file, &suffix).is_some() {
            return Some(suffix);
        }
    }
    None
}

fn cpp_declaration_prefix_before_first_declarator(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let first_declarator = node.named_children(&mut cursor).find_map(|child| {
        if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if cpp_is_declarator_node(child) {
            Some(child)
        } else {
            None
        }
    })?;
    source
        .get(node.start_byte()..first_declarator.start_byte())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn cpp_normalize_declared_type_text(text: &str) -> String {
    const DECLARATION_SPECIFIERS: [&str; 10] = [
        "const ",
        "volatile ",
        "static ",
        "extern ",
        "mutable ",
        "constexpr ",
        "constinit ",
        "inline ",
        "register ",
        "thread_local ",
    ];

    let mut normalized = normalize_cpp_type_text(text);
    loop {
        let Some(stripped) = DECLARATION_SPECIFIERS
            .iter()
            .find_map(|specifier| normalized.strip_prefix(specifier))
        else {
            return normalized;
        };
        normalized = normalize_cpp_type_text(stripped);
    }
}

fn cpp_constructor_style_local_declaration(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    declarator: Node<'_>,
    type_text: Option<&str>,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let Some(parameters) = declarator.child_by_field_name("parameters") else {
        return false;
    };
    if parameters.named_child_count() == 0 {
        return false;
    }
    if extract_variable_name(declarator, source).is_none() {
        return false;
    }
    if !type_text
        .and_then(|text| visibility.resolve_type(file, text))
        .is_some_and(|unit| unit.is_class())
    {
        return false;
    }
    cpp_constructor_arguments_look_like_expressions(visibility, file, source, parameters, bindings)
}

fn cpp_constructor_arguments_look_like_expressions(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    parameters: Node<'_>,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let text = cpp_node_text(parameters, source);
    let inner = text.trim().trim_start_matches('(').trim_end_matches(')');
    cpp_split_top_level_commas(inner).any(|argument| {
        let argument = argument.trim();
        !argument.is_empty()
            && !cpp_argument_looks_like_parameter_declaration(visibility, file, argument, bindings)
    })
}

fn cpp_argument_looks_like_parameter_declaration(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    argument: &str,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let without_default = argument.split('=').next().unwrap_or(argument).trim();
    if without_default.is_empty() {
        return false;
    }
    if is_cpp_local_symbol_expression(without_default, bindings) {
        return false;
    }
    if cpp_builtin_type_text(without_default) {
        return true;
    }
    visibility
        .resolve_type(file, &cpp_parameter_type_text(without_default))
        .is_some()
}

fn is_cpp_local_symbol_expression(
    argument: &str,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    argument
        .chars()
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !bindings.resolve_symbol(argument).is_unknown()
}

fn cpp_builtin_type_text(text: &str) -> bool {
    // Builtin-ness is a property of the base type, independent of pointer depth,
    // so drop the trailing `*` markers that `cpp_parameter_type_text` appends.
    let normalized = cpp_parameter_type_text(text);
    let normalized = normalized.trim_end_matches('*');
    let tokens: Vec<_> = normalized.split_whitespace().collect();
    !tokens.is_empty()
        && tokens.iter().all(|token| {
            matches!(
                *token,
                "auto"
                    | "bool"
                    | "char"
                    | "char8_t"
                    | "char16_t"
                    | "char32_t"
                    | "const"
                    | "double"
                    | "float"
                    | "int"
                    | "long"
                    | "short"
                    | "signed"
                    | "size_t"
                    | "unsigned"
                    | "void"
                    | "volatile"
                    | "wchar_t"
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn cpp_seed_binding(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    lexical_namespace: Option<&str>,
    name: &str,
    type_text: Option<&str>,
    type_node: Option<Node<'_>>,
    declarator_depth: i32,
    root: Option<Node<'_>>,
    value: Option<Node<'_>>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_text
        .filter(|text| *text != "auto")
        .map(|text| {
            let name = normalize_cpp_type_name(text);
            let structured_template_node = type_node.filter(|node| cpp_contains_template_id(*node));
            let unit = match structured_template_node
                .map(|node| visibility.resolve_type_node_result(file, node, source))
            {
                Some(Ok(Some(unit))) => Some(unit),
                Some(Err(())) => None,
                Some(Ok(None)) | None => cpp_resolve_type_unit_in_namespace(
                    analyzer,
                    visibility,
                    file,
                    &name,
                    lexical_namespace,
                ),
            };
            CppType {
                name: name.clone(),
                unit,
                indirection: 0,
                alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &name),
            }
        })
        .or_else(|| {
            value.and_then(|value| {
                cpp_infer_type_from_value(analyzer, support, visibility, file, source, root, value)
            })
        });
    match resolved {
        Some(mut cpp_type) => {
            // The declarator (`T* p`, `T** pp`) adds to whatever the type spelling
            // or inferred value contributed.
            cpp_type.indirection += declarator_depth;
            bindings.seed_symbol(name.to_string(), cpp_type);
        }
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn cpp_contains_template_id(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "template_type" {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn cpp_resolve_type_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<CodeUnit> {
    cpp_resolve_type_unit_in_namespace(analyzer, visibility, file, type_text, None)
}

fn cpp_resolve_type_unit_in_namespace(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
    lexical_namespace: Option<&str>,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    if name.contains("::")
        && !type_text.trim_start().starts_with("::")
        && let Some(unit) = lexical_namespace
            .into_iter()
            .flat_map(|namespace| cpp_namespace_relative_names(namespace, &name))
            .find_map(|candidate| {
                let mut seen = HashSet::default();
                cpp_resolve_type_unit_inner(analyzer, visibility, file, &candidate, &mut seen)
            })
    {
        return Some(unit);
    }
    let mut seen = HashSet::default();
    cpp_resolve_type_unit_inner(analyzer, visibility, file, type_text, &mut seen)
}

fn cpp_resolve_type_alias_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    visibility
        .type_name_candidates(file, &name)
        .into_iter()
        .find_map(|unit| {
            (cpp_unit_is_type_alias(analyzer, unit) && cpp_type_unit_matches_name(unit, &name))
                .then(|| unit.clone())
        })
}

fn cpp_resolve_type_unit_inner(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
    seen: &mut HashSet<String>,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    if !seen.insert(name.clone()) {
        return None;
    }
    let mut targets = visibility
        .type_name_candidates(file, &name)
        .into_iter()
        .filter(|unit| {
            (unit.is_class() || cpp_unit_is_type_alias(analyzer, unit))
                && cpp_type_unit_matches_name(unit, &name)
        })
        .filter_map(|unit| {
            cpp_alias_target_unit(analyzer, visibility, file, unit, seen)
                .or_else(|| (!cpp_unit_is_type_alias(analyzer, unit)).then(|| unit.clone()))
        })
        .collect::<Vec<_>>();
    if targets.is_empty()
        && let Some(unit) = visibility.resolve_type(file, type_text)
    {
        targets
            .push(cpp_alias_target_unit(analyzer, visibility, file, &unit, seen).unwrap_or(unit));
    }
    cpp_choose_canonical_type(analyzer, targets)
}

fn cpp_type_unit_matches_name(unit: &CodeUnit, name: &str) -> bool {
    if name.contains("::") {
        cpp_name_for(unit) == name
    } else {
        unit.identifier() == name
    }
}

fn cpp_namespace_relative_names(namespace: &str, name: &str) -> Vec<String> {
    let parts = namespace
        .split("::")
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    (1..=parts.len())
        .rev()
        .map(|len| format!("{}::{name}", parts[..len].join("::")))
        .collect()
}

fn cpp_choose_canonical_type(
    analyzer: &dyn IAnalyzer,
    mut candidates: Vec<CodeUnit>,
) -> Option<CodeUnit> {
    sort_units(&mut candidates);
    candidates.dedup();
    let first = candidates.first()?.clone();
    let cpp_name = cpp_name_for(&first);
    if !candidates
        .iter()
        .all(|candidate| cpp_name_for(candidate) == cpp_name)
    {
        return (candidates.len() == 1).then_some(first);
    }
    candidates
        .iter()
        .find(|candidate| cpp_type_has_definition_body(analyzer, candidate))
        .or(Some(&first))
        .cloned()
}

fn cpp_type_has_definition_body(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.signature()
        .is_some_and(|signature| signature.contains('{') || signature.contains(':'))
        || analyzer
            .signatures(unit)
            .iter()
            .any(|signature| signature.contains('{') || signature.contains(':'))
        || analyzer
            .get_source(unit, false)
            .is_some_and(|source| source.contains('{') || source.contains(':'))
}

fn cpp_alias_target_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    unit: &CodeUnit,
    seen: &mut HashSet<String>,
) -> Option<CodeUnit> {
    if !cpp_unit_is_type_alias(analyzer, unit) {
        return None;
    }
    cpp_alias_target_texts(analyzer, unit)
        .find_map(|rhs| cpp_resolve_type_unit_inner(analyzer, visibility, file, &rhs, seen))
}

/// Resolve the receiver type reached by `receiver->member` when `receiver` has a template
/// alias type such as `using NodeDefPtr = shared_ptr<NodeDef>`. `->` is governed by the
/// wrapper's `operator->` return type, so we resolve the wrapper class, read that operator's
/// declared return type, substitute the alias's template arguments for the wrapper's
/// parameters, and resolve the pointee. This models the language rule rather than assuming the
/// wrapper exposes its first template argument.
fn cpp_alias_arrow_target_unit(ctx: CppLookupCtx<'_, '_>, alias: &CodeUnit) -> Option<CodeUnit> {
    cpp_alias_target_texts(ctx.analyzer, alias).find_map(|rhs| {
        let head = rhs.split('<').next()?.trim();
        let args = cpp_angle_group_items(&rhs);
        let mut wrapper_seen = HashSet::default();
        let wrapper = cpp_resolve_type_unit_inner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            head,
            &mut wrapper_seen,
        )?;
        let params = cpp_template_parameter_names(ctx.analyzer, &wrapper);
        let arrow = cpp_member_candidates(ctx, vec![wrapper], "operator->", None, None)
            .into_iter()
            .next()?;
        let return_text = cpp_function_return_type_text(ctx.analyzer, &arrow)?;
        // `receiver->member` follows one level of pointer indirection from operator->'s result.
        if cpp_type_text_pointer_depth(&return_text) < 1 {
            return None;
        }
        let pointee = return_text
            .trim()
            .strip_suffix('*')
            .unwrap_or(&return_text)
            .trim();
        let pointee = cpp_substitute_template_param(&params, &args, pointee);
        let mut pointee_seen = HashSet::default();
        cpp_resolve_type_unit_inner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            &pointee,
            &mut pointee_seen,
        )
    })
}

/// Substitute a wrapper template parameter name appearing in `type_text` with the matching
/// argument supplied by the alias, by declaration order. Non-parameter text (a concrete return
/// type) is returned unchanged.
fn cpp_substitute_template_param(params: &[String], args: &[String], type_text: &str) -> String {
    let target = type_text.trim();
    params
        .iter()
        .position(|param| param == target)
        .and_then(|index| args.get(index))
        .map(|arg| arg.trim().to_string())
        .unwrap_or_else(|| target.to_string())
}

/// Names of the template parameters a class/alias unit declares, e.g. `["T"]` for
/// `template <class T> class shared_ptr`. Empty when the unit is not a template.
fn cpp_template_parameter_names(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<String> {
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(unit).first().cloned())
        .unwrap_or_default();
    let Some(group) = cpp_first_angle_group(&signature) else {
        return Vec::new();
    };
    cpp_split_top_level_commas(group)
        .filter_map(|param| cpp_trailing_identifier(param.split('=').next().unwrap_or(param)))
        .collect()
}

/// Top-level comma-separated items inside the first balanced `<...>` group of `text`, e.g. the
/// template arguments of `shared_ptr<NodeDef>`.
fn cpp_angle_group_items(text: &str) -> Vec<String> {
    cpp_first_angle_group(text)
        .map(|group| {
            cpp_split_top_level_commas(group)
                .map(|item| item.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Contents of the first balanced `<...>` group in `text`, ignoring nested angle brackets.
fn cpp_first_angle_group(text: &str) -> Option<&str> {
    let open = text.find('<')?;
    let mut depth = 0i32;
    for (offset, ch) in text[open..].char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[open + 1..open + offset].trim());
                }
            }
            _ => {}
        }
    }
    None
}

/// The trailing identifier of a template parameter declaration, e.g. `T` from `class T`.
fn cpp_trailing_identifier(text: &str) -> Option<String> {
    let name: String = text
        .trim()
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
}

fn cpp_alias_target_texts<'a>(
    analyzer: &'a dyn IAnalyzer,
    unit: &'a CodeUnit,
) -> impl Iterator<Item = String> + 'a {
    let mut signatures: Vec<String> = unit.signature().map(str::to_string).into_iter().collect();
    signatures.extend(analyzer.signatures(unit));
    signatures.extend(analyzer.get_source(unit, false));
    signatures
        .into_iter()
        .filter_map(|signature| cpp_alias_target_text(&signature))
}

fn cpp_alias_target_text(signature: &str) -> Option<String> {
    let signature = signature.trim();
    let rhs = if let Some((_, rhs)) = signature.split_once('=') {
        rhs
    } else if let Some(rest) = signature.strip_prefix("typedef ") {
        rest.rsplit_once(char::is_whitespace)?.0
    } else {
        return None;
    };
    Some(rhs.trim().trim_end_matches(';').trim().to_string())
}

fn cpp_infer_type_from_value(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Option<Node<'_>>,
    node: Node<'_>,
) -> Option<CppType> {
    match node.kind() {
        "new_expression" => {
            let text = cpp_node_text(node, source).trim();
            let rest = text.strip_prefix("new ").unwrap_or(text);
            let type_text = rest.split(['(', '{']).next().unwrap_or(rest);
            Some(CppType::from_text(analyzer, visibility, file, type_text, 1))
        }
        "call_expression" => cpp_call_return_type(
            analyzer, support, visibility, file, source, root, node,
        )
        .or_else(|| {
            node.child_by_field_name("function")
                .and_then(|function| visibility.resolve_type(file, cpp_node_text(function, source)))
                .map(|unit| CppType::from_unit(unit, 0))
        }),
        _ => None,
    }
}

fn cpp_call_return_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Option<Node<'_>>,
    call: Node<'_>,
) -> Option<CppType> {
    let function = call.child_by_field_name("function")?;
    let CallArityEvidence::Exact(arity) = visibility.call_arity_evidence(file, call, source) else {
        return None;
    };
    let candidates = match function.kind() {
        "qualified_identifier" => {
            let scope = function.child_by_field_name("scope")?;
            let name = function
                .child_by_field_name("name")
                .and_then(cpp_callable_name_node)?;
            let owner = visibility.resolve_type(file, cpp_node_text(scope, source))?;
            cpp_filter_candidates_by_arity(
                cpp_direct_member_candidates(
                    analyzer,
                    support,
                    &[owner],
                    cpp_node_text(name, source),
                ),
                Some(arity),
            )
        }
        "identifier" | "dependent_name" | "template_function" | "template_method" => {
            let name = cpp_callable_name_node(function)?;
            cpp_filter_candidates_by_arity(
                cpp_visible_name_candidates(
                    analyzer,
                    visibility,
                    file,
                    support,
                    cpp_node_text(name, source),
                    Some(CppTargetKind::FreeFunction),
                    None,
                ),
                Some(arity),
            )
        }
        "field_expression" => {
            let root = root?;
            let member = function
                .child_by_field_name("field")
                .and_then(cpp_callable_name_node)
                .map(|field| cpp_node_text(field, source))?;
            let receiver = function
                .child_by_field_name("argument")
                .or_else(|| function.named_child(0))?;
            let owners = cpp_field_receiver_type_units(
                analyzer, support, visibility, file, source, root, function, receiver,
            );
            cpp_member_candidates(
                CppLookupCtx {
                    analyzer,
                    support,
                    file,
                    visibility,
                    source,
                    root,
                },
                owners,
                member,
                Some(arity),
                None,
            )
        }
        _ => Vec::new(),
    };
    cpp_unanimous_function_return_type(analyzer, visibility, file, &candidates)
}

fn cpp_unanimous_function_return_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    candidates: &[CodeUnit],
) -> Option<CppType> {
    let mut resolved_return: Option<CppType> = None;
    for candidate in candidates {
        let return_type = cpp_function_return_type(analyzer, visibility, file, candidate)?;
        if let Some(existing) = resolved_return.as_ref()
            && (existing.name != return_type.name
                || existing.indirection != return_type.indirection)
        {
            return None;
        }
        resolved_return = Some(return_type);
    }
    resolved_return
}

fn cpp_function_return_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    function: &CodeUnit,
) -> Option<CppType> {
    let type_text = cpp_function_return_type_text(analyzer, function)?;
    let indirection = cpp_type_text_pointer_depth(&type_text);
    let type_text = normalize_cpp_type_text(&type_text);
    Some(CppType::from_text(
        analyzer,
        visibility,
        file,
        &type_text,
        indirection,
    ))
}

fn cpp_unresolved_include_boundary(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if !reference.contains("::") && !reference.chars().next().is_some_and(char::is_uppercase) {
        return false;
    }
    let include_targets =
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|cpp| cpp.include_target_index());
    analyzer.import_statements(file).iter().any(|import| {
        cpp_include_paths(std::slice::from_ref(import)).iter().any(
            |include| match include_targets {
                Some(index) => resolve_include_targets_with_index(file, include, index).is_empty(),
                None => resolve_include_targets(analyzer.project(), file, include).is_empty(),
            },
        )
    })
}

fn cpp_lexical_namespace(node: Node<'_>, source: &str) -> Option<String> {
    let mut names = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent.child_by_field_name("name")
        {
            names.push(cpp_node_text(name, source).trim().to_string());
        }
        current = parent.parent();
    }
    names.reverse();
    (!names.is_empty()).then(|| names.join("::"))
}
