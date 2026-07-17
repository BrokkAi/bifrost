use super::*;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{AnalyzerDefinitionLookup, BoundedDefinitionLookup};

pub(crate) enum JavaTypeLookupResolution {
    Type {
        fqn: String,
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JavaMemberLookupKind {
    Field,
    Method,
}

pub(crate) fn java_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<JavaTypeLookupResolution> {
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    let node = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    java_type_lookup_node_fqn(analyzer, java, file, source, root, node)
}

pub(super) fn resolve_java(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return no_definition("java_analyzer_unavailable", "Java analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("java_parse_failed", "Java source could not be parsed");
    };

    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Java definition",
                site.text
            ),
        );
    };

    if is_java_declaration_or_import_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Java reference site", site.text),
        );
    }

    match node.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            if let Some(creation) = java_enclosing_object_creation(node) {
                return resolve_java_constructor_call(
                    analyzer, java, support, file, source, creation,
                );
            }
            resolve_java_type_reference(analyzer, java, support, file, source, node)
        }
        "object_creation_expression" => {
            resolve_java_constructor_call(analyzer, java, support, file, source, node)
        }
        "method_invocation" => {
            resolve_java_method_invocation(analyzer, support, file, source, root, node)
        }
        "method_reference" => {
            resolve_java_method_reference(analyzer, java, support, file, source, root, node)
        }
        "field_access" => resolve_java_field_access(analyzer, support, file, source, root, node),
        "identifier" => {
            if let Some(parent) = node.parent() {
                match parent.kind() {
                    "method_invocation" => {
                        return resolve_java_method_invocation(
                            analyzer, support, file, source, root, parent,
                        );
                    }
                    "field_access" => {
                        return match qualified_access_focus(node, parent, &["object"], &["field"]) {
                            Some(QualifiedAccessFocus::Qualifier)
                                if java_field_access_is_simple_focused_qualifier(
                                    root, site, parent, node,
                                ) =>
                            {
                                java_receiver_type(analyzer, file, source, root, node)
                                    .map(|unit| candidates_outcome(vec![unit]))
                                    .unwrap_or_else(|| {
                                        resolve_java_bare_identifier(
                                            analyzer, java, support, file, source, root, node,
                                        )
                                    })
                            }
                            Some(QualifiedAccessFocus::Member)
                            | Some(QualifiedAccessFocus::Qualifier) => resolve_java_field_access(
                                analyzer, support, file, source, root, parent,
                            ),
                            None => no_definition(
                                "unsupported_java_reference_shape",
                                format!(
                                    "`{}` is a Java `{}` reference shape that get_definition does not resolve yet",
                                    site.text,
                                    node.kind()
                                ),
                            ),
                        };
                    }
                    "method_reference" => {
                        return resolve_java_method_reference(
                            analyzer, java, support, file, source, root, parent,
                        );
                    }
                    _ => {}
                }
            }
            resolve_java_bare_identifier(analyzer, java, support, file, source, root, node)
        }
        _ => no_definition(
            "unsupported_java_reference_shape",
            format!(
                "`{}` is a Java `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn java_type_lookup_node_fqn(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<JavaTypeLookupResolution> {
    if matches!(
        node.kind(),
        "type_identifier" | "scoped_type_identifier" | "generic_type"
    ) {
        return java_type_from_node_with_context(analyzer, java, file, source, node).map(|unit| {
            JavaTypeLookupResolution::Type {
                fqn: unit.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::TypeReference,
            }
        });
    }

    if node.kind() != "identifier" {
        return None;
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "field_access"
            && parent.child_by_field_name("object") == Some(node)
            && let Some(receiver) = java_receiver_type(analyzer, file, source, root, node)
        {
            return Some(JavaTypeLookupResolution::Type {
                fqn: receiver.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
        if parent.kind() == "method_invocation"
            && parent.child_by_field_name("object") == Some(node)
            && let Some(receiver) = java_receiver_type(analyzer, file, source, root, node)
        {
            return Some(JavaTypeLookupResolution::Type {
                fqn: receiver.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
        if java_is_callable_declaration_name(parent, node) {
            return Some(JavaTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(declared) =
            java_declaration_name_type(analyzer, java, file, source, root, parent, node)
        {
            return Some(JavaTypeLookupResolution::Type {
                fqn: declared.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
    }

    let name = java_node_text(node, source);
    java_type_of_identifier_before(analyzer, java, file, source, root, name, node.start_byte()).map(
        |unit| JavaTypeLookupResolution::Type {
            fqn: unit.fq_name().to_string(),
            target_kind: TypeLookupTargetKind::ValueExpression,
        },
    )
}

fn java_declaration_name_type(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    parent: Node<'_>,
    name: Node<'_>,
) -> Option<CodeUnit> {
    match parent.kind() {
        "formal_parameter" if parent.child_by_field_name("name") == Some(name) => {
            parent.child_by_field_name("type").and_then(|type_node| {
                java_type_from_node_with_context(analyzer, java, file, source, type_node)
            })
        }
        "variable_declarator" if parent.child_by_field_name("name") == Some(name) => {
            let declaration = parent.parent()?;
            if !matches!(
                declaration.kind(),
                "local_variable_declaration" | "field_declaration"
            ) {
                return None;
            }
            declaration
                .child_by_field_name("type")
                .and_then(|type_node| {
                    java_type_from_node_with_context(analyzer, java, file, source, type_node)
                })
        }
        _ => java_type_of_identifier_before(
            analyzer,
            java,
            file,
            source,
            root,
            java_node_text(name, source),
            name.end_byte(),
        ),
    }
}

pub(super) fn parse_java_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn is_java_declaration_or_import_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "import_declaration" || parent.kind() == "package_declaration" {
        return true;
    }
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "field_declaration"
                | "variable_declarator"
                | "formal_parameter"
        )
}

fn resolve_java_type_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let raw = java_node_text(node, source);
    let normalized = normalize_java_type_text(raw);
    if normalized.is_empty() {
        return no_definition("no_reference_text", "Java type reference is blank");
    }
    if let Some(outcome) =
        java_explicit_scoped_type_reference(analyzer, java, support, file, source, node)
    {
        return outcome;
    }
    if let Some(unit) = java_nested_type_from_context(analyzer, file, normalized, node.start_byte())
    {
        return candidates_outcome(vec![unit]);
    }
    if let Some(unit) = java.resolve_type_name_in_file(file, normalized) {
        return candidates_outcome(vec![unit]);
    }
    if let Some(unit) = java_qualified_nested_type(analyzer, java, file, source, node) {
        return candidates_outcome(vec![unit]);
    }
    if java_import_boundary_for_type(java, support, file, normalized) {
        return boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{normalized}` did not resolve to an indexed Java type"),
    )
}

fn java_explicit_scoped_type_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let scoped = java_enclosing_scoped_type_identifier(node)?;
    let normalized = normalize_java_type_text(java_node_text(scoped, source));
    let terminal = normalize_java_type_text(java_node_text(node, source));
    if normalized.is_empty() || normalized == terminal {
        return None;
    }

    if let Some(unit) = java.resolve_type_name_in_file(file, normalized) {
        return Some(candidates_outcome(vec![unit]));
    }
    if let Some(unit) = java_qualified_nested_type(analyzer, java, file, source, node) {
        return Some(candidates_outcome(vec![unit]));
    }
    if java
        .resolve_type_name_with_external(file, normalized)
        .is_some()
    {
        return Some(boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        )));
    }
    if java_scoped_type_qualifier_resolves_in_source(java, file, source, scoped) {
        return Some(no_definition(
            "no_indexed_definition",
            format!("`{normalized}` did not resolve to an indexed Java type"),
        ));
    }
    let qualifier_is_in_workspace = java_scoped_type_qualifier_text(scoped, source)
        .is_some_and(|qualifier| java_workspace_package_exists(support, qualifier));
    if java_import_boundary_for_type(java, support, file, normalized) || !qualifier_is_in_workspace
    {
        return Some(boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        )));
    }
    Some(no_definition(
        "no_indexed_definition",
        format!("`{normalized}` did not resolve to an indexed Java type"),
    ))
}

fn resolve_java_method_invocation(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = node.child_by_field_name("name") else {
        return no_definition("no_method_name", "Java method invocation has no name");
    };
    let name = java_node_text(name_node, source);
    if name.is_empty() {
        return no_definition("no_method_name", "Java method invocation has a blank name");
    }
    let arity = java_argument_count(node);

    if let Some(object) = node.child_by_field_name("object") {
        if let Some(owner) = java_receiver_type(analyzer, file, source, root, object) {
            return java_member_candidates(
                analyzer,
                support,
                &owner.fq_name(),
                name,
                JavaMemberLookupKind::Method,
                true,
                Some(arity),
            );
        }
        return no_definition(
            "unsupported_java_receiver",
            format!("receiver for Java method `{name}` is not resolved"),
        );
    }

    let static_import = java_static_import_candidates(
        analyzer,
        support,
        file,
        name,
        JavaMemberLookupKind::Method,
        Some(arity),
    );
    if static_import.status != DefinitionLookupStatus::NoDefinition
        && static_import
            .definitions
            .iter()
            .any(|unit| java_callable_accepts_arity(analyzer, unit, arity))
    {
        return static_import;
    }

    let class_ranges = ClassRangeIndex::build(analyzer, file);
    if let Some(owner_fqn) = class_ranges.enclosing(name_node.start_byte()) {
        let outcome = java_member_candidates(
            analyzer,
            support,
            owner_fqn,
            name,
            JavaMemberLookupKind::Method,
            true,
            Some(arity),
        );
        if outcome
            .definitions
            .iter()
            .any(|unit| java_callable_accepts_arity(analyzer, unit, arity))
        {
            return outcome;
        }
    }

    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java method"),
    )
}

fn resolve_java_method_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = java_node_text(node, source);
    let Some(separator) = text.find("::") else {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has no `::` separator",
        );
    };
    let receiver_text = text[..separator].trim();
    let member = java_method_reference_member_name(text[separator + 2..].trim());
    if receiver_text.is_empty() || member.is_empty() {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has a blank receiver or member",
        );
    }
    if member == "new" {
        let owner = java_method_reference_receiver_node(node, node.start_byte() + separator)
            .and_then(|receiver| java_receiver_type(analyzer, file, source, root, receiver))
            .or_else(|| {
                java_type_text_with_context(
                    analyzer,
                    java,
                    file,
                    normalize_java_type_text(receiver_text),
                    node.start_byte(),
                )
            });
        if let Some(owner) = owner {
            return java_constructor_outcome(analyzer, support, owner, None);
        }
        return resolve_java_type_reference(analyzer, java, support, file, source, node);
    }

    let separator_byte = node.start_byte() + separator;
    let receiver_node = java_method_reference_receiver_node(node, separator_byte);
    let owner = receiver_node
        .and_then(|receiver| java_receiver_type(analyzer, file, source, root, receiver))
        .or_else(|| {
            java_type_text_with_context(
                analyzer,
                java,
                file,
                normalize_java_type_text(receiver_text),
                node.start_byte(),
            )
        });
    if let Some(owner) = owner {
        return java_member_candidates(
            analyzer,
            support,
            &owner.fq_name(),
            member,
            JavaMemberLookupKind::Method,
            true,
            None,
        );
    }

    no_definition(
        "unsupported_java_receiver",
        format!("receiver for Java method reference `{member}` is not resolved"),
    )
}

fn resolve_java_constructor_call(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(type_node) = node.child_by_field_name("type") else {
        return no_definition("no_indexed_definition", "Java constructor call has no type");
    };
    let owner =
        java_type_from_node_with_context(analyzer, java, file, source, type_node).or_else(|| {
            let raw = java_node_text(type_node, source);
            java_type_text_with_context(
                analyzer,
                java,
                file,
                normalize_java_type_text(raw),
                type_node.start_byte(),
            )
        });
    if let Some(owner) = owner {
        return java_constructor_outcome(analyzer, support, owner, Some(java_argument_count(node)));
    }
    resolve_java_type_reference(analyzer, java, support, file, source, type_node)
}

fn java_constructor_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: CodeUnit,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let mut constructors = support.fqn(&format!("{}.{}", owner.fq_name(), owner.identifier()));
    constructors.retain(|unit| unit.is_function() && !unit.is_synthetic());
    constructors = java_filter_candidates_by_arity(analyzer, constructors, arity);
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }

    let indexed_owner = support.fqn(&owner.fq_name());
    if indexed_owner.is_empty() {
        candidates_outcome(vec![owner])
    } else {
        candidates_outcome(indexed_owner)
    }
}

fn java_enclosing_object_creation(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "type_identifier" | "scoped_type_identifier" | "generic_type"
        ) {
            current = parent;
            continue;
        }
        if parent.kind() == "object_creation_expression"
            && parent.child_by_field_name("type") == Some(current)
        {
            return Some(parent);
        }
        return None;
    }
    None
}

fn java_filter_candidates_by_arity(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| java_callable_accepts_arity(analyzer, unit, expected))
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn java_arity_candidates(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
    arity: Option<usize>,
) -> Option<Vec<CodeUnit>> {
    let expected = arity?;
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| java_callable_accepts_arity(analyzer, unit, expected))
        .cloned()
        .collect();
    (!filtered.is_empty()).then_some(filtered)
}

fn java_callable_accepts_arity(analyzer: &dyn IAnalyzer, unit: &CodeUnit, actual: usize) -> bool {
    analyzer
        .signature_metadata(unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| {
            crate::analyzer::CallableArity::exact(java_signature_arity(unit.signature()))
        })
        .accepts(actual)
}

fn java_argument_count(node: Node<'_>) -> usize {
    node.child_by_field_name("arguments")
        .map(|arguments| arguments.named_child_count())
        .unwrap_or(0)
}

fn java_method_reference_receiver_node(node: Node<'_>, separator_byte: usize) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.end_byte() <= separator_byte)
        .last()
}

fn java_method_reference_member_name(mut text: &str) -> &str {
    if let Some(rest) = text.strip_prefix('<')
        && let Some((_, after_type_args)) = rest.split_once('>')
    {
        text = after_type_args.trim_start();
    }
    let end = text
        .char_indices()
        .find(|(_, ch)| *ch != '_' && !ch.is_ascii_alphanumeric())
        .map(|(idx, _)| idx)
        .unwrap_or(text.len());
    &text[..end]
}

fn java_field_access_is_nested_object(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_access" && parent.child_by_field_name("object") == Some(node)
    })
}

fn java_field_access_is_simple_focused_qualifier(
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    access: Node<'_>,
    focus: Node<'_>,
) -> bool {
    !java_field_access_is_nested_object(access)
        && access.child_by_field_name("object") == Some(focus)
        && smallest_named_node_covering(root, site.range.start_byte, site.range.end_byte)
            == Some(access)
}

fn resolve_java_field_access(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(field_node) = node.child_by_field_name("field") else {
        return no_definition("no_field_name", "Java field access has no field name");
    };
    let field = java_node_text(field_node, source);
    let Some(object) = node.child_by_field_name("object") else {
        return no_definition("no_field_receiver", "Java field access has no receiver");
    };
    if let Some(owner) = java_receiver_type(analyzer, file, source, root, object) {
        return java_member_candidates(
            analyzer,
            support,
            &owner.fq_name(),
            field,
            JavaMemberLookupKind::Field,
            false,
            None,
        );
    }
    no_definition(
        "unsupported_java_receiver",
        format!("receiver for Java field `{field}` is not resolved"),
    )
}

fn resolve_java_bare_identifier(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = java_node_text(node, source);
    if let Some(unit) = java.resolve_type_name_in_file(file, name) {
        return candidates_outcome(vec![unit]);
    }
    let static_import = java_static_import_candidates(
        analyzer,
        support,
        file,
        name,
        JavaMemberLookupKind::Field,
        None,
    );
    if static_import.status != DefinitionLookupStatus::NoDefinition {
        return static_import;
    }
    // A bare identifier can be an unqualified field access — resolve it to a
    // field of the enclosing class (or an inherited one), unless the name is
    // bound locally (a local, parameter, or type variable), in which case it is
    // not this field.
    if !java_local_binding_before(source, root, name, node.start_byte()) {
        let class_ranges = ClassRangeIndex::build(analyzer, file);
        if let Some(owner_fqn) = class_ranges.enclosing(node.start_byte()) {
            let outcome = java_member_candidates(
                analyzer,
                support,
                owner_fqn,
                name,
                JavaMemberLookupKind::Field,
                false,
                None,
            );
            if outcome.status == DefinitionLookupStatus::Resolved {
                return outcome;
            }
        }
    }
    if java_import_boundary_for_type(java, support, file, name) {
        return boundary(format!(
            "`{name}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java definition"),
    )
}

fn java_receiver_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    java_receiver_type_for_java(analyzer, java, file, source, root, object).or_else(|| {
        matches!(object.kind(), "this" | "super")
            .then(|| {
                ClassRangeIndex::build(analyzer, file)
                    .enclosing(object.start_byte())
                    .and_then(|fqn| analyzer.definitions(fqn).next())
            })
            .flatten()
    })
}

fn java_receiver_type_for_java(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "object_creation_expression" => object.child_by_field_name("type").and_then(|type_node| {
            java_type_from_node_with_context(analyzer, java, file, source, type_node)
        }),
        "type_identifier" | "scoped_type_identifier" | "generic_type" | "annotated_type" => {
            let raw = java_node_text(object, source);
            java_type_text_with_context(
                analyzer,
                java,
                file,
                normalize_java_type_text(raw),
                object.start_byte(),
            )
        }
        "identifier" => {
            let name = java_node_text(object, source);
            java_type_of_identifier_before(
                analyzer,
                java,
                file,
                source,
                root,
                name,
                object.start_byte(),
            )
            .or_else(|| {
                let support = AnalyzerDefinitionLookup::new(analyzer, Language::Java);
                java_lambda_parameter_type_before(
                    analyzer,
                    java,
                    &support,
                    file,
                    source,
                    root,
                    name,
                    object.start_byte(),
                )
            })
            .or_else(|| {
                (!java_identifier_binding_before(source, root, name, object.start_byte()))
                    .then(|| java.resolve_type_name_in_file(file, name))
                    .flatten()
            })
        }
        // A method-call receiver (`getABC().i`) is typed by the called method's
        // declared return type.
        "method_invocation" => {
            let support = AnalyzerDefinitionLookup::new(analyzer, Language::Java);
            let outcome =
                resolve_java_method_invocation(analyzer, &support, file, source, root, object);
            let method_unit = outcome.definitions.into_iter().next()?;
            java_method_return_type_unit(analyzer, java, file, source, root, &method_unit)
        }
        _ => None,
    }
}

/// Resolve the class named by a method's declared return type. The return type
/// lives on the method's declaration AST node (the stored signature keeps only
/// the parameter list), so read the `type` field from the declaration — using
/// the current tree when the method is in this file, otherwise re-parsing the
/// method's own file.
fn java_method_return_type_unit(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    method_unit: &CodeUnit,
) -> Option<CodeUnit> {
    let method_range = analyzer.ranges(method_unit).first().copied()?;
    let method_file = method_unit.source();
    if method_file == file {
        let type_node = java_return_type_node_covering(root, &method_range)?;
        return java_type_from_node_with_context(analyzer, java, file, source, type_node);
    }
    let method_source = method_file.read_to_string().ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(method_source.as_str(), None)?;
    let type_node = java_return_type_node_covering(tree.root_node(), &method_range)?;
    java_type_from_node_with_context(analyzer, java, method_file, &method_source, type_node)
}

/// The `type` (return-type) node of the innermost `method_declaration` whose
/// span covers `range`.
fn java_return_type_node_covering<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    let mut result = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
            continue;
        }
        if node.kind() == "method_declaration"
            && let Some(type_node) = node.child_by_field_name("type")
        {
            result = Some(type_node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    result
}

fn java_is_callable_declaration_name(parent: Node<'_>, name: Node<'_>) -> bool {
    parent.child_by_field_name("name") == Some(name)
        && matches!(
            parent.kind(),
            "method_declaration" | "constructor_declaration"
        )
}

/// Resolve the name of a `scoped_type_identifier` (`B.Foo`) by resolving the
/// qualifier (`B`) and finding the nested type `Foo` in it — directly or via a
/// superclass/interface. Handles cases the from-context nested lookup misses,
/// like `class A extends B.Foo`.
fn java_qualified_nested_type(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let parent = node.parent()?;
    if parent.kind() != "scoped_type_identifier" {
        return None;
    }
    let mut cursor = parent.walk();
    let qualifier = parent
        .named_children(&mut cursor)
        .find(|child| child.id() != node.id() && child.end_byte() <= node.start_byte())?;
    let qualifier_type = java_type_from_node_with_context(analyzer, java, file, source, qualifier)?;
    let name = java_node_text(node, source);

    let nested = |owner: &CodeUnit| {
        analyzer
            .definitions(&format!("{}.{}", owner.fq_name(), name))
            .find(|unit| unit.is_class())
    };
    if let Some(unit) = nested(&qualifier_type) {
        return Some(unit);
    }
    analyzer
        .type_hierarchy_provider()?
        .get_ancestors(&qualifier_type)
        .into_iter()
        .find_map(|ancestor| nested(&ancestor))
}

fn java_enclosing_scoped_type_identifier(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        if current.kind() == "scoped_type_identifier" {
            return Some(current);
        }
        let parent = current.parent()?;
        if !matches!(
            parent.kind(),
            "annotated_type" | "generic_type" | "scoped_type_identifier"
        ) {
            return None;
        }
        current = parent;
    }
}

fn java_scoped_type_qualifier_resolves_in_source(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    scoped: Node<'_>,
) -> bool {
    java_scoped_type_qualifier_text(scoped, source)
        .and_then(|qualifier| java.resolve_type_name_in_file(file, qualifier))
        .is_some()
}

fn java_scoped_type_qualifier_text<'a>(scoped: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut cursor = scoped.walk();
    scoped
        .named_children(&mut cursor)
        .find(|child| child.end_byte() < scoped.end_byte())
        .map(|qualifier| java_node_text(qualifier, source))
        .filter(|qualifier| !qualifier.is_empty())
}

fn java_type_from_node_with_context(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CodeUnit> {
    java_type_text_with_context(
        analyzer,
        java,
        file,
        normalize_java_type_text(java_node_text(type_node, source)),
        type_node.start_byte(),
    )
}

fn java_type_text_with_context(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    normalized: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if normalized.is_empty() {
        return None;
    }
    if !normalized.contains('.')
        && let Some(unit) = java_nested_type_from_context(analyzer, file, normalized, byte)
    {
        return Some(unit);
    }
    java.resolve_type_name_in_file(file, normalized)
}

fn java_nested_type_from_context(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    normalized: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if normalized.contains('.') || normalized.is_empty() {
        return None;
    }
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    let mut owner = class_ranges
        .enclosing(byte)
        .and_then(|fqn| analyzer.definitions(fqn).next());
    while let Some(current) = owner {
        let child_fqn = format!("{}.{}", current.fq_name(), normalized);
        if let Some(child) = analyzer
            .definitions(&child_fqn)
            .find(|code_unit| code_unit.is_class())
        {
            return Some(child);
        }
        owner = analyzer.parent_of(&current);
    }
    None
}

fn java_type_of_identifier_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let bindings = java_bindings_before_scoped(analyzer, java, file, source, root, before_byte);
    first_precise(&bindings, name)
}

const JAVA_TYPE_LOOKUP_SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "block",
    "lambda_expression",
    "catch_clause",
    "enhanced_for_statement",
    "for_statement",
];

fn java_bindings_before_scoped(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CodeUnit> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    java_seed_active_path(
        analyzer,
        java,
        file,
        source,
        root,
        cutoff_start,
        &mut bindings,
    );
    bindings
}

fn java_seed_active_path(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = JAVA_TYPE_LOOKUP_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            continue;
        }
        if enters_scope {
            bindings.enter_scope();
            java_seed_scope_declarations(analyzer, java, file, source, node, bindings);
        } else {
            java_seed_inline_typed_binding(analyzer, java, file, source, node, bindings);
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node
            .named_children(&mut cursor)
            .take_while(|child| child.start_byte() < cutoff_start)
            .collect();
        children.reverse();
        stack.extend(children);
    }
}

fn java_seed_scope_declarations(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" => {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for parameter in parameters.named_children(&mut cursor) {
                    if parameter.kind() == "formal_parameter" {
                        java_seed_inline_typed_binding(
                            analyzer, java, file, source, parameter, bindings,
                        );
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                java_seed_inline_typed_binding(analyzer, java, file, source, parameter, bindings);
            }
        }
        "enhanced_for_statement" => {
            if let Some(name) = node.child_by_field_name("name") {
                bindings.declare_shadow(java_node_text(name, source));
            }
        }
        _ => {}
    }
}

fn java_seed_inline_typed_binding(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration" => {
            let resolved = node.child_by_field_name("type").and_then(|type_node| {
                java_type_from_node_with_context(analyzer, java, file, source, type_node)
            });
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                let binding_name = java_node_text(name, source);
                if let Some(unit) = resolved.as_ref() {
                    bindings.seed_symbol(binding_name, unit.clone());
                } else {
                    bindings.declare_shadow(binding_name);
                }
            }
        }
        "formal_parameter" => {
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            let binding_name = java_node_text(name, source);
            if let Some(unit) = node.child_by_field_name("type").and_then(|type_node| {
                java_type_from_node_with_context(analyzer, java, file, source, type_node)
            }) {
                bindings.seed_symbol(binding_name, unit);
            } else {
                bindings.declare_shadow(binding_name);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn java_lambda_parameter_type_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let type_text = java_lambda_parameter_type_text_before(
        analyzer,
        java,
        support,
        file,
        source,
        root,
        name,
        before_byte,
    )?;
    java_type_text_with_context(
        analyzer,
        java,
        file,
        normalize_java_type_text(&type_text),
        before_byte,
    )
}

#[allow(clippy::too_many_arguments)]
fn java_lambda_parameter_type_text_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let lambda = java_matching_lambda_parameter(root, source, name, before_byte)?;
    let invocation = java_ancestor_method_invocation(lambda)?;
    let method = invocation
        .child_by_field_name("name")
        .map(|node| java_node_text(node, source))?;
    let object = invocation.child_by_field_name("object")?;
    match method {
        "filter" => {
            if object.kind() == "method_invocation"
                && object
                    .child_by_field_name("name")
                    .is_some_and(|node| java_node_text(node, source) == "stream")
                && let Some(collection) = object.child_by_field_name("object")
            {
                return java_collection_element_type_text(
                    analyzer,
                    java,
                    support,
                    file,
                    source,
                    root,
                    collection,
                    lambda.start_byte(),
                );
            }
            java_collection_element_type_text(
                analyzer,
                java,
                support,
                file,
                source,
                root,
                object,
                lambda.start_byte(),
            )
        }
        "forEach" => java_collection_element_type_text(
            analyzer,
            java,
            support,
            file,
            source,
            root,
            object,
            lambda.start_byte(),
        ),
        _ => None,
    }
}

fn java_matching_lambda_parameter<'tree>(
    root: Node<'tree>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > before_byte || node.end_byte() < before_byte {
            continue;
        }
        if node.kind() == "lambda_expression"
            && java_lambda_has_parameter(node, source, name, before_byte)
        {
            let span = node.end_byte() - node.start_byte();
            if best
                .map(|current: Node<'_>| span < current.end_byte() - current.start_byte())
                .unwrap_or(true)
            {
                best = Some(node);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= before_byte && child.end_byte() >= before_byte {
                stack.push(child);
            }
        }
    }
    best
}

fn java_lambda_has_parameter(
    lambda: Node<'_>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> bool {
    let mut cursor = lambda.walk();
    for child in lambda.named_children(&mut cursor) {
        if child.start_byte() >= before_byte {
            continue;
        }
        if child.kind() == "identifier" && java_node_text(child, source) == name {
            return true;
        }
        if matches!(child.kind(), "formal_parameters" | "inferred_parameters") {
            let mut inner = child.walk();
            if child
                .named_children(&mut inner)
                .any(|param| param.kind() == "identifier" && java_node_text(param, source) == name)
            {
                return true;
            }
        }
    }
    false
}

fn java_ancestor_method_invocation(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "method_invocation" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn java_collection_element_type_text(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    if expression.kind() == "method_invocation"
        && expression
            .child_by_field_name("name")
            .is_some_and(|node| java_node_text(node, source) == "values")
        && let Some(object) = expression.child_by_field_name("object")
    {
        let type_text = java_expression_type_text(
            analyzer,
            java,
            support,
            file,
            source,
            root,
            object,
            before_byte,
        )?;
        if !java_is_map_type(&type_text) {
            return None;
        }
        return java_generic_arg(&type_text, 1);
    }
    let type_text = java_expression_type_text(
        analyzer,
        java,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
    )?;
    if !java_is_collection_type(&type_text) {
        return None;
    }
    java_generic_arg(&type_text, 0)
}

#[allow(clippy::too_many_arguments)]
fn java_expression_type_text(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let name = java_node_text(expression, source);
            java_identifier_type_text_before(java, file, source, root, name, before_byte).or_else(
                || {
                    java_lambda_parameter_type_text_before(
                        analyzer,
                        java,
                        support,
                        file,
                        source,
                        root,
                        name,
                        before_byte,
                    )
                },
            )
        }
        "field_access" => {
            let field_node = expression.child_by_field_name("field")?;
            let field = java_node_text(field_node, source);
            let object = expression.child_by_field_name("object")?;
            let owner = java_receiver_type(analyzer, file, source, root, object)?;
            let unit = support
                .fqn(&format!("{}.{}", owner.fq_name(), field))
                .into_iter()
                .next()?;
            let signature = unit
                .signature()
                .map(str::to_string)
                .or_else(|| analyzer.signatures(&unit).first().cloned())?;
            java_field_type_text_from_signature(&signature, field)
        }
        "method_invocation" => {
            if expression
                .child_by_field_name("name")
                .is_some_and(|node| java_node_text(node, source) == "values")
                && let Some(object) = expression.child_by_field_name("object")
            {
                let type_text = java_expression_type_text(
                    analyzer,
                    java,
                    support,
                    file,
                    source,
                    root,
                    object,
                    before_byte,
                )?;
                if !java_is_map_type(&type_text) {
                    return None;
                }
                return java_generic_arg(&type_text, 1);
            }
            None
        }
        _ => None,
    }
}

fn java_identifier_type_text_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let mut found = None;
    collect_java_type_text_binding_before(java, file, source, root, name, before_byte, &mut found);
    found
}

fn collect_java_type_text_binding_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    found: &mut Option<String>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        match node.kind() {
            "local_variable_declaration" | "field_declaration" => {
                if let Some(type_node) = node.child_by_field_name("type") {
                    let type_text = normalize_java_type_text(java_node_text(type_node, source));
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        if child.kind() == "variable_declarator"
                            && let Some(name_node) = child.child_by_field_name("name")
                            && name_node.start_byte() < before_byte
                            && java_node_text(name_node, source) == name
                        {
                            *found = Some(type_text.to_string());
                        }
                    }
                }
            }
            "formal_parameter" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && name_node.start_byte() < before_byte
                    && java_node_text(name_node, source) == name
                    && let Some(type_node) = node.child_by_field_name("type")
                {
                    *found = Some(
                        normalize_java_type_text(java_node_text(type_node, source)).to_string(),
                    );
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            if child.start_byte() < before_byte {
                stack.push(child);
            }
        }
    }
    if found.is_none() && java.resolve_type_name_in_file(file, name).is_some() {
        *found = Some(name.to_string());
    }
}

fn java_field_type_text_from_signature(signature: &str, field: &str) -> Option<String> {
    let before_initializer = signature.split('=').next().unwrap_or(signature);
    let field_start = before_initializer.rfind(field)?;
    let mut type_text = before_initializer[..field_start].trim();
    for modifier in [
        "public",
        "protected",
        "private",
        "static",
        "final",
        "transient",
        "volatile",
    ] {
        type_text = type_text
            .strip_prefix(modifier)
            .unwrap_or(type_text)
            .trim_start();
    }
    (!type_text.is_empty()).then(|| type_text.to_string())
}

fn java_generic_arg(type_text: &str, index: usize) -> Option<String> {
    let start = type_text.find('<')?;
    let end = type_text.rfind('>')?;
    if end <= start {
        return None;
    }
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut arg_start = start + 1;
    let inner = &type_text[start + 1..end];
    for (offset, ch) in inner.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(inner[arg_start - start - 1..offset].trim().to_string());
                arg_start = start + 1 + offset + ch.len_utf8();
            }
            _ => {}
        }
    }
    args.push(type_text[arg_start..end].trim().to_string());
    args.get(index).filter(|arg| !arg.is_empty()).cloned()
}

fn java_is_map_type(type_text: &str) -> bool {
    matches!(
        java_raw_type_name(type_text).as_deref(),
        Some("Map")
            | Some("HashMap")
            | Some("LinkedHashMap")
            | Some("NavigableMap")
            | Some("SortedMap")
            | Some("TreeMap")
            | Some("ConcurrentMap")
            | Some("ConcurrentHashMap")
    )
}

fn java_is_collection_type(type_text: &str) -> bool {
    matches!(
        java_raw_type_name(type_text).as_deref(),
        Some("Iterable")
            | Some("Collection")
            | Some("List")
            | Some("ArrayList")
            | Some("LinkedList")
            | Some("Set")
            | Some("HashSet")
            | Some("LinkedHashSet")
            | Some("SortedSet")
            | Some("NavigableSet")
            | Some("Stream")
    )
}

fn java_raw_type_name(type_text: &str) -> Option<String> {
    let raw = type_text
        .trim()
        .split('<')
        .next()
        .unwrap_or(type_text)
        .trim();
    let name = raw.rsplit('.').next().unwrap_or(raw).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn java_identifier_binding_before(
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> bool {
    let mut found = false;
    collect_java_identifier_binding_before(source, root, name, before_byte, true, &mut found);
    found
}

/// Like [`java_identifier_binding_before`] but counts only local variables and
/// parameters, not field declarations — used to decide whether a bare name is
/// shadowed by a local (and so is not a field reference).
fn java_local_binding_before(source: &str, root: Node<'_>, name: &str, before_byte: usize) -> bool {
    let mut found = false;
    collect_java_identifier_binding_before(source, root, name, before_byte, false, &mut found);
    found
}

fn collect_java_identifier_binding_before(
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    include_fields: bool,
    found: &mut bool,
) {
    if *found {
        return;
    }
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        match node.kind() {
            "local_variable_declaration" | "field_declaration"
                if include_fields || node.kind() == "local_variable_declaration" =>
            {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "variable_declarator"
                        && let Some(name_node) = child.child_by_field_name("name")
                        && name_node.start_byte() < before_byte
                        && java_node_text(name_node, source) == name
                    {
                        *found = true;
                        return;
                    }
                }
            }
            "formal_parameter" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && name_node.start_byte() < before_byte
                    && java_node_text(name_node, source) == name
                {
                    *found = true;
                    return;
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            if child.start_byte() < before_byte {
                stack.push(child);
            }
        }
    }
}

fn java_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    member: &str,
    kind: JavaMemberLookupKind,
    allow_generated_accessors: bool,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let mut candidates =
        java_filter_member_candidates(support.fqn(&format!("{owner_fqn}.{member}")), kind);
    sort_units(&mut candidates);
    candidates.dedup();
    if let Some(filtered_candidates) = java_arity_candidates(analyzer, &candidates, arity) {
        return candidates_outcome(filtered_candidates);
    }
    if !candidates.is_empty() && arity.is_none() {
        return candidates_outcome(candidates);
    }
    let mut fallback_candidates = (!candidates.is_empty()).then_some(candidates);

    let owner = analyzer.definitions(owner_fqn).next();
    if allow_generated_accessors && let Some(owner) = owner.as_ref() {
        let generated_accessor_candidates =
            java_lombok_accessor_field_candidates(analyzer, support, owner, member);
        if !generated_accessor_candidates.is_empty() {
            return candidates_outcome(generated_accessor_candidates);
        }
    }

    if let Some(owner) = owner
        && let Some(provider) = analyzer.type_hierarchy_provider()
    {
        let mut seen = HashSet::default();
        let mut level = provider.get_direct_ancestors(&owner);
        seen.insert(owner);
        while !level.is_empty() {
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates.extend(java_filter_member_candidates(
                    support.fqn(&format!("{}.{}", ancestor.fq_name(), member)),
                    kind,
                ));
                next_level.extend(provider.get_direct_ancestors(&ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            if let Some(filtered_level_candidates) =
                java_arity_candidates(analyzer, &level_candidates, arity)
            {
                return candidates_outcome(filtered_level_candidates);
            }
            if !level_candidates.is_empty() {
                if arity.is_none() {
                    return candidates_outcome(level_candidates);
                }
                fallback_candidates.get_or_insert(level_candidates);
            }
            level = next_level;
        }
    }
    if let Some(candidates) = fallback_candidates {
        return candidates_outcome(candidates);
    }
    no_definition(
        "no_indexed_definition",
        format!("`{owner_fqn}.{member}` is not indexed as a Java definition"),
    )
}

fn java_filter_member_candidates(
    candidates: Vec<CodeUnit>,
    kind: JavaMemberLookupKind,
) -> Vec<CodeUnit> {
    candidates
        .into_iter()
        .filter(|unit| match kind {
            JavaMemberLookupKind::Field => unit.is_field(),
            JavaMemberLookupKind::Method => unit.is_function(),
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JavaAccessorKind {
    Getter,
    Setter,
}

struct JavaAccessorProperty {
    kind: JavaAccessorKind,
    field_name: String,
    requires_boolean_field: bool,
}

pub(crate) fn java_lombok_accessor_field_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    member: &str,
) -> Vec<CodeUnit> {
    let Some(accessor) = java_accessor_property(member) else {
        return Vec::new();
    };
    let mut fields: Vec<_> = support
        .fqn(&format!("{}.{}", owner.fq_name(), accessor.field_name))
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    sort_units(&mut fields);
    fields.dedup();
    if accessor.requires_boolean_field {
        fields.retain(|field| java_field_is_boolean(analyzer, field));
    }
    if fields.is_empty() {
        return Vec::new();
    }

    let owner_has_accessor_annotation = analyzer.get_source(owner, false).is_some_and(|source| {
        java_class_source_has_lombok_accessor_annotation(&source, accessor.kind)
    });
    if owner_has_accessor_annotation {
        return fields;
    }

    fields
        .into_iter()
        .filter(|field| {
            analyzer.get_source(field, false).is_some_and(|source| {
                java_field_source_has_lombok_accessor_annotation(&source, accessor.kind)
            })
        })
        .collect()
}

fn java_accessor_property(member: &str) -> Option<JavaAccessorProperty> {
    let (kind, suffix, requires_boolean_field) = if let Some(suffix) = member.strip_prefix("get") {
        (JavaAccessorKind::Getter, suffix, false)
    } else if let Some(suffix) = member.strip_prefix("is") {
        (JavaAccessorKind::Getter, suffix, true)
    } else if let Some(suffix) = member.strip_prefix("set") {
        (JavaAccessorKind::Setter, suffix, false)
    } else {
        return None;
    };
    if suffix.is_empty()
        || !suffix
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_uppercase())
    {
        return None;
    }
    Some(JavaAccessorProperty {
        kind,
        field_name: java_bean_decapitalize(suffix),
        requires_boolean_field,
    })
}

fn java_field_is_boolean(analyzer: &dyn IAnalyzer, field: &CodeUnit) -> bool {
    let signature = field
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(field).first().cloned());
    let type_text = java_field_type_text_from_source(analyzer, field).or_else(|| {
        signature.as_deref().and_then(|signature| {
            java_field_type_text_from_signature(signature, field.identifier())
        })
    });
    type_text
        .as_deref()
        .and_then(java_raw_type_name)
        .is_some_and(|raw| matches!(raw.as_str(), "boolean" | "Boolean"))
}

fn java_field_type_text_from_source(analyzer: &dyn IAnalyzer, field: &CodeUnit) -> Option<String> {
    let source = analyzer.get_source(field, false)?;
    let wrapped = format!("class __BifrostLombokField {{\n{source}\n}}");
    let tree = parse_java_tree(&wrapped)?;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "field_declaration"
            && let Some(type_node) = node.child_by_field_name("type")
        {
            return Some(java_node_text(type_node, &wrapped).trim().to_string());
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    None
}

fn java_bean_decapitalize(name: &str) -> String {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    if first.is_ascii_uppercase()
        && chars
            .clone()
            .next()
            .is_some_and(|second| second.is_ascii_uppercase())
    {
        return name.to_string();
    }
    let mut out = String::with_capacity(name.len());
    out.push(first.to_ascii_lowercase());
    out.extend(chars);
    out
}

fn java_class_source_has_lombok_accessor_annotation(source: &str, kind: JavaAccessorKind) -> bool {
    java_source_declaration_has_lombok_accessor_annotation(
        source,
        &[
            "class_declaration",
            "record_declaration",
            "enum_declaration",
            "interface_declaration",
        ],
        kind,
    )
}

fn java_field_source_has_lombok_accessor_annotation(source: &str, kind: JavaAccessorKind) -> bool {
    if java_source_declaration_has_lombok_accessor_annotation(source, &["field_declaration"], kind)
    {
        return true;
    }
    let wrapped = format!("class __BifrostLombokAccessor {{\n{source}\n}}");
    java_source_declaration_has_lombok_accessor_annotation(&wrapped, &["field_declaration"], kind)
}

fn java_source_declaration_has_lombok_accessor_annotation(
    source: &str,
    declaration_kinds: &[&str],
    kind: JavaAccessorKind,
) -> bool {
    let Some(tree) = parse_java_tree(source) else {
        return false;
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if declaration_kinds.contains(&node.kind())
            && java_modifiers_have_lombok_accessor_annotation(node, source, kind)
        {
            return true;
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    false
}

fn java_modifiers_have_lombok_accessor_annotation(
    declaration: Node<'_>,
    source: &str,
    kind: JavaAccessorKind,
) -> bool {
    let Some(modifiers) = java_named_child_by_kind(declaration, "modifiers") else {
        return false;
    };
    let mut cursor = modifiers.walk();
    modifiers
        .named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "annotation" | "marker_annotation"))
        .filter_map(|annotation| java_annotation_short_name(annotation, source))
        .any(|name| java_lombok_annotation_generates_accessor(&name, kind))
}

fn java_named_child_by_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn java_annotation_short_name(annotation: Node<'_>, source: &str) -> Option<String> {
    let raw = if let Some(name_node) = annotation.child_by_field_name("name") {
        java_node_text(name_node, source)
    } else {
        java_node_text(annotation, source)
    };
    let trimmed = raw.trim().trim_start_matches('@');
    let short = trimmed.rsplit('.').next().unwrap_or(trimmed).trim();
    (!short.is_empty()).then(|| short.to_string())
}

fn java_lombok_annotation_generates_accessor(name: &str, kind: JavaAccessorKind) -> bool {
    match name {
        "Data" | "Value" => kind == JavaAccessorKind::Getter,
        "Getter" => kind == JavaAccessorKind::Getter,
        "Setter" => kind == JavaAccessorKind::Setter,
        _ => false,
    }
}

fn java_static_import_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    member: &str,
    kind: JavaMemberLookupKind,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let mut candidates = Vec::new();
    let mut saw_external = false;
    for import in analyzer.import_statements(file) {
        let Some(path) = java_static_import_path(&import) else {
            continue;
        };
        if let Some(owner) = path.strip_suffix(".*") {
            let owner_candidates =
                java_filter_member_candidates(support.fqn(&format!("{owner}.{member}")), kind);
            if owner_candidates.is_empty() && !java_workspace_fqn_exists(support, owner) {
                saw_external = true;
            }
            candidates.extend(owner_candidates);
            continue;
        }
        let Some((owner, imported_member)) = path.rsplit_once('.') else {
            continue;
        };
        if imported_member != member {
            continue;
        }
        let imported = java_filter_member_candidates(support.fqn(path), kind);
        if imported.is_empty() && !java_workspace_fqn_exists(support, owner) {
            saw_external = true;
        }
        candidates.extend(imported);
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if let Some(filtered_candidates) = java_arity_candidates(analyzer, &candidates, arity) {
        return candidates_outcome(filtered_candidates);
    }
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if saw_external {
        return boundary(format!(
            "`{member}` appears to cross a Java static import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_static_import_match",
        format!("`{member}` did not match an indexed Java static import"),
    )
}

fn java_import_boundary_for_type(
    java: &JavaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    name: &str,
) -> bool {
    for import in java.import_statements(file) {
        let trimmed = import.trim();
        if trimmed.starts_with("import static ") {
            continue;
        }
        let Some(path) = trimmed
            .strip_prefix("import ")
            .and_then(|rest| rest.strip_suffix(';'))
            .map(str::trim)
        else {
            continue;
        };
        if let Some(package) = path.strip_suffix(".*") {
            if !package.is_empty() && !java_workspace_package_exists(support, package) {
                return true;
            }
            continue;
        }
        if path.rsplit('.').next() == Some(name) {
            let package = path
                .rsplit_once('.')
                .map(|(package, _)| package)
                .unwrap_or("");
            return !java_workspace_package_exists(support, package);
        }
    }
    false
}

fn java_static_import_path(import: &str) -> Option<&str> {
    import
        .trim()
        .strip_prefix("import static ")
        .and_then(|rest| rest.strip_suffix(';'))
        .map(str::trim)
}

fn java_workspace_fqn_exists(support: &dyn BoundedDefinitionLookup, fqn: &str) -> bool {
    support.fqn_exists(fqn)
}

fn java_workspace_package_exists(support: &dyn BoundedDefinitionLookup, package: &str) -> bool {
    support.package_exists(package) || support.fqn_prefix_exists(package)
}

fn java_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

fn normalize_java_type_text(raw: &str) -> &str {
    raw.split('<')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches("[]")
        .trim()
}
