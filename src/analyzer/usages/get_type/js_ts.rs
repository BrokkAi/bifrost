use super::{TypeLookupOutcome, candidates_outcome, no_type};
use crate::analyzer::usages::get_definition::js_ts::{
    jsts_type_space_candidates, resolve_js_ts_module_binding_candidates,
    ts_function_return_property_owners, ts_receiver_owner_candidates_at_byte,
    ts_resolve_type_text_to_property_owners, ts_type_annotation_text,
};
use crate::analyzer::usages::js_ts_graph::compute_jsts_import_binder;
use crate::analyzer::usages::model::{ImportBinder, ImportKind};
use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, smallest_named_node_covering,
};
use crate::analyzer::{
    AliasResolver, CodeUnit, DefinitionLookupIndex, IAnalyzer, Language, ProjectFile,
};
use tree_sitter::{Node, Tree};

pub(super) fn resolve_js_ts_type(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
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

    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_type(
            "no_reference_node",
            "no JS/TS syntax node at reference location",
        );
    };
    let imports = compute_jsts_import_binder(source, tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());

    if let Some(type_node) = type_reference_node(node)
        && let Some(type_name) = type_reference_name(type_node, source)
    {
        return resolve_declared_type_name(
            analyzer, support, file, language, &imports, &aliases, type_name,
        );
    }

    if let Some(type_node) = declaration_type_node_for_reference(node, source, site) {
        return resolve_declared_type_text(
            analyzer, support, file, source, &imports, &aliases, type_node,
        );
    }

    let expression = semantic_expression(node);
    if expression.kind() == "call_expression"
        && let Some(callee_name) = call_expression_name(expression, source)
    {
        let candidates = identifier_candidates(
            analyzer,
            support,
            file,
            language,
            &imports,
            &aliases,
            &callee_name,
            true,
        );
        let mut owners = Vec::new();
        for candidate in candidates {
            owners.extend(ts_function_return_property_owners(
                analyzer, support, &candidate, 0,
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
            analyzer,
            support,
            file,
            source,
            tree.root_node(),
            &imports,
            &aliases,
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
                analyzer, support, file, source, &imports, &aliases, type_node,
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
            analyzer, support, file, source, &imports, &aliases, type_node,
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

fn resolve_declared_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    type_node: Node<'_>,
) -> TypeLookupOutcome {
    let type_text = ts_type_annotation_text(type_node, source);
    if let Some((type_name, candidates)) = qualified_imported_type_candidates(
        analyzer, support, file, type_node, source, imports, aliases,
    ) {
        return candidates_outcome(type_name, candidates);
    }

    if let Some(type_name) = leading_type_identifier(&type_text) {
        let candidates = identifier_candidates(
            analyzer,
            support,
            file,
            Language::TypeScript,
            imports,
            aliases,
            type_name,
            false,
        );
        if !candidates.is_empty() {
            return candidates_outcome(type_name.to_string(), candidates);
        }
    }

    let owners = ts_resolve_type_text_to_property_owners(
        analyzer, support, file, source, imports, aliases, &type_text, 0,
    );
    let owners = prefer_type_definitions(owners);
    if !owners.is_empty() {
        return candidates_outcome(type_lookup_name(&owners, &type_text), owners);
    }

    no_type(
        "unsupported_type_annotation",
        format!("`{type_text}` is not a supported named TypeScript type"),
    )
}

fn resolve_declared_type_name(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    type_name: &str,
) -> TypeLookupOutcome {
    let candidates = identifier_candidates(
        analyzer, support, file, language, imports, aliases, type_name, false,
    );
    if candidates.is_empty() {
        return no_type(
            "no_indexed_type_definition",
            format!("`{type_name}` did not resolve to an indexed TypeScript type"),
        );
    }
    candidates_outcome(type_name.to_string(), candidates)
}

#[allow(clippy::too_many_arguments)]
fn identifier_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = if let Some(binding) = imports.bindings.get(name) {
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(name),
            ImportKind::Default => "default",
            ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => name,
        };
        if matches!(binding.kind, ImportKind::Named | ImportKind::Default) {
            resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                language,
                file,
                &binding.module_specifier,
                exported_name,
                Some(aliases),
                value_position,
            )
        } else {
            Vec::new()
        }
    } else {
        support.file_identifier(file, name)
    };
    if !value_position {
        candidates = jsts_type_space_candidates(analyzer, candidates);
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
    matches!(
        node.kind(),
        "program"
            | "statement_block"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
    )
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
        | "variable_declarator" => {
            child_text_matches(node, "name", source, name)
                || declaration_pattern_node(node)
                    .is_some_and(|pattern| pattern_binds_name(pattern, source, name))
        }
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
        .and_then(|child| source.get(child.start_byte()..child.end_byte()))
        .is_some_and(|text| text.trim() == expected)
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

fn leading_type_identifier(text: &str) -> Option<&str> {
    let text = text.trim().trim_start_matches(':').trim();
    let end = text
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
        .unwrap_or(text.len());
    (end > 0).then_some(&text[..end])
}

#[allow(clippy::too_many_arguments)]
fn qualified_imported_type_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    type_node: Node<'_>,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
) -> Option<(String, Vec<CodeUnit>)> {
    let identifiers = type_identifier_texts(type_node, source);
    let namespace = identifiers.first()?;
    let type_name = identifiers.last()?;
    if namespace == type_name {
        return None;
    }
    let binding = imports.bindings.get(namespace.as_str())?;
    if !matches!(
        binding.kind,
        ImportKind::Namespace | ImportKind::CommonJsRequire
    ) {
        return None;
    }
    let candidates = resolve_js_ts_module_binding_candidates(
        analyzer,
        support,
        Language::TypeScript,
        file,
        &binding.module_specifier,
        type_name,
        Some(aliases),
        false,
    );
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
    identifier_text(node, source).is_some_and(|text| text == name) || {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|child| pattern_binds_name(child, source, name))
    }
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
